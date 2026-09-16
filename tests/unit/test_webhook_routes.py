"""Tests for api/routes/webhooks.py"""

from datetime import datetime
from types import SimpleNamespace
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, patch
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.middleware.auth import get_current_user
from api.routes.webhooks import router
from core.database import get_db
from core.services.webhook_service import InvalidWebhookURLError, WebhookLimitExceededError

if TYPE_CHECKING:
    from core.models.webhook import Webhook

USER1 = SimpleNamespace(id=str(uuid4()))
USER2 = SimpleNamespace(id=str(uuid4()))


def make_webhook(user_id):
    now = datetime.utcnow()
    return SimpleNamespace(
        id=str(uuid4()),
        user_id=user_id,
        url="https://hooks.example.com/hook",
        secret="super-secret-value",
        events=["review.completed", "review.failed"],
        description=None,
        is_active=True,
        last_delivery_status=None,
        last_delivery_at=None,
        created_at=now,
        updated_at=now,
    )


@pytest.mark.unit
class TestWebhookRoutes:
    @pytest.fixture
    def app(self):
        app = FastAPI()
        app.include_router(router)

        async def fake_db():
            yield AsyncMock()

        app.dependency_overrides[get_db] = fake_db
        return app

    @pytest.fixture
    def client_as(self, app):
        def _client(user):
            app.dependency_overrides[get_current_user] = lambda: user
            return TestClient(app)

        return _client

    @pytest.fixture
    def store(self):
        """A tiny fake of the ownership-checked service lookups."""
        webhooks: dict[str, Webhook] = {}

        async def fake_get(db, webhook_id, user_id):
            webhook = webhooks.get(str(webhook_id))
            return webhook if webhook and webhook.user_id == user_id else None

        async def fake_delete(db, webhook_id, user_id):
            webhook = await fake_get(db, webhook_id, user_id)
            if not webhook:
                return False
            del webhooks[str(webhook_id)]
            return True

        with (
            patch("api.routes.webhooks.get_webhook", side_effect=fake_get),
            patch("api.routes.webhooks.delete_webhook", side_effect=fake_delete),
        ):
            yield webhooks

    def test_create_returns_201_with_secret(self, client_as):
        webhook = make_webhook(USER1.id)
        with patch("api.routes.webhooks.create_webhook", AsyncMock(return_value=webhook)):
            response = client_as(USER1).post(
                "/webhooks", json={"url": "https://hooks.example.com/hook"}
            )

        assert response.status_code == 201
        assert response.json()["secret"] == "super-secret-value"
        assert response.json()["events"] == ["review.completed", "review.failed"]

    def test_list_and_get_never_include_secret(self, client_as, store):
        webhook = make_webhook(USER1.id)
        store[webhook.id] = webhook
        client = client_as(USER1)

        with patch("api.routes.webhooks.list_webhooks", AsyncMock(return_value=[webhook])):
            listed = client.get("/webhooks")
        fetched = client.get(f"/webhooks/{webhook.id}")

        assert listed.status_code == 200
        assert fetched.status_code == 200
        assert "secret" not in listed.json()[0]
        assert "secret" not in fetched.json()
        assert "super-secret-value" not in listed.text + fetched.text

    def test_other_user_gets_404_on_get_and_delete(self, client_as, store):
        webhook = make_webhook(USER1.id)
        store[webhook.id] = webhook

        client = client_as(USER2)
        assert client.get(f"/webhooks/{webhook.id}").status_code == 404
        assert client.delete(f"/webhooks/{webhook.id}").status_code == 404
        assert webhook.id in store

    def test_owner_can_delete(self, client_as, store):
        webhook = make_webhook(USER1.id)
        store[webhook.id] = webhook

        response = client_as(USER1).delete(f"/webhooks/{webhook.id}")

        assert response.status_code == 204
        assert webhook.id not in store

    def test_limit_exceeded_returns_409(self, client_as):
        with patch(
            "api.routes.webhooks.create_webhook",
            AsyncMock(side_effect=WebhookLimitExceededError()),
        ):
            response = client_as(USER1).post(
                "/webhooks", json={"url": "https://hooks.example.com/hook"}
            )
        assert response.status_code == 409

    def test_invalid_url_returns_422(self, client_as):
        with patch(
            "api.routes.webhooks.create_webhook",
            AsyncMock(side_effect=InvalidWebhookURLError("Webhook URL must use https")),
        ):
            response = client_as(USER1).post("/webhooks", json={"url": "http://127.0.0.1/"})
        assert response.status_code == 422
        assert response.json()["detail"] == "Webhook URL must use https"

    def test_unknown_event_type_returns_422(self, client_as):
        response = client_as(USER1).post(
            "/webhooks",
            json={"url": "https://hooks.example.com/hook", "events": ["review.deleted"]},
        )
        assert response.status_code == 422

    def test_unauthenticated_returns_401(self, app):
        response = TestClient(app).get("/webhooks")
        assert response.status_code == 401
