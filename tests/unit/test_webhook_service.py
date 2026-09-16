"""Tests for webhook_service.py and the webhook hooks in review_service.process_review."""

import hashlib
import hmac
import json
import time
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch
from uuid import uuid4

import httpx
import pytest
from tenacity import wait_none
from werkzeug import Response

from api.schemas.review import ReviewResponse
from api.schemas.webhook import WebhookCreate, WebhookEvent, WebhookEventPayload
from core.config import settings
from core.services import review_service
from core.services.review_service import (
    INTERNAL_ERROR_MESSAGE,
    PROFILE_NOT_FOUND_MESSAGE,
    SAFETY_CHECK_FAILED_MESSAGE,
    process_review,
)
from core.services.webhook_service import (
    MAX_WEBHOOKS_PER_USER,
    InvalidWebhookURLError,
    WebhookLimitExceededError,
    create_webhook,
    deliver,
    dispatch_review_event,
    get_webhook,
    sign_payload,
    validate_callback_url,
)

PUBLIC_IP = "93.184.216.34"


# ---- Helpers ----


def make_result(first=None, all_=None, scalar_one=None):
    """Mock of a SQLAlchemy Result supporting .scalars().first()/.all() and .scalar_one()."""
    result = Mock()
    result.scalars.return_value.first.return_value = first
    result.scalars.return_value.all.return_value = all_ or []
    result.scalar_one.return_value = scalar_one
    return result


def make_session(*execute_results):
    """Mock AsyncSession usable as `async with AsyncSessionLocal() as db`."""
    session = AsyncMock()
    session.add = Mock()
    session.execute = AsyncMock(side_effect=list(execute_results))
    session.__aenter__.return_value = session
    session.__aexit__.return_value = False
    return session


def make_review(status="complete", error_message=None, profile_id=None):
    now = datetime.utcnow()
    return SimpleNamespace(
        id=str(uuid4()),
        profile_id=profile_id or str(uuid4()),
        status=status,
        sections=(
            [
                {
                    "section_name": "Technical Skills",
                    "content": "Good",
                    "confidence": 0.9,
                    "suggestions": ["More tests"],
                }
            ]
            if status == "complete"
            else None
        ),
        overall_score=0.81 if status == "complete" else None,
        error_message=error_message,
        created_at=now,
        updated_at=now,
    )


def make_webhook(url, events=None):
    return SimpleNamespace(
        id=str(uuid4()),
        url=url,
        secret="test-secret",
        events=events or [e.value for e in WebhookEvent],
    )


def make_payload(review=None, event_type=WebhookEvent.REVIEW_COMPLETED):
    return WebhookEventPayload(
        id=f"evt_{uuid4()}",
        type=event_type,
        created_at=datetime.utcnow(),
        data=ReviewResponse.model_validate(review or make_review()),
    )


def logged_events(mock_log):
    """[(level, event_name, kwargs), ...] from a patched structlog logger."""
    return [(c[0], c[1][0], c[2]) for c in mock_log.mock_calls if c[1]]


@pytest.fixture
def allow_private():
    with patch.object(settings, "webhook_allow_private_urls", True):
        yield


@pytest.fixture
def no_retry_wait():
    with patch("core.services.webhook_service.RETRY_WAIT", wait_none()):
        yield


@pytest.fixture
def mock_log():
    with patch("core.services.webhook_service.log") as log:
        yield log


# ---- URL validation ----


@pytest.mark.unit
class TestValidateCallbackUrl:
    @pytest.mark.asyncio
    async def test_accepts_public_https_url(self):
        with patch(
            "core.services.webhook_service._resolve_host",
            AsyncMock(return_value=[PUBLIC_IP]),
        ):
            await validate_callback_url("https://hooks.example.com/pathreview")

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "url",
        [
            "ftp://hooks.example.com/hook",
            "http://hooks.example.com/hook",
            "https://user:pass@hooks.example.com/hook",
            "https://127.0.0.1/hook",
            "https://localhost/hook",
            "https://10.0.0.1/hook",
            "https://192.168.1.1/hook",
            "https://169.254.169.254/latest/meta-data",
            "https://[::1]/hook",
            "https:///no-host",
        ],
    )
    async def test_rejects_unsafe_urls(self, url):
        with pytest.raises(InvalidWebhookURLError):
            await validate_callback_url(url)

    @pytest.mark.asyncio
    async def test_rejects_httpserver_url_by_default(self, httpserver):
        with pytest.raises(InvalidWebhookURLError):
            await validate_callback_url(httpserver.url_for("/hook"))

    @pytest.mark.asyncio
    async def test_rejects_hostname_resolving_to_private_ip(self):
        with (
            patch(
                "core.services.webhook_service._resolve_host",
                AsyncMock(return_value=[PUBLIC_IP, "10.0.0.5"]),
            ),
            pytest.raises(InvalidWebhookURLError),
        ):
            await validate_callback_url("https://hooks.example.com/hook")

    @pytest.mark.asyncio
    async def test_allows_localhost_when_setting_enabled(self, allow_private):
        await validate_callback_url("http://localhost:9000/hook")


# ---- Signing ----


@pytest.mark.unit
class TestSignPayload:
    def test_matches_independent_hmac(self):
        body = b'{"hello": "world"}'
        expected = hmac.new(b"secret", b"1700000000." + body, hashlib.sha256).hexdigest()
        assert sign_payload("secret", 1700000000, body) == f"sha256={expected}"

    def test_changes_with_body_and_timestamp(self):
        base = sign_payload("secret", 1700000000, b"{}")
        assert sign_payload("secret", 1700000000, b'{"a":1}') != base
        assert sign_payload("secret", 1700000001, b"{}") != base


# ---- CRUD ----


@pytest.mark.unit
class TestWebhookCrud:
    @pytest.mark.asyncio
    async def test_create_generates_secret_and_dedupes_events(self):
        db = make_session(make_result(scalar_one=0))
        data = WebhookCreate(
            url="https://hooks.example.com/hook",
            events=[WebhookEvent.REVIEW_COMPLETED, WebhookEvent.REVIEW_COMPLETED],
        )
        with patch(
            "core.services.webhook_service._resolve_host",
            AsyncMock(return_value=[PUBLIC_IP]),
        ):
            webhook = await create_webhook(db, uuid4(), data)

        assert len(webhook.secret) >= 32
        assert webhook.events == ["review.completed"]
        db.add.assert_called_once()
        db.commit.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_create_rejects_when_limit_reached(self):
        db = make_session(make_result(scalar_one=MAX_WEBHOOKS_PER_USER))
        data = WebhookCreate(url="https://hooks.example.com/hook")
        with (
            patch(
                "core.services.webhook_service._resolve_host",
                AsyncMock(return_value=[PUBLIC_IP]),
            ),
            pytest.raises(WebhookLimitExceededError),
        ):
            await create_webhook(db, uuid4(), data)
        db.add.assert_not_called()

    @pytest.mark.asyncio
    async def test_create_rejects_unsafe_url_before_touching_db(self):
        db = make_session()
        with pytest.raises(InvalidWebhookURLError):
            await create_webhook(db, uuid4(), WebhookCreate(url="https://127.0.0.1/hook"))
        db.execute.assert_not_called()

    @pytest.mark.asyncio
    async def test_get_filters_by_owner(self):
        db = make_session(make_result(first=None))
        user_id = uuid4()
        await get_webhook(db, uuid4(), user_id)

        stmt = db.execute.call_args[0][0]
        compiled = stmt.compile()
        assert "webhooks.user_id = " in str(compiled)
        assert user_id in compiled.params.values()


# ---- Delivery ----


@pytest.mark.unit
class TestDeliver:
    @pytest.mark.asyncio
    async def test_completed_review_delivers_envelope_and_headers(
        self, httpserver, allow_private, mock_log
    ):
        httpserver.expect_request("/hook", method="POST").respond_with_data("ok")
        webhook = make_webhook(httpserver.url_for("/hook"))
        review = make_review()
        payload = make_payload(review)

        async with httpx.AsyncClient() as client:
            ok = await deliver(client, webhook, payload)

        assert ok is True
        assert len(httpserver.log) == 1
        request, _ = httpserver.log[0]
        body = request.get_data()
        envelope = json.loads(body)

        assert envelope["id"] == payload.id
        assert envelope["type"] == "review.completed"
        assert envelope["data"]["id"] == review.id
        assert envelope["data"]["status"] == "complete"
        assert envelope["data"]["overall_score"] == 0.81
        assert ReviewResponse.model_validate(envelope["data"])

        headers = request.headers
        assert headers["Content-Type"] == "application/json"
        assert headers["User-Agent"] == "PathReview-Webhooks/1.0"
        assert headers["X-PathReview-Event"] == "review.completed"
        assert headers["X-PathReview-Delivery"] == payload.id
        timestamp = int(headers["X-PathReview-Timestamp"])
        assert abs(time.time() - timestamp) < 60
        assert headers["X-PathReview-Signature"] == sign_payload("test-secret", timestamp, body)

        assert ("info", "webhook_delivery_succeeded") in [
            (level, name) for level, name, _ in logged_events(mock_log)
        ]

    @pytest.mark.asyncio
    async def test_retries_on_500_then_succeeds(
        self, httpserver, allow_private, no_retry_wait, mock_log
    ):
        responses = iter([500, 500, 200])
        httpserver.expect_request("/hook").respond_with_handler(
            lambda request: Response("x", status=next(responses))
        )
        webhook = make_webhook(httpserver.url_for("/hook"))

        async with httpx.AsyncClient() as client:
            ok = await deliver(client, webhook, make_payload())

        assert ok is True
        assert len(httpserver.log) == 3
        events = logged_events(mock_log)
        assert [name for _, name, _ in events].count("webhook_delivery_retrying") == 2
        success = [kw for _, name, kw in events if name == "webhook_delivery_succeeded"]
        assert success[0]["attempt"] == 3

    @pytest.mark.asyncio
    async def test_400_is_not_retried(self, httpserver, allow_private, no_retry_wait, mock_log):
        httpserver.expect_request("/hook").respond_with_data("bad", status=400)
        webhook = make_webhook(httpserver.url_for("/hook"))

        async with httpx.AsyncClient() as client:
            ok = await deliver(client, webhook, make_payload())

        assert ok is False
        assert len(httpserver.log) == 1
        failed = [
            kw for _, name, kw in logged_events(mock_log) if name == "webhook_delivery_failed"
        ]
        assert failed[0]["status_code"] == 400

    @pytest.mark.asyncio
    async def test_429_is_retried(self, httpserver, allow_private, no_retry_wait):
        httpserver.expect_request("/hook").respond_with_data("slow down", status=429)
        webhook = make_webhook(httpserver.url_for("/hook"))

        async with httpx.AsyncClient() as client:
            ok = await deliver(client, webhook, make_payload())

        assert ok is False
        assert len(httpserver.log) == settings.webhook_max_attempts

    @pytest.mark.asyncio
    async def test_timeout_retries_then_gives_up(self, allow_private, no_retry_wait, mock_log):
        # A mocked client rather than a slow httpserver handler: a sleeping handler thread
        # outlives the test and leaks its request into the next test's httpserver.log.
        client = AsyncMock()
        client.post = AsyncMock(side_effect=httpx.ReadTimeout("timed out"))
        webhook = make_webhook("http://localhost:9000/hook")

        with patch.object(settings, "webhook_max_attempts", 2):
            ok = await deliver(client, webhook, make_payload())

        assert ok is False
        assert client.post.await_count == 2
        events = logged_events(mock_log)
        assert [name for _, name, _ in events].count("webhook_delivery_retrying") == 1
        failed = [kw for _, name, kw in events if name == "webhook_delivery_failed"]
        assert failed[0]["reason"] == "timeout"
        assert failed[0]["attempt"] == 2

    @pytest.mark.asyncio
    async def test_redirect_is_not_followed(self, httpserver, allow_private, no_retry_wait):
        httpserver.expect_request("/hook").respond_with_data(
            "", status=302, headers={"Location": httpserver.url_for("/elsewhere")}
        )
        httpserver.expect_request("/elsewhere").respond_with_data("ok")
        webhook = make_webhook(httpserver.url_for("/hook"))

        async with httpx.AsyncClient(follow_redirects=False) as client:
            ok = await deliver(client, webhook, make_payload())

        assert ok is False
        assert [req.path for req, _ in httpserver.log] == ["/hook"]

    @pytest.mark.asyncio
    async def test_httpserver_url_blocked_at_delivery_by_default(self, httpserver, mock_log):
        httpserver.expect_request("/hook").respond_with_data("ok")
        webhook = make_webhook(httpserver.url_for("/hook"))

        async with httpx.AsyncClient() as client:
            ok = await deliver(client, webhook, make_payload())

        assert ok is False
        assert len(httpserver.log) == 0

    @pytest.mark.asyncio
    async def test_dns_rebinding_blocked_at_delivery(self, mock_log):
        # The hostname passed registration, but now resolves to an internal address
        webhook = make_webhook("https://hooks.example.com/hook")
        client = AsyncMock()
        with patch(
            "core.services.webhook_service._resolve_host",
            AsyncMock(return_value=["10.0.0.5"]),
        ):
            ok = await deliver(client, webhook, make_payload())

        assert ok is False
        client.post.assert_not_called()
        failed = [
            kw for _, name, kw in logged_events(mock_log) if name == "webhook_delivery_failed"
        ]
        assert failed[0]["reason"].startswith("blocked_url")


# ---- Dispatch ----


@pytest.mark.unit
class TestDispatchReviewEvent:
    def patch_sessions(self, review, profile, webhooks):
        load = make_session(
            make_result(first=review),
            make_result(first=profile),
            make_result(all_=webhooks),
        )
        status_update = make_session(Mock(), Mock())
        factory = Mock(side_effect=[load, status_update])
        return factory, load, status_update

    @pytest.mark.asyncio
    async def test_opens_own_session_and_sends_to_all_webhooks(
        self, httpserver, allow_private, mock_log
    ):
        httpserver.expect_request("/a").respond_with_data("ok")
        httpserver.expect_request("/b").respond_with_data("ok")
        review = make_review()
        profile = SimpleNamespace(id=review.profile_id, user_id=str(uuid4()))
        webhooks = [make_webhook(httpserver.url_for("/a")), make_webhook(httpserver.url_for("/b"))]
        factory, _, status_update = self.patch_sessions(review, profile, webhooks)

        with patch("core.services.webhook_service.AsyncSessionLocal", factory):
            await dispatch_review_event(review.id, WebhookEvent.REVIEW_COMPLETED)

        assert factory.call_count == 2
        assert sorted(req.path for req, _ in httpserver.log) == ["/a", "/b"]
        # One UPDATE for the succeeded webhooks, then commit
        assert status_update.execute.await_count == 1
        params = status_update.execute.call_args[0][0].compile().params
        assert params["last_delivery_status"] == "succeeded"
        assert params["last_delivery_at"] is not None
        status_update.commit.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_marks_last_delivery_failed_after_exhausted_retries(
        self, httpserver, allow_private, no_retry_wait, mock_log
    ):
        httpserver.expect_request("/hook").respond_with_data("err", status=503)
        review = make_review()
        profile = SimpleNamespace(id=review.profile_id, user_id=str(uuid4()))
        factory, _, status_update = self.patch_sessions(
            review, profile, [make_webhook(httpserver.url_for("/hook"))]
        )

        with patch("core.services.webhook_service.AsyncSessionLocal", factory):
            await dispatch_review_event(review.id, WebhookEvent.REVIEW_COMPLETED)

        params = status_update.execute.call_args[0][0].compile().params
        assert params["last_delivery_status"] == "failed"

    @pytest.mark.asyncio
    async def test_failed_review_sends_review_failed_with_error_message(
        self, httpserver, allow_private, mock_log
    ):
        httpserver.expect_request("/hook").respond_with_data("ok")
        review = make_review(status="failed", error_message=INTERNAL_ERROR_MESSAGE)
        profile = SimpleNamespace(id=review.profile_id, user_id=str(uuid4()))
        factory, _, _ = self.patch_sessions(
            review, profile, [make_webhook(httpserver.url_for("/hook"))]
        )

        with patch("core.services.webhook_service.AsyncSessionLocal", factory):
            await dispatch_review_event(review.id, WebhookEvent.REVIEW_FAILED)

        request, _ = httpserver.log[0]
        envelope = json.loads(request.get_data())
        assert request.headers["X-PathReview-Event"] == "review.failed"
        assert envelope["type"] == "review.failed"
        assert envelope["data"]["status"] == "failed"
        assert envelope["data"]["error_message"] == INTERNAL_ERROR_MESSAGE

    @pytest.mark.asyncio
    async def test_webhook_not_subscribed_to_failed_receives_nothing(
        self, httpserver, allow_private, mock_log
    ):
        review = make_review(status="failed", error_message=SAFETY_CHECK_FAILED_MESSAGE)
        profile = SimpleNamespace(id=review.profile_id, user_id=str(uuid4()))
        webhook = make_webhook(httpserver.url_for("/hook"), events=["review.completed"])
        factory, _, _ = self.patch_sessions(review, profile, [webhook])

        with patch("core.services.webhook_service.AsyncSessionLocal", factory):
            await dispatch_review_event(review.id, WebhookEvent.REVIEW_FAILED)

        assert len(httpserver.log) == 0
        skipped = [
            kw for _, name, kw in logged_events(mock_log) if name == "webhook_dispatch_skipped"
        ]
        assert skipped[0]["reason"] == "no_webhooks"

    @pytest.mark.asyncio
    async def test_skips_when_profile_missing(self, mock_log):
        review = make_review(status="failed")
        load = make_session(make_result(first=review), make_result(first=None))
        factory = Mock(return_value=load)

        with (
            patch("core.services.webhook_service.AsyncSessionLocal", factory),
            patch("core.services.webhook_service.httpx.AsyncClient") as client_cls,
        ):
            await dispatch_review_event(review.id, WebhookEvent.REVIEW_FAILED)

        client_cls.assert_not_called()
        skipped = [
            kw for _, name, kw in logged_events(mock_log) if name == "webhook_dispatch_skipped"
        ]
        assert skipped[0]["reason"] == "no_owner"


# ---- process_review integration points ----


@pytest.mark.unit
class TestProcessReviewWebhooks:
    @pytest.fixture
    def review(self):
        return SimpleNamespace(
            id=str(uuid4()),
            status="pending",
            error_message=None,
            sections=None,
            overall_score=None,
            updated_at=None,
        )

    @pytest.fixture
    def profile(self):
        return SimpleNamespace(id=str(uuid4()), user_id=str(uuid4()))

    @pytest.fixture
    def stubbed_pipeline(self):
        with patch.object(review_service, "_run_ingestion_pipeline", AsyncMock(return_value=[])):
            yield

    @pytest.mark.asyncio
    async def test_success_sends_review_completed(self, review, profile, stubbed_pipeline):
        db = make_session(make_result(first=review), make_result(first=profile))
        with patch.object(review_service, "dispatch_review_event", AsyncMock()) as dispatch:
            await process_review(db, review.id, profile.id)

        assert review.status == "complete"
        dispatch.assert_awaited_once_with(review.id, WebhookEvent.REVIEW_COMPLETED)

    @pytest.mark.asyncio
    async def test_safety_check_failure_sends_review_failed(
        self, review, profile, stubbed_pipeline
    ):
        db = make_session(make_result(first=review), make_result(first=profile))
        with (
            patch.object(review_service, "_run_safety_checks", AsyncMock(return_value=False)),
            patch.object(review_service, "dispatch_review_event", AsyncMock()) as dispatch,
        ):
            await process_review(db, review.id, profile.id)

        assert review.status == "failed"
        assert review.error_message == SAFETY_CHECK_FAILED_MESSAGE
        dispatch.assert_awaited_once_with(review.id, WebhookEvent.REVIEW_FAILED)

    @pytest.mark.asyncio
    async def test_unexpected_error_uses_generic_message(self, review, profile, stubbed_pipeline):
        raw = "connection to db-internal:5432 failed, password=hunter2"
        db = make_session(
            make_result(first=review), make_result(first=profile), make_result(first=review)
        )
        with (
            patch.object(
                review_service, "_run_agent_orchestration", AsyncMock(side_effect=RuntimeError(raw))
            ),
            patch.object(review_service, "dispatch_review_event", AsyncMock()) as dispatch,
        ):
            await process_review(db, review.id, profile.id)

        assert review.status == "failed"
        assert review.error_message == INTERNAL_ERROR_MESSAGE
        assert "hunter2" not in review.error_message
        dispatch.assert_awaited_once_with(review.id, WebhookEvent.REVIEW_FAILED)

    @pytest.mark.asyncio
    async def test_profile_not_found_marks_failed_and_skips_delivery(self, review, mock_log):
        db = make_session(make_result(first=review), make_result(first=None))
        # dispatch_review_event runs for real and finds no owner
        load = make_session(
            make_result(first=make_review(status="failed")), make_result(first=None)
        )
        with (
            patch("core.services.webhook_service.AsyncSessionLocal", Mock(return_value=load)),
            patch("core.services.webhook_service.httpx.AsyncClient") as client_cls,
        ):
            await process_review(db, review.id, uuid4())

        assert review.status == "failed"
        assert review.error_message == PROFILE_NOT_FOUND_MESSAGE
        client_cls.assert_not_called()
        skipped = [
            kw for _, name, kw in logged_events(mock_log) if name == "webhook_dispatch_skipped"
        ]
        assert skipped[0]["reason"] == "no_owner"

    @pytest.mark.asyncio
    async def test_dispatch_error_does_not_affect_review(self, review, profile, stubbed_pipeline):
        db = make_session(make_result(first=review), make_result(first=profile))
        with patch.object(
            review_service,
            "dispatch_review_event",
            AsyncMock(side_effect=RuntimeError("receiver exploded")),
        ):
            await process_review(db, review.id, profile.id)  # must not raise

        assert review.status == "complete"
        assert review.error_message is None
