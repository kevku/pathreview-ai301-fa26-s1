import asyncio
import hashlib
import hmac
import ipaddress
import secrets
import socket
import time
from datetime import UTC, datetime
from urllib.parse import urlsplit
from uuid import UUID, uuid4

import httpx
import structlog
from sqlalchemy import func, select, update
from tenacity import (
    AsyncRetrying,
    RetryCallState,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from api.schemas.review import ReviewResponse
from api.schemas.webhook import WebhookCreate, WebhookEvent, WebhookEventPayload
from core.config import settings
from core.database import AsyncSessionLocal
from core.models.profile import Profile
from core.models.review import Review
from core.models.webhook import Webhook

log = structlog.get_logger()

MAX_WEBHOOKS_PER_USER = 10
USER_AGENT = "PathReview-Webhooks/1.0"

# Backoff between delivery attempts: 1s, 2s, 4s, ... Tests patch this to wait_none().
RETRY_WAIT = wait_exponential(multiplier=1, max=10)


class InvalidWebhookURLError(ValueError):
    """The callback URL is malformed or points somewhere we refuse to send requests."""


class WebhookLimitExceededError(Exception):
    """The user already has the maximum number of webhooks."""


class _RetryableDeliveryError(Exception):
    """Network error, timeout, 429, or 5xx. Worth trying again."""

    def __init__(self, reason: str, status_code: int | None = None):
        super().__init__(reason)
        self.status_code = status_code


class _PermanentDeliveryError(Exception):
    """Blocked URL, redirect, or non-429 4xx. Retrying will not help."""

    def __init__(self, reason: str, status_code: int | None = None):
        super().__init__(reason)
        self.status_code = status_code


# ---- URL validation (SSRF protection) ----


async def _resolve_host(host: str, port: int) -> list[str]:
    """Return every IP address the host resolves to. IP literals resolve to themselves."""
    try:
        return [str(ipaddress.ip_address(host))]
    except ValueError:
        pass
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return [str(info[4][0]) for info in infos]


def _is_blocked_ip(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
        or not ip.is_global
    )


async def validate_callback_url(url: str) -> None:
    """
    Raise InvalidWebhookURLError unless the URL is safe to POST to.
    Called at registration and again before every delivery attempt (DNS rebinding).
    """
    allow_private = settings.webhook_allow_private_urls
    parts = urlsplit(url)

    allowed_schemes = {"https", "http"} if allow_private else {"https"}
    if parts.scheme not in allowed_schemes:
        raise InvalidWebhookURLError("Webhook URL must use https")
    if parts.username or parts.password:
        raise InvalidWebhookURLError("Webhook URL must not contain credentials")
    if not parts.hostname:
        raise InvalidWebhookURLError("Webhook URL must include a host")
    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError:
        raise InvalidWebhookURLError("Webhook URL has an invalid port")

    if allow_private:
        return

    try:
        addresses = await _resolve_host(parts.hostname, port)
    except (socket.gaierror, UnicodeError):
        raise InvalidWebhookURLError("Webhook URL host could not be resolved")
    if not addresses:
        raise InvalidWebhookURLError("Webhook URL host could not be resolved")
    if any(_is_blocked_ip(address) for address in addresses):
        raise InvalidWebhookURLError("Webhook URL resolves to a private or reserved address")


# ---- CRUD ----


async def create_webhook(
    db,
    user_id: UUID | str,
    data: WebhookCreate,
) -> Webhook:
    """
    Register a webhook for a user. Generates the signing secret.
    Raises InvalidWebhookURLError or WebhookLimitExceededError.
    """
    await validate_callback_url(data.url)

    count_stmt = select(func.count()).select_from(Webhook).where(Webhook.user_id == user_id)
    count_result = await db.execute(count_stmt)
    if count_result.scalar_one() >= MAX_WEBHOOKS_PER_USER:
        raise WebhookLimitExceededError()

    webhook = Webhook(
        user_id=user_id,
        url=data.url,
        secret=secrets.token_urlsafe(32),
        # Deduplicate while keeping order
        events=list(dict.fromkeys(event.value for event in data.events)),
        description=data.description,
        is_active=True,
    )
    db.add(webhook)
    await db.commit()
    await db.refresh(webhook)
    return webhook


async def list_webhooks(
    db,
    user_id: UUID | str,
) -> list[Webhook]:
    """
    List a user's webhooks, oldest first.
    """
    stmt = select(Webhook).where(Webhook.user_id == user_id).order_by(Webhook.created_at)
    result = await db.execute(stmt)
    return list(result.scalars().all())


async def get_webhook(
    db,
    webhook_id: UUID,
    user_id: UUID | str,
) -> Webhook | None:
    """
    Get a webhook by ID, checking ownership.
    """
    stmt = select(Webhook).where((Webhook.id == webhook_id) & (Webhook.user_id == user_id))
    result = await db.execute(stmt)
    return result.scalars().first()


async def delete_webhook(
    db,
    webhook_id: UUID,
    user_id: UUID | str,
) -> bool:
    """
    Delete a webhook, checking ownership. Returns False if not found.
    """
    webhook = await get_webhook(db, webhook_id, user_id)
    if not webhook:
        return False
    await db.delete(webhook)
    await db.commit()
    return True


# ---- Delivery ----


def sign_payload(secret: str, timestamp: int, body: bytes) -> str:
    """HMAC-SHA256 over "{timestamp}.{body}", formatted as "sha256=<hex>"."""
    message = f"{timestamp}.".encode() + body
    digest = hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


async def _post_once(
    client: httpx.AsyncClient,
    webhook: Webhook,
    payload: WebhookEventPayload,
    body: bytes,
) -> int:
    """Make one delivery attempt. Returns the status code on 2xx, raises otherwise."""
    try:
        await validate_callback_url(webhook.url)
    except InvalidWebhookURLError as exc:
        raise _PermanentDeliveryError(f"blocked_url: {exc}")

    timestamp = int(time.time())
    headers = {
        "Content-Type": "application/json",
        "User-Agent": USER_AGENT,
        "X-PathReview-Event": payload.type.value,
        "X-PathReview-Delivery": payload.id,
        "X-PathReview-Timestamp": str(timestamp),
        "X-PathReview-Signature": sign_payload(webhook.secret, timestamp, body),
    }

    try:
        response = await client.post(webhook.url, content=body, headers=headers)
    except httpx.TimeoutException:
        raise _RetryableDeliveryError("timeout")
    except httpx.TransportError as exc:
        raise _RetryableDeliveryError(f"network_error: {type(exc).__name__}")

    code = response.status_code
    if 200 <= code < 300:
        return code
    if code == 429 or code >= 500:
        raise _RetryableDeliveryError("retryable_status", status_code=code)
    if 300 <= code < 400:
        raise _PermanentDeliveryError("redirect_not_followed", status_code=code)
    raise _PermanentDeliveryError("rejected_status", status_code=code)


async def deliver(
    client: httpx.AsyncClient,
    webhook: Webhook,
    payload: WebhookEventPayload,
) -> bool:
    """
    Deliver one event to one webhook, retrying transient failures.
    Never raises. Returns True if the receiver accepted the event.
    """
    body = payload.model_dump_json().encode()
    log_ctx = {
        "webhook_id": str(webhook.id),
        "review_id": str(payload.data.id),
        "event_type": payload.type.value,
    }

    def _log_retry(retry_state: RetryCallState) -> None:
        exc = retry_state.outcome.exception() if retry_state.outcome else None
        log.warning(
            "webhook_delivery_retrying",
            **log_ctx,
            attempt=retry_state.attempt_number,
            status_code=getattr(exc, "status_code", None),
            reason=str(exc),
        )

    attempt_number = 0
    try:
        async for attempt in AsyncRetrying(
            stop=stop_after_attempt(settings.webhook_max_attempts),
            wait=RETRY_WAIT,
            retry=retry_if_exception_type(_RetryableDeliveryError),
            before_sleep=_log_retry,
            reraise=True,
        ):
            with attempt:
                attempt_number = attempt.retry_state.attempt_number
                status_code = await _post_once(client, webhook, payload, body)
    except (_RetryableDeliveryError, _PermanentDeliveryError) as exc:
        log.warning(
            "webhook_delivery_failed",
            **log_ctx,
            attempt=attempt_number,
            status_code=exc.status_code,
            reason=str(exc),
        )
        return False
    except Exception as exc:
        log.error(
            "webhook_delivery_failed",
            **log_ctx,
            attempt=attempt_number,
            status_code=None,
            reason=f"unexpected_error: {type(exc).__name__}",
        )
        return False

    log.info(
        "webhook_delivery_succeeded",
        **log_ctx,
        attempt=attempt_number,
        status_code=status_code,
    )
    return True


async def dispatch_review_event(review_id: UUID, event_type: WebhookEvent) -> None:
    """
    Send a review event to every active webhook of the review's owner that subscribes to it.
    Uses its own sessions so it never touches the caller's session.
    """
    # Load everything up front, then release the connection before making HTTP calls.
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Review).where(Review.id == review_id))
        review = result.scalars().first()
        if not review:
            log.warning(
                "webhook_dispatch_skipped", review_id=str(review_id), reason="review_not_found"
            )
            return

        result = await db.execute(select(Profile).where(Profile.id == review.profile_id))
        profile = result.scalars().first()
        if not profile:
            log.info("webhook_dispatch_skipped", review_id=str(review_id), reason="no_owner")
            return

        result = await db.execute(
            select(Webhook).where(
                (Webhook.user_id == profile.user_id) & (Webhook.is_active.is_(True))
            )
        )
        webhooks = [w for w in result.scalars().all() if event_type.value in (w.events or [])]
        if not webhooks:
            log.info("webhook_dispatch_skipped", review_id=str(review_id), reason="no_webhooks")
            return

        payload = WebhookEventPayload(
            id=f"evt_{uuid4()}",
            type=event_type,
            created_at=datetime.now(UTC),
            data=ReviewResponse.model_validate(review),
        )

    async with httpx.AsyncClient(
        timeout=settings.webhook_timeout_seconds, follow_redirects=False
    ) as client:
        results = await asyncio.gather(*(deliver(client, w, payload) for w in webhooks))

    succeeded = [w.id for w, ok in zip(webhooks, results) if ok]
    failed = [w.id for w, ok in zip(webhooks, results) if not ok]

    try:
        now = datetime.utcnow()
        async with AsyncSessionLocal() as db:
            for ids, status_value in ((succeeded, "succeeded"), (failed, "failed")):
                if ids:
                    await db.execute(
                        update(Webhook)
                        .where(Webhook.id.in_(ids))
                        .values(last_delivery_status=status_value, last_delivery_at=now)
                    )
            await db.commit()
    except Exception as exc:
        log.error("webhook_delivery_status_update_failed", review_id=str(review_id), error=str(exc))
