from uuid import UUID

import structlog
from fastapi import APIRouter, Depends, HTTPException, status

from api.middleware.auth import get_current_user
from api.schemas.webhook import WebhookCreate, WebhookCreatedResponse, WebhookResponse
from core.database import get_db
from core.models.user import User
from core.services.webhook_service import (
    MAX_WEBHOOKS_PER_USER,
    InvalidWebhookURLError,
    WebhookLimitExceededError,
    create_webhook,
    delete_webhook,
    get_webhook,
    list_webhooks,
)

log = structlog.get_logger()

router = APIRouter(prefix="/webhooks", tags=["webhooks"])


@router.post("", response_model=WebhookCreatedResponse, status_code=status.HTTP_201_CREATED)
async def create_webhook_endpoint(
    data: WebhookCreate,
    current_user: User = Depends(get_current_user),
    db=Depends(get_db),
):
    """
    Register a callback URL that receives review.completed / review.failed events.
    The signing secret is returned in this response only.
    Returns 422 for an unsafe URL and 409 when the user already has the maximum.
    """
    try:
        webhook = await create_webhook(db=db, user_id=current_user.id, data=data)

        log.info(
            "webhook_created",
            webhook_id=str(webhook.id),
            user_id=str(current_user.id),
            events=webhook.events,
        )

        return WebhookCreatedResponse.model_validate(webhook)

    except InvalidWebhookURLError as exc:
        log.warning("webhook_creation_invalid_url", user_id=str(current_user.id), reason=str(exc))
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        )
    except WebhookLimitExceededError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user can register at most {MAX_WEBHOOKS_PER_USER} webhooks",
        )
    except HTTPException:
        raise
    except Exception as exc:
        log.error("webhook_creation_error", error=str(exc))
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create webhook",
        )


@router.get("", response_model=list[WebhookResponse])
async def list_webhooks_endpoint(
    current_user: User = Depends(get_current_user),
    db=Depends(get_db),
):
    """
    List the current user's webhooks. Secrets are never included.
    """
    try:
        webhooks = await list_webhooks(db=db, user_id=current_user.id)
        return [WebhookResponse.model_validate(w) for w in webhooks]

    except Exception as exc:
        log.error("list_webhooks_error", error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to list webhooks",
        )


@router.get("/{webhook_id}", response_model=WebhookResponse)
async def get_webhook_endpoint(
    webhook_id: UUID,
    current_user: User = Depends(get_current_user),
    db=Depends(get_db),
):
    """
    Get a webhook by ID.
    Returns 404 if not found or not owned by current user.
    """
    try:
        webhook = await get_webhook(db=db, webhook_id=webhook_id, user_id=current_user.id)

        if not webhook:
            log.warning(
                "webhook_not_found",
                webhook_id=str(webhook_id),
                user_id=str(current_user.id),
            )
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Webhook not found",
            )

        return WebhookResponse.model_validate(webhook)

    except HTTPException:
        raise
    except Exception as exc:
        log.error("get_webhook_error", error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve webhook",
        )


@router.delete("/{webhook_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_webhook_endpoint(
    webhook_id: UUID,
    current_user: User = Depends(get_current_user),
    db=Depends(get_db),
):
    """
    Delete a webhook.
    Returns 404 if not found or not owned by current user.
    """
    try:
        deleted = await delete_webhook(db=db, webhook_id=webhook_id, user_id=current_user.id)

        if not deleted:
            log.warning(
                "webhook_not_found",
                webhook_id=str(webhook_id),
                user_id=str(current_user.id),
            )
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Webhook not found",
            )

        log.info("webhook_deleted", webhook_id=str(webhook_id), user_id=str(current_user.id))

    except HTTPException:
        raise
    except Exception as exc:
        log.error("delete_webhook_error", error=str(exc))
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete webhook",
        )
