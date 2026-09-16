from datetime import datetime
from enum import StrEnum
from uuid import UUID

from pydantic import BaseModel, Field

from api.schemas.review import ReviewResponse


class WebhookEvent(StrEnum):
    REVIEW_COMPLETED = "review.completed"
    REVIEW_FAILED = "review.failed"


class WebhookCreate(BaseModel):
    url: str = Field(max_length=2048)
    events: list[WebhookEvent] = Field(default_factory=lambda: list(WebhookEvent), min_length=1)
    description: str | None = Field(default=None, max_length=255)


class WebhookResponse(BaseModel):
    id: UUID
    url: str
    events: list[WebhookEvent]
    description: str | None
    is_active: bool
    last_delivery_status: str | None
    last_delivery_at: datetime | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class WebhookCreatedResponse(WebhookResponse):
    # Only returned once, at creation. Used to verify X-PathReview-Signature.
    secret: str


class WebhookEventPayload(BaseModel):
    id: str
    type: WebhookEvent
    created_at: datetime
    data: ReviewResponse
