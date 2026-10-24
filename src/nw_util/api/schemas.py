from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    network: str | None = None
    timeout: float = Field(default=0.5, gt=0, le=30)
    workers: int = Field(default=64, gt=0, le=512)
    max_hosts: int = Field(default=1024, gt=0, le=65_536)
    deep: bool = False
    discover: bool = False
    mdns_timeout: float = Field(default=2.0, gt=0, le=30)
    record_history: bool = True


class WatchRequest(ScanRequest):
    interval: float = Field(default=10.0, ge=1, le=3600)


class AliasRequest(BaseModel):
    name: str = Field(min_length=1, max_length=120)


class SecurityRequest(BaseModel):
    target: str = Field(min_length=1, max_length=255)
    timeout: float = Field(default=1.0, gt=0, le=10)


class ErrorDetail(BaseModel):
    code: str
    message: str
    field: str | None = None
    retryable: bool = False


class ErrorDocument(BaseModel):
    error: ErrorDetail


JobState = Literal["queued", "running", "completed", "failed", "cancelling", "cancelled"]

