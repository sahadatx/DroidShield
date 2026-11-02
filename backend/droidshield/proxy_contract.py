"""Only bounded, redacted traffic observations cross the runtime boundary."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictInt, field_validator, model_validator

PROXY_VERSION = "droidshield-proxy-1"
PROXY_LIMITATIONS = [
    "Only explicitly approved HTTPS GET/HEAD endpoints are forwarded; other methods, targets and redirects are blocked.",
    "The application must use the configured lab proxy and trust its dedicated CA; certificate pinning and TLS validation are not bypassed.",
    "Only status, TLS version and byte counts are retained; URLs, query strings, headers, bodies and credentials are not captured as evidence.",
    "Observation is time and request bounded; absent traffic does not establish security or complete assessment coverage.",
]


class ProxyObservation(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    target_index: StrictInt = Field(ge=0, le=9)
    method: Literal["GET", "HEAD"]
    status_code: StrictInt = Field(ge=100, le=599)
    tls_version: Literal["TLSv1.2", "TLSv1.3"]
    response_bytes: StrictInt = Field(ge=0, le=262144)


class ProxySummary(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    engine_version: Literal[PROXY_VERSION] = PROXY_VERSION
    requests_forwarded: StrictInt = Field(ge=0, le=60)
    blocked_requests: StrictInt = Field(ge=0, le=10000)
    tls_failures: StrictInt = Field(ge=0, le=10000)
    response_bytes: StrictInt = Field(ge=0, le=60 * 262144)
    observations: list[ProxyObservation] = Field(max_length=60)
    requires_review: Literal[True] = True
    limitations: list[str] = Field(min_length=4, max_length=4)

    @field_validator("limitations")
    @classmethod
    def fixed_limitations(cls, value):
        if value != PROXY_LIMITATIONS:
            raise ValueError("Unexpected traffic limitations")
        return value

    @model_validator(mode="after")
    def consistent(self):
        if self.requests_forwarded != len(self.observations) or self.response_bytes != sum(
            item.response_bytes for item in self.observations
        ):
            raise ValueError("Inconsistent traffic summary")
        return self
