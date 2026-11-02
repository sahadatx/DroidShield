"""Strict safe metadata contract for isolated cross-platform intake."""

from typing import Literal

from pydantic import Field, StrictBool, StrictInt, field_validator

from droidshield.analysis_contract import ContractModel, ManifestMetadata
from droidshield.mobile_engine import LIMITATIONS


class AABMetadata(ManifestMetadata):
    platform: Literal["android"]
    artifact_format: Literal["aab"]


class IPAMetadata(ContractModel):
    platform: Literal["ios"]
    artifact_format: Literal["ipa"]
    package_name: str = Field(
        max_length=255, pattern=r"^[A-Za-z0-9][A-Za-z0-9-]*(?:\.[A-Za-z0-9][A-Za-z0-9-]*)+$"
    )
    version_name: str | None = Field(max_length=128, pattern=r"^[A-Za-z0-9_.+() -]+$")
    version_code: None
    build_number: str | None = Field(max_length=128, pattern=r"^[A-Za-z0-9_.+() -]+$")
    minimum_os: str | None = Field(max_length=128, pattern=r"^[A-Za-z0-9_.+() -]+$")
    ats_allows_arbitrary_loads: StrictBool | None
    url_scheme_count: StrictInt = Field(ge=0, le=65536)
    usage_description_count: StrictInt = Field(ge=0, le=4096)
    executable_present: Literal[True]
    signature_directory_present: StrictBool


class MobileIntakeResult(ContractModel):
    schema_version: Literal[4]
    engine_version: Literal["droidshield-mobile-intake-1"]
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    file_size: StrictInt = Field(gt=0)
    metadata: IPAMetadata | AABMetadata
    indicators: list = Field(max_length=0)
    limitations: list[str] = Field(min_length=3, max_length=3)

    @field_validator("limitations")
    @classmethod
    def fixed_limitations(cls, value):
        if value != LIMITATIONS:
            raise ValueError("Unexpected limitations")
        return value

    @field_validator("schema_version", mode="before")
    @classmethod
    def exact_version(cls, value):
        if type(value) is not int or value != 4:
            raise ValueError("Unknown intake protocol")
        return value
