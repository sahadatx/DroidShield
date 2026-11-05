"""Strict, bounded allowlists for data crossing the untrusted worker boundary."""

import re
from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    field_validator,
    model_validator,
)

from droidshield.apk_engine import analyze
from droidshield.dex_engine import (
    APIS as DEX_APIS,
)
from droidshield.dex_engine import (
    LIMITATIONS as DEX_LIMITATIONS,
)
from droidshield.dex_engine import (
    make_indicator,
)

ENGINE_VERSION = "droidshield-manifest-2"
LIMITATIONS = (
    "Manifest-only static analysis; application code is not executed or inspected.",
    "Indicators require analyst verification and do not establish exploitability.",
    "APK signing certificates and signature validity are not evaluated by this engine.",
    "Runtime behavior, dependencies, secrets and backend APIs are not evaluated.",
)
IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+\Z")
COMPONENT = re.compile(r"[A-Za-z_][A-Za-z0-9_$]*(?:\.[A-Za-z_][A-Za-z0-9_$]*)+\Z")


class ContractModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class ApplicationMetadata(ContractModel):
    debuggable: StrictBool | None
    uses_cleartext_traffic: StrictBool | None
    allow_backup: StrictBool | None
    test_only: StrictBool | None


class ComponentMetadata(ContractModel):
    kind: Literal["activity", "activity-alias", "service", "receiver", "provider"]
    name: str = Field(min_length=1, max_length=512)
    exported: StrictBool | None
    permission: str | None = Field(max_length=512)

    @field_validator("name", "permission")
    @classmethod
    def identifier(cls, value: str | None) -> str | None:
        if value is not None and not COMPONENT.fullmatch(value):
            raise ValueError("Invalid component identifier")
        return value


class ManifestMetadata(ContractModel):
    package_name: str = Field(min_length=3, max_length=255)
    version_name: str | None = Field(max_length=128)
    version_code: StrictInt | None = Field(ge=0, lt=2**63)
    min_sdk: StrictInt | None = Field(ge=1, le=10000)
    target_sdk: StrictInt | None = Field(ge=1, le=10000)
    permissions: list[str] = Field(max_length=2048)
    application: ApplicationMetadata
    components: list[ComponentMetadata] = Field(max_length=2048)
    signing_certificate: None

    @field_validator("package_name")
    @classmethod
    def package(cls, value: str) -> str:
        if not IDENTIFIER.fullmatch(value):
            raise ValueError("Invalid package identifier")
        return value

    @field_validator("version_name")
    @classmethod
    def safe_version(cls, value: str | None) -> str | None:
        if value is not None and not re.fullmatch(r"[A-Za-z0-9_.+() -]{1,128}", value):
            raise ValueError("Invalid version label")
        return value

    @field_validator("permissions")
    @classmethod
    def safe_permissions(cls, values: list[str]) -> list[str]:
        if values != sorted(set(values)) or any(
            len(value) > 512 or not IDENTIFIER.fullmatch(value) for value in values
        ):
            raise ValueError("Invalid permissions")
        return values


class ManifestEvidence(ContractModel):
    source: Literal["AndroidManifest.xml"]
    attribute: Literal[
        "android:debuggable",
        "android:usesCleartextTraffic",
        "android:allowBackup",
        "android:exported",
    ]
    observed: Literal["true", "implicit_true"]


class ManifestIndicator(ContractModel):
    rule_id: Literal[
        "MANIFEST_DEBUGGABLE",
        "MANIFEST_CLEARTEXT",
        "MANIFEST_BACKUP",
        "MANIFEST_EXPORTED_UNPROTECTED",
    ]
    severity: Literal["high", "medium", "low"]
    title: str = Field(min_length=1, max_length=200)
    affected_component: str = Field(min_length=3, max_length=512)
    description: str = Field(min_length=1, max_length=2000)
    impact: str = Field(min_length=1, max_length=2000)
    remediation: str = Field(min_length=1, max_length=2000)
    reproduction_steps: str = Field(min_length=1, max_length=2000)
    evidence: ManifestEvidence

    @field_validator("affected_component")
    @classmethod
    def component(cls, value: str) -> str:
        if not COMPONENT.fullmatch(value):
            raise ValueError("Invalid component identifier")
        return value

    @field_validator("title", "description", "impact", "remediation", "reproduction_steps")
    @classmethod
    def safe_text(cls, value: str) -> str:
        if not value.isascii() or any(ord(char) < 32 for char in value):
            raise ValueError("Unsafe indicator text")
        return value


class AnalysisResult(ContractModel):
    schema_version: Literal[1]
    engine_version: Literal["droidshield-manifest-2"]
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    file_size: StrictInt = Field(gt=0)
    metadata: ManifestMetadata
    indicators: list[ManifestIndicator] = Field(max_length=2051)
    limitations: list[str] = Field(min_length=4, max_length=4)

    @field_validator("schema_version", mode="before")
    @classmethod
    def exact_protocol_version(cls, value):
        if type(value) is not int or value != 1:
            raise ValueError("Unknown analysis protocol")
        return value

    @field_validator("limitations")
    @classmethod
    def known_limitations(cls, values: list[str]) -> list[str]:
        if values != list(LIMITATIONS):
            raise ValueError("Unknown limitations")
        return values

    @model_validator(mode="after")
    def fixed_indicator_narratives(self):
        # Only the pure text generator is used in the parent; APK parsing remains isolated.
        if self.indicators and [item.model_dump() for item in self.indicators] != analyze(
            self.metadata.model_dump()
        ):
            raise ValueError("Unexpected indicator data")
        return self


class DexEvidence(ContractModel):
    source: str = Field(pattern=r"^classes(?:[2-9]|[1-9][0-9]+)?\.dex$", max_length=32)
    method_index: StrictInt = Field(ge=0, le=65534)
    instruction_offset: StrictInt = Field(ge=0, le=64_000_000)
    observed: Literal["invocation_reference", "const_string_reference"]
    target_api: (
        Literal[
            "java.util.Random.<init>",
            "java.security.MessageDigest.getInstance",
            "javax.crypto.Cipher.getInstance",
            "android.webkit.WebSettings.setJavaScriptEnabled",
            "android.webkit.WebView.setWebContentsDebuggingEnabled",
            "android.webkit.WebSettings.setAllowFileAccess",
            "android.webkit.WebSettings.setAllowFileAccessFromFileURLs",
            "android.webkit.WebSettings.setAllowUniversalAccessFromFileURLs",
        ]
        | None
    )
    literal_category: (
        Literal["md5", "sha1", "des", "ecb", "aws_access_key", "private_key", "credential_literal"]
        | None
    )
    literal_length: StrictInt | None = Field(ge=1, le=65535)


class DexIndicator(ContractModel):
    rule_id: Literal[
        "DEX_INSECURE_RANDOM",
        "DEX_WEAK_HASH_MD5",
        "DEX_WEAK_HASH_SHA1",
        "DEX_WEAK_CIPHER_DES",
        "DEX_CIPHER_ECB",
        "DEX_WEBVIEW_JAVASCRIPT",
        "DEX_WEBVIEW_DEBUGGING",
        "DEX_WEBVIEW_FILE_ACCESS",
        "DEX_SECRET_LITERAL",
    ]
    severity: Literal["high", "medium", "low"]
    title: str = Field(min_length=1, max_length=200)
    affected_component: str = Field(min_length=3, max_length=255)
    description: str = Field(min_length=1, max_length=2000)
    impact: str = Field(min_length=1, max_length=2000)
    remediation: str = Field(min_length=1, max_length=2000)
    reproduction_steps: str = Field(min_length=1, max_length=2000)
    evidence: DexEvidence

    @model_validator(mode="after")
    def fixed_narrative_and_evidence(self):
        if not IDENTIFIER.fullmatch(self.affected_component):
            raise ValueError("Invalid component identifier")
        if self.model_dump() != make_indicator(
            self.rule_id, self.affected_component, self.evidence.model_dump()
        ):
            raise ValueError("Unexpected indicator data")
        evidence = self.evidence
        if self.rule_id == "DEX_SECRET_LITERAL":
            if not (
                evidence.target_api is None
                and evidence.observed == "const_string_reference"
                and evidence.literal_category
                in ("aws_access_key", "private_key", "credential_literal")
                and evidence.literal_length is not None
            ):
                raise ValueError("Invalid redacted literal evidence")
            return self
        if evidence.observed != "invocation_reference" or evidence.literal_length is not None:
            raise ValueError("Invalid invocation evidence")
        crypto = {
            "DEX_WEAK_HASH_MD5": ("java.security.MessageDigest.getInstance", "md5"),
            "DEX_WEAK_HASH_SHA1": ("java.security.MessageDigest.getInstance", "sha1"),
            "DEX_WEAK_CIPHER_DES": ("javax.crypto.Cipher.getInstance", "des"),
            "DEX_CIPHER_ECB": ("javax.crypto.Cipher.getInstance", "ecb"),
        }
        if self.rule_id in crypto:
            if (evidence.target_api, evidence.literal_category) != crypto[self.rule_id]:
                raise ValueError("Invalid cryptographic evidence")
        elif evidence.literal_category is not None or not any(
            (rule, api) == (self.rule_id, evidence.target_api) for rule, api in DEX_APIS.values()
        ):
            raise ValueError("Invalid API evidence")
        return self


class DexSummary(ContractModel):
    dex_files: StrictInt = Field(ge=0, le=128)
    classes: StrictInt = Field(ge=0, le=2_000_000)
    methods: StrictInt = Field(ge=0, le=2_000_000)
    strings: StrictInt = Field(ge=0, le=2_000_000)
    analyzed_methods: StrictInt = Field(ge=0, le=2_000_000)
    code_units: StrictInt = Field(ge=0, le=64_000_000)


class DexAnalysisResult(ContractModel):
    schema_version: Literal[2]
    engine_version: Literal["droidshield-dex-2"]
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    file_size: StrictInt = Field(gt=0)
    metadata: ManifestMetadata
    indicators: list[ManifestIndicator | DexIndicator] = Field(max_length=4099)
    limitations: list[str] = Field(min_length=4, max_length=4)
    dex_summary: DexSummary

    @field_validator("schema_version", mode="before")
    @classmethod
    def exact_protocol_version(cls, value):
        if type(value) is not int or value != 2:
            raise ValueError("Unknown analysis protocol")
        return value

    @field_validator("limitations")
    @classmethod
    def known_limitations(cls, values):
        if values != DEX_LIMITATIONS:
            raise ValueError("Unknown limitations")
        return values

    @model_validator(mode="after")
    def consistent_result(self):
        manifest = [
            item.model_dump() for item in self.indicators if isinstance(item, ManifestIndicator)
        ]
        if manifest != analyze(self.metadata.model_dump()):
            raise ValueError("Unexpected manifest indicators")
        summary = self.dex_summary
        if summary.analyzed_methods > summary.methods:
            raise ValueError("Inconsistent DEX counts")
        if summary.dex_files == 0 and any(
            (
                summary.classes,
                summary.methods,
                summary.strings,
                summary.analyzed_methods,
                summary.code_units,
            )
        ):
            raise ValueError("Inconsistent empty DEX summary")
        seen = set()
        for item in self.indicators:
            if not isinstance(item, DexIndicator):
                continue
            evidence = item.evidence
            dex_number = 1 if evidence.source == "classes.dex" else int(evidence.source[7:-4])
            key = evidence.source, evidence.method_index, item.rule_id
            if not (
                item.affected_component == self.metadata.package_name
                and dex_number <= summary.dex_files
                and evidence.method_index < summary.methods
                and evidence.instruction_offset < summary.code_units
                and key not in seen
            ):
                raise ValueError("Inconsistent DEX evidence")
            seen.add(key)
        return self


def validate_dex_result(value: dict) -> dict:
    """Validate persisted/untrusted DEX output without parsing application bytes."""
    return DexAnalysisResult.model_validate(value).model_dump()
