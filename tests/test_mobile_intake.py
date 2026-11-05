"""Cross-platform intake uses the real resource-limited Bubblewrap boundary."""

import hashlib
import io
import plistlib
import stat
import struct
import zipfile
from uuid import uuid4

import pytest

from tests.apk_factory import build_apk
from tests.test_api import PREFIX, expect, make_assessment, make_authorization, make_project
from tests.test_uploads import upload_api as _upload_api

upload_api = _upload_api


def ipa_bytes(bundle="com.example.mobile-app", *, binary=True, extra=None, version="1.0"):
    output = io.BytesIO()
    info = {
        "CFBundlePackageType": "APPL",
        "CFBundleIdentifier": bundle,
        "CFBundleExecutable": "Example",
        "CFBundleShortVersionString": version,
        "CFBundleVersion": "42",
        "MinimumOSVersion": "15.0",
        "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True},
        "CFBundleURLTypes": [{"CFBundleURLSchemes": ["sample"]}],
        "NSCameraUsageDescription": "Do not expose this private purpose text",
        "internal_api_key": "not-returned-private-value",
    }
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr(
            "Payload/Example.app/Info.plist",
            plistlib.dumps(info, fmt=plistlib.FMT_BINARY if binary else plistlib.FMT_XML),
        )
        archive.writestr(
            "Payload/Example.app/Example",
            struct.pack("<IIIIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 0, 0, 0, 0),
        )
        for name, data in extra or []:
            archive.writestr(name, data)
    return output.getvalue()


def varint(number):
    result = bytearray()
    while number > 127:
        result.append((number & 127) | 128)
        number >>= 7
    result.append(number)
    return bytes(result)


def proto_field(field, value):
    if isinstance(value, str):
        value = value.encode()
    return varint(field << 3 | 2) + varint(len(value)) + value


def proto_attribute(name, value, *, android=False, compiled=False):
    result = proto_field(2, name)
    if android:
        result += proto_field(1, "http://schemas.android.com/apk/res/android")
    if compiled:
        kind = 8 if type(value) is bool else 7
        primitive = varint(kind << 3) + varint(int(value))
        result += proto_field(6, proto_field(7, primitive))
    else:
        result += proto_field(3, value)
    return result


def aab_bytes(
    *, package="com.example.store", manifest=None, version_code=9, version_code_major=None
):
    app = proto_field(3, "application") + proto_field(
        4, proto_attribute("debuggable", True, android=True, compiled=True)
    )
    root = (
        proto_field(3, "manifest")
        + proto_field(4, proto_attribute("package", package))
        + proto_field(4, proto_attribute("versionCode", str(version_code), android=True))
        + proto_field(4, proto_attribute("versionName", "2.0", android=True))
        + proto_field(5, proto_field(1, app))
    )
    if version_code_major is not None:
        root += proto_field(
            4,
            proto_attribute("versionCodeMajor", version_code_major, android=True, compiled=True),
        )
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr("BundleConfig.pb", b"\x0a\x00")
        archive.writestr(
            "base/manifest/AndroidManifest.xml",
            manifest if manifest is not None else proto_field(1, root),
        )
        archive.writestr("base/dex/classes.dex", b"intake-does-not-inspect-code")
    return output.getvalue()


def draft(api, platform="android", *, assessment_type="full"):
    if platform == "ios":
        android = make_project(api)
        project = expect(
            api.patch(
                f"/projects/{android['id']}",
                {
                    "revision": android["revision"],
                    "platform": "ios",
                    "package_id": "com.example.mobile-app",
                },
            )
        )
    else:
        project = make_project(api)
    target = ("bundle:" if platform == "ios" else "package:") + project["package_id"]
    permit = make_authorization(api, project, approved_targets=[target], verify=True)
    assessment = make_assessment(
        api, project, permit, targets=[target], assessment_type=assessment_type
    )
    return project, assessment


def put(api, assessment, content, filename, *, role="admin", key=None, endpoint="artifact"):
    return api.client.post(
        PREFIX + f"/assessments/{assessment['id']}/{endpoint}",
        data={"revision": str(assessment["revision"])},
        files={"file": (filename, content, "application/octet-stream")},
        headers=api.headers(role, key or str(uuid4())),
    )


@pytest.mark.parametrize("binary", [True, False])
def test_ipa_private_intake_preserves_hash_identity_and_safe_metadata(upload_api, binary):
    api = upload_api
    project, assessment = draft(api, "ios")
    content = ipa_bytes(binary=binary)
    item = expect(put(api, assessment, content, "example.ipa"), 201)
    assert item["platform"] == "ios" and item["artifact_format"] == "ipa"
    assert item["sha256"] == hashlib.sha256(content).hexdigest()
    detail = expect(api.get(f"/artifacts/{item['id']}"))
    assert detail["metadata"]["ats_allows_arbitrary_loads"] is True
    assert detail["metadata"]["package_name"] == project["package_id"]
    assert detail["metadata"]["build_number"] == "42"
    assert "private-value" not in str(detail) and "private purpose" not in str(detail)
    downloaded = api.get(f"/artifacts/{item['id']}/download")
    assert downloaded.content == content
    versions = expect(api.get(f"/projects/{project['id']}/versions"))
    assert versions["items"][0]["artifact_format"] == "ipa"
    current = expect(api.get(f"/assessments/{assessment['id']}"))
    expect(
        api.post(f"/assessments/{assessment['id']}/queue", {"revision": current["revision"]}), 409
    )


def test_aab_protobuf_manifest_intake_is_not_automated_apk_execution(upload_api):
    api = upload_api
    _, assessment = draft(api, assessment_type="static")
    content = aab_bytes()
    item = expect(put(api, assessment, content, "example.aab"), 201)
    assert item["artifact_format"] == "aab" and item["platform"] == "android"
    detail = expect(api.get(f"/artifacts/{item['id']}"))
    assert detail["metadata"]["application"]["debuggable"] is True
    assert detail["version_code"] == 9
    current = expect(api.get(f"/assessments/{assessment['id']}"))
    expect(
        api.post(f"/assessments/{assessment['id']}/queue", {"revision": current["revision"]}), 409
    )
    assert expect(api.get(f"/assessments/{assessment['id']}/findings"))["total"] == 0


def test_aab_long_version_code_is_preserved_through_artifact_storage(upload_api):
    api = upload_api
    _, assessment = draft(api, assessment_type="static")
    content = aab_bytes(version_code=23, version_code_major=17)
    item = expect(put(api, assessment, content, "example.aab"), 201)
    full_code = (17 << 32) | 23
    assert item["version_code"] == full_code
    detail = expect(api.get(f"/artifacts/{item['id']}"))
    assert detail["version_code"] == full_code
    assert detail["metadata"]["version_code"] == full_code


def test_aab_rejects_version_code_components_outside_supported_android_range(upload_api):
    api = upload_api
    _, assessment = draft(api, assessment_type="static")
    content = aab_bytes(version_code=9, version_code_major=2**31)
    expect(put(api, assessment, content, "unsupported.aab"), 422)


def test_generic_apk_upload_preserves_legacy_metadata_and_idempotency(upload_api):
    api = upload_api
    _, assessment = draft(api)
    content = build_apk(package_name="com.example.store")
    key = str(uuid4())
    first = expect(put(api, assessment, content, "example.apk", key=key), 201)
    replay = expect(put(api, assessment, content, "example.apk", key=key), 201)
    assert first["id"] == replay["id"] and first["artifact_format"] == "apk"
    expect(put(api, assessment, content, "changed.apk", key=key), 409)


@pytest.mark.parametrize(
    "filename,content",
    [
        ("wrong.ipa", ipa_bytes(bundle="com.other.app")),
        ("traversal.ipa", ipa_bytes(extra=[("../escape", b"x")])),
        ("duplicate.ipa", ipa_bytes(extra=[("Payload/Second.app/Info.plist", b"x")])),
        ("corrupt.ipa", b"not an archive"),
        ("corrupt.aab", aab_bytes(manifest=b"\x0a\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff")),
    ],
)
def test_rejected_mobile_archives_never_create_artifacts(upload_api, filename, content):
    api = upload_api
    project, assessment = draft(api, "android" if filename.endswith("aab") else "ios")
    expect(put(api, assessment, content, filename), 422)
    assert expect(api.get(f"/projects/{project['id']}/versions"))["total"] == 0


def test_mobile_artifact_rbac_platform_and_legacy_endpoint_fail_closed(upload_api):
    api = upload_api
    _, assessment = draft(api)
    content = ipa_bytes()
    expect(put(api, assessment, content, "example.ipa", role="viewer"), 403)
    expect(put(api, assessment, content, "example.ipa", role="other_admin"), 404)
    expect(put(api, assessment, content, "example.ipa"), 422)
    expect(put(api, assessment, content, "example.ipa", endpoint="apk"), 422)
    api.client.app.state.settings.sandbox_executable = "/missing"
    expect(put(api, assessment, aab_bytes(), "example.aab"), 503)


def test_bundle_targets_and_project_identity_validation(upload_api):
    api = upload_api
    project = make_project(api)
    expect(
        api.patch(
            f"/projects/{project['id']}",
            {"revision": project["revision"], "package_id": "com.invalid-id"},
        ),
        422,
    )
    project = expect(
        api.patch(
            f"/projects/{project['id']}",
            {"revision": project["revision"], "platform": "ios", "package_id": "com.valid-id"},
        )
    )
    make_assessment(api, project, targets=["bundle:com.valid-id"], assessment_type="full")
    expect(
        api.patch(
            f"/projects/{project['id']}",
            {
                "revision": project["revision"],
                "platform": "android",
                "package_id": "com.example.store",
            },
        ),
        409,
    )
    for target in ("bundle:../../etc", "bundle:com.example.*", "bundle:com._invalid"):
        expect(
            api.post(
                "/assessments",
                {
                    "project_id": project["id"],
                    "name": "Rejected",
                    "assessment_type": "full",
                    "requested_targets": [target],
                },
            ),
            422,
        )


def test_ipa_symlink_rejected_inside_sandbox(upload_api):
    api = upload_api
    project, assessment = draft(api, "ios")
    source = io.BytesIO(ipa_bytes())
    with zipfile.ZipFile(source, "a") as archive:
        link = zipfile.ZipInfo("Payload/Example.app/escape")
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(link, "/etc/passwd")
    expect(put(api, assessment, source.getvalue(), "symlink.ipa"), 422)
    assert expect(api.get(f"/projects/{project['id']}/versions"))["total"] == 0


@pytest.mark.parametrize("first_format,second_format", [("apk", "aab"), ("aab", "apk")])
def test_polyglot_dedup_preserves_first_classification_without_binding_second_assessment(
    upload_api, first_format, second_format
):
    api = upload_api
    project, first_assessment = draft(api, assessment_type="static")
    second_assessment = make_assessment(
        api,
        project,
        {"id": first_assessment["authorization_id"]},
        targets=["package:" + project["package_id"]],
        assessment_type="static",
    )
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        for encoded in (
            build_apk(package_name=project["package_id"]),
            aab_bytes(package=project["package_id"]),
        ):
            with zipfile.ZipFile(io.BytesIO(encoded)) as source:
                for entry in source.infolist():
                    archive.writestr(entry, source.read(entry))
    content = output.getvalue()
    first = expect(put(api, first_assessment, content, "polyglot." + first_format), 201)
    original_metadata = expect(api.get(f"/artifacts/{first['id']}"))
    assert first["artifact_format"] == first_format
    expect(put(api, second_assessment, content, "polyglot." + second_format), 409)
    assert expect(api.get(f"/artifacts/{first['id']}")) == original_metadata
    versions = expect(api.get(f"/projects/{project['id']}/versions"))
    assert versions["total"] == 1
    assert versions["items"][0]["id"] == first["id"]
    unbound = expect(api.get(f"/assessments/{second_assessment['id']}"))
    assert unbound["artifact_id"] is None
    assert unbound["revision"] == second_assessment["revision"]
