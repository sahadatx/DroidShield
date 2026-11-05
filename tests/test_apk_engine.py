import hashlib
import io
import shutil
import struct
import subprocess
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from droidshield.analysis_contract import AnalysisResult
from droidshield.apk_engine import (
    ANDROID_ATTRIBUTES,
    InvalidAPK,
    inspect_apk,
    metadata_from_nodes,
    parse_manifest,
    string_pool,
)
from tests.apk_factory import binary_manifest, build_apk


def engine_args(**updates):
    values = dict(
        mode="analyze",
        max_bytes=100 * 1024 * 1024,
        max_entries=10000,
        max_uncompressed=512 * 1024 * 1024,
        max_manifest=4 * 1024 * 1024,
        max_ratio=100,
    )
    values.update(updates)
    return SimpleNamespace(**values)


@pytest.mark.parametrize("utf8", [True, False])
def test_binary_manifest_parses_real_attributes_and_candidates(tmp_path, utf8):
    apk = build_apk(
        utf8=utf8,
        debuggable=True,
        cleartext=True,
        allow_backup=True,
        permissions=("android.permission.INTERNET", "android.permission.CAMERA"),
        components=(
            {"name": ".MainActivity", "exported": True},
            {
                "name": "ProtectedService",
                "kind": "service",
                "exported": True,
                "permission": "com.example.SECURE",
            },
            {"name": ".PrivateReceiver", "kind": "receiver", "exported": False},
        ),
    )
    path = tmp_path / "app.apk"
    path.write_bytes(apk)
    result = inspect_apk(path, engine_args())
    assert AnalysisResult.model_validate(result).model_dump() == result
    assert result["sha256"] == hashlib.sha256(apk).hexdigest()
    assert result["file_size"] == len(apk)
    assert result["metadata"]["version_name"] == "1.2.3"
    assert result["metadata"]["version_code"] == 7
    assert result["metadata"]["min_sdk"] == 23
    assert result["metadata"]["target_sdk"] == 35
    assert result["metadata"]["permissions"] == [
        "android.permission.CAMERA",
        "android.permission.INTERNET",
    ]
    assert [item["rule_id"] for item in result["indicators"]] == [
        "MANIFEST_DEBUGGABLE",
        "MANIFEST_CLEARTEXT",
        "MANIFEST_BACKUP",
        "MANIFEST_EXPORTED_UNPROTECTED",
    ]
    assert result["indicators"][-1]["affected_component"] == "com.example.app.MainActivity"
    assert all("Confirmed" not in item["description"] for item in result["indicators"])


def test_inspection_has_no_findings_and_inherited_permission_is_preserved(tmp_path):
    path = tmp_path / "app.apk"
    path.write_bytes(
        build_apk(
            debuggable=True,
            application_permission="com.example.SECURE",
            components=({"name": ".Main", "exported": True},),
        )
    )
    result = inspect_apk(path, engine_args(mode="inspect"))
    assert result["indicators"] == []
    assert result["metadata"]["components"][0]["permission"] == "com.example.SECURE"


def test_full_android_version_code_is_composed_and_bounded(tmp_path):
    path = tmp_path / "version.apk"
    path.write_bytes(build_apk(version_code=9, version_code_major=2))
    result = inspect_apk(path, engine_args())
    assert result["metadata"]["version_code"] == (2 << 32) | 9
    assert AnalysisResult.model_validate(result)
    path.write_bytes(build_apk(version_code=2**31 - 1, version_code_major=2**31 - 1))
    result = inspect_apk(path, engine_args())
    assert result["metadata"]["version_code"] == ((2**31 - 1) << 32) | (2**31 - 1)
    assert AnalysisResult.model_validate(result)
    for kwargs in (
        {"version_code": 2**31},
        {"version_code": "@integer/version_code"},
        {"version_code_major": 2**31},
        {"version_code_major": "@integer/version_major"},
    ):
        path.write_bytes(build_apk(**kwargs))
        with pytest.raises(InvalidAPK):
            inspect_apk(path, engine_args())
    result["metadata"]["version_code"] = 2**63
    with pytest.raises(ValidationError):
        AnalysisResult.model_validate(result)


@pytest.mark.parametrize(
    "manifest",
    [
        b"<manifest package='com.example.app'/>",
        b"\x03\x00\x08\x00\x08\x00\x00\x00",
        binary_manifest()[:-1],
        binary_manifest(package_name="../../secret"),
        binary_manifest(permissions=("bad\npermission",)),
        binary_manifest(components=({"name": "../../../bad", "exported": True},)),
    ],
)
def test_rejects_non_binary_corrupt_and_unsafe_manifest(manifest):
    with pytest.raises((InvalidAPK, UnicodeError)):
        metadata_from_nodes(parse_manifest(manifest))


def test_rejects_out_of_bounds_chunks_and_string_offsets():
    manifest = bytearray(binary_manifest())
    struct.pack_into("<I", manifest, 8 + 4, len(manifest) + 100)
    with pytest.raises(InvalidAPK):
        parse_manifest(manifest)
    manifest = bytearray(binary_manifest())
    struct.pack_into("<I", manifest, 8 + 28, 0xFFFFFFFE)
    with pytest.raises(InvalidAPK):
        parse_manifest(manifest)


@pytest.mark.parametrize(
    "name",
    [
        "../escape",
        "/absolute",
        "res/../escape",
        "res\\escape",
        "res//escape",
        "C:escape",
        "res/\x01escape",
    ],
)
def test_rejects_archive_paths(tmp_path, name):
    path = tmp_path / "unsafe.apk"
    path.write_bytes(build_apk(extra_entries=((name, b"value"),)))
    with pytest.raises(InvalidAPK):
        inspect_apk(path, engine_args())


def test_rejects_zip_bombs_and_archive_limits(tmp_path):
    path = tmp_path / "bomb.apk"
    path.write_bytes(
        build_apk(compression=zipfile.ZIP_DEFLATED, extra_entries=(("assets/bomb", b"x" * 100000),))
    )
    with pytest.raises(InvalidAPK):
        inspect_apk(path, engine_args())
    path.write_bytes(build_apk())
    for args in (
        engine_args(max_bytes=1),
        engine_args(max_entries=1),
        engine_args(max_uncompressed=1),
        engine_args(max_manifest=1),
    ):
        with pytest.raises(InvalidAPK):
            inspect_apk(path, args)


def test_rejects_symlinks_duplicates_encryption_and_unsupported_compression(tmp_path):
    for attack in ("symlink", "duplicate", "encrypted", "bzip2"):
        path = tmp_path / "unsafe.apk"
        if attack == "symlink":
            info = zipfile.ZipInfo("assets/link")
            info.create_system = 3
            info.external_attr = 0o120777 << 16
            data = build_apk(extra_entries=((info, b"/etc/passwd"),))
        elif attack == "duplicate":
            with pytest.warns(UserWarning):
                data = build_apk(extra_entries=(("classes.dex", b"duplicate"),))
        elif attack == "encrypted":
            data = bytearray(build_apk())
            central = data.index(b"PK\x01\x02")
            struct.pack_into("<H", data, central + 8, 1)
        else:
            data = build_apk(compression=zipfile.ZIP_BZIP2)
        path.write_bytes(data)
        with pytest.raises(InvalidAPK):
            inspect_apk(path, engine_args())


def test_zip_disguised_as_apk_is_not_accepted(tmp_path):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr("AndroidManifest.xml", binary_manifest())
        archive.writestr("random.txt", b"not an APK")
    path = tmp_path / "disguised.apk"
    path.write_bytes(output.getvalue())
    with pytest.raises(InvalidAPK):
        inspect_apk(path, engine_args())


def test_parent_contract_rejects_extra_keys_or_unsafe_metadata(tmp_path):
    path = tmp_path / "app.apk"
    path.write_bytes(build_apk())
    result = inspect_apk(path, engine_args())
    result["raw_request"] = "must not escape"
    with pytest.raises(ValidationError):
        AnalysisResult.model_validate(result)
    result.pop("raw_request")
    result["metadata"]["package_name"] = "com.example.app\nsecret"
    with pytest.raises(ValidationError):
        AnalysisResult.model_validate(result)
    result["metadata"]["package_name"] = "com.example.app"
    result["schema_version"] = True
    with pytest.raises(ValidationError):
        AnalysisResult.model_validate(result)


def test_parent_contract_rejects_arbitrary_indicator_narrative(tmp_path):
    path = tmp_path / "app.apk"
    path.write_bytes(build_apk(debuggable=True))
    result = inspect_apk(path, engine_args())
    result["indicators"][0]["description"] = "A raw secret must not enter a finding"
    with pytest.raises(ValidationError):
        AnalysisResult.model_validate(result)


def test_rejects_spoofed_attribute_namespace_and_conflicting_typed_values():
    manifest = bytearray(binary_manifest(debuggable=True))
    # Locate the binary application start node and its first attribute.
    offset = 8
    elements = []
    while offset < len(manifest):
        kind, _, size = struct.unpack_from("<HHI", manifest, offset)
        if kind == 0x0102:
            elements.append(offset)
        offset += size
    first_attribute = elements[-1] + 36
    struct.pack_into("<I", manifest, first_attribute, 0xFFFFFFFF)
    with pytest.raises(InvalidAPK):
        parse_manifest(manifest)
    manifest = bytearray(binary_manifest(debuggable=True))
    # The package string's raw value disagrees with its typed string index.
    first_attribute = elements[0] + 36
    struct.pack_into("<I", manifest, first_attribute + 16, 0)
    with pytest.raises(InvalidAPK):
        parse_manifest(manifest)


def test_resource_map_spoofing_and_duplicate_maps_are_rejected():
    manifest = binary_manifest(debuggable=True)
    _, pool_header, pool_size = struct.unpack_from("<HHI", manifest, 8)
    strings = string_pool(manifest[8 : 8 + pool_size], pool_header)
    resource_ids = [ANDROID_ATTRIBUTES.get(value, 0) for value in strings]

    def with_maps(*ids):
        maps = b"".join(
            struct.pack("<HHI", 0x0180, 8, 8 + len(values) * 4)
            + struct.pack("<" + "I" * len(values), *values)
            for values in ids
        )
        result = bytearray(manifest[: 8 + pool_size] + maps + manifest[8 + pool_size :])
        struct.pack_into("<I", result, 4, len(result))
        return result

    assert (
        metadata_from_nodes(parse_manifest(with_maps(resource_ids)))["application"]["debuggable"]
        is True
    )
    with pytest.raises(InvalidAPK):
        parse_manifest(with_maps(resource_ids, resource_ids))
    resource_ids[strings.index("debuggable")] = ANDROID_ATTRIBUTES["exported"]
    with pytest.raises(InvalidAPK):
        parse_manifest(with_maps(resource_ids))


def test_independent_aapt_compiled_manifest_is_supported(tmp_path):
    aapt = shutil.which("aapt")
    framework = Path("/usr/share/android-framework-res/framework-res.apk")
    if aapt is None or not framework.is_file():
        pytest.skip("Optional Android aapt fixture compiler is not installed")
    manifest = tmp_path / "AndroidManifest.xml"
    manifest.write_text("""<manifest xmlns:android="http://schemas.android.com/apk/res/android"
        package="com.independent.sample" android:versionCode="12" android:versionName="2.0">
        <uses-sdk android:minSdkVersion="23" android:targetSdkVersion="28" />
        <uses-permission android:name="android.permission.INTERNET" />
        <application android:debuggable="true" android:usesCleartextTraffic="true">
            <activity android:name=".MainActivity" android:exported="true" />
        </application>
    </manifest>""")
    values = tmp_path / "res" / "values"
    values.mkdir(parents=True)
    (values / "strings.xml").write_text(
        '<resources><string name="app_name">Sample</string></resources>'
    )
    apk = tmp_path / "compiled.apk"
    subprocess.run(
        [
            aapt,
            "package",
            "-f",
            "-M",
            str(manifest),
            "-S",
            str(tmp_path / "res"),
            "-I",
            str(framework),
            "-F",
            str(apk),
        ],
        check=True,
        capture_output=True,
        timeout=15,
    )
    result = inspect_apk(apk, engine_args())
    assert result["metadata"]["package_name"] == "com.independent.sample"
    assert result["metadata"]["version_code"] == 12
    assert result["metadata"]["application"]["debuggable"] is True
    assert len(result["indicators"]) == 3
