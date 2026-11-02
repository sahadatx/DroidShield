"""Small, real Android binary-XML fixtures; no Android build tools required."""

import io
import struct
import zipfile
from pathlib import Path

ANDROID_NS = "http://schemas.android.com/apk/res/android"


def binary_manifest(
    package_name="com.example.app",
    debuggable=False,
    cleartext=False,
    allow_backup=False,
    test_only=False,
    version_name="1.2.3",
    version_code=7,
    version_code_major=None,
    min_sdk=23,
    target_sdk=35,
    permissions=("android.permission.INTERNET",),
    components=(),
    utf8=True,
    application_permission=None,
):
    nodes = [
        (
            "manifest",
            {"package": package_name, "versionName": version_name, "versionCode": version_code},
        ),
        ("uses-sdk", {"minSdkVersion": min_sdk, "targetSdkVersion": target_sdk}),
    ]
    if version_code_major is not None:
        nodes[0][1]["versionCodeMajor"] = version_code_major
    nodes.extend(("uses-permission", {"name": permission}) for permission in permissions)
    application = {
        "debuggable": debuggable,
        "usesCleartextTraffic": cleartext,
        "allowBackup": allow_backup,
        "testOnly": test_only,
    }
    if application_permission is not None:
        application["permission"] = application_permission
    nodes.append(("application", application))
    component_nodes = []
    for component in components:
        attrs = {"name": component["name"]}
        attrs.update(
            {key: component[key] for key in ("exported", "permission") if key in component}
        )
        component_nodes.append((component.get("kind", "activity"), attrs))
    strings = [ANDROID_NS, "android"]
    for name, attrs in nodes + component_nodes:
        for value in [name, *attrs.keys(), *[v for v in attrs.values() if isinstance(v, str)]]:
            if value not in strings:
                strings.append(value)
    lookup = {value: i for i, value in enumerate(strings)}
    encoded = bytearray()
    offsets = []

    def length8(value):
        return bytes([value]) if value < 128 else bytes([(value >> 8) | 0x80, value & 255])

    for value in strings:
        offsets.append(len(encoded))
        if utf8:
            raw = value.encode("utf-8")
            encoded.extend(length8(len(value)) + length8(len(raw)) + raw + b"\0")
        else:
            raw = value.encode("utf-16-le")
            encoded.extend(struct.pack("<H", len(raw) // 2) + raw + b"\0\0")
    encoded.extend(b"\0" * (-len(encoded) % 4))
    start = 28 + len(offsets) * 4
    pool = struct.pack(
        "<HHIIIIII", 1, 28, start + len(encoded), len(offsets), 0, 0x100 if utf8 else 0, start, 0
    )
    pool += struct.pack("<" + "I" * len(offsets), *offsets) + encoded
    chunks = [pool]
    chunks.append(
        struct.pack(
            "<HHIIIII", 0x0100, 16, 24, 1, 0xFFFFFFFF, lookup["android"], lookup[ANDROID_NS]
        )
    )

    def begin(name, attrs):
        attributes = bytearray()
        for key, value in attrs.items():
            if value is None:
                continue
            ns = 0xFFFFFFFF if key == "package" else lookup[ANDROID_NS]
            raw = 0xFFFFFFFF
            if type(value) is bool:
                kind, data = 0x12, 0xFFFFFFFF if value else 0
            elif type(value) is int:
                kind, data = 0x10, value
            else:
                raw = lookup[value]
                kind, data = 3, lookup[value]
            attributes.extend(struct.pack("<IIIHBBI", ns, lookup[key], raw, 8, 0, kind, data))
        chunk = struct.pack("<HHIII", 0x0102, 16, 36 + len(attributes), 1, 0xFFFFFFFF)
        chunk += struct.pack(
            "<IIHHHHHH", 0xFFFFFFFF, lookup[name], 20, 20, len(attributes) // 20, 0, 0, 0
        )
        chunks.append(chunk + attributes)

    def end(name):
        chunks.append(
            struct.pack("<HHIIIII", 0x0103, 16, 24, 1, 0xFFFFFFFF, 0xFFFFFFFF, lookup[name])
        )

    begin(*nodes[0])
    for node in nodes[1:-1]:
        begin(*node)
        end(node[0])
    begin(*nodes[-1])
    for node in component_nodes:
        begin(*node)
        end(node[0])
    end("application")
    end("manifest")
    chunks.append(
        struct.pack(
            "<HHIIIII", 0x0101, 16, 24, 1, 0xFFFFFFFF, lookup["android"], lookup[ANDROID_NS]
        )
    )
    body = b"".join(chunks)
    return struct.pack("<HHI", 3, 8, len(body) + 8) + body


def build_apk(*, manifest=None, extra_entries=(), compression=zipfile.ZIP_STORED, **kwargs):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=compression) as archive:
        entries = [
            ("AndroidManifest.xml", binary_manifest(**kwargs) if manifest is None else manifest),
            ("classes.dex", b"dex\n035\0" + b"\0" * 104),
            *extra_entries,
        ]
        for name, value in entries:
            info = (
                name
                if isinstance(name, zipfile.ZipInfo)
                else zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
            )
            info.compress_type = compression
            archive.writestr(info, value)
    return output.getvalue()


def write_apk(path: Path, **kwargs):
    path.write_bytes(build_apk(**kwargs))
    return path
