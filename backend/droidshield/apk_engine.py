"""Standalone stdlib-only APK manifest reader. Always launch through sandbox.py.

No extraction, shell, external tools, network or DEX execution occurs here.

Binary structures follow AOSP ResourceTypes.h: ResStringPool_header,
ResXMLTree_attrExt, ResXMLTree_attribute and Res_value.
https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/libs/androidfw/include/androidfw/ResourceTypes.h
"""

import argparse
import hashlib
import json
import os
import re
import resource
import stat
import struct
import sys
import zipfile
import zlib

ENGINE_VERSION = "droidshield-manifest-2"
LIMITATIONS = [
    "Manifest-only static analysis; application code is not executed or inspected.",
    "Indicators require analyst verification and do not establish exploitability.",
    "APK signing certificates and signature validity are not evaluated by this engine.",
    "Runtime behavior, dependencies, secrets and backend APIs are not evaluated.",
]
ANDROID_NS = "http://schemas.android.com/apk/res/android"
ANDROID_VERSION_CODE_COMPONENT_MAX = 2**31 - 1
ANDROID_LONG_VERSION_CODE_MAX = 2**63 - 1
IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+\Z")
COMPONENT = re.compile(r"[A-Za-z_][A-Za-z0-9_$]*(?:\.[A-Za-z_][A-Za-z0-9_$]*)+\Z")
KINDS = {"activity", "activity-alias", "service", "receiver", "provider"}
ANDROID_ATTRIBUTES = {
    "name": 0x01010003,
    "permission": 0x01010006,
    "debuggable": 0x0101000F,
    "exported": 0x01010010,
    "minSdkVersion": 0x0101020C,
    "versionCode": 0x0101021B,
    "versionName": 0x0101021C,
    "targetSdkVersion": 0x01010270,
    "testOnly": 0x01010272,
    "allowBackup": 0x01010280,
    "usesCleartextTraffic": 0x010104EC,
    "versionCodeMajor": 0x01010576,
}


class InvalidAPK(ValueError):
    pass


def checked(condition):
    if not condition:
        raise InvalidAPK("Invalid APK")


def unpack(fmt, data, offset):
    checked(offset >= 0 and offset + struct.calcsize(fmt) <= len(data))
    return struct.unpack_from(fmt, data, offset)


def string_length(data, offset, utf8, end=None):
    end = len(data) if end is None else end
    if utf8:
        checked(offset < end)
        length = data[offset]
        offset += 1
        if length & 0x80:
            checked(offset < end)
            length = ((length & 0x7F) << 8) | data[offset]
            offset += 1
    else:
        checked(offset + 2 <= end)
        (length,) = unpack("<H", data, offset)
        offset += 2
        if length & 0x8000:
            checked(offset + 2 <= end)
            (low,) = unpack("<H", data, offset)
            length = ((length & 0x7FFF) << 16) | low
            offset += 2
    return length, offset


def string_pool(chunk, header_size):
    checked(header_size == 28)
    count, style_count, flags, start, styles_start = unpack("<IIIII", chunk, 8)
    checked(count <= 100000 and style_count == 0 and flags & ~0x101 == 0)
    checked(header_size + 4 * (count + style_count) <= start <= len(chunk))
    checked(not styles_start or start <= styles_start <= len(chunk))
    string_end = styles_start or len(chunk)
    utf8 = bool(flags & 0x100)
    result = []
    for index in range(count):
        (relative,) = unpack("<I", chunk, header_size + index * 4)
        offset = start + relative
        checked(start <= offset < string_end)
        char_count, offset = string_length(chunk, offset, utf8, string_end)
        checked(char_count <= 65535)
        if utf8:
            byte_count, offset = string_length(chunk, offset, True, string_end)
            end = offset + byte_count
            checked(end < string_end and chunk[end] == 0)
            text = chunk[offset:end].decode("utf-8", errors="strict")
            checked(len(text.encode("utf-16-le")) // 2 == char_count)
        else:
            end = offset + char_count * 2
            checked(end + 2 <= string_end and chunk[end : end + 2] == b"\0\0")
            text = chunk[offset:end].decode("utf-16-le", errors="strict")
        checked("\x00" not in text)
        result.append(text)
    return result


def parse_manifest(data):
    kind, header_size, total = unpack("<HHI", data, 0)
    checked(kind == 0x0003 and header_size == 8 and total == len(data))
    strings = None
    nodes = []
    stack = []
    namespaces = []
    resource_map = None
    offset = header_size

    def string(index, nullable=False):
        if nullable and index == 0xFFFFFFFF:
            return None
        checked(strings is not None and 0 <= index < len(strings))
        return strings[index]

    while offset < total:
        chunk_type, size, length = unpack("<HHI", data, offset)
        checked(size >= 8 and length >= size and offset + length <= total and length % 4 == 0)
        chunk = data[offset : offset + length]
        if chunk_type == 0x0001:
            checked(strings is None and not nodes)
            strings = string_pool(chunk, size)
        elif chunk_type == 0x0102:
            checked(size == 16 and length >= 36 and len(nodes) < 10000 and len(stack) < 128)
            namespace, name, attr_start, attr_size, count, _, _, _ = unpack("<IIHHHHHH", chunk, 16)
            checked(attr_start >= 20 and attr_size >= 20 and count <= 2048)
            checked(16 + attr_start + attr_size * count <= length)
            attributes = {}
            for index in range(count):
                pos = 16 + attr_start + index * attr_size
                ns, attr_name, raw, value_size, zero, value_type, value = unpack(
                    "<IIIHBBI", chunk, pos
                )
                checked(value_size == 8 and zero == 0)
                key = (string(ns, True), string(attr_name))
                checked(key not in attributes)
                if key[1] in ANDROID_ATTRIBUTES:
                    checked(key[0] == ANDROID_NS)
                if key[1] == "package":
                    checked(key[0] is None)
                if key[0] is not None:
                    checked(any(uri == key[0] for _, uri, _ in namespaces))
                if resource_map is not None and attr_name < len(resource_map):
                    resource_id = resource_map[attr_name]
                    expected_id = ANDROID_ATTRIBUTES.get(key[1])
                    if expected_id is not None:
                        checked(resource_id == expected_id)
                    if resource_id in ANDROID_ATTRIBUTES.values():
                        checked(expected_id == resource_id and key[0] == ANDROID_NS)
                if value_type == 0x03:
                    parsed = string(value)
                elif value_type == 0x12:
                    checked(value in (0, 0xFFFFFFFF, 1))
                    parsed = bool(value)
                elif value_type in (0x10, 0x11):
                    parsed = value
                else:
                    parsed = None
                if raw != 0xFFFFFFFF:
                    original = string(raw)
                    if value_type == 0x03:
                        checked(original == parsed)
                    elif value_type == 0x12:
                        checked(original == ("true" if parsed else "false"))
                    elif value_type in (0x10, 0x11):
                        try:
                            numeric = int(original, 16 if original.lower().startswith("0x") else 10)
                        except ValueError as exc:
                            raise InvalidAPK("Invalid typed value") from exc
                        checked(numeric == parsed)
                attributes[key] = parsed
            node = {
                "name": string(name),
                "namespace": string(namespace, True),
                "attrs": attributes,
                "parent": stack[-1] if stack else None,
            }
            nodes.append(node)
            stack.append(len(nodes) - 1)
        elif chunk_type == 0x0103:
            checked(size == 16 and length >= 24 and stack)
            namespace, name = unpack("<II", chunk, 16)
            previous = nodes[stack.pop()]
            checked(
                previous["name"] == string(name)
                and previous["namespace"] == string(namespace, True)
            )
        elif chunk_type in (0x0100, 0x0101):
            checked(size == 16 and length == 24)
            prefix, uri = unpack("<II", chunk, 16)
            pair = (string(prefix, True), string(uri), len(stack))
            if chunk_type == 0x0100:
                checked(pair not in namespaces and len(namespaces) < 128)
                namespaces.append(pair)
            else:
                checked(namespaces and namespaces.pop() == pair)
        elif chunk_type == 0x0180:
            checked(
                strings is not None
                and not nodes
                and resource_map is None
                and size == 8
                and (length - size) % 4 == 0
            )
            count = (length - size) // 4
            checked(count <= len(strings))
            resource_map = unpack("<" + "I" * count, chunk, size)
        else:
            raise InvalidAPK("Unsupported manifest")
        offset += length
    checked(offset == total and strings is not None and nodes and not stack and not namespaces)
    checked(nodes[0]["name"] == "manifest" and nodes[0]["namespace"] is None)
    checked(all(node["parent"] is not None for node in nodes[1:]))
    return nodes


def integer(value, maximum=2**63 - 1):
    if value is None:
        return None
    checked(type(value) is int or (isinstance(value, str) and re.fullmatch(r"[0-9]{1,19}", value)))
    result = int(value)
    checked(0 <= result <= maximum)
    return result


def boolean(value):
    if value is None:
        return None
    if type(value) is bool:
        return value
    checked(value in ("true", "false"))
    return value == "true"


def identifier(value, pattern=IDENTIFIER, maximum=512):
    checked(isinstance(value, str) and len(value) <= maximum and pattern.fullmatch(value))
    return value


def metadata_from_nodes(nodes):
    attrs = nodes[0]["attrs"]
    package = identifier(attrs.get((None, "package")), maximum=255)
    version = attrs.get((ANDROID_NS, "versionName"))
    if not isinstance(version, str) or not re.fullmatch(r"[A-Za-z0-9_.+() -]{1,128}", version):
        version = None
    major_key = (ANDROID_NS, "versionCodeMajor")
    minor_key = (ANDROID_NS, "versionCode")
    major = 0
    if major_key in attrs:
        major = integer(attrs[major_key], ANDROID_VERSION_CODE_COMPONENT_MAX)
        checked(major is not None)
    minor = None
    if minor_key in attrs:
        minor = integer(attrs[minor_key], ANDROID_VERSION_CODE_COMPONENT_MAX)
        checked(minor is not None)
    version_code = None if minor is None and major == 0 else (major << 32) | (minor or 0)
    checked(version_code is None or version_code <= ANDROID_LONG_VERSION_CODE_MAX)
    metadata = {
        "package_name": package,
        "version_name": version,
        "version_code": version_code,
        "min_sdk": None,
        "target_sdk": None,
        "permissions": [],
        "application": {
            "debuggable": None,
            "uses_cleartext_traffic": None,
            "allow_backup": None,
            "test_only": None,
        },
        "components": [],
        "signing_certificate": None,
    }
    applications = [
        i
        for i, node in enumerate(nodes)
        if node["name"] == "application" and node["parent"] == 0 and node["namespace"] is None
    ]
    checked(len(applications) == 1)
    application_index = applications[0]
    application = nodes[application_index]["attrs"]
    for output, name in (
        ("debuggable", "debuggable"),
        ("uses_cleartext_traffic", "usesCleartextTraffic"),
        ("allow_backup", "allowBackup"),
        ("test_only", "testOnly"),
    ):
        metadata["application"][output] = boolean(application.get((ANDROID_NS, name)))
    app_permission = application.get((ANDROID_NS, "permission"))
    if app_permission:
        identifier(app_permission)
    permissions = set()
    sdk_count = 0
    names = set()
    for node in nodes:
        attrs = node["attrs"]
        if node["namespace"] is not None:
            continue
        if node["name"] == "uses-sdk" and node["parent"] == 0:
            sdk_count += 1
            checked(sdk_count == 1)
            for output, name in (("min_sdk", "minSdkVersion"), ("target_sdk", "targetSdkVersion")):
                value = attrs.get((ANDROID_NS, name))
                # Preview SDK codenames are unsupported, rather than invented SDK numbers.
                metadata[output] = integer(value, 10000)
                checked(metadata[output] is None or metadata[output] > 0)
        elif node["name"] in ("uses-permission", "uses-permission-sdk-23") and node["parent"] == 0:
            permissions.add(identifier(attrs.get((ANDROID_NS, "name"))))
            checked(len(permissions) <= 2048)
        elif node["name"] in KINDS and node["parent"] == application_index:
            name = attrs.get((ANDROID_NS, "name"))
            checked(isinstance(name, str) and len(name) <= 512)
            if name.startswith("."):
                name = package + name
            elif "." not in name:
                name = package + "." + name
            identifier(name, COMPONENT)
            checked((node["name"], name) not in names)
            names.add((node["name"], name))
            permission = attrs.get((ANDROID_NS, "permission"), app_permission)
            if permission == "":
                permission = None
            if permission is not None:
                identifier(permission)
            metadata["components"].append(
                {
                    "kind": node["name"],
                    "name": name,
                    "exported": boolean(attrs.get((ANDROID_NS, "exported"))),
                    "permission": permission,
                }
            )
            checked(len(metadata["components"]) <= 2048)
    metadata["permissions"] = sorted(permissions)
    metadata["components"].sort(key=lambda item: (item["kind"], item["name"]))
    return metadata


def analyze(metadata):
    indicators = []

    def add(rule, severity, title, component, description, impact, remediation, attribute):
        indicators.append(
            {
                "rule_id": rule,
                "severity": severity,
                "title": title,
                "affected_component": component,
                "description": description,
                "impact": impact,
                "remediation": remediation,
                "reproduction_steps": "Review the stated manifest attribute and verify the behavior on an authorized test device.",
                "evidence": {
                    "source": "AndroidManifest.xml",
                    "attribute": attribute,
                    "observed": "true",
                },
            }
        )

    app = metadata["application"]
    package = metadata["package_name"]
    if app["debuggable"] is True:
        add(
            "MANIFEST_DEBUGGABLE",
            "high",
            "Application explicitly enables debugging",
            package,
            "The application declares android:debuggable=true.",
            "Debug interfaces may expose runtime state and sensitive application data.",
            "Disable debugging in release builds and verify the signed release artifact.",
            "android:debuggable",
        )
    if app["uses_cleartext_traffic"] is True:
        add(
            "MANIFEST_CLEARTEXT",
            "medium",
            "Application explicitly permits cleartext traffic",
            package,
            "The application declares android:usesCleartextTraffic=true. Network security configuration and runtime behavior require review.",
            "Unencrypted connections may expose data in transit when the application uses them.",
            "Require TLS and review network security configuration and all runtime connections.",
            "android:usesCleartextTraffic",
        )
    if app["allow_backup"] is True:
        add(
            "MANIFEST_BACKUP",
            "low",
            "Application explicitly permits backup",
            package,
            "The application declares android:allowBackup=true. Effective backup behavior depends on Android version and backup rules.",
            "Sensitive application data may enter backups if backup rules do not exclude it.",
            "Review backup and data-extraction rules and exclude sensitive data where required.",
            "android:allowBackup",
        )
    for component in metadata["components"]:
        if component["exported"] is True and component["permission"] is None:
            add(
                "MANIFEST_EXPORTED_UNPROTECTED",
                "medium",
                "Exported component has no manifest permission",
                component["name"],
                "The component explicitly declares android:exported=true without a component or inherited application permission. Custom runtime checks require review.",
                "Other applications may invoke the component; impact depends on exposed functionality and runtime authorization.",
                "Disable unnecessary exports or enforce appropriate permissions and runtime authorization.",
                "android:exported",
            )
    return indicators


def inspect_apk(path, args):
    size = os.stat(path).st_size
    checked(0 < size <= args.max_bytes)
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        checked(0 < len(entries) <= args.max_entries)
        names = set()
        total = 0
        manifest = None
        has_code_or_resources = False
        for entry in entries:
            name = entry.filename
            checked(name and len(name) <= 1024 and name == entry.orig_filename)
            checked(not name.startswith("/") and "\\" not in name and "\x00" not in name)
            parts = name.rstrip("/").split("/")
            checked(all(part and part not in (".", "..") and ":" not in part for part in parts))
            checked(all(ord(char) >= 32 and ord(char) != 127 for char in name))
            checked(name not in names and not (entry.flag_bits & 1))
            names.add(name)
            mode = entry.external_attr >> 16
            checked(stat.S_IFMT(mode) in (0, stat.S_IFREG, stat.S_IFDIR))
            checked(entry.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED))
            checked(entry.file_size <= args.max_uncompressed)
            total += entry.file_size
            checked(total <= args.max_uncompressed)
            checked(
                entry.file_size == 0
                or entry.file_size <= max(entry.compress_size, 1) * args.max_ratio
            )
            if name == "AndroidManifest.xml":
                checked(0 < entry.file_size <= args.max_manifest and not entry.is_dir())
                manifest = entry
            if name in ("classes.dex", "resources.arsc") or name.startswith("res/"):
                has_code_or_resources = True
        checked(manifest is not None and has_code_or_resources)
        # Bounded read checks local headers and CRC without expanding arbitrary entries.
        with archive.open(manifest) as source:
            data = source.read(args.max_manifest + 1)
        checked(len(data) == manifest.file_size and len(data) <= args.max_manifest)
    nodes = parse_manifest(data)
    metadata = metadata_from_nodes(nodes)
    return {
        "schema_version": 1,
        "engine_version": ENGINE_VERSION,
        "sha256": digest.hexdigest(),
        "file_size": size,
        "metadata": metadata,
        "indicators": analyze(metadata) if args.mode == "analyze" else [],
        "limitations": LIMITATIONS,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("inspect", "analyze"), required=True)
    parser.add_argument("--input", required=True)
    for name in (
        "max-bytes",
        "max-entries",
        "max-uncompressed",
        "max-manifest",
        "max-ratio",
        "cpu-seconds",
        "memory-bytes",
        "output-bytes",
    ):
        parser.add_argument("--" + name, type=int, required=True)
    args = parser.parse_args()
    try:
        for name, value in vars(args).items():
            if name not in ("mode", "input"):
                checked(0 < value <= 2**40)
        for limit, value in (
            (resource.RLIMIT_CPU, args.cpu_seconds),
            (resource.RLIMIT_AS, args.memory_bytes),
            (resource.RLIMIT_FSIZE, args.output_bytes),
            (resource.RLIMIT_NOFILE, 32),
            (resource.RLIMIT_NPROC, 1),
            (resource.RLIMIT_CORE, 0),
        ):
            resource.setrlimit(limit, (value, value))
        result = inspect_apk(args.input, args)
        payload = json.dumps(result, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        checked(len(payload) <= args.output_bytes)
        sys.stdout.buffer.write(payload)
        sys.stdout.buffer.flush()
        return 0
    except (
        InvalidAPK,
        OSError,
        ValueError,
        OverflowError,
        MemoryError,
        zipfile.BadZipFile,
        NotImplementedError,
        RuntimeError,
        RecursionError,
        EOFError,
        struct.error,
        zlib.error,
    ):
        # No exception text, paths, input bytes or tracebacks cross this boundary.
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
