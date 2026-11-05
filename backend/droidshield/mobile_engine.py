"""Bounded IPA/AAB metadata intake. Launch through Sandbox, never in the API.

No extraction or application/tool execution. AAB XML wire fields follow AOSP
tools/aapt2/Resources.proto; plist keys follow Apple's Info.plist reference.
This is identity/configuration inspection, not a binary security assessment.
"""

import argparse
import hashlib
import json
import os
import plistlib
import re
import stat
import struct
import sys
import zipfile
import zlib

if __name__ == "__main__":
    sys.path.insert(0, "/engine")
    from apk_engine import InvalidAPK, checked, metadata_from_nodes
else:
    from droidshield.apk_engine import InvalidAPK, checked, metadata_from_nodes

ENGINE_VERSION = "droidshield-mobile-intake-2"
LIMITATIONS = [
    "Identity and configuration intake only; no application code is executed or decompiled.",
    "Signatures, entitlements, secret values, libraries and binary protections are not verified.",
    "IPA runtime testing requires an external authorized iOS lab; AAB execution requires generated APKs.",
]
BUNDLE = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]*(?:\.[A-Za-z0-9][A-Za-z0-9-]*)+\Z")
VERSION = re.compile(r"[A-Za-z0-9_.+() -]{1,128}\Z")


def _varint(data, offset):
    value = 0
    for shift in range(0, 70, 7):
        checked(offset < len(data))
        byte = data[offset]
        offset += 1
        checked(shift != 63 or byte <= 1)
        value |= (byte & 127) << shift
        if byte < 128:
            return value, offset
    raise InvalidAPK("Invalid protobuf")


def _fields(data):
    result, offset = {}, 0
    while offset < len(data):
        tag, offset = _varint(data, offset)
        field, wire = tag >> 3, tag & 7
        checked(0 < field < 2**29 and len(result) < 128)
        if wire == 0:
            value, offset = _varint(data, offset)
        elif wire in (1, 5):
            length = 8 if wire == 1 else 4
            checked(offset + length <= len(data))
            value = data[offset : offset + length]
            offset += length
        elif wire == 2:
            length, offset = _varint(data, offset)
            checked(offset + length <= len(data))
            value = data[offset : offset + length]
            offset += length
        else:
            raise InvalidAPK("Unsupported protobuf wire type")
        values = result.setdefault(field, [])
        checked(len(values) < 10_000)
        values.append((wire, value))
    return result


def _one(fields, field, wire=2, default=b""):
    values = fields.get(field, [])
    checked(len(values) <= 1 and (not values or values[0][0] == wire))
    return values[0][1] if values else default


def _text(fields, field):
    value = _one(fields, field).decode("utf-8", errors="strict")
    checked(len(value) <= 4096 and not any(ord(c) < 32 for c in value))
    return value


def _attribute(raw):
    fields = _fields(raw)
    namespace, name = _text(fields, 1) or None, _text(fields, 2)
    checked(name)
    value = _text(fields, 3)
    compiled = _one(fields, 6)
    if compiled:
        item = _fields(compiled)
        choices = [key for key in range(1, 8) if key in item]
        checked(len(choices) <= 1)
        if choices and choices[0] in (2, 3):
            value = _text(_fields(_one(item, choices[0])), 1)
        elif choices == [7]:
            primitive = _fields(_one(item, 7))
            checked(len(primitive) == 1)
            key = next(iter(primitive))
            if key in (6, 7, 8):
                number = _one(primitive, key, wire=0, default=0)
                checked(number <= (1 if key == 8 else 2**31 - 1))
                value = bool(number) if key == 8 else number
            else:
                raise InvalidAPK("Unsupported compiled manifest value")
        elif choices:
            # Resource references do not establish resolved metadata.
            value = None
    return (namespace, name), value


def aab_metadata(data):
    nodes, pending = [], [(data, None, 0)]
    while pending:
        raw, parent, depth = pending.pop()
        checked(depth <= 64 and len(nodes) < 4096)
        node = _fields(raw)
        if 1 not in node:
            checked(2 in node)
            continue
        checked(2 not in node)
        element = _fields(_one(node, 1))
        name, namespace = _text(element, 3), _text(element, 2) or None
        checked(name)
        attributes = {}
        for wire, raw_attribute in element.get(4, []):
            checked(wire == 2 and len(attributes) < 128)
            key, value = _attribute(raw_attribute)
            checked(key not in attributes)
            attributes[key] = value
        index = len(nodes)
        nodes.append({"name": name, "namespace": namespace, "attrs": attributes, "parent": parent})
        for wire, child in reversed(element.get(5, [])):
            checked(wire == 2)
            pending.append((child, index, depth + 1))
        checked(len(pending) <= 4096)
    checked(nodes and nodes[0]["name"] == "manifest" and nodes[0]["namespace"] is None)
    metadata = metadata_from_nodes(nodes)
    return {**metadata, "platform": "android", "artifact_format": "aab"}


def _plist_shape(value):
    # Reject recursive/aliased container graphs and oversized structures. The
    # parser itself is additionally bounded by the subprocess memory/CPU limit.
    pending, seen, count = [(value, 0)], set(), 0
    while pending:
        value, depth = pending.pop()
        count += 1
        checked(count <= 10_000 and depth <= 32)
        if isinstance(value, (dict, list)):
            checked(id(value) not in seen)
            seen.add(id(value))
            children = list(value.values()) if isinstance(value, dict) else value
            checked(len(children) <= 4096)
            pending.extend((child, depth + 1) for child in children)


def ipa_metadata(archive, names, args):
    candidates = [name for name in names if re.fullmatch(r"Payload/[^/]+\.app/Info\.plist", name)]
    checked(len(candidates) == 1)
    info_path = candidates[0]
    entry = archive.getinfo(info_path)
    checked(0 < entry.file_size <= args.max_manifest)
    data = archive.read(entry)
    checked(len(data) == entry.file_size)
    info = plistlib.loads(data)
    _plist_shape(info)
    checked(isinstance(info, dict) and info.get("CFBundlePackageType") == "APPL")
    bundle = info.get("CFBundleIdentifier")
    checked(isinstance(bundle, str) and len(bundle) <= 255 and BUNDLE.fullmatch(bundle))
    executable = info.get("CFBundleExecutable")
    checked(isinstance(executable, str) and re.fullmatch(r"[A-Za-z0-9_+.-]{1,200}", executable))
    checked(executable not in {".", ".."})
    executable_path = info_path.removesuffix("Info.plist") + executable
    checked(executable_path in names)
    with archive.open(executable_path) as stream:
        magic = stream.read(4)
    checked(
        magic
        in (
            b"\xfe\xed\xfa\xce",
            b"\xce\xfa\xed\xfe",
            b"\xfe\xed\xfa\xcf",
            b"\xcf\xfa\xed\xfe",
            b"\xca\xfe\xba\xbe",
            b"\xbe\xba\xfe\xca",
            b"\xca\xfe\xba\xbf",
            b"\xbf\xba\xfe\xca",
        )
    )
    ats = info.get("NSAppTransportSecurity", {})
    checked(isinstance(ats, dict))
    allows = ats.get("NSAllowsArbitraryLoads")
    checked(allows is None or type(allows) is bool)
    schemes = info.get("CFBundleURLTypes", [])
    checked(isinstance(schemes, list) and len(schemes) <= 256)
    scheme_count = 0
    for item in schemes:
        checked(isinstance(item, dict))
        values = item.get("CFBundleURLSchemes", [])
        checked(isinstance(values, list) and len(values) <= 256)
        scheme_count += len(values)

    def label(key):
        value = info.get(key)
        return value if isinstance(value, str) and VERSION.fullmatch(value) else None

    return {
        "platform": "ios",
        "artifact_format": "ipa",
        "package_name": bundle,
        "version_name": label("CFBundleShortVersionString"),
        "version_code": None,
        "build_number": label("CFBundleVersion"),
        "minimum_os": label("MinimumOSVersion"),
        "ats_allows_arbitrary_loads": allows,
        "url_scheme_count": scheme_count,
        "usage_description_count": sum(key.endswith("UsageDescription") for key in info),
        "executable_present": True,
        "signature_directory_present": any(
            name.startswith(info_path.removesuffix("Info.plist") + "_CodeSignature/")
            for name in names
        ),
    }


def inspect_mobile(path, args):
    size = os.stat(path).st_size
    checked(0 < size <= args.max_bytes and args.mode == "inspect")
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        checked(0 < len(entries) <= args.max_entries)
        names, total = set(), 0
        for entry in entries:
            name = entry.filename
            checked(name and len(name) <= 1024 and name == entry.orig_filename)
            checked(not name.startswith("/") and "\\" not in name and "\x00" not in name)
            checked(
                all(
                    part and part not in (".", "..") and ":" not in part
                    for part in name.rstrip("/").split("/")
                )
            )
            checked(all(ord(char) >= 32 and ord(char) != 127 for char in name))
            checked(name not in names and not (entry.flag_bits & 1))
            names.add(name)
            checked(stat.S_IFMT(entry.external_attr >> 16) in (0, stat.S_IFREG, stat.S_IFDIR))
            checked(entry.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED))
            total += entry.file_size
            checked(total <= args.max_uncompressed)
            checked(entry.file_size <= max(entry.compress_size, 1) * args.max_ratio)
        if args.format == "ipa":
            metadata = ipa_metadata(archive, names, args)
        else:
            checked("BundleConfig.pb" in names and "base/manifest/AndroidManifest.xml" in names)
            checked(
                any(name.startswith("base/dex/") or name == "base/resources.pb" for name in names)
            )
            entry = archive.getinfo("base/manifest/AndroidManifest.xml")
            checked(0 < entry.file_size <= args.max_manifest)
            data = archive.read(entry)
            checked(len(data) == entry.file_size)
            metadata = aab_metadata(data)
    return {
        "schema_version": 4,
        "engine_version": ENGINE_VERSION,
        "sha256": digest.hexdigest(),
        "file_size": size,
        "metadata": metadata,
        "indicators": [],
        "limitations": LIMITATIONS,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("inspect",), required=True)
    parser.add_argument("--format", choices=("ipa", "aab"), required=True)
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
        result = inspect_mobile(args.input, args)
        payload = json.dumps(result, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        checked(len(payload) <= args.output_bytes)
        sys.stdout.buffer.write(payload)
        sys.stdout.buffer.flush()
        return 0
    except (
        InvalidAPK,
        OSError,
        ValueError,
        TypeError,
        OverflowError,
        MemoryError,
        zipfile.BadZipFile,
        NotImplementedError,
        RuntimeError,
        RecursionError,
        EOFError,
        struct.error,
        zlib.error,
        plistlib.InvalidFileException,
    ):
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
