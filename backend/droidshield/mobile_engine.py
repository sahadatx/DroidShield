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

ENGINE_VERSION = "droidshield-mobile-intake-3"
LIMITATIONS = [
    "Bounded identity/configuration and Mach-O header inspection only; no application code is executed or decompiled.",
    "Signature validity and entitlement values are not verified; secrets, libraries and binary protections are not inspected.",
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


_MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce": (">", 28),
    b"\xce\xfa\xed\xfe": ("<", 28),
    b"\xfe\xed\xfa\xcf": (">", 32),
    b"\xcf\xfa\xed\xfe": ("<", 32),
}
_FAT_MAGICS = {
    b"\xca\xfe\xba\xbe": (">", False),
    b"\xbe\xba\xfe\xca": ("<", False),
    b"\xca\xfe\xba\xbf": (">", True),
    b"\xbf\xba\xfe\xca": ("<", True),
}
_CPU_TYPES = {
    7: "x86",
    12: "arm",
    18: "powerpc",
    0x01000007: "x86_64",
    0x0100000C: "arm64",
    0x01000012: "powerpc64",
}
_MACHO_FILE_TYPES = {2: "executable", 6: "dylib", 8: "bundle"}
_LC_CODE_SIGNATURE = 0x1D
_CSMAGIC_EMBEDDED_SIGNATURE = 0xFADE0CC0
_CSMAGIC_EMBEDDED_ENTITLEMENTS = 0xFADE7171
_CSMAGIC_EMBEDDED_DER_ENTITLEMENTS = 0xFADE7172
_CSSLOT_ENTITLEMENTS = 5
_CSSLOT_DER_ENTITLEMENTS = 7


def _read_at(stream, offset, length, limit):
    checked(offset >= 0 and length >= 0 and offset + length <= limit)
    stream.seek(offset)
    result = stream.read(length)
    checked(len(result) == length)
    return result


def _thin_macho(stream, offset, slice_size, args):
    magic = _read_at(stream, offset, 4, offset + slice_size)
    checked(magic in _MACHO_MAGICS)
    endian, header_size = _MACHO_MAGICS[magic]
    header = _read_at(stream, offset, header_size, offset + slice_size)
    if header_size == 28:
        _, cpu_type, _, file_type, command_count, commands_size, _ = struct.unpack(
            endian + "IiiIIII", header
        )
    else:
        _, cpu_type, _, file_type, command_count, commands_size, _, _ = struct.unpack(
            endian + "IiiIIIII", header
        )
    checked(command_count <= 4096 and commands_size <= args.max_manifest)
    checked(header_size + commands_size <= slice_size)
    commands = _read_at(stream, offset + header_size, commands_size, offset + slice_size)
    position, code_signature, entitlements = 0, False, False
    for _ in range(command_count):
        checked(position + 8 <= len(commands))
        command, command_size = struct.unpack_from(endian + "II", commands, position)
        checked(command_size >= 8 and command_size % 4 == 0)
        checked(position + command_size <= len(commands))
        if command == _LC_CODE_SIGNATURE:
            checked(not code_signature and command_size >= 16)
            code_signature = True
            data_offset, data_size = struct.unpack_from(endian + "II", commands, position + 8)
            if data_size:
                checked(data_size >= 12)
                checked(data_offset >= header_size + commands_size)
                checked(data_offset + data_size <= slice_size)
                absolute_data = offset + data_offset
                superblob_header = _read_at(stream, absolute_data, 12, offset + slice_size)
                magic, blob_length, blob_count = struct.unpack(">III", superblob_header)
                if magic == _CSMAGIC_EMBEDDED_SIGNATURE:
                    checked(12 <= blob_length <= data_size and blob_count <= 4096)
                    index_size = 12 + blob_count * 8
                    checked(index_size <= blob_length and index_size <= args.max_manifest)
                    indexes = _read_at(
                        stream,
                        absolute_data + 12,
                        blob_count * 8,
                        absolute_data + blob_length,
                    )
                    for index in range(blob_count):
                        slot, blob_offset = struct.unpack_from(">II", indexes, index * 8)
                        if slot in (_CSSLOT_ENTITLEMENTS, _CSSLOT_DER_ENTITLEMENTS):
                            checked(blob_offset >= index_size and blob_offset + 8 <= blob_length)
                            entitlement_header = _read_at(
                                stream,
                                absolute_data + blob_offset,
                                8,
                                absolute_data + blob_length,
                            )
                            entitlement_magic, entitlement_length = struct.unpack(
                                ">II", entitlement_header
                            )
                            expected_magic = (
                                _CSMAGIC_EMBEDDED_ENTITLEMENTS
                                if slot == _CSSLOT_ENTITLEMENTS
                                else _CSMAGIC_EMBEDDED_DER_ENTITLEMENTS
                            )
                            checked(
                                entitlement_magic == expected_magic
                                and entitlement_length >= 8
                                and blob_offset + entitlement_length <= blob_length
                            )
                            entitlements = True
        position += command_size
    checked(position == len(commands))
    return {
        "architecture": _CPU_TYPES.get(cpu_type, "other"),
        "file_type": _MACHO_FILE_TYPES.get(file_type, "other"),
        "load_command_count": command_count,
        "code_signature_command_present": code_signature,
        "embedded_entitlements_blob_present": entitlements,
    }


def _macho_metadata(archive, path, args):
    entry = archive.getinfo(path)
    checked(0 < entry.file_size <= args.max_uncompressed)
    with archive.open(entry) as stream:
        magic = _read_at(stream, 0, 4, entry.file_size)
        if magic in _MACHO_MAGICS:
            slices = [_thin_macho(stream, 0, entry.file_size, args)]
        else:
            checked(magic in _FAT_MAGICS)
            endian, fat64 = _FAT_MAGICS[magic]
            header = _read_at(stream, 0, 8, entry.file_size)
            count = struct.unpack_from(endian + "I", header, 4)[0]
            arch_size = 32 if fat64 else 20
            checked(0 < count <= 32)
            table_end = 8 + count * arch_size
            checked(table_end <= entry.file_size)
            table = _read_at(stream, 8, count * arch_size, entry.file_size)
            slices = []
            ranges = []
            for index in range(count):
                start = index * arch_size
                if fat64:
                    cpu_type, _, slice_offset, slice_size, _, _ = struct.unpack_from(
                        endian + "iiQQII", table, start
                    )
                else:
                    cpu_type, _, slice_offset, slice_size, _ = struct.unpack_from(
                        endian + "iiIII", table, start
                    )
                checked(slice_offset >= table_end and slice_size >= 28)
                checked(slice_offset + slice_size <= entry.file_size)
                checked(
                    all(
                        slice_offset + slice_size <= left or slice_offset >= right
                        for left, right in ranges
                    )
                )
                item = _thin_macho(stream, slice_offset, slice_size, args)
                checked(item["architecture"] == _CPU_TYPES.get(cpu_type, "other"))
                slices.append(item)
                ranges.append((slice_offset, slice_offset + slice_size))
            checked(len({item["file_type"] for item in slices}) == 1)
    return {
        "architectures": list(dict.fromkeys(item["architecture"] for item in slices)),
        "file_type": slices[0]["file_type"],
        "load_command_count": max(item["load_command_count"] for item in slices),
        "code_signature_command_present": any(
            item["code_signature_command_present"] for item in slices
        ),
        "embedded_entitlements_blob_present": any(
            item["embedded_entitlements_blob_present"] for item in slices
        ),
    }


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
    macho = _macho_metadata(archive, executable_path, args)
    ats = info.get("NSAppTransportSecurity", {})
    checked(isinstance(ats, dict))
    allows = ats.get("NSAllowsArbitraryLoads")
    checked(allows is None or type(allows) is bool)
    exceptions = ats.get("NSExceptionDomains", {})
    checked(isinstance(exceptions, dict) and len(exceptions) <= 256)
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

    usage_count = sum(key.endswith("UsageDescription") for key in info)
    checked(usage_count <= 4096)
    return {
        "platform": "ios",
        "artifact_format": "ipa",
        "package_name": bundle,
        "version_name": label("CFBundleShortVersionString"),
        "version_code": None,
        "build_number": label("CFBundleVersion"),
        "minimum_os": label("MinimumOSVersion"),
        "ats_allows_arbitrary_loads": allows,
        "ats_exception_domain_count": len(exceptions),
        "url_scheme_count": scheme_count,
        "usage_description_count": usage_count,
        "executable_present": True,
        "signature_directory_present": any(
            name.startswith(info_path.removesuffix("Info.plist") + "_CodeSignature/")
            for name in names
        ),
        "embedded_provisioning_profile_present": (
            info_path.removesuffix("Info.plist") + "embedded.mobileprovision" in names
        ),
        **macho,
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
        "schema_version": 5,
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
