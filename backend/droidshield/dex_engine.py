"""Bounded, stdlib-only DEX instruction inspection; launch only through sandbox.py.

Structures and opcode widths follow the AOSP DEX and Dalvik bytecode specifications:
https://source.android.com/docs/core/runtime/dex-format
https://source.android.com/docs/core/runtime/dalvik-bytecode
No DEX, native library, application code or archive member is executed or extracted.
"""

import argparse
import hashlib
import json
import re
import resource
import struct
import sys
import zipfile
import zlib

# -I -S deliberately excludes the script directory. Only this trusted, read-only
# directory is added; APK paths, environment and writable directories never are.
if __name__ == "__main__":
    sys.path.insert(0, "/engine")
    from apk_engine import InvalidAPK, checked, inspect_apk
else:
    from droidshield.apk_engine import InvalidAPK, checked, inspect_apk

ENGINE_VERSION = "droidshield-dex-2"
LIMITATIONS = [
    "Bounded manifest and DEX instruction inspection; application code is never executed.",
    "Instruction references and same-method literals require analyst verification; reachability, arguments and exploitability are not established.",
    "Secret-like literal values are redacted; detection is heuristic and incomplete.",
    "Native code, reflection, packed or encrypted code, dependencies, signing validity, runtime behavior and backend APIs are not evaluated.",
]
DEX_NAME = re.compile(r"classes(?:[2-9]|[1-9][0-9]+)?\.dex\Z")
TYPE_NAME = re.compile(r"\[*([VZBSCIJFD]|L[^.;\[\x00-\x20]+;)\Z")
NO_INDEX = 0xFFFFFFFF

# Known, fixed output text. Never incorporate arbitrary strings or identifiers
# from DEX into narratives, API names, evidence or log/error messages.
RULES = {
    "DEX_INSECURE_RANDOM": (
        "medium",
        "Non-cryptographic random API invocation reference",
        "A decoded invoke instruction references java.util.Random. Security-sensitive use and runtime reachability require review.",
        "Predictable random values can weaken security tokens or cryptographic operations when used for those purposes.",
        "Use a suitable cryptographic random generator for security-sensitive values and verify the calling context.",
    ),
    "DEX_WEAK_HASH_MD5": (
        "medium",
        "MD5 literal and digest API reference in the same method",
        "A method contains both an MD5 literal reference and a MessageDigest.getInstance invocation reference. Data flow is not established.",
        "MD5 is unsuitable where collision resistance is required; non-security checksum uses need context.",
        "Review argument flow and use an appropriate modern digest or password hashing scheme for the security requirement.",
    ),
    "DEX_WEAK_HASH_SHA1": (
        "medium",
        "SHA-1 literal and digest API reference in the same method",
        "A method contains both a SHA-1 literal reference and a MessageDigest.getInstance invocation reference. Data flow is not established.",
        "SHA-1 is unsuitable where collision resistance is required; actual use needs verification.",
        "Review argument flow and replace security-sensitive SHA-1 uses with an appropriate modern primitive.",
    ),
    "DEX_WEAK_CIPHER_DES": (
        "medium",
        "DES literal and cipher API reference in the same method",
        "A method contains both a DES or DESede transformation literal and a Cipher.getInstance invocation reference. Data flow is not established.",
        "Legacy DES-family encryption may provide inadequate protection for sensitive data.",
        "Review argument flow and migrate security-sensitive encryption to an appropriate authenticated encryption scheme.",
    ),
    "DEX_CIPHER_ECB": (
        "medium",
        "ECB literal and cipher API reference in the same method",
        "A method contains both an ECB transformation literal and a Cipher.getInstance invocation reference. Data flow is not established.",
        "ECB encryption can reveal patterns in repeated plaintext blocks.",
        "Verify the transformation and use an appropriate authenticated encryption mode with correct nonce handling.",
    ),
    "DEX_WEBVIEW_JAVASCRIPT": (
        "low",
        "WebView JavaScript configuration invocation reference",
        "A decoded invoke instruction references WebSettings.setJavaScriptEnabled. The boolean argument and loaded content are not evaluated.",
        "Enabling JavaScript can increase exposure when a WebView loads untrusted content or exposes native bridges.",
        "Review the effective argument, content origins and native bridges; enable JavaScript only where required.",
    ),
    "DEX_WEBVIEW_DEBUGGING": (
        "medium",
        "WebView debugging configuration invocation reference",
        "A decoded invoke instruction references WebView.setWebContentsDebuggingEnabled. The boolean argument is not evaluated.",
        "Enabled WebView debugging in a release build may expose web content and runtime state.",
        "Verify the effective argument and disable WebView debugging in production builds.",
    ),
    "DEX_WEBVIEW_FILE_ACCESS": (
        "medium",
        "WebView file-access configuration invocation reference",
        "A decoded invoke instruction references a WebSettings file-access setter. The boolean argument and runtime behavior are not evaluated.",
        "Permissive file-access settings can expose local data when combined with untrusted content.",
        "Review effective arguments, disable unnecessary file access and restrict loaded content origins.",
    ),
    "DEX_SECRET_LITERAL": (
        "high",
        "Secret-like literal instruction reference (redacted)",
        "A decoded const-string instruction references a literal matching a known credential heuristic. Its value is withheld and validity is not evaluated.",
        "A valid embedded credential can be recovered from distributed application code.",
        "Review the protected APK in an authorized environment, revoke any real exposed credential and remove it from distributed builds.",
    ),
}
APIS = {
    ("Ljava/util/Random;", "<init>", "()V"): ("DEX_INSECURE_RANDOM", "java.util.Random.<init>"),
    ("Ljava/util/Random;", "<init>", "(J)V"): ("DEX_INSECURE_RANDOM", "java.util.Random.<init>"),
    (
        "Ljava/security/MessageDigest;",
        "getInstance",
        "(Ljava/lang/String;)Ljava/security/MessageDigest;",
    ): (None, "java.security.MessageDigest.getInstance"),
    (
        "Ljava/security/MessageDigest;",
        "getInstance",
        "(Ljava/lang/String;Ljava/lang/String;)Ljava/security/MessageDigest;",
    ): (None, "java.security.MessageDigest.getInstance"),
    (
        "Ljava/security/MessageDigest;",
        "getInstance",
        "(Ljava/lang/String;Ljava/security/Provider;)Ljava/security/MessageDigest;",
    ): (None, "java.security.MessageDigest.getInstance"),
    ("Ljavax/crypto/Cipher;", "getInstance", "(Ljava/lang/String;)Ljavax/crypto/Cipher;"): (
        None,
        "javax.crypto.Cipher.getInstance",
    ),
    (
        "Ljavax/crypto/Cipher;",
        "getInstance",
        "(Ljava/lang/String;Ljava/lang/String;)Ljavax/crypto/Cipher;",
    ): (None, "javax.crypto.Cipher.getInstance"),
    (
        "Ljavax/crypto/Cipher;",
        "getInstance",
        "(Ljava/lang/String;Ljava/security/Provider;)Ljavax/crypto/Cipher;",
    ): (None, "javax.crypto.Cipher.getInstance"),
    ("Landroid/webkit/WebSettings;", "setJavaScriptEnabled", "(Z)V"): (
        "DEX_WEBVIEW_JAVASCRIPT",
        "android.webkit.WebSettings.setJavaScriptEnabled",
    ),
    ("Landroid/webkit/WebView;", "setWebContentsDebuggingEnabled", "(Z)V"): (
        "DEX_WEBVIEW_DEBUGGING",
        "android.webkit.WebView.setWebContentsDebuggingEnabled",
    ),
}
for _setter in (
    "setAllowFileAccess",
    "setAllowFileAccessFromFileURLs",
    "setAllowUniversalAccessFromFileURLs",
):
    APIS[("Landroid/webkit/WebSettings;", _setter, "(Z)V")] = (
        "DEX_WEBVIEW_FILE_ACCESS",
        "android.webkit.WebSettings." + _setter,
    )


def make_indicator(rule, package, evidence):
    severity, title, description, impact, remediation = RULES[rule]
    return {
        "rule_id": rule,
        "severity": severity,
        "title": title,
        "affected_component": package,
        "description": description,
        "impact": impact,
        "remediation": remediation,
        "reproduction_steps": "Review the referenced DEX method and instruction in the protected APK; verify behavior only within the authorized assessment scope.",
        "evidence": evidence,
    }


def literal_category(value):
    upper = value.upper()
    if upper == "MD5":
        return "md5"
    if upper in ("SHA1", "SHA-1"):
        return "sha1"
    if upper.split("/")[0] in ("DES", "DESEDE"):
        return "des"
    if "/ECB/" in upper:
        return "ecb"
    if re.fullmatch(r"(?:AKIA|ASIA)[A-Z0-9]{16}", value):
        return "aws_access_key"
    if re.search(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", value):
        return "private_key"
    if re.fullmatch(
        r"(?i)(?:api[_-]?key|secret|password|access[_-]?token)\s*[:=]\s*[^\s]{12,4096}", value
    ):
        return "credential_literal"
    return None


class DexReader:
    def __init__(self, data, args, budget):
        self.data, self.args, self.budget = data, args, budget
        self.data_start = 0
        self.data_end = len(data)
        self.used_code = set()
        self.regions = []

    def read(self, fmt, offset):
        checked(0 <= offset <= len(self.data) - struct.calcsize(fmt))
        return struct.unpack_from(fmt, self.data, offset)

    def data_offset(self, offset, size=1, alignment=1):
        checked(self.data_start <= offset <= self.data_end - size and offset % alignment == 0)

    def leb(self, offset, signed=False):
        value = 0
        for index in range(5):
            self.data_offset(offset)
            byte = self.data[offset]
            offset += 1
            value |= (byte & 0x7F) << (7 * index)
            if not byte & 0x80:
                if signed and byte & 0x40:
                    value -= 1 << (7 * (index + 1))
                checked(-(2**31) <= value <= (2**31 - 1 if signed else 2**32 - 1))
                return value, offset
        raise InvalidAPK("Invalid DEX")

    def string(self, offset):
        length, offset = self.leb(offset)
        checked(length <= 65535)
        units = []
        while True:
            self.data_offset(offset)
            first = self.data[offset]
            offset += 1
            if not first:
                break
            if first < 0x80:
                unit = first
            elif first & 0xE0 == 0xC0:
                self.data_offset(offset)
                second = self.data[offset]
                offset += 1
                checked(second & 0xC0 == 0x80)
                unit = ((first & 0x1F) << 6) | (second & 0x3F)
                checked(unit == 0 or unit >= 0x80)
            elif first & 0xF0 == 0xE0:
                self.data_offset(offset, 2)
                second, third = self.data[offset : offset + 2]
                offset += 2
                checked(second & 0xC0 == third & 0xC0 == 0x80)
                unit = ((first & 15) << 12) | ((second & 63) << 6) | (third & 63)
                checked(unit >= 0x800)
            else:
                raise InvalidAPK("Invalid DEX")
            units.append(unit)
            checked(len(units) <= length)
        checked(len(units) == length)
        # DEX MUTF-8 represents UTF-16 code units, including surrogate pairs.
        value = struct.pack("<" + "H" * len(units), *units).decode("utf-16-le", "surrogatepass")
        return value, offset

    def type_list(self, offset):
        if not offset:
            return ()
        self.data_offset(offset, 4, 4)
        (count,) = self.read("<I", offset)
        checked(count <= 65535)
        self.data_offset(offset + 4, count * 2)
        values = self.read("<" + "H" * count, offset + 4)
        checked(all(value < len(self.types) and self.types[value] != "V" for value in values))
        return values

    def header(self):
        data = self.data
        checked(len(data) >= 112 and data[:4] == b"dex\n" and data[7:8] == b"\0")
        checked(data[4:7] in (b"035", b"037", b"038", b"039", b"040"))
        self.version = int(data[4:7])
        checked(self.read("<I", 8)[0] == zlib.adler32(data[12:]) & 0xFFFFFFFF)
        checked(data[12:32] == hashlib.sha1(data[32:]).digest())
        fields = self.read("<20I", 32)
        size, header_size, endian, link_size, link_off, map_off = fields[:6]
        checked(size == len(data) and header_size == 112 and endian == 0x12345678)
        checked(link_size == link_off == 0)
        self.data_size, self.data_start = fields[-2:]
        checked(self.data_start >= 112 and self.data_start % 4 == 0)
        checked(self.data_size > 0 and self.data_start + self.data_size == len(data))
        self.tables = {}
        regions = [(0, 112)]
        for table_type, count, offset, width in zip(
            range(1, 7), fields[6:18:2], fields[7:18:2], (4, 4, 12, 8, 8, 32), strict=True
        ):
            checked(count <= self.args.dex_max_ids)
            self.budget["ids"] += count
            checked(self.budget["ids"] <= self.args.dex_max_ids)
            if table_type in (2, 3, 4, 5):
                checked(count <= 65535)
            checked(
                (count == 0 and offset == 0)
                or (
                    count > 0
                    and offset >= 112
                    and offset % 4 == 0
                    and offset + count * width <= self.data_start
                )
            )
            self.tables[table_type] = (count, offset)
            if count:
                regions.append((offset, offset + count * width))
        regions.sort()
        checked(all(left[1] <= right[0] for left, right in zip(regions, regions[1:], strict=False)))
        self.data_offset(map_off, 4, 4)
        (map_count,) = self.read("<I", map_off)
        checked(1 <= map_count <= 32)
        self.data_offset(map_off + 4, map_count * 12)
        mapped, previous = {}, -1
        for index in range(map_count):
            kind, unused, count, offset = self.read("<HHII", map_off + 4 + index * 12)
            checked(unused == 0 and count > 0 and kind not in mapped and offset > previous)
            checked(
                kind
                in {
                    0,
                    1,
                    2,
                    3,
                    4,
                    5,
                    6,
                    7,
                    8,
                    0x1000,
                    0x1001,
                    0x1002,
                    0x1003,
                    0x2000,
                    0x2001,
                    0x2002,
                    0x2003,
                    0x2004,
                    0x2005,
                    0x2006,
                    0xF000,
                }
            )
            checked(count <= self.args.dex_max_ids and offset < len(data))
            if kind >= 0x1000:
                self.data_offset(offset)
            mapped[kind] = (count, offset)
            previous = offset
        checked(mapped.get(0) == (1, 0) and mapped.get(0x1000) == (1, map_off))
        for kind, pair in self.tables.items():
            checked(mapped.get(kind, (0, 0)) == pair)
        self.mapped = mapped
        if 7 in mapped or 8 in mapped:
            checked(self.version >= 38)
        self.call_sites = mapped.get(7, (0, 0))[0]
        self.handles = mapped.get(8, (0, 0))[0]
        for kind, width in ((7, 4), (8, 8)):
            count, offset = mapped.get(kind, (0, 0))
            if count:
                checked(offset % 4 == 0 and offset + count * width <= len(data))
        self.strings = []
        string_offsets = set()
        string_count, string_off = self.tables[1]
        for index in range(string_count):
            (offset,) = self.read("<I", string_off + index * 4)
            checked(offset not in string_offsets)
            string_offsets.add(offset)
            value, end = self.string(offset)
            self.budget["string_bytes"] += end - offset
            checked(self.budget["string_bytes"] <= self.args.dex_max_bytes)
            self.strings.append(value)
        checked(mapped.get(0x2002, (0, 0))[0] == string_count)
        # Sorting uses UTF-16 code units, not Python's Unicode scalar ordering.
        previous = None
        for value in self.strings:
            key = tuple(
                struct.unpack(
                    "<" + "H" * (len(value.encode("utf-16-le", "surrogatepass")) // 2),
                    value.encode("utf-16-le", "surrogatepass"),
                )
            )
            checked(previous is None or previous < key)
            previous = key
        self.types = []
        count, offset = self.tables[2]
        previous = -1
        for index in range(count):
            (string_id,) = self.read("<I", offset + index * 4)
            checked(previous < string_id < len(self.strings))
            value = self.strings[string_id]
            checked(
                len(value) <= 1024
                and TYPE_NAME.fullmatch(value)
                and value.count("[") <= 255
                and not value.startswith("[V")
            )
            self.types.append(value)
            previous = string_id
        self.protos = []
        count, offset = self.tables[3]
        previous = None
        for index in range(count):
            shorty, result, params = self.read("<III", offset + index * 12)
            checked(shorty < len(self.strings) and result < len(self.types))
            parameters = self.type_list(params)
            key = result, parameters
            checked(previous is None or previous < key)
            previous = key
            names = [self.types[result], *[self.types[item] for item in parameters]]
            expected = "".join("L" if name.startswith(("L", "[")) else name for name in names)
            checked(self.strings[shorty] == expected)
            self.protos.append("(" + "".join(names[1:]) + ")" + names[0])
        self.fields = []
        count, offset = self.tables[4]
        previous = None
        for index in range(count):
            owner, value_type, name = self.read("<HHI", offset + index * 8)
            checked(
                owner < len(self.types)
                and value_type < len(self.types)
                and name < len(self.strings)
            )
            checked(self.types[owner].startswith("L") and self.types[value_type] != "V")
            key = owner, name, value_type
            checked(previous is None or previous < key)
            previous = key
            self.fields.append(owner)
        self.methods = []
        self.method_owners = []
        count, offset = self.tables[5]
        previous = None
        for index in range(count):
            owner, proto, name = self.read("<HHI", offset + index * 8)
            checked(
                owner < len(self.types) and proto < len(self.protos) and name < len(self.strings)
            )
            checked(self.types[owner].startswith(("L", "[")))
            key = owner, name, proto
            checked(previous is None or previous < key)
            previous = key
            self.methods.append(
                APIS.get((self.types[owner], self.strings[name], self.protos[proto]))
            )
            self.method_owners.append(owner)
        for index in range(self.handles):
            kind, unused, target, unused2 = self.read("<HHHH", mapped[8][1] + index * 8)
            checked(unused == unused2 == 0 and 0 <= kind <= 8)
            checked(target < len(self.fields if kind <= 3 else self.methods))
        return self.tables[6][0]

    def code(self, offset, method_id):
        self.data_offset(offset, 16, 4)
        checked(offset not in self.used_code)
        self.used_code.add(offset)
        registers, incoming, outgoing, tries, debug, count = self.read("<HHHHII", offset)
        checked(incoming <= registers and outgoing <= 65535 and count > 0)
        if debug:
            self.data_offset(debug)
        self.budget["code_units"] += count
        self.budget["analyzed_methods"] += 1
        checked(self.budget["code_units"] <= self.args.dex_max_code_units)
        self.data_offset(offset + 16, count * 2)
        units = memoryview(self.data)[offset + 16 : offset + 16 + count * 2]
        invocations, literals = [], []
        pc = 0

        def unit(index):
            checked(0 <= index < count)
            return struct.unpack_from("<H", units, index * 2)[0]

        while pc < count:
            word = unit(pc)
            opcode = word & 0xFF
            width = INSTRUCTION_WIDTHS.get(opcode)
            checked(width is not None)
            if opcode == 0 and word:
                checked(pc % 2 == 0)
                size = unit(pc + 1)
                if word == 0x0100:
                    width = 4 + 2 * size
                elif word == 0x0200:
                    width = 2 + 4 * size
                elif word == 0x0300:
                    checked(size in (1, 2, 4, 8))
                    elements = unit(pc + 2) | (unit(pc + 3) << 16)
                    width = 4 + (size * elements + 1) // 2
                else:
                    raise InvalidAPK("Invalid DEX")
            checked(pc + width <= count)
            if opcode in (0x1A, 0x1B):
                string_id = unit(pc + 1)
                if opcode == 0x1B:
                    string_id |= unit(pc + 2) << 16
                checked(string_id < len(self.strings) and word >> 8 < registers)
                value = self.strings[string_id]
                category = literal_category(value)
                if category:
                    literals.append((pc, category, len(value)))
                if category != "ecb" and "/ECB/" in value.upper():
                    literals.append((pc, "ecb", len(value)))
            elif 0x6E <= opcode <= 0x72 or 0x74 <= opcode <= 0x78 or opcode in (0xFA, 0xFB):
                method_index = unit(pc + 1)
                checked(method_index < len(self.methods))
                argument_count = (
                    word >> 12 if opcode in range(0x6E, 0x73) or opcode == 0xFA else word >> 8
                )
                checked(argument_count <= outgoing)
                if opcode in range(0x6E, 0x73) or opcode == 0xFA:
                    checked(argument_count <= 5)
                    packed = unit(pc + 2)
                    arguments = [(packed >> (4 * i)) & 15 for i in range(4)] + [(word >> 8) & 15]
                    checked(all(register < registers for register in arguments[:argument_count]))
                else:
                    checked(unit(pc + 2) + argument_count <= registers)
                if opcode in (0xFA, 0xFB):
                    checked(self.version >= 38 and unit(pc + 3) < len(self.protos))
                api = self.methods[method_index]
                if api:
                    invocations.append((pc, api))
            elif opcode in (0xFC, 0xFD):
                checked(self.version >= 38 and unit(pc + 1) < self.call_sites)
            elif opcode in (0xFE, 0xFF):
                checked(
                    self.version >= 39
                    and unit(pc + 1) < (self.handles if opcode == 0xFE else len(self.protos))
                )
            elif opcode in (0x1C, 0x1F, 0x20, 0x22, 0x23, 0x24, 0x25):
                checked(unit(pc + 1) < len(self.types))
            elif 0x52 <= opcode <= 0x6D:
                checked(unit(pc + 1) < len(self.fields))
            pc += width
        checked(pc == count)
        end = offset + 16 + count * 2
        if tries:
            if count % 2:
                checked(self.read("<H", end)[0] == 0)
                end += 2
            self.data_offset(end, tries * 8)
            handlers_start = end + tries * 8
            handlers, cursor = self.leb(handlers_start)
            checked(0 < handlers <= 65535)
            valid_handlers = set()
            for _ in range(handlers):
                valid_handlers.add(cursor - handlers_start)
                size, cursor = self.leb(cursor, signed=True)
                checked(abs(size) <= 65535)
                for _ in range(abs(size)):
                    type_id, cursor = self.leb(cursor)
                    target, cursor = self.leb(cursor)
                    checked(type_id < len(self.types) and target < count)
                if size <= 0:
                    target, cursor = self.leb(cursor)
                    checked(target < count)
            previous_end = 0
            for index in range(tries):
                start, size, handler = self.read("<IHH", end + index * 8)
                checked(
                    size > 0
                    and start >= previous_end
                    and start + size <= count
                    and handler in valid_handlers
                )
                previous_end = start + size
            end = cursor
        self.regions.append((offset, end))
        return invocations, literals

    def scan(self):
        class_count = self.header()
        count, offset = self.tables[6]
        seen_classes, seen_methods = set(), set()
        matches = []
        for index in range(count):
            owner, _flags, superclass, interfaces, source, annotations, class_data, values = (
                self.read("<8I", offset + index * 32)
            )
            checked(
                owner < len(self.types)
                and self.types[owner].startswith("L")
                and owner not in seen_classes
            )
            checked(
                superclass == NO_INDEX
                or superclass < len(self.types)
                and self.types[superclass].startswith("L")
            )
            checked(source == NO_INDEX or source < len(self.strings))
            for linked in (annotations, values):
                if linked:
                    self.data_offset(linked)
            self.type_list(interfaces)
            seen_classes.add(owner)
            if not class_data:
                continue
            cursor = class_data
            counts = []
            for _ in range(4):
                value, cursor = self.leb(cursor)
                checked(value <= self.args.dex_max_ids)
                counts.append(value)
            for field_count in counts[:2]:
                field_id = 0
                for field_number in range(field_count):
                    difference, cursor = self.leb(cursor)
                    checked(field_number == 0 or difference > 0)
                    field_id += difference
                    checked(field_id < len(self.fields) and self.fields[field_id] == owner)
                    _, cursor = self.leb(cursor)
            for method_count in counts[2:]:
                method_id = 0
                for method_number in range(method_count):
                    difference, cursor = self.leb(cursor)
                    checked(method_number == 0 or difference > 0)
                    method_id += difference
                    flags, cursor = self.leb(cursor)
                    code_offset, cursor = self.leb(cursor)
                    checked(
                        method_id < len(self.methods)
                        and self.method_owners[method_id] == owner
                        and method_id not in seen_methods
                    )
                    seen_methods.add(method_id)
                    checked(bool(code_offset) == (not bool(flags & (0x100 | 0x400))))
                    if not code_offset:
                        continue
                    invocations, literals = self.code(code_offset, method_id)
                    # One candidate per rule per method, with bounded first evidence.
                    method_matches = {}
                    for pc, category, length in literals:
                        if category in ("aws_access_key", "private_key", "credential_literal"):
                            method_matches.setdefault(
                                "DEX_SECRET_LITERAL", (pc, None, category, length)
                            )
                    for pc, (rule, api) in invocations:
                        if rule:
                            method_matches.setdefault(rule, (pc, api, None, None))
                        categories = {category for _, category, _ in literals}
                        pairs = []
                        if api == "java.security.MessageDigest.getInstance":
                            pairs = [("md5", "DEX_WEAK_HASH_MD5"), ("sha1", "DEX_WEAK_HASH_SHA1")]
                        elif api == "javax.crypto.Cipher.getInstance":
                            pairs = [("des", "DEX_WEAK_CIPHER_DES"), ("ecb", "DEX_CIPHER_ECB")]
                        for category, crypto_rule in pairs:
                            if category in categories:
                                method_matches.setdefault(crypto_rule, (pc, api, category, None))
                    for rule, (pc, api, category, length) in sorted(method_matches.items()):
                        matches.append((rule, method_id, pc, api, category, length))
                    checked(len(matches) <= 2048)
        self.regions.sort()
        checked(
            all(
                left[1] <= right[0]
                for left, right in zip(self.regions, self.regions[1:], strict=False)
            )
        )
        checked(len(self.used_code) == self.mapped.get(0x2001, (0, 0))[0])
        return matches, {
            "classes": class_count,
            "methods": len(self.methods),
            "strings": len(self.strings),
        }


# Standard DEX opcodes only; optimized/quickened/unused opcodes fail closed.
INSTRUCTION_WIDTHS = {}
for _start, _end, _width in (
    (0x00, 0x01, 1),
    (0x02, 0x02, 2),
    (0x03, 0x03, 3),
    (0x04, 0x04, 1),
    (0x05, 0x05, 2),
    (0x06, 0x06, 3),
    (0x07, 0x07, 1),
    (0x08, 0x08, 2),
    (0x09, 0x09, 3),
    (0x0A, 0x12, 1),
    (0x13, 0x13, 2),
    (0x14, 0x14, 3),
    (0x15, 0x16, 2),
    (0x17, 0x17, 3),
    (0x18, 0x18, 5),
    (0x19, 0x1A, 2),
    (0x1B, 0x1B, 3),
    (0x1C, 0x1C, 2),
    (0x1D, 0x1E, 1),
    (0x1F, 0x20, 2),
    (0x21, 0x21, 1),
    (0x22, 0x23, 2),
    (0x24, 0x26, 3),
    (0x27, 0x28, 1),
    (0x29, 0x29, 2),
    (0x2A, 0x2C, 3),
    (0x2D, 0x3D, 2),
    (0x44, 0x6D, 2),
    (0x6E, 0x72, 3),
    (0x74, 0x78, 3),
    (0x7B, 0x8F, 1),
    (0x90, 0xAF, 2),
    (0xB0, 0xCF, 1),
    (0xD0, 0xE2, 2),
    (0xFA, 0xFB, 4),
    (0xFC, 0xFD, 3),
    (0xFE, 0xFF, 2),
):
    for _opcode in range(_start, _end + 1):
        INSTRUCTION_WIDTHS[_opcode] = _width


def analyze_dex_apk(path, args):
    checked(args.mode == "analyze")
    result = inspect_apk(path, args)
    result.update(schema_version=2, engine_version=ENGINE_VERSION, limitations=LIMITATIONS)
    summary = dict(dex_files=0, classes=0, methods=0, strings=0, analyzed_methods=0, code_units=0)
    budget = dict(ids=0, string_bytes=0, analyzed_methods=0, code_units=0)
    total = 0
    with zipfile.ZipFile(path) as archive:
        entries = [entry for entry in archive.infolist() if entry.filename.endswith(".dex")]
        checked(len(entries) <= args.dex_max_files)
        # Embedded/nonstandard DEX is unsupported, never silently omitted.
        checked(all(DEX_NAME.fullmatch(entry.filename) and not entry.is_dir() for entry in entries))
        entries.sort(
            key=lambda entry: 1 if entry.filename == "classes.dex" else int(entry.filename[7:-4])
        )
        checked(
            [entry.filename for entry in entries]
            == [
                "classes.dex" if index == 1 else f"classes{index}.dex"
                for index in range(1, len(entries) + 1)
            ]
        )
        for entry in entries:
            total += entry.file_size
            checked(112 <= entry.file_size <= args.dex_max_bytes and total <= args.dex_max_bytes)
            with archive.open(entry) as source:
                data = source.read(entry.file_size + 1)
            checked(len(data) == entry.file_size)
            matches, counts = DexReader(data, args, budget).scan()
            summary["dex_files"] += 1
            for key, count in counts.items():
                summary[key] += count
            for rule, method, pc, api, category, length in matches:
                evidence = {
                    "source": entry.filename,
                    "method_index": method,
                    "instruction_offset": pc,
                    "observed": "const_string_reference" if api is None else "invocation_reference",
                    "target_api": api,
                    "literal_category": category,
                    "literal_length": length,
                }
                result["indicators"].append(
                    make_indicator(rule, result["metadata"]["package_name"], evidence)
                )
                checked(len(result["indicators"]) <= 4099)
    summary.update(analyzed_methods=budget["analyzed_methods"], code_units=budget["code_units"])
    result["dex_summary"] = summary
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("analyze",), required=True)
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
        "dex-max-files",
        "dex-max-bytes",
        "dex-max-ids",
        "dex-max-code-units",
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
        result = analyze_dex_apk(args.input, args)
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
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
