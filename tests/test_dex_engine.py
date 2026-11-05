import copy
import hashlib
import json
import shutil
import struct
import subprocess
import zipfile

import pytest
from pydantic import ValidationError

from droidshield.analysis_contract import AnalysisResult, DexAnalysisResult, validate_dex_result
from droidshield.apk_engine import InvalidAPK
from droidshield.dex_engine import INSTRUCTION_WIDTHS, DexReader, analyze_dex_apk
from droidshield.sandbox import Sandbox, SandboxCancelled, SandboxError
from tests.dex_factory import COMPILED_DEX, EDGE_DEX, EDGE_SOURCE, SMALI_SOURCE, dex_apk, rehash_dex
from tests.test_apk_engine import engine_args
from tests.test_sandbox import sandbox_settings


def dex_args(**updates):
    values = dict(
        dex_max_files=16,
        dex_max_bytes=64 * 1024 * 1024,
        dex_max_ids=100_000,
        dex_max_code_units=4_000_000,
    )
    values.update(updates)
    return engine_args(**values)


def analyze(tmp_path, data=None, **limits):
    path = tmp_path / "app.apk"
    path.write_bytes(dex_apk() if data is None else data)
    return analyze_dex_apk(path, dex_args(**limits))


def mapped_sections(data):
    (offset,) = struct.unpack_from("<I", data, 52)
    (count,) = struct.unpack_from("<I", data, offset)
    sections = {}
    for index in range(count):
        kind, _zero, size, position = struct.unpack_from("<HHII", data, offset + 4 + 12 * index)
        sections[kind] = size, position
    return sections


def reader(data=COMPILED_DEX, **limits):
    budget = dict(ids=0, string_bytes=0, analyzed_methods=0, code_units=0)
    return DexReader(data, dex_args(**limits), budget)


def test_real_compiled_dex_has_decoded_method_evidence_and_no_literal_values(tmp_path):
    result = analyze(tmp_path)
    assert validate_dex_result(result) == result
    assert result["schema_version"] == 2
    assert result["engine_version"] == "droidshield-dex-2"
    assert result["sha256"] == hashlib.sha256(dex_apk()).hexdigest()
    assert result["dex_summary"] == {
        "dex_files": 1,
        "classes": 1,
        "methods": 10,
        "strings": 29,
        "analyzed_methods": 2,
        "code_units": 44,
    }
    indicators = {item["rule_id"]: item for item in result["indicators"]}
    assert set(indicators) == {
        "DEX_INSECURE_RANDOM",
        "DEX_SECRET_LITERAL",
        "DEX_WEAK_CIPHER_DES",
        "DEX_CIPHER_ECB",
        "DEX_WEAK_HASH_MD5",
        "DEX_WEAK_HASH_SHA1",
        "DEX_WEBVIEW_DEBUGGING",
        "DEX_WEBVIEW_FILE_ACCESS",
        "DEX_WEBVIEW_JAVASCRIPT",
    }
    literal = indicators["DEX_SECRET_LITERAL"]["evidence"]
    assert literal == {
        "source": "classes.dex",
        "method_index": 6,
        "instruction_offset": 36,
        "observed": "const_string_reference",
        "target_api": None,
        "literal_category": "aws_access_key",
        "literal_length": 20,
    }
    assert (
        indicators["DEX_WEAK_HASH_MD5"]["evidence"]["target_api"]
        == "java.security.MessageDigest.getInstance"
    )
    # The fixture deliberately passes false to the setters; no enabling claim is made.
    assert "not evaluated" in indicators["DEX_WEBVIEW_JAVASCRIPT"]["description"]
    serialized = json.dumps(result)
    for secret in ("AKIA0123456789ABCDEF", "do-not-expose", "private.example", "password="):
        assert secret not in serialized


def test_dex_manifest_candidates_preserve_existing_protocol(tmp_path):
    result = analyze(tmp_path, dex_apk(debuggable=True))
    assert result["indicators"][0]["rule_id"] == "MANIFEST_DEBUGGABLE"
    DexAnalysisResult.model_validate(result)
    with pytest.raises(ValidationError):
        AnalysisResult.model_validate(result)


def test_unreferenced_method_identifiers_are_not_reported(tmp_path):
    data = bytearray(COMPILED_DEX)
    code_reader = reader()
    code_reader.header()
    first_code = mapped_sections(data)[0x2001][1]
    # Discover code offsets from the fixture's contiguous code items. Replace
    # invoke instructions with same-width nops, retaining all method-id names.
    position = first_code
    for _ in range(2):
        count = struct.unpack_from("<I", data, position + 12)[0]
        pc = 0
        while pc < count:
            word = struct.unpack_from("<H", data, position + 16 + pc * 2)[0]
            opcode = word & 255
            width = INSTRUCTION_WIDTHS[opcode]
            if 0x6E <= opcode <= 0x72:
                data[position + 16 + pc * 2 : position + 16 + (pc + width) * 2] = b"\0" * (
                    2 * width
                )
            pc += width
        position = (position + 16 + 2 * count + 3) & ~3
    result = analyze(tmp_path, dex_apk(rehash_dex(data)))
    assert [item["rule_id"] for item in result["indicators"]] == ["DEX_SECRET_LITERAL"]


@pytest.mark.parametrize("version", [b"035", b"037", b"038", b"039", b"040"])
def test_supported_dex_versions(tmp_path, version):
    data = bytearray(COMPILED_DEX)
    data[4:7] = version
    result = analyze(tmp_path, dex_apk(rehash_dex(data)))
    assert result["dex_summary"]["analyzed_methods"] == 2


@pytest.mark.parametrize("version", [b"036", b"041", b"999"])
def test_unsupported_dex_versions_fail_closed(tmp_path, version):
    data = bytearray(COMPILED_DEX)
    data[4:7] = version
    with pytest.raises(InvalidAPK):
        analyze(tmp_path, dex_apk(rehash_dex(data)))


@pytest.mark.parametrize("position", [8, 12, 32, 40, 104, 108, 150, -1])
def test_checksums_and_header_corruption_reject(tmp_path, position):
    data = bytearray(COMPILED_DEX)
    data[position] ^= 1
    with pytest.raises(InvalidAPK):
        analyze(tmp_path, dex_apk(data))


@pytest.mark.parametrize(
    "offset,value",
    [
        (32, 1),
        (36, 120),
        (40, 0x78563412),
        (44, 1),
        (52, 4),
        (56, 0xFFFFFFFF),
        (60, 108),
        (104, 4),
        (108, 112),
    ],
)
def test_structurally_invalid_headers_reject_even_with_correct_checksums(tmp_path, offset, value):
    data = bytearray(COMPILED_DEX)
    struct.pack_into("<I", data, offset, value)
    with pytest.raises(InvalidAPK):
        analyze(tmp_path, dex_apk(rehash_dex(data)))


def test_invalid_string_offsets_mutf8_and_method_references_reject(tmp_path):
    sections = mapped_sections(COMPILED_DEX)
    _, string_table = sections[1]
    string_offset = struct.unpack_from("<I", COMPILED_DEX, string_table)[0]
    for position, fmt, value in (
        (string_table, "<I", len(COMPILED_DEX)),
        (string_offset, "<B", 0x7F),
        (string_offset + 1, "<B", 0xFF),
        (sections[5][1], "<H", 0xFFFF),
        (sections[5][1] + 2, "<H", 0xFFFF),
    ):
        data = bytearray(COMPILED_DEX)
        struct.pack_into(fmt, data, position, value)
        with pytest.raises(InvalidAPK):
            analyze(tmp_path, dex_apk(rehash_dex(data)))


def test_bad_code_counts_invalid_opcode_and_bad_invoke_index_reject(tmp_path):
    offset = mapped_sections(COMPILED_DEX)[0x2001][1]
    # First method is the harmless() method; a fake invocation index is still
    # validated, and a fake payload cannot cause arbitrary-width stepping.
    for relative, fmt, value in (
        (12, "<I", 0xFFFFFFFF),
        (16, "<H", 0x003E),
        (16, "<H", 0x0100),
        (16, "<H", 0x0071),
        (18, "<H", 0xFFFF),
    ):
        data = bytearray(COMPILED_DEX)
        struct.pack_into(fmt, data, offset + relative, value)
        with pytest.raises(InvalidAPK):
            analyze(tmp_path, dex_apk(rehash_dex(data)))


@pytest.mark.parametrize(
    "limit,value",
    [
        ("dex_max_files", 1),
        ("dex_max_bytes", 1000),
        ("dex_max_ids", 10),
        ("dex_max_code_units", 20),
    ],
)
def test_cumulative_dex_budgets_reject(tmp_path, limit, value):
    data = dex_apk(dex_entries=[("classes.dex", COMPILED_DEX), ("classes2.dex", COMPILED_DEX)])
    with pytest.raises(InvalidAPK):
        analyze(tmp_path, data, **{limit: value})


def test_multidex_and_resource_only_apks_report_precise_counts(tmp_path):
    result = analyze(
        tmp_path,
        dex_apk(dex_entries=[("classes.dex", COMPILED_DEX), ("classes2.dex", COMPILED_DEX)]),
    )
    assert result["dex_summary"]["dex_files"] == 2
    assert result["dex_summary"]["analyzed_methods"] == 4
    assert {item["evidence"]["source"] for item in result["indicators"]} == {
        "classes.dex",
        "classes2.dex",
    }
    DexAnalysisResult.model_validate(result)
    empty = analyze(tmp_path, dex_apk(None))
    assert not any(empty["dex_summary"].values()) and empty["indicators"] == []
    DexAnalysisResult.model_validate(empty)


@pytest.mark.parametrize(
    "names",
    [
        ["classes2.dex"],
        ["classes.dex", "classes3.dex"],
        ["classes.dex", "assets/hidden.dex"],
        ["classes.dex", "classes01.dex"],
    ],
)
def test_hidden_or_noncontiguous_dex_is_rejected(tmp_path, names):
    with pytest.raises(InvalidAPK):
        analyze(tmp_path, dex_apk(dex_entries=[(name, COMPILED_DEX) for name in names]))


def test_archive_expansion_budget_applies_before_dex_parsing(tmp_path):
    data = dex_apk(
        dex_entries=[("classes.dex", COMPILED_DEX), ("classes2.dex", b"\0" * 500_000)],
        compression=zipfile.ZIP_DEFLATED,
    )
    with pytest.raises(InvalidAPK):
        analyze(tmp_path, data)


@pytest.mark.parametrize(
    "mutation",
    ["text", "secret", "api", "rule", "counts", "duplicate", "limitations", "boolean_version"],
)
def test_untrusted_dex_result_contract_rejects_injected_or_inconsistent_output(tmp_path, mutation):
    result = copy.deepcopy(analyze(tmp_path))
    if mutation == "text":
        result["indicators"][0]["description"] = "arbitrary parser output"
    elif mutation == "secret":
        result["indicators"][0]["evidence"]["literal_value"] = "DO NOT EXPOSE"
    elif mutation == "api":
        result["indicators"][0]["evidence"]["target_api"] = "private.application.token"
    elif mutation == "rule":
        result["indicators"][0]["evidence"]["target_api"] = "java.util.Random.<init>"
    elif mutation == "counts":
        result["dex_summary"]["dex_files"] = 0
    elif mutation == "duplicate":
        result["indicators"].append(copy.deepcopy(result["indicators"][0]))
    elif mutation == "limitations":
        result["limitations"][0] = "fully verified runtime vulnerability"
    else:
        result["schema_version"] = True
    with pytest.raises(ValidationError):
        DexAnalysisResult.model_validate(result)


def test_real_bubblewrap_dex_engine_and_manifest_default(tmp_path):
    path = tmp_path / "app.apk"
    path.write_bytes(dex_apk(debuggable=True))
    sandbox = Sandbox(sandbox_settings())
    try:
        result = sandbox.run(path, mode="analyze", engine="dex")
    except SandboxError as exc:
        if exc.code == "isolation_unavailable":
            pytest.skip("Bubblewrap user namespaces unavailable")
        raise
    assert result == analyze_dex_apk(path, dex_args())
    manifest = sandbox.run(path, mode="analyze")
    assert manifest["engine_version"] == "droidshield-manifest-2"
    assert len(manifest["indicators"]) == 1
    assert "dex_summary" not in manifest
    path.write_bytes(dex_apk(b"dex\n035\0" + bytes(104)))
    # Intake remains manifest-only and can accept code it does not inspect.
    assert sandbox.run(path)["schema_version"] == 1
    with pytest.raises(SandboxError) as error:
        sandbox.run(path, mode="analyze", engine="dex")
    assert error.value.code == "invalid_apk"


def test_dex_engine_modes_and_cancellation_fail_closed(tmp_path):
    sandbox = Sandbox(sandbox_settings(sandbox_executable="/missing/bwrap"))
    with pytest.raises(ValueError):
        sandbox.run(tmp_path / "missing", engine="dex")
    with pytest.raises(ValueError):
        sandbox.run(tmp_path / "missing", engine="unknown", mode="analyze")
    with pytest.raises(SandboxCancelled):
        sandbox.run(tmp_path / "missing", engine="dex", mode="analyze", should_cancel=lambda: True)


@pytest.mark.parametrize(
    "source_text,expected", [(SMALI_SOURCE, COMPILED_DEX), (EDGE_SOURCE, EDGE_DEX)]
)
def test_fixture_can_be_reproduced_with_independent_android_assembler(
    tmp_path, source_text, expected
):
    smali = shutil.which("smali")
    if not smali:
        pytest.skip("Optional independent smali assembler unavailable")
    source = tmp_path / "Probe.smali"
    source.write_text(source_text)
    output = tmp_path / "classes.dex"
    subprocess.run(
        [smali, "assemble", str(source), "-o", str(output)],
        check=True,
        capture_output=True,
        timeout=30,
    )
    assert output.read_bytes() == expected


def test_payloads_handlers_and_mutf8_parse_without_treating_payload_as_code(tmp_path):
    result = analyze(tmp_path, dex_apk(EDGE_DEX))
    assert result["dex_summary"]["analyzed_methods"] == 4
    assert [item["rule_id"] for item in result["indicators"]] == ["DEX_WEAK_HASH_MD5"]
    dex_reader = reader(EDGE_DEX)
    dex_reader.header()
    assert "A\0é😀" in dex_reader.strings
    # Three aligned instructions inside an array payload are only data.
    data = bytearray(EDGE_DEX)
    pattern = struct.pack("<HHI", 0x0300, 4, 3)
    start = data.index(pattern) + 8
    struct.pack_into("<HHH", data, start, 0x0071, 0xFFFF, 0)
    assert [
        item["rule_id"] for item in analyze(tmp_path, dex_apk(rehash_dex(data)))["indicators"]
    ] == ["DEX_WEAK_HASH_MD5"]


def test_payload_width_and_catch_handler_bounds_fail_closed(tmp_path):
    pattern = struct.pack("<HHI", 0x0300, 4, 3)
    payload = EDGE_DEX.index(pattern)
    for offset, fmt, value in ((payload + 2, "<H", 3), (payload + 4, "<I", 0xFFFFFFFF)):
        data = bytearray(EDGE_DEX)
        struct.pack_into(fmt, data, offset, value)
        with pytest.raises(InvalidAPK):
            analyze(tmp_path, dex_apk(rehash_dex(data)))


@pytest.mark.parametrize(
    "encoded",
    [
        b"\x01\xff\0",
        b"\x01\xc0\x81\0",
        b"\x01\xe0\x80\x81\0",
        b"\x01\xf0\x90\x80\x80\0",
        b"\x01A",
        b"\xff\xff\xff\xff\x10\0",
    ],
)
def test_invalid_mutf8_and_oversized_leb_fail_closed(encoded):
    dex_reader = reader(encoded)
    with pytest.raises(InvalidAPK):
        dex_reader.string(0)
