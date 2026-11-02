# Isolated DEX analysis

The `droidshield-dex-1` engine adds real DEX instruction inspection to the existing
protected APK workflow. It reads the binary manifest and standard `classes.dex`,
`classes2.dex`, etc. inside the existing network-disabled Bubblewrap sandbox.
No archive is extracted, no application code is loaded or executed, and there is
no unsandboxed fallback. Intake continues to use the manifest engine: successful
upload is not a claim that the DEX has passed analysis.

The worker can select `Sandbox.run(path, mode="analyze", engine="dex")`. Omitting
`engine` preserves the manifest engine and its original schema. `inspect` mode
is intentionally unavailable for the DEX engine. Both engines use the existing
unprivileged-account requirement, read-only input/runtime/engine mounts, isolated
user/network/PID namespaces, cleared environment, bounded temporary storage,
CPU/memory/time/output limits, cancellation callback and independent watchdog.
Only the two trusted engine source files are added to `/engine`; no broader host
directory is mounted. The standalone isolated interpreter imports shared manifest
logic exclusively from that trusted, read-only directory.

## What is actually inspected

The parser checks supported DEX headers, file size, endian tag, SHA-1 signature,
Adler-32 checksum, nonoverlapping identifier tables, bounded map/table counts,
MUTF-8 strings, type/prototype/field/method references, class data, concrete method
code ranges and standard instruction widths. It resolves invocation indexes in
decoded code items; matching an API name in the string or method pool alone does
not create an indicator. Variable-size switch/array payloads are skipped according
to their format, rather than scanned as instructions. Try/catch ranges and handler
references are bounded. This is a security-indicator parser, not a replacement for
the Android runtime's full verifier. It does not establish control-flow reachability
or validate every debug/annotation semantic.

Supported DEX format versions are **035, 037, 038, 039 and 040**. Reverse endian,
optimized/quickened, malformed or unsupported instruction formats fail closed.
Version 041's container format is unsupported. Nonstandard/embedded `.dex` members,
gaps in multidex numbering and excessive DEX counts/sizes reject analysis instead
of silently reducing coverage. APKs containing resources and no DEX produce a
zero DEX summary. Native libraries, reflection, dynamically loaded, packed and
encrypted code are outside coverage.

Implementation references: [AOSP DEX format](https://source.android.com/docs/core/runtime/dex-format)
and [Dalvik bytecode](https://source.android.com/docs/core/runtime/dalvik-bytecode).

## Candidate rules and evidence

| Candidate | Evidence and limit |
| --- | --- |
| Non-cryptographic random | A decoded invoke instruction references a recognized `java.util.Random` constructor; security-sensitive use is unknown |
| MD5 / SHA-1 | A recognized `MessageDigest.getInstance` invocation and a matching `const-string` reference occur in the same method; argument data flow is unknown |
| DES / DESede and ECB | A recognized `Cipher.getInstance` invocation and a matching transformation literal occur in the same method; argument data flow is unknown |
| WebView JavaScript / debugging / file access | A recognized setter invocation is referenced; its boolean argument, effective configuration and loaded content are unknown |
| Secret-like literals | A decoded `const-string` references an AWS access-key shape, private-key marker or credential-assignment heuristic; validity is unknown |

The WebView rules deliberately report configuration API references even when an
argument is `false`; neither enabling nor exploitability is inferred. Crypto
literals elsewhere in the DEX or in another method do not trigger crypto rules.
Only recognized full API signatures match, not arbitrary similarly named methods.

Evidence contains only a validated DEX filename, numeric method index and code-unit
instruction offset, fixed API/category identifiers and, for secret-like literals,
their length. **Literal values, tokens, private keys, URLs, arbitrary DEX class or
method names and string excerpts never appear in results or ordinary API responses.**
No secret fingerprint is emitted. Use the protected APK and the numeric evidence
location for authorized manual review. Detection is intentionally heuristic and
incomplete; a result without candidates is not proof that an APK has no secrets.

One candidate per rule per method is retained, up to the bounded result capacity;
exceeding capacity fails the attempt instead of returning a silent partial report.
Manifest candidates are retained unchanged. All candidates remain **Unreviewed**
and require analyst verification; successful processing still means Needs Review.

## Output contract and resource limits

DEX results use `schema_version: 2`, `engine_version: droidshield-dex-1`, the same
server-matched APK SHA-256, byte size and manifest metadata, fixed candidate
narratives, four exact limitation statements and `dex_summary` with:

- `dex_files`: standard DEX files inspected;
- `classes`: class-definition count;
- `methods`: method identifiers, including external references;
- `strings`: string identifiers;
- `analyzed_methods`: concrete code items inspected;
- `code_units`: cumulative 16-bit instruction/payload units inspected.

The parent validates all output with `DexAnalysisResult` or `validate_dex_result`
before publication. The original `AnalysisResult` remains the strict schema-1
manifest contract. Additional or arbitrary evidence/narrative fields are rejected.

| Setting | Default | Application |
| --- | --- | --- |
| `DEX_MAX_FILES` | 16 | Maximum standard multidex entries |
| `DEX_MAX_BYTES` | 67,108,864 | Cumulative uncompressed DEX bytes, also a decoded-string byte budget |
| `DEX_MAX_IDS` | 100,000 | Cumulative string/type/proto/field/method/class table entries |
| `DEX_MAX_CODE_UNITS` | 4,000,000 | Cumulative code-item 16-bit units |

These are additional limits; APK archive/expansion, manifest, process CPU/memory,
wall time and total output limits still apply. Large otherwise valid apps can
exceed the deployment's configured budgets and fail safely. Checksums detect
internal corruption; they do not authenticate a publisher or verify APK signing.

## Verification

`tests/dex_factory.py` contains a real DEX assembled with smali 2.5.2 plus the
reproducible source. CI uses the compiled bytes without requiring an SDK. Where
smali is installed, a test independently reassembles and compares the bytes.
Tests exercise actual Bubblewrap DEX execution, original manifest compatibility,
multidex and resource-only APKs, unreferenced method-pool names, altered checksums,
bad offsets/MUTF-8/method references/instructions, expansion/count/code budgets,
strict output validation, cancellation and absence of raw literals in results.

Run `pytest tests/test_dex_engine.py tests/test_apk_engine.py tests/test_sandbox.py`
and the repository's normal backend checks. Runtime/lab/MobSF operation is managed
by its separate adapter and workflow; this engine never connects to an external
service or starts a device session.
