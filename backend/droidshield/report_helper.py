"""Fixed, resource-limited PDF renderer; input and output travel only over pipes."""

import json
import resource
import sys


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (20, 21))
    resource.setrlimit(resource.RLIMIT_AS, (512 * 1024**2, 512 * 1024**2))
    resource.setrlimit(resource.RLIMIT_FSIZE, (16 * 1024**2, 16 * 1024**2))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    resource.setrlimit(resource.RLIMIT_NPROC, (64, 64))
    encoded = sys.stdin.buffer.read(2 * 1024**2 + 8193)
    if len(encoded) > 2 * 1024**2 + 8192:
        return 2
    from droidshield.report_pdf import render_pdf

    content = render_pdf(json.loads(encoded))
    if not content.startswith(b"%PDF-") or len(content) > 16 * 1024**2:
        return 2
    sys.stdout.buffer.write(content)
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    try:
        result = main()
    except Exception:
        # Never disclose report text, tool evidence, paths or interpreter errors.
        result = 2
    raise SystemExit(result)
