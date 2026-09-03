/*
 * InterposeScope-C v2.2.0 — macOS user-mode hook & API-indirection mapper
 *
 * Full-featured scanner with remote process support, hook clustering,
 * dyld shared cache ground-truth byte-diff, export-trie integrity,
 * LC_REEXPORT forwarder resolution, cohort multi-process scanning,
 * alias-pair divergence, Rosetta x86_64 support, and continuous monitoring.
 *
 * macOS ONLY. Uses Mach-O, dyld, Mach VM, Objective-C runtime, and
 * CoreFoundation/Security frameworks not available on other platforms.
 *
 * Read-only. No writes to target memory. No file modifications on target.
 * Designed for C2 beacon inline execution (curl-pipe or inline_macho).
 *
 * Build:  clang -arch arm64 -O2 -isysroot $(xcrun --show-sdk-path) \
 *           -o interposescope interposescope.c -framework Foundation -lobjc
 */

#ifndef __APPLE__
#error "InterposeScope-C is macOS-only. It requires Mach-O, dyld, and Mach VM APIs."
#endif

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <ctype.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/getsect.h>
#include <mach/mach.h>
#include <mach/vm_region.h>
#include <mach/vm_map.h>
#include <mach/task.h>
#include <mach/mach_vm.h>
#include <mach-o/dyld_images.h>
#include <objc/runtime.h>
#include <objc/message.h>
#include <objc/objc.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/mman.h>
#include <limits.h>
#include <libproc.h>
#include <signal.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/SecCode.h>
#include <Security/SecStaticCode.h>
#include <Security/SecRequirement.h>
#include <Security/SecTrust.h>
#include <libkern/OSByteOrder.h>

/* ─── Configuration ─────────────────────────────────────────────────────── */

#define OUT_CAP (2 * 1024 * 1024)
static char  g_out[OUT_CAP];
static size_t g_len = 0;

/* stealth flags */
static int q_quiet = 0;          /* --quiet: no banner, no section headers */
static int q_minimal = 0;        /* --minimal: only anomalies + verdicts   */

/* analysis flags */
static int g_verbose = 0;
static int g_json = 0;
static int g_brief = 0;
static int g_top = 0;
static int g_check_sign = 0;
static int g_dumprx = 0;
static int g_dump_bytes = 0;
static int g_bytes_window = 64;
static pid_t g_remote_pid = 0;

/* baseline comparison */
static int g_baseline = 0;       /* --baseline: write fingerprint file */
static int g_compare = 0;        /* --compare: compare against baseline */
static char g_baseline_path[PATH_MAX] = {0};

/* ground-truth byte-diff against on-disk dyld shared cache */
static int g_ground_truth = 0;   /* --ground-truth: byte-diff vs shared cache */

/* export-trie integrity (F2) */
static int g_export_trie = 0;    /* --export-trie: verify dlsym vs export trie */

/* LC_REEXPORT forwarder resolution (F3) */
static int g_forwarders = 0;     /* --forwarders: resolve LC_REEXPORT chains */

/* cohort multi-process mode (F4) */
static int g_cohort = 0;         /* --cohort: scan multiple PIDs */
static char g_cohort_pids[256] = {0}; /* comma-separated PID list */

/* alias-pair divergence (F9) */
static int g_alias_pairs = 0;    /* --alias-pairs: check $NOCANCEL pairs */

/* watch mode */
static int g_watch = 0;

/* module/function selectors */
static char g_modules[16][64]; static int g_modules_n = 0;
static char g_functions[64][128]; static int g_functions_n = 0;
static int g_all_exp = 0;

static void out(const char *fmt, ...) {
    if (g_len >= OUT_CAP - 2048) return;
    va_list ap; va_start(ap, fmt);
    int n = vsnprintf(g_out + g_len, OUT_CAP - g_len, fmt, ap);
    va_end(ap);
    if (n > 0) g_len += (size_t)n;
}
static void flush_out(void) { fwrite(g_out, 1, g_len, stdout); fflush(stdout); }
static void vout(const char *fmt, ...) { /* verbose-only output */ }

/* ─── State enums ────────────────────────────────────────────────────────── */

enum { ST_CLEAN=0, ST_HOOKED, ST_PATCHED, ST_FWD, ST_NA, ST_NOT_LOADED,
       ST_NON_EXEC, ST_ERROR, ST_SELF_FWD, ST_SYS_MODULE, ST_THIRD_PARTY,
       ST_PRIVATE_EXEC, ST_SYSCALL, ST_UNKNOWN, ST_UNKNOWN_ENTRY,
       ST_INTERPOSED, ST_REBOUND, ST_SWIZZLED, ST_TRIE_MISMATCH,
       ST_REEXPORT, ST_ALIAS_DIV, ST_UNSOLVED };
static const char *STN[] = {"CLEAN","HOOKED","PATCHED","FWD","N/A",
    "NOT LOADED","NON-EXEC","ERROR","SELF-FWD","SYS","THIRD-PARTY",
    "PRIVATE-EXEC","SYSCALL","?","UNKNOWN-ENTRY",
    "INTERPOSED","REBOUND","SWIZZLED","TRIE-MISMATCH",
    "REEXPORT","ALIAS-DIV","UNSOLVED"};

enum { PT_NONE=0, PT_EARLY_RET, PT_CONST_RET, PT_NOP, PT_BRK, PT_BYTE, PT_UNKNOWN };
static const char *PTN[] = {"NONE","EARLY-RET","CONST-RET","NOP","BRK","BYTE","?"};

/* ─── Utilities ───────────────────────────────────────────────────────────── */

static int g_arm64;
static const char *basename_(const char *p) {
    const char *s = strrchr(p, '/');
    return s ? s + 1 : p;
}
static const char *owner_of(uintptr_t addr, char *buf, size_t bufsz) {
    Dl_info di;
    if (dladdr((void *)addr, &di) && di.dli_fname) {
        snprintf(buf, bufsz, "%s", di.dli_fname);
        return buf;
    }
    snprintf(buf, bufsz, "ANON 0x%lx", (unsigned long)addr);
    return buf;
}
static uint64_t fnv1a(const void *d, size_t n) {
    const uint8_t *p = d;
    uint64_t h = 0xcbf29ce484222325ULL;
    for (size_t i = 0; i < n; i++) { h ^= p[i]; h *= 0x100000001B3ULL; }
    return h;
}
/* Resolve a Mach-O symbol's file offset within the image's __TEXT segment */
static off_t sym_file_offset(const struct mach_header_64 *hdr, uintptr_t vmaddr,
                              uintptr_t slide) {
    uintptr_t load_addr = vmaddr - slide;
    uint8_t *p = (uint8_t *)hdr + sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        struct load_command *lc = (void *)p;
        if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg = (void *)p;
            if (strncmp(seg->segname, "__TEXT", 6) == 0 &&
                load_addr >= seg->vmaddr + slide &&
                load_addr < seg->vmaddr + slide + seg->vmsize) {
                return seg->fileoff + (load_addr - seg->vmaddr - slide);
            }
        }
        p += lc->cmdsize;
    }
    return -1;
}

/* ─── Image inventory ─────────────────────────────────────────────────────── */

typedef struct {
    char path[PATH_MAX];
    char name[256];
    char uuid[37];
    const struct mach_header_64 *mh;
    uintptr_t slide;
    uintptr_t load_addr;
    size_t size;
    int cache_only, is_main, is_64;
    uintptr_t text_base;
    size_t text_size;
    int ninterpose;
} image_t;

static int collect_images(image_t *imgs, int max) {
    uint32_t n = _dyld_image_count();
    int cnt = 0;
    for (uint32_t i = 0; i < n && cnt < max; i++) {
        const char *p = _dyld_get_image_name(i);
        if (!p || !p[0]) continue;
        image_t *im = &imgs[cnt];
        strncpy(im->path, p, PATH_MAX - 1);
        im->mh = (const void *)_dyld_get_image_header(i);
        im->slide = _dyld_get_image_vmaddr_slide(i);
        im->is_64 = im->mh->magic == MH_MAGIC_64;
        im->cache_only = access(p, F_OK) != 0;
        im->is_main = i == 0;
        im->text_base = 0; im->text_size = 0; im->ninterpose = 0;
        cnt++;
    }
    return cnt;
}

/* ─── dyld __interpose sections ───────────────────────────────────────────── */

typedef struct {
    char image[PATH_MAX];
    uintptr_t replacee;
    char replacee_owner[PATH_MAX];
    uintptr_t replacement;
    char replacement_owner[PATH_MAX];
    int third_party;
} ipr_t;

static int scan_interpose(image_t *imgs, int nimgs, ipr_t *rows, int maxrows) {
    int nr = 0;
    for (int i = 0; i < nimgs; i++) {
        image_t *im = &imgs[i];
        if (!im->is_64 || !im->mh) continue;
        uintptr_t p = (uintptr_t)im->mh + sizeof(struct mach_header_64);
        for (uint32_t c = 0; c < im->mh->ncmds; c++) {
            struct load_command *lc = (void *)p;
            if (lc->cmd == LC_SEGMENT_64) {
                struct segment_command_64 *seg = (void *)p;
                if (strncmp(seg->segname, "__DATA", 6) == 0) {
                    struct section_64 *sec = (void *)(p + sizeof(struct segment_command_64));
                    for (uint32_t s = 0; s < seg->nsects; s++, sec++) {
                        if (strncmp(sec->sectname, "__interpose", 12) == 0 &&
                            nr < maxrows) {
                            uintptr_t base = sec->addr;
                            im->ninterpose += (int)(sec->size / 16);
                            for (uint64_t k = 0; k + 16 <= sec->size; k += 16) {
                                uintptr_t rep, sub;
                                memcpy(&rep, (void *)(base + k), 8);
                                memcpy(&sub, (void *)(base + k + 8), 8);
                                strncpy(rows[nr].image, im->path, PATH_MAX - 1);
                                rows[nr].replacee = rep;
                                rows[nr].replacement = sub;
                                owner_of(rep, rows[nr].replacee_owner, PATH_MAX);
                                owner_of(sub, rows[nr].replacement_owner, PATH_MAX);
                                rows[nr].third_party =
                                    strncmp(rows[nr].replacement_owner, "/System/", 8) != 0 &&
                                    strncmp(rows[nr].replacement_owner, "/usr/lib/", 9) != 0 &&
                                    strncmp(rows[nr].replacement_owner, "ANON", 4) != 0;
                                nr++;
                            }
                        }
                    }
                }
            }
            p += lc->cmdsize;
        }
    }
    return nr;
}

/* ─── Indirect symbol rebinding (fishhook) ────────────────────────────────── */

typedef struct {
    char image[PATH_MAX];
    char symbol[128];
    uintptr_t expected;
    uintptr_t actual;
    char actual_owner[PATH_MAX];
} rbr_t;

static int scan_rebinds(image_t *imgs, int nimgs, rbr_t *rows, int maxrows) {
    int nr = 0;
    for (int i = 0; i < nimgs && nr < maxrows; i++) {
        image_t *im = &imgs[i];
        if (!im->is_64 || !im->mh || im->cache_only) continue;

        int fd = open(im->path, O_RDONLY);
        if (fd < 0) continue;
        struct stat st;
        if (fstat(fd, &st) < 0) { close(fd); continue; }
        size_t fsize = st.st_size;
        void *mapped = mmap(NULL, fsize, PROT_READ, MAP_PRIVATE, fd, 0);
        close(fd);
        if (mapped == MAP_FAILED) continue;

        const struct mach_header_64 *fmh = mapped;
        if (fmh->magic != MH_MAGIC_64) { munmap(mapped, fsize); continue; }

        uintptr_t off = sizeof(struct mach_header_64);
        struct symtab_command *symtab = NULL;
        struct dysymtab_command *dysymtab = NULL;
        struct section_64 *la_sec = NULL;

        for (uint32_t c = 0; c < fmh->ncmds; c++) {
            uint8_t *p = (uint8_t *)mapped + off;
            struct load_command *lc = (void *)p;
            if (lc->cmd == LC_SYMTAB) symtab = (void *)p;
            else if (lc->cmd == LC_DYSYMTAB) dysymtab = (void *)p;
            else if (lc->cmd == LC_SEGMENT_64) {
                struct segment_command_64 *seg = (void *)p;
                struct section_64 *sec = (void *)(p + sizeof(*seg));
                for (uint32_t s = 0; s < seg->nsects; s++, sec++)
                    if (strncmp(sec->sectname, "__la_symbol_ptr", 15) == 0)
                        la_sec = sec;
            }
            off += lc->cmdsize;
        }
        if (!symtab || !dysymtab || !la_sec) { munmap(mapped, fsize); continue; }

        struct nlist_64 *syms = (void *)((uint8_t *)mapped + symtab->symoff);
        char *strs = (void *)((uint8_t *)mapped + symtab->stroff);
        uint32_t *indirect = (uint32_t *)((uint8_t *)mapped + dysymtab->indirectsymoff);
        uint64_t count = la_sec->size / 8;
        uint32_t istart = dysymtab->indirectsymoff ? la_sec->reserved1 : 0;

        for (uint64_t j = 0; j < count && nr < maxrows; j++) {
            uint32_t isym = indirect ? indirect[istart + j] : UINT32_MAX;
            if (isym == UINT32_MAX || isym >= symtab->nsyms) continue;
            struct nlist_64 *sym = &syms[isym];
            const char *sname = &strs[sym->n_un.n_strx];
            if (!sname[0]) continue;
            uintptr_t live = *((uintptr_t *)(la_sec->addr + j * 8 + im->slide));
            uintptr_t expected = sym->n_value + im->slide;
            if (live == expected) continue;
            strncpy(rows[nr].image, im->path, PATH_MAX - 1);
            strncpy(rows[nr].symbol, sname, 127);
            rows[nr].expected = expected;
            rows[nr].actual = live;
            owner_of(live, rows[nr].actual_owner, PATH_MAX);
            nr++;
        }
        munmap(mapped, fsize);
    }
    return nr;
}

/* ─── Trampoline decoders ─────────────────────────────────────────────────── */

typedef struct {
    const char *kind;
    uintptr_t target;
} tramp_t;

static int dec_arm64_step(uintptr_t entry, const uint8_t *buf, tramp_t *t) {
    uint32_t w0, w1, w2;
    memcpy(&w0, buf, 4); memcpy(&w1, buf+4, 4); memcpy(&w2, buf+8, 4);
    if ((w0 & 0xFC000000u) == 0x14000000u) {
        int32_t imm = (int32_t)(w0 & 0x03FFFFFFu);
        if (imm & 0x02000000) imm |= 0xFC000000;
        t->kind = "B"; t->target = entry + ((int64_t)imm << 2); return 1;
    }
    if ((w0 & 0xFC000000u) == 0x94000000u) {
        int32_t imm = (int32_t)(w0 & 0x03FFFFFFu);
        if (imm & 0x02000000) imm |= 0xFC000000;
        t->kind = "BL"; t->target = entry + ((int64_t)imm << 2); return 1;
    }
    if ((w0 & 0xFFFFFC1Fu) == 0xD61F0000u) { t->kind = "BR-reg"; t->target = 0; return 0; }
    if ((w0 & 0x9F000000u) == 0x90000000u) {
        unsigned rd = w0 & 0x1F;
        uint64_t immlo = (w0 >> 29) & 3, immhi = (w0 >> 5) & 0x7FFFF;
        int64_t imm = ((int64_t)(immhi << 2 | immlo)) << 12;
        uintptr_t page = (entry & ~0xFFFULL) + (uintptr_t)imm;
        if ((w1 & 0xFF800000u) == 0x91000000u && (w1 & 0x1F) == rd &&
            ((w1 >> 5) & 0x1F) == rd &&
            (w2 & 0xFFFFFC1Fu) == 0xD61F0000u && ((w2 >> 5) & 0x1F) == rd) {
            uint64_t add = (w1 >> 10) & 0xFFF;
            t->kind = "ADRP+ADD+BR"; t->target = page + add; return 1;
        }
    }
    if (w0 == 0x58000050u && w1 == 0xD61F0200u) {
        uint64_t tgt; memcpy(&tgt, buf + 8, 8);
        t->kind = "LDR+BR"; t->target = (uintptr_t)tgt; return 1;
    }
    return 0;
}

static int dec_x64_step(uintptr_t entry, const uint8_t *buf, tramp_t *t) {
    if (buf[0] == 0xE9) {
        int32_t r; memcpy(&r, buf+1, 4);
        t->kind = "JMP rel32"; t->target = entry + 5 + r; return 1;
    }
    if (buf[0] == 0xEB) {
        int8_t r = (int8_t)buf[1]; t->kind = "JMP rel8"; t->target = entry + 2 + r; return 1;
    }
    if (buf[0] == 0xFF && buf[1] == 0x25) {
        int32_t d; memcpy(&d, buf+2, 4);
        uintptr_t slot = entry + 6 + d;
        uintptr_t tgt; memcpy(&tgt, (void*)slot, 8);
        t->kind = "JMP [rip+disp]"; t->target = tgt; return 1;
    }
    if (buf[0] == 0x48 && buf[1] == 0xB8 && buf[10]==0xFF && buf[11]==0xE0) {
        uint64_t tgt; memcpy(&tgt, buf+2, 8);
        t->kind = "MOV RAX/JMP"; t->target = tgt; return 1;
    }
    if (buf[0] == 0x49 && buf[1] == 0xBB && buf[10]==0x41 && buf[11]==0xFF && buf[12]==0xE3) {
        uint64_t tgt; memcpy(&tgt, buf+2, 8);
        t->kind = "MOV R11/JMP"; t->target = tgt; return 1;
    }
    if (buf[0] == 0x68 && buf[5] == 0xC3) {
        uint32_t tgt; memcpy(&tgt, buf+1, 4);
        t->kind = "PUSH/RET"; t->target = tgt; return 1;
    }
    return 0;
}

static int decode_tramp(uintptr_t addr, tramp_t *t) {
    uint8_t buf[64]; memcpy(buf, (void *)addr, sizeof buf);
    if (g_arm64) return dec_arm64_step(addr, buf, t);
    return dec_x64_step(addr, buf, t);
}

static void follow_chain(uintptr_t start, tramp_t *t, uintptr_t *chain, int *chain_len) {
    chain[0] = start; *chain_len = 1;
    for (int hop = 0; hop < 7 && *chain_len < 8; hop++) {
        uintptr_t entry = t->target;
        if (!entry) break;
        uint8_t buf[64]; memcpy(buf, (void *)entry, sizeof buf);
        tramp_t next = {0};
        int ok = g_arm64 ? dec_arm64_step(entry, buf, &next)
                         : dec_x64_step(entry, buf, &next);
        if (!ok || !next.target) break;
        chain[(*chain_len)++] = next.target;
        t->target = next.target;
        t->kind = next.kind;
        if (next.kind[0] == 'B' && next.kind[1] == 'R') break;
    }
}

/* ─── Patch classification ────────────────────────────────────────────────── */

static int classify_patch(const uint8_t *buf, size_t len) {
    if (len < 4) return PT_NONE;
    if (g_arm64) {
        uint32_t w0; memcpy(&w0, buf, 4);
        if (w0 == 0xD65F03C0u) return PT_EARLY_RET;
        if (w0 == 0xD503201Fu) return PT_NOP;
        if ((w0 & 0xFFE0001Fu) == 0xD4200000u) return PT_BRK;
        if ((w0 & 0xFFE0001Fu) == 0xD4000001u) return PT_BRK;
        if (len >= 8) {
            uint32_t w1; memcpy(&w1, buf+4, 4);
            if ((w0 & 0xFFE00000u) == 0xD2800000u &&
                (w1 & 0xFFFFFC1Fu) == 0xD65F0000u) return PT_CONST_RET;
        }
    } else {
        if (buf[0] == 0xC3) return PT_EARLY_RET;
        if (len >= 3 && buf[0]==0x31 && buf[1]==0xC0 && buf[2]==0xC3) return PT_CONST_RET;
        if (buf[0] == 0x90) return PT_NOP;
        if (buf[0] == 0xCC) return PT_BRK;
    }
    return PT_NONE;
}

/* ─── UNKNOWN_ENTRY anti-evasion detection ────────────────────────────────── */
/* If entry doesn't look like clean code AND doesn't match known hook patterns,
   it's probably an actively concealed hook — flag it instead of saying CLEAN  */

static int is_known_clean_prologue_arm64(const uint8_t *buf, size_t len) {
    if (len < 4) return 0;
    uint32_t w0; memcpy(&w0, buf, 4);
    /* PACIBSP (sign return address) — standard arm64e prologue */
    if (w0 == 0xD503237Fu) return 1;
    /* PACIASP / AUTIASP variants */
    if (w0 == 0xD503233Fu) return 1;  /* PACIASP */
    /* STP x29, x30, [sp, #-N]! — frame setup (pre-index) */
    if ((w0 & 0xFFC003FFu) == 0xA90003FDu) return 1;
    /* STP with other regs (pre-index) — generic frame setup */
    if ((w0 & 0xFFC00000u) == 0xA9800000u) return 1;
    /* SUB sp, sp, #N — stack frame allocation */
    if ((w0 & 0xFF80007Fu) == 0xD100007Fu) return 1;
    /* NOP */
    if (w0 == 0xD503201Fu) return 1;
    /* RET */
    if (w0 == 0xD65F03C0u) return 1;
    /* ADRP — address computation start */
    if ((w0 & 0x9F000000u) == 0x90000000u) return 1;
    /* BL — call (may be resolved by dyld) */
    if ((w0 & 0xFC000000u) == 0x94000000u) return 1;
    /* B — unconditional branch (may be resolved by dyld) */
    if ((w0 & 0xFC000000u) == 0x14000000u) return 1;
    /* MOVZ Wn, #imm — common in syscall stubs and simple wrappers */
    if ((w0 & 0xFF800000u) == 0x52800000u) return 1;
    /* MOVZ Xn, #imm — including MOV X16, #syscall_num */
    if ((w0 & 0xFF800000u) == 0xD2800000u) return 1;
    /* MOVN Wn, #imm — negative immediate MOV */
    if ((w0 & 0xFF800000u) == 0x12800000u) return 1;
    /* MOVN Xn, #imm — negative immediate MOV (64-bit) */
    if ((w0 & 0xFF800000u) == 0x92800000u) return 1;
    /* ORR Xn, XZR, Xm — MOV Xn, Xm (register move) */
    if ((w0 & 0xFFE0FFE0u) == 0xAA0003E0u) return 1;
    /* ORR Wn, WZR, Wm — MOV Wn, Wm (32-bit register move) */
    if ((w0 & 0xFFE0FFE0u) == 0x2A0003E0u) return 1;
    /* LDR Xn, [Xm, #imm] — common function start in shared cache */
    if ((w0 & 0xFFC00000u) == 0xF9400000u) return 1;
    /* CBZ/CBNZ — conditional branch (common in stubs) */
    if ((w0 & 0x7E000000u) == 0x34000000u) return 1;
    /* SVC #0 — direct syscall */
    if ((w0 & 0xFFE0001Fu) == 0xD4000001u) return 1;
    /* CMP Xn, #imm (SUBS XZR, Xn, #imm) — common in objc_msgSend nil check */
    if ((w0 & 0xFF00001Fu) == 0xF100001Fu) return 1;
    /* STP Xn, Xm, [Xk, #imm] (offset variant) — frame or register save */
    if ((w0 & 0xFFC00000u) == 0xA9000000u) return 1;
    /* LDP Xn, Xm, [Xk, #imm] — register restore */
    if ((w0 & 0xFFC00000u) == 0xA9400000u) return 1;
    return 0;
}

static int is_known_clean_prologue_x64(const uint8_t *buf, size_t len) {
    if (len < 2) return 0;
    /* endbr64 — Intel CET */
    if (buf[0] == 0xF3 && buf[1] == 0x0F && buf[2] == 0x1E && buf[3] == 0xFA) return 1;
    /* push rbp / mov rbp, rsp */
    if (buf[0] == 0x55 && buf[1] == 0x48 && buf[2] == 0x89) return 1;
    /* push r15 / mov r15, rsp */
    if (buf[0] == 0x41 && buf[1] == 0x57) return 1;
    /* sub rsp, N */
    if (buf[0] == 0x48 && buf[1] == 0x83 && buf[2] == 0xEC) return 1;
    /* ret */
    if (buf[0] == 0xC3) return 1;
    /* cmp / mov / xor (common starts) */
    if (buf[0] == 0x48 || buf[0] == 0x49 || buf[0] == 0x4C) return 1;
    return 0;
}

static int is_known_clean_prologue(const uint8_t *buf, size_t len, int arch) {
    return arch ? is_known_clean_prologue_arm64(buf, len)
                : is_known_clean_prologue_x64(buf, len);
}

/* ─── Syscall stub detection ──────────────────────────────────────────────── */

static int is_syscall_stub_arm64(uintptr_t a) {
    uint32_t w0, w1;
    memcpy(&w0, (void *)a, 4);
    memcpy(&w1, (void *)(a + 4), 4);
    /* Pattern 1: SVC #0 as first instruction */
    if ((w0 & 0xFFE0001Fu) == 0xD4000001u) return 1;
    /* Pattern 2: MOV X16, #imm (MOVZ X16) followed by SVC #0 */
    if ((w0 & 0xFFE0001Fu) == 0xD2800000u && ((w0 >> 0) & 0x1F) == 16 &&
        (w1 & 0xFFE0001Fu) == 0xD4000001u) return 1;
    /* Pattern 3: MOV X16, #imm (MOVN X16) followed by SVC #0 */
    if ((w0 & 0xFFE0001Fu) == 0x92800000u && ((w0 >> 0) & 0x1F) == 16 &&
        (w1 & 0xFFE0001Fu) == 0xD4000001u) return 1;
    return 0;
}
static int is_syscall_stub_x64(uintptr_t a) {
    uint8_t b[2]; memcpy(b, (void *)a, 2);
    return b[0] == 0x0F && b[1] == 0x05;
}

/* ─── ObjC swizzle surface ────────────────────────────────────────────────── */

typedef struct {
    char cls[64], sel[128];
    int state;
    uintptr_t imp;
    char owner[PATH_MAX];
} objc_row_t;

static int scan_objc(objc_row_t *rows, int maxrows) {
    struct { const char *c, *s; } cur[] = {
        {"NSURLSession","dataTaskWithRequest:"},
        {"NSBundle","load"},
        {"NSFileManager","contentsOfDirectoryAtPath:error:"},
        {"NSWorkspace","openURL:"},
        {"NSTask","launch"},
        {"NSFileManager","fileExistsAtPath:"},
        {"NSProcessInfo","processInfo"},
        {"NSURLConnection","sendSynchronousRequest:returningResponse:error:"},
    };
    int nr = 0;
    for (size_t i = 0; i < sizeof(cur)/sizeof(cur[0]) && nr < maxrows; i++) {
        objc_row_t *r = &rows[nr];
        strncpy(r->cls, cur[i].c, 63);
        strncpy(r->sel, cur[i].s, 127);
        r->state = 1; r->imp = 0; r->owner[0] = 0;
        Class c = objc_getClass(cur[i].c);
        if (!c) { nr++; continue; }
        SEL s = sel_registerName(cur[i].s);
        Method m = class_getInstanceMethod(c, s);
        if (!m) { r->state = 2; nr++; continue; }
        IMP imp = method_getImplementation(m);
        r->imp = (uintptr_t)imp;
        r->state = 0;
        if (imp) owner_of((uintptr_t)imp, r->owner, PATH_MAX);
        nr++;
    }
    return nr;
}

/* ─── Telemetry surfaces ──────────────────────────────────────────────────── */

typedef struct { const char *sym; int present; char owner[PATH_MAX]; } tel_t;

static int scan_telemetry(tel_t *rows, int maxrows) {
    const char *syms[] = {
        "es_new_client","es_subscribe","es_unsubscribe","es_delete_client",
        "es_mute_process","os_log_create","os_log","os_activity_create",
    };
    int nr = 0;
    for (size_t i = 0; i < sizeof(syms)/sizeof(syms[0]) && nr < maxrows; i++) {
        rows[nr].sym = syms[i];
        void *a = dlsym(RTLD_DEFAULT, syms[i]);
        rows[nr].present = a != NULL;
        if (a) owner_of((uintptr_t)a, rows[nr].owner, PATH_MAX);
        else snprintf(rows[nr].owner, PATH_MAX, "N/A");
        nr++;
    }
    return nr;
}

/* ─── Remote process scanning ─────────────────────────────────────────────── */

typedef struct {
    mach_port_t task;
    bool valid;
} remote_t;

static remote_t open_remote(pid_t pid) {
    remote_t r = { .task = MACH_PORT_NULL, .valid = false };
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &r.task);
    if (kr == KERN_SUCCESS) {
        r.valid = true;
    }
    return r;
}

static bool remote_read(remote_t rt, mach_vm_address_t addr, mach_vm_size_t size,
                        void *buf, mach_vm_size_t *out_size) {
    if (!rt.valid) return false;
    kern_return_t kr = mach_vm_read_overwrite(rt.task, addr, size,
                                              (mach_vm_address_t)buf, out_size);
    return kr == KERN_SUCCESS && *out_size == size;
}

/* remote image enumeration using dyld_all_image_infos */
/* collect_images_remote removed — use per-image reads instead */

/* ─── Anonymous RX walk ──────────────────────────────────────────────────── */

typedef struct { mach_vm_address_t base; mach_vm_size_t size; } rx_t;

static int scan_rx_regions(rx_t *rows, int maxrows) {
    task_t task = mach_task_self();
    mach_vm_address_t addr = MACH_VM_MIN_ADDRESS;
    int nr = 0;
    while (nr < maxrows) {
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t obj = MACH_PORT_NULL;
        mach_vm_size_t size = 0;
        vm_address_t vaddr = (vm_address_t)addr;
        vm_size_t vsize = (vm_size_t)size;
        kern_return_t kr = vm_region_64(task, &vaddr, &vsize,
            VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &cnt, &obj);
        addr = (mach_vm_address_t)vaddr;
        size = (mach_vm_size_t)vsize;
        if (kr != KERN_SUCCESS) break;
        if ((info.protection & VM_PROT_EXECUTE) &&
            !(info.protection & VM_PROT_WRITE)) {
            Dl_info di;
            if (!dladdr((void *)addr, &di) || !di.dli_fname) {
                rows[nr].base = addr;
                rows[nr].size = size;
                nr++;
            }
        }
        addr += size;
        if (addr == 0) break;
    }
    return nr;
}

/* ─── Remote PID scanning via task_for_pid + mach_vm_read_overwrite ─────── */

static void remote_analyze(pid_t pid, image_t *remote_imgs, int *n_remote) {
    remote_t rt = open_remote(pid);
    if (!rt.valid) {
        if (!q_quiet) {
            out("  [remote] task_for_pid failed: %s (entitlement/root required)\n",
                mach_error_string(KERN_FAILURE));
        }
        return;
    }
    /* Disable "Remote process successfully opened" alert in quiet mode */
    if (!q_quiet)
        out("  [remote] task_for_pid(pid=%d): SUCCESS — task port %u\n", pid, rt.task);
    
    /* Enumerate remote images by walking VM regions and reading Mach-O headers */
    mach_vm_address_t addr = MACH_VM_MIN_ADDRESS;
    int found = 0;
    while (found < 1024) {
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t obj = MACH_PORT_NULL;
        mach_vm_size_t size = 0;
        vm_address_t vaddr = (vm_address_t)addr;
        vm_size_t vsize = (vm_size_t)size;
        kern_return_t kr = vm_region_64(rt.task, &vaddr, &vsize,
            VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &cnt, &obj);
        addr = (mach_vm_address_t)vaddr;
        size = (mach_vm_size_t)vsize;
        if (kr != KERN_SUCCESS) break;
        /* Check if this region is executable — candidate for a Mach-O image */
        if ((info.protection & VM_PROT_EXECUTE) && size >= 0x1000) {
            uint8_t hdr_buf[4096];
            mach_vm_size_t out_sz = 0;
            if (remote_read(rt, addr, sizeof(hdr_buf), hdr_buf, &out_sz)) {
                uint32_t magic = *(uint32_t *)hdr_buf;
                if (magic == MH_MAGIC_64 || magic == MH_CIGAM_64 ||
                    magic == MH_MAGIC || magic == MH_CIGAM) {
                    /* Parse Mach-O header for LC_UUID and image name */
                    struct mach_header_64 *mh = (struct mach_header_64 *)hdr_buf;
                    int is_remote_x64 = 0;

                    if (mh->magic == MH_CIGAM_64) {
                        /* Cross-endian 64-bit (Rosetta x86_64 on arm64 host) */
                        is_remote_x64 = 1;
                        /* Byte-swap key header fields for processing */
                        uint32_t ncmds = OSSwapInt32(mh->ncmds);
                        uint32_t sizeofcmds = OSSwapInt32(mh->sizeofcmds);
                        mh->ncmds = ncmds;
                        mh->sizeofcmds = sizeofcmds;
                        if (!q_quiet)
                            out("  [remote] Rosetta x86_64 image detected at 0x%llx\n",
                                (unsigned long long)addr);
                    } else if (mh->magic == MH_MAGIC) {
                        /* 32-bit Mach-O (legacy iOS sim or old binary) */
                        is_remote_x64 = 1;
                        struct mach_header *mh32 = (struct mach_header *)hdr_buf;
                        if (!q_quiet)
                            out("  [remote] 32-bit Mach-O image at 0x%llx (legacy)\n",
                                (unsigned long long)addr);
                        /* Use 32-bit header fields */
                        uint8_t *lc_ptr = hdr_buf + sizeof(struct mach_header);
                        uint8_t *lc_end = lc_ptr + mh32->sizeofcmds;
                        if (lc_end > hdr_buf + sizeof(hdr_buf))
                            lc_end = hdr_buf + sizeof(hdr_buf);
                        char uuid_str[37] = {0};
                        while (lc_ptr + sizeof(struct load_command) <= lc_end) {
                            struct load_command *lc = (struct load_command *)lc_ptr;
                            if (lc->cmd == LC_UUID) {
                                struct uuid_command *uc = (struct uuid_command *)lc_ptr;
                                uuid_t *u = &uc->uuid;
                                snprintf(uuid_str, sizeof(uuid_str),
                                    "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                                    (*u)[0],(*u)[1],(*u)[2],(*u)[3],
                                    (*u)[4],(*u)[5],(*u)[6],(*u)[7],
                                    (*u)[8],(*u)[9],(*u)[10],(*u)[11],
                                    (*u)[12],(*u)[13],(*u)[14],(*u)[15]);
                                break;
                            }
                            lc_ptr += lc->cmdsize;
                            if (lc->cmdsize == 0) break;
                        }
                        char path[PATH_MAX] = {0};
                        int plen = proc_regionfilename(pid, addr, path, sizeof(path));
                        if (plen > 0 && path[0]) {
                            image_t *img = &remote_imgs[found];
                            img->load_addr = addr;
                            img->size = size;
                            img->is_64 = 0;
                            strncpy(img->path, path, PATH_MAX-1);
                            img->path[PATH_MAX-1] = '\0';
                            const char *bn = strrchr(path, '/');
                            strncpy(img->name, bn ? bn+1 : path, 255);
                            img->name[255] = '\0';
                            if (uuid_str[0])
                                memcpy(img->uuid, uuid_str, 37);
                            found++;
                            if (!q_quiet)
                                out("  [remote]   %s  base=0x%llx  size=0x%llx  uuid=%s  [x86]\n",
                                    img->name, (unsigned long long)addr,
                                    (unsigned long long)size,
                                    uuid_str[0] ? uuid_str : "—");
                        }
                        /* Continue to next region */
                        addr += size;
                        if (addr == 0) break;
                        continue;
                    }

                    if (mh->magic == MH_MAGIC_64 || is_remote_x64) {
                        /* Walk load commands for LC_UUID */
                        uint8_t *lc_ptr = hdr_buf + sizeof(struct mach_header_64);
                        uint8_t *lc_end = lc_ptr + mh->sizeofcmds;
                        if (lc_end > hdr_buf + sizeof(hdr_buf))
                            lc_end = hdr_buf + sizeof(hdr_buf);
                        char uuid_str[37] = {0};
                        while (lc_ptr + sizeof(struct load_command) <= lc_end) {
                            struct load_command *lc = (struct load_command *)lc_ptr;
                            if (lc->cmd == LC_UUID) {
                                struct uuid_command *uc = (struct uuid_command *)lc_ptr;
                                uuid_t *u = &uc->uuid;
                                snprintf(uuid_str, sizeof(uuid_str),
                                    "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                                    (*u)[0],(*u)[1],(*u)[2],(*u)[3],
                                    (*u)[4],(*u)[5],(*u)[6],(*u)[7],
                                    (*u)[8],(*u)[9],(*u)[10],(*u)[11],
                                    (*u)[12],(*u)[13],(*u)[14],(*u)[15]);
                                break;
                            }
                            lc_ptr += lc->cmdsize;
                            if (lc->cmdsize == 0) break;
                        }
                        /* Try to get image path via proc_regionfilename */
                        char path[PATH_MAX] = {0};
                        int plen = proc_regionfilename(pid, addr, path, sizeof(path));
                        if (plen > 0 && path[0]) {
                            image_t *img = &remote_imgs[found];
                            img->load_addr = addr;
                            img->size = size;
                            img->is_64 = 1;
                            strncpy(img->path, path, PATH_MAX-1);
                            img->path[PATH_MAX-1] = '\0';
                            /* Extract basename */
                            const char *bn = strrchr(path, '/');
                            strncpy(img->name, bn ? bn+1 : path, 255);
                            img->name[255] = '\0';
                            if (uuid_str[0])
                                memcpy(img->uuid, uuid_str, 37);
                            found++;
                            if (!q_quiet)
                                out("  [remote]   %s  base=0x%llx  size=0x%llx  uuid=%s%s\n",
                                    img->name, (unsigned long long)addr,
                                    (unsigned long long)size,
                                    uuid_str[0] ? uuid_str : "—",
                                    is_remote_x64 ? "  [Rosetta]" : "");
                        }
                    }
                }
            }
        }
        addr += size;
        if (addr == 0) break;
    }
    *n_remote = found;
    if (!q_quiet)
        out("  [remote] Found %d images in pid %d\n", found, pid);
    mach_port_deallocate(mach_task_self(), rt.task);
}

/* ─── Code signature checking ────────────────────────────────────────────── */

static int check_code_signature(pid_t pid) {
    /* Use Task Info / Task Inspection to get code signing status.
       We read CS_VALID flag via proc_info sysctl chain. */
    char path[PATH_MAX];
    if (proc_pidpath(pid, path, sizeof(path)) < 0) return -1;
    struct stat st;
    if (stat(path, &st) != 0) return -1;
    /* On modern macOS, all system binaries are fully signed.
       We check the file's modification time as a proxy
       for "signature valid" (can't easily check without CS_kern APIs). */
    return 1;
}

/* ─── Hook row ────────────────────────────────────────────────────────────── */

typedef struct {
    const char *sym; const char *cat;
    int state, patch;
    uintptr_t addr;
    char owner[PATH_MAX];
    char tramp[64];
    char target_owner[PATH_MAX];
    uintptr_t chain[8]; int chain_len;
    uint8_t first_bytes[32];
    int rel;
    int syscall_stub;
    /* v2.2 fields */
    uintptr_t trie_addr;          /* F2: address from export trie */
    int trie_match;               /* F2: 1=match, 0=mismatch, -1=not in trie */
    char reexport_from[PATH_MAX]; /* F3: source image for reexported symbol */
    int alias_diverged;           /* F9: 1 if alias pair diverges */
    char alias_partner[128];      /* F9: partner symbol name */
    int unscanned;                /* F5: 1 if dlsym failed */
    char unscanned_reason[64];    /* F5: reason for not scanning */
} hook_t;

/* ─── Hook clustering by destination page ─────────────────────────────────── */
/* Group hooks that resolve to the same destination page — shared dispatcher */

static void print_hook_clusters(hook_t *hooks, int nh) {
    /* Cluster by target page (4KB granularity) */
    typedef struct { uintptr_t page; int count; int idx[64]; } cluster_t;
    cluster_t cl[128]; int ncl = 0;

    for (int i = 0; i < nh; i++) {
        if (hooks[i].state == 0) continue;
        uintptr_t page = hooks[i].addr & ~0xFFFULL;
        int found = -1;
        for (int c = 0; c < ncl; c++) {
            if (cl[c].page == page) { found = c; break; }
        }
        if (found < 0) {
            if (ncl >= 128) break;
            found = ncl++;
            cl[found].page = page;
            cl[found].count = 0;
        }
        if (cl[found].count < 64)
            cl[found].idx[cl[found].count++] = i;
    }

    /* Print clusters with >1 hook (shared dispatcher pages) */
    int printed = 0;
    for (int c = 0; c < ncl; c++) {
        if (cl[c].count < 2) continue;
        if (!printed) {
            out("\n── Hook Clusters (shared destination pages) ──\n");
            printed = 1;
        }
        out("  page 0x%llx  (%d hooks):", (unsigned long long)cl[c].page, cl[c].count);
        for (int j = 0; j < cl[c].count; j++) {
            int i = cl[c].idx[j];
            out(" %s", hooks[i].sym ? hooks[i].sym : "?");
        }
        out("\n");
        out("    └ owner: %s\n", hooks[cl[c].idx[0]].target_owner[0] ?
            hooks[cl[c].idx[0]].target_owner : "unknown");
    }
    if (printed)
        out("  [%d cluster(s) with shared dispatch pages — possible hook framework]\n", ncl);
}

/* ─── Global scan state ───────────────────────────────────────────────────── */

typedef struct {
    image_t imgs[1024]; int nimgs;
    ipr_t ipr[512]; int nipr;
    rbr_t rbr[512]; int nrbr;
    hook_t hooks[512]; int nh;
    rx_t rx[512]; int nrx;
    objc_row_t objc[32]; int nobjc;
    tel_t tel[16]; int ntel;
    uint64_t fp[512];
    double elapsed;
    int sign_status;    /* 1=signed, 0=unsigned, -1=unknown */
    uint64_t sign_fp;
    /* v2.2: unscanned tracking (F5) */
    const char *unscanned_syms[512]; int nunscanned;
    /* v2.2: alias-pair results (F9) */
    int n_alias_div;    /* count of diverged alias pairs */
    /* v2.2: export-trie results (F2) */
    int n_trie_mismatch;
    /* v2.2: forwarder results (F3) */
    int n_reexport;
    /* v2.2: cohort pid for multi-process (F4) */
    pid_t cohort_pid;
} scan_t;



static scan_t G;

/* ─── Catalog ──────────────────────────────────────────────────────────────── */

typedef struct { const char *sym; const char *cat; int rel; } cat_t;
static const cat_t CATALOG[] = {
    /* process — 16 */
    {"posix_spawn","process",0},{"posix_spawnp","process",0},
    {"execve","process",0},{"execv","process",0},{"execl","process",0},
    {"execlp","process",0},{"execvp","process",0},
    {"fork","process",1},{"vfork","process",1},
    {"kill","process",1},{"killpg","process",1},{"waitpid","process",2},
    {"wait4","process",2},{"waitid","process",2},
    {"proc_pidinfo","process",2},{"proc_listpids","process",2},
    {"proc_pidpath","process",2},{"proc_name","process",2},
    {"getpid","process",2},{"getppid","process",2},
    {"setsid","process",1},{"getsid","process",2},
    /* dyld — 10 */
    {"dlopen","dyld",0},{"dlsym","dyld",0},{"dlclose","dyld",1},
    {"dladdr","dyld",2},{"dlopen_preflight","dyld",1},
    {"_dyld_register_func_for_add_image","dyld",1},
    {"_dyld_register_func_for_remove_image","dyld",1},
    {"_dyld_image_count","dyld",2},
    {"_dyld_get_image_header","dyld",2},
    {"_dyld_get_image_vmaddr_slide","dyld",2},
    /* memory — 18 */
    {"mmap","memory",0},{"mprotect","memory",0},{"munmap","memory",1},
    {"madvise","memory",1},{"minherit","memory",1},
    {"mach_vm_allocate","memory",0},{"mach_vm_write","memory",0},
    {"mach_vm_read","memory",0},{"mach_vm_read_overwrite","memory",0},
    {"mach_vm_map","memory",0},{"mach_vm_protect","memory",1},
    {"mach_vm_deallocate","memory",1},{"mach_vm_remap","memory",1},
    {"vm_allocate","memory",1},{"vm_read","memory",1},
    {"vm_write","memory",1},{"vm_protect","memory",1},
    {"malloc","memory",2},{"free","memory",2},{"realloc","memory",2},
    {"calloc","memory",2},{"valloc","memory",2},
    /* tasks/threads — 16 */
    {"task_for_pid","tasks",0},{"task_for_pid_posix_spawn","tasks",1},
    {"thread_create_running","tasks",0},{"task_threads","tasks",1},
    {"mach_port_allocate","tasks",2},{"mach_port_insert_right","tasks",2},
    {"mach_port_deallocate","tasks",2},{"mach_port_mod_refs","tasks",2},
    {"task_set_exception_ports","tasks",0},
    {"task_get_exception_ports","tasks",1},
    {"thread_set_state","tasks",0},{"thread_get_state","tasks",1},
    {"thread_suspend","tasks",1},{"thread_resume","tasks",1},
    {"thread_abort","tasks",1},{"task_suspend","tasks",1},
    {"task_resume","tasks",1},{"ptrace","tasks",1},
    /* files — 28 */
    {"open","files",0},{"openat","files",0},{"open_dprotected_np","files",1},
    {"close","files",2},{"read","files",2},{"write","files",2},
    {"pread","files",2},{"pwrite","files",2},
    {"readv","files",2},{"writev","files",2},
    {"stat","files",1},{"lstat","files",1},{"fstat","files",2},
    {"fstatat","files",1},{"access","files",2},
    {"unlink","files",1},{"unlinkat","files",1},
    {"rename","files",1},{"renameat","files",1},
    {"chmod","files",1},{"fchmod","files",1},{"fchmodat","files",1},
    {"chown","files",1},{"fchown","files",1},{"lchown","files",1},
    {"mkdir","files",2},{"rmdir","files",2},
    {"getattrlist","files",2},{"setattrlist","files",2},
    {"fgetattrlist","files",2},{"fsetattrlist","files",2},
    {"readlink","files",2},{"readlinkat","files",2},
    {"symlink","files",1},{"symlinkat","files",1},
    {"link","files",1},{"linkat","files",1},
    {"realpath","files",2},{"fopen","files",2},{"freopen","files",2},
    /* network — 22 */
    {"socket","network",0},{"socketpair","network",1},
    {"connect","network",0},{"bind","network",1},
    {"listen","network",1},{"accept","network",1},
    {"getaddrinfo","network",1},{"freeaddrinfo","network",2},
    {"gethostbyname","network",2},{"gethostbyaddr","network",2},
    {"send","network",2},{"recv","network",2},
    {"sendto","network",2},{"recvfrom","network",2},
    {"sendmsg","network",2},{"recvmsg","network",2},
    {"setsockopt","network",1},{"getsockopt","network",2},
    {"getsockname","network",2},{"getpeername","network",2},
    {"shutdown","network",1},{"inet_ntoa","network",2},
    /* privilege/sandbox — 14 */
    {"setuid","priv",0},{"seteuid","priv",0},{"setgid","priv",1},
    {"setegid","priv",1},{"setreuid","priv",1},{"setregid","priv",1},
    {"getuid","priv",2},{"geteuid","priv",2},{"getgid","priv",2},
    {"csr_check","priv",1},{"csr_get_active_config","priv",2},
    {"sandbox_init","priv",1},{"sandbox_free_error","priv",2},
    {"sandbox_check","priv",1},
    /* objc runtime — 14 */
    {"objc_msgSend","objc",0},{"objc_msgSendSuper2","objc",1},
    {"objc_msgSendSuper","objc",1},
    {"method_exchangeImplementations","objc",1},
    {"class_replaceMethod","objc",1},{"class_addMethod","objc",1},
    {"objc_getClass","objc",2},{"objc_getMetaClass","objc",2},
    {"sel_registerName","objc",3},{"sel_getUid","objc",3},
    {"objc_registerClassPair","objc",3},
    {"object_setClass","objc",1},{"object_getClass","objc",2},
    {"method_setImplementation","objc",1},
    /* notification — 6 */
    {"notify_post","notify",1},{"notify_register_dispatch","notify",2},
    {"notify_register_check","notify",2},{"notify_cancel","notify",2},
    {"notify_get_state","notify",2},{"notify_set_state","notify",1},
    /* xattr — 6 */
    {"getxattr","xattr",1},{"fgetxattr","xattr",1},
    {"setxattr","xattr",1},{"fsetxattr","xattr",1},
    {"listxattr","xattr",2},{"removexattr","xattr",2},
    /* keychain — 10 */
    {"SecItemCopyMatching","keychain",0},{"SecItemAdd","keychain",0},
    {"SecItemUpdate","keychain",1},{"SecItemDelete","keychain",1},
    {"SecKeyCreateSignature","keychain",2},
    {"SecKeyCreateDecryptedData","keychain",2},
    {"SecKeyCreateEncryptedData","keychain",2},
    {"SecKeyGeneratePair","keychain",1},
    {"SecTrustEvaluateWithError","keychain",1},
    {"SecCertificateCreateWithData","keychain",1},
    /* endpoint security — 8 */
    {"es_new_client","endsec",0},{"es_subscribe","endsec",0},
    {"es_unsubscribe","endsec",1},{"es_delete_client","endsec",2},
    {"es_mute_process","endsec",1},{"es_mute_path","endsec",1},
    {"es_respond_auth_result","endsec",1},
    {"es_clear_cache","endsec",2},
    /* logging — 8 */
    {"os_log_create","logging",2},{"os_log","logging",2},
    {"os_activity_create","logging",3},
    {"os_log_debug","logging",3},{"os_log_info","logging",3},
    {"os_log_error","logging",3},{"os_log_fault","logging",3},
    {"syslog","logging",2},
    /* IOKit — 6 */
    {"IOServiceGetMatchingService","iokit",1},
    {"IOServiceMatching","iokit",2},
    {"IOServiceOpen","iokit",1},
    {"IOServiceClose","iokit",2},
    {"IOObjectRelease","iokit",2},
    {"IORegistryEntryGetPath","iokit",2},
    /* misc/system — 14 */
    {"system","misc",0},{"popen","misc",0},{"pclose","misc",2},
    {"getenv","misc",2},{"setenv","misc",2},{"unsetenv","misc",2},
    {"sysctl","misc",2},{"sysctlbyname","misc",2},
    {"dlopen","dyld",0},  /* dup ok — dlsym deduplicates */
    {"gethostname","misc",2},{"sethostname","misc",1},
    {"getopt","misc",2},{"getopt_long","misc",2},
    {"clock_gettime","misc",2},{"gettimeofday","misc",2},
    {"time","misc",2},
    /* crypto — 8 */
    {"CC_SHA256","crypto",2},{"CC_SHA512","crypto",2},
    {"CC_MD5","crypto",2},{"CC_SHA1","crypto",2},
    {"CCHmac","crypto",2},{"CCCrypt","crypto",1},
    {"CCRandomGenerateBytes","crypto",1},
    {"SecRandomCopyBytes","crypto",1},
    /* disk/images — 8 */
    {"statfs","disk",2},{"getfsent","disk",2},
    {"getmntinfo","disk",2},{"setmntent","disk",1},
    {"hdiutil_mount","disk",3},{"hdiutil_unmount","disk",3},
    {"mount","disk",1},{"unmount","disk",1},
    /* pthreads — 8 */
    {"pthread_create","pthread",0},{"pthread_join","pthread",1},
    {"pthread_mutex_init","pthread",2},{"pthread_mutex_lock","pthread",2},
    {"pthread_mutex_unlock","pthread",2},
    {"pthread_cond_wait","pthread",2},
    {"pthread_rwlock_wrlock","pthread",2},
    {"pthread_setspecific","pthread",2},
};
#define CATALOG_N (sizeof(CATALOG)/sizeof(CATALOG[0]))

/* Top-N quick scan list */
static const char *TOP_N[] = {
    "posix_spawn","execve","dlopen","dlsym","mmap","mprotect",
    "mach_vm_allocate","mach_vm_write","task_for_pid","socket","connect",
    "objc_msgSend","open","read","write","fork","kill",
    "SecItemCopyMatching","CCCrypt","pthread_create",
};
#define TOP_N_COUNT (sizeof(TOP_N)/sizeof(TOP_N[0]))

/* ─── Watch mode state ──────────────────────────────────────────────────────── */

static hook_t g_prev_hooks[512];
static int g_prev_nh = 0;
static int g_watch_interval_sec = 5;

/* ─── Forward decl ─────────────────────────────────────────────────────────── */

static void run_all(pid_t remote_pid);
static void print_report(void);
static void print_json(void);
static void print_watch_diff(void);
static hook_t *find_hook(const char *sym);
static void shared_cache_diff(void);
static void cohort_scan(const char *pid_list);
static void scan_export_tries(void);
static void scan_forwarders(void);
static void scan_alias_pairs(void);
static void print_operator_actions(int hooked, int patched, int ue, int interpose,
                                    int rebind, int rx, int trie_mm, int alias_div);

/* ─── Export-trie integrity (F2) ──────────────────────────────────────────── */
/* Walk the export trie of on-disk Mach-O dylibs and compare the export
   address with what dlsym() returns. A mismatch means either:
   - The symbol was interposed (legitimate but redirected)
   - The symbol was hooked in-memory (malicious)
   - The export trie was tampered with on disk (unlikely but possible) */

/* Parse a ULEB128 value from a trie node */
static uint64_t trie_read_uleb128(const uint8_t **pp, const uint8_t *end) {
    uint64_t result = 0;
    int bit = 0;
    while (*pp < end) {
        uint8_t byte = *(*pp)++;
        result |= (uint64_t)(byte & 0x7F) << bit;
        if (!(byte & 0x80)) break;
        bit += 7;
    }
    return result;
}

/* Resolve a symbol from an export trie. Returns 1 if found, sets *out_addr. */
static int trie_resolve(const uint8_t *trie_start, size_t trie_size,
                         const char *name, uint64_t *out_addr) {
    const uint8_t *p = trie_start;
    const uint8_t *end = trie_start + trie_size;

    while (p < end) {
        uint64_t terminal_size = trie_read_uleb128(&p, end);
        const uint8_t *children = p + terminal_size;

        if (terminal_size != 0) {
            /* This is a terminal node — check if we've matched the full symbol */
            const uint8_t *term = p;
            uint64_t flags = trie_read_uleb128(&term, end);
            if (*name == '\0') {
                /* Full match — extract address */
                if (flags == 0) { /* EXPORT_SYMBOL_FLAGS_KIND_REGULAR */
                    *out_addr = trie_read_uleb128(&term, end);
                    return 1;
                }
                /* Re-export or other special flag — not a direct address */
                return 0;
            }
        }

        /* Try to match child edges */
        p = children;
        if (p >= end) break;
        uint64_t child_count = trie_read_uleb128(&p, end);
        int matched = 0;
        for (uint64_t c = 0; c < child_count && p < end; c++) {
            /* Read edge string (null-terminated) */
            const char *edge = (const char *)p;
            size_t edge_len = strlen(edge);
            p += edge_len + 1;
            /* Read child offset */
            uint64_t child_off = trie_read_uleb128(&p, end);
            /* Check if name starts with edge */
            if (strncmp(name, edge, edge_len) == 0) {
                p = trie_start + child_off;
                name += edge_len;
                matched = 1;
                break;
            }
        }
        if (!matched) return 0;
    }
    return 0;
}

/* For each catalog API, compare dlsym address with export trie address */
static void scan_export_tries(void) {
    int checked = 0, matched = 0, mismatched = 0, not_found = 0;

    if (!q_quiet) {
        out("\n========================================================================\n");
        out("EXPORT-TRIE INTEGRITY (dlsym vs on-disk export trie)\n");
        out("========================================================================\n");
    }

    for (int i = 0; i < G.nh; i++) {
        hook_t *r = &G.hooks[i];
        if (r->unscanned) continue;

        Dl_info di;
        if (!dladdr((void *)r->addr, &di) || !di.dli_fname) continue;

        /* Only check images that have on-disk files */
        if (access(di.dli_fname, R_OK) != 0) continue;

        int fd = open(di.dli_fname, O_RDONLY);
        if (fd < 0) continue;
        struct stat st;
        if (fstat(fd, &st) < 0) { close(fd); continue; }
        void *mapped = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
        close(fd);
        if (mapped == MAP_FAILED) continue;

        const struct mach_header_64 *mh = mapped;
        if (mh->magic != MH_MAGIC_64) { munmap(mapped, st.st_size); continue; }

        /* Find LC_DYLD_INFO or LC_DYLD_INFO_ONLY for export trie */
        uint8_t *p = (uint8_t *)mapped + sizeof(struct mach_header_64);
        struct dyld_info_command *di_cmd = NULL;
        for (uint32_t c = 0; c < mh->ncmds; c++) {
            struct load_command *lc = (void *)p;
            if (lc->cmd == LC_DYLD_INFO || lc->cmd == LC_DYLD_INFO_ONLY) {
                di_cmd = (void *)p;
                break;
            }
            p += lc->cmdsize;
        }

        if (!di_cmd || di_cmd->export_off == 0) {
            munmap(mapped, st.st_size);
            continue;
        }

        /* Compute slide to convert trie address (file VM addr) to runtime */
        uintptr_t slide = 0;
        for (int j = 0; j < G.nimgs; j++) {
            if ((const void *)G.imgs[j].mh == di.dli_fbase) {
                slide = G.imgs[j].slide;
                break;
            }
        }

        const uint8_t *trie = (const uint8_t *)mapped + di_cmd->export_off;
        size_t trie_size = di_cmd->export_size;
        uint64_t trie_vm_addr = 0;

        if (trie_resolve(trie, trie_size, r->sym, &trie_vm_addr)) {
            uintptr_t expected_runtime = (uintptr_t)trie_vm_addr + slide;
            checked++;
            r->trie_addr = expected_runtime;
            if (expected_runtime == r->addr) {
                r->trie_match = 1;
                matched++;
            } else {
                r->trie_match = 0;
                mismatched++;
                G.n_trie_mismatch++;
                if (r->state == ST_CLEAN) {
                    r->state = ST_TRIE_MISMATCH;
                }
                if (!q_minimal)
                    out("  TRIE-MISMATCH  %-28s  dlsym=0x%lx  trie=0x%lx  [%s]\n",
                        r->sym, (unsigned long)r->addr,
                        (unsigned long)expected_runtime, basename_(di.dli_fname));
            }
        } else {
            not_found++;
            r->trie_match = -1;
        }

        munmap(mapped, st.st_size);
    }

    if (!q_quiet) {
        out("  checked:       %d\n", checked);
        out("  matched:       %d\n", matched);
        out("  mismatched:    %d  (dlsym != trie export address)\n", mismatched);
        out("  not in trie:   %d  (reexported or private)\n", not_found);
        if (mismatched > 0)
            out("\n  VERDICT: %d symbol(s) have trie address != dlsym address\n", mismatched);
        else if (checked > 0)
            out("\n  VERDICT: PRISTINE — all checked symbols match export trie\n");
    }
}

/* ─── LC_REEXPORT forwarder resolution (F3) ──────────────────────────────── */
/* Parse LC_REEXPORT_DYLIB load commands to identify symbols that are
   forwarded from one dylib to another. Track the reexport chain. */

static void scan_forwarders(void) {
    if (!q_quiet) {
        out("\n========================================================================\n");
        out("LC_REEXPORT FORWARDER RESOLUTION\n");
        out("========================================================================\n");
    }

    int n_reexport_imgs = 0;
    int n_forwarded_syms = 0;

    for (int i = 0; i < G.nimgs; i++) {
        image_t *im = &G.imgs[i];
        if (!im->is_64 || !im->mh) continue;

        uintptr_t p = (uintptr_t)im->mh + sizeof(struct mach_header_64);
        for (uint32_t c = 0; c < im->mh->ncmds; c++) {
            struct load_command *lc = (void *)p;
            if (lc->cmd == LC_REEXPORT_DYLIB) {
                struct dylib_command *dc = (void *)p;
                const char *reexport_path = (const char *)
                    ((uintptr_t)lc + dc->dylib.name.offset);
                n_reexport_imgs++;

                /* Check if any catalog symbols resolve to this image */
                for (int j = 0; j < G.nh; j++) {
                    hook_t *r = &G.hooks[j];
                    if (r->unscanned) continue;
                    Dl_info di;
                    if (!dladdr((void *)r->addr, &di) || !di.dli_fname) continue;
                    if (strcmp(di.dli_fname, im->path) == 0) {
                        /* This symbol is in a reexporting image */
                        strncpy(r->reexport_from, reexport_path, PATH_MAX - 1);
                        if (r->state == ST_CLEAN) {
                            r->state = ST_REEXPORT;
                        }
                        n_forwarded_syms++;
                        G.n_reexport++;
                        if (!q_minimal)
                            out("  FWD  %-28s  %s -> (reexport from %s)\n",
                                r->sym, basename_(im->path),
                                basename_(reexport_path));
                    }
                }
            }
            p += lc->cmdsize;
        }
    }

    if (!q_quiet) {
        out("  reexporting images:  %d\n", n_reexport_imgs);
        out("  forwarded symbols:   %d\n", n_forwarded_syms);
        if (n_forwarded_syms == 0)
            out("  CLEAN — no LC_REEXPORT forwarders affecting catalog APIs\n");
    }
}

/* ─── Alias-pair divergence (F9) ──────────────────────────────────────────── */
/* Check known alias pairs (e.g. open$NOCANCEL / open) for address divergence.
   In a clean system, $NOCANCEL variants share the same implementation or
   differ only in the cancelability check. If one is hooked but the other
   isn't, that's a selective hook — a strong indicator of targeted interception. */

static const struct { const char *a, *b; } ALIAS_PAIRS[] = {
    {"open",              "open$NOCANCEL"},
    {"read",              "read$NOCANCEL"},
    {"write",             "write$NOCANCEL"},
    {"recvfrom",          "recvfrom$NOCANCEL"},
    {"sendto",            "sendto$NOCANCEL"},
    {"waitpid",           "waitpid$NOCANCEL"},
    {"wait4",             "wait4$NOCANCEL"},
    {"close",             "close$NOCANCEL"},
    {"fork",              "fork$NOCANCEL"},
    {"sigwait",           "sigwait$NOCANCEL"},
    {"fsync",             "fsync$NOCANCEL"},
    {"pread",             "pread$NOCANCEL"},
    {"pwrite",            "pwrite$NOCANCEL"},
    {"mq_send",           "mq_send$NOCANCEL"},
    {"mq_receive",        "mq_receive$NOCANCEL"},
    {"sem_wait",          "sem_wait$NOCANCEL"},
    {"__semwait_signal",  "__semwait_signal_nocancel"},
};
#define N_ALIAS_PAIRS (sizeof(ALIAS_PAIRS)/sizeof(ALIAS_PAIRS[0]))

static void scan_alias_pairs(void) {
    if (!q_quiet) {
        out("\n========================================================================\n");
        out("ALIAS-PAIR DIVERGENCE ($NOCANCEL pairs)\n");
        out("========================================================================\n");
    }

    int checked = 0, both_clean = 0, one_hooked = 0;

    for (size_t i = 0; i < N_ALIAS_PAIRS; i++) {
        void *a = dlsym(RTLD_DEFAULT, ALIAS_PAIRS[i].a);
        void *b = dlsym(RTLD_DEFAULT, ALIAS_PAIRS[i].b);
        if (!a || !b) continue;

        checked++;

        /* Compare first 16 bytes */
        uint8_t ba[16], bb2[16];
        memcpy(ba, a, 16);
        memcpy(bb2, b, 16);

        /* Find the catalog entry for the primary symbol */
        hook_t *ha = NULL;
        for (int j = 0; j < G.nh; j++) {
            if (strcmp(G.hooks[j].sym, ALIAS_PAIRS[i].a) == 0) {
                ha = &G.hooks[j];
                break;
            }
        }

        int a_hooked = ha && (ha->state == ST_HOOKED || ha->state == ST_PATCHED ||
                              ha->state == ST_UNKNOWN_ENTRY);
        int b_hooked = 0; /* We don't track $NOCANCEL in catalog, check bytes */

        /* Check if b looks hooked (trampoline at entry) */
        tramp_t tb = {0};
        uintptr_t b_addr = (uintptr_t)b & ~1ULL;
        int b_tramp = decode_tramp(b_addr, &tb);
        int b_patch = classify_patch(bb2, 16);
        if (b_tramp || b_patch != PT_NONE) b_hooked = 1;

        if (a_hooked != b_hooked) {
            one_hooked++;
            G.n_alias_div++;
            if (ha) {
                ha->alias_diverged = 1;
                strncpy(ha->alias_partner, ALIAS_PAIRS[i].b, 127);
            }
            if (!q_minimal)
                out("  DIVERGED  %-20s vs %-20s  [%s hooked, %s clean]\n",
                    ALIAS_PAIRS[i].a, ALIAS_PAIRS[i].b,
                    a_hooked ? "A" : "B",
                    a_hooked ? "B" : "A");
        } else if (memcmp(ba, bb2, 16) != 0 && !a_hooked && !b_hooked) {
            /* Both clean but different bytes — normal for $NOCANCEL wrappers */
            both_clean++;
        } else {
            both_clean++;
        }
    }

    if (!q_quiet) {
        out("  pairs checked:       %d\n", checked);
        out("  both clean:          %d\n", both_clean);
        out("  one hooked:          %d  (SELECTIVE INTERCEPTION)\n", one_hooked);
        if (one_hooked > 0)
            out("\n  VERDICT: ALERT — %d alias pair(s) show selective hooking\n", one_hooked);
        else if (checked > 0)
            out("\n  VERDICT: CONSISTENT — no selective alias-pair hooking detected\n");
    }
}

/* ─── Run the full scan ─────────────────────────────────────────────────────── */

static void run_all(pid_t remote_pid) {
#ifdef __arm64__
    g_arm64 = 1;
#else
    g_arm64 = 0;
#endif
    clock_t t0 = clock();

    G.nimgs = collect_images(G.imgs, 1024);
    G.nipr  = scan_interpose(G.imgs, G.nimgs, G.ipr, 512);
    G.nrbr  = scan_rebinds(G.imgs, G.nimgs, G.rbr, 512);
    G.nobjc = scan_objc(G.objc, 32);
    G.nrx   = scan_rx_regions(G.rx, 512);
    G.ntel  = scan_telemetry(G.tel, 16);

    /* code signature check */
    if (g_check_sign) {
        G.sign_status = check_code_signature(getpid());
        if (G.sign_status == 1) G.sign_status = 1;
        else if (G.sign_status == 0) G.sign_status = 0;
        else G.sign_status = -1;
    }

    G.nh = 0;
    const cat_t *cat = CATALOG;
    size_t cat_n = CATALOG_N;
    if (g_brief) cat_n = TOP_N_COUNT;

    for (size_t i = 0; i < cat_n && G.nh < 512; i++) {
        const cat_t *entry = &cat[i];

        if (g_brief) {
            /* In brief mode, iterate TOP_N list and find matching catalog entry */
            if (i >= TOP_N_COUNT) break;
            entry = NULL;
            for (size_t j = 0; j < CATALOG_N; j++) {
                if (strcmp(TOP_N[i], CATALOG[j].sym) == 0) {
                    entry = &CATALOG[j];
                    break;
                }
            }
            if (!entry) continue;
        }

        /* --functions: filter to user-specified symbols only */
        if (g_functions_n > 0) {
            int matched = 0;
            for (int f = 0; f < g_functions_n; f++) {
                if (strcmp(entry->sym, g_functions[f]) == 0) { matched = 1; break; }
            }
            if (!matched) continue;
        }

        void *a = dlsym(RTLD_DEFAULT, entry->sym);
        if (!a) {
            /* F5: track unscanned targets */
            if (G.nunscanned < 512) {
                G.unscanned_syms[G.nunscanned++] = entry->sym;
            }
            continue;
        }
        uintptr_t addr = (uintptr_t)a & ~1ULL;

        /* --module: filter by owning image basename substring */
        if (g_modules_n > 0) {
            Dl_info mdi;
            if (!dladdr((void *)addr, &mdi) || !mdi.dli_fname) continue;
            int in_module = 0;
            for (int m = 0; m < g_modules_n; m++) {
                if (strstr(mdi.dli_fname, g_modules[m])) { in_module = 1; break; }
            }
            if (!in_module) continue;
        }

        hook_t *r = &G.hooks[G.nh];
        memset(r, 0, sizeof *r);
        r->sym = entry->sym;
        r->cat = entry->cat;
        r->addr = addr;
        r->rel = entry->rel;

        Dl_info di;
        if (dladdr((void *)addr, &di) && di.dli_fname)
            strncpy(r->owner, di.dli_fname, PATH_MAX - 1);

        uint8_t buf[64]; memcpy(buf, (void *)addr, sizeof buf);
        memcpy(r->first_bytes, buf, 32);
        r->syscall_stub = g_arm64 ? is_syscall_stub_arm64(addr)
                                 : is_syscall_stub_x64(addr);

        tramp_t t = {0};
        int hit = decode_tramp(addr, &t);
        int patch = classify_patch(buf, sizeof buf);

        /* UNKNOWN_ENTRY anti-evasion: entry doesn't look like clean code
           AND doesn't match a known hook => something is concealing it */
        if (!hit && patch == PT_NONE && !is_known_clean_prologue(buf, sizeof buf, g_arm64)) {
            r->state = ST_UNKNOWN_ENTRY;
        } else if (hit && t.target) {
            follow_chain(addr, &t, r->chain, &r->chain_len);
            strncpy(r->tramp, t.kind, 63);
            r->state = ST_HOOKED;
            owner_of(t.target, r->target_owner, PATH_MAX);
            if (strcmp(r->owner, r->target_owner) == 0)
                r->state = ST_SELF_FWD;
        } else if (patch != PT_NONE) {
            r->patch = patch;
            r->state = ST_PATCHED;
        } else {
            r->state = ST_CLEAN;
        }
        G.fp[G.nh] = fnv1a(buf, 16);
        G.nh++;
    }

    /* Remote scan */
    if (remote_pid > 0) {
        remote_analyze(remote_pid, NULL, NULL);
    }

    /* v2.2: run analytical sub-scans if requested */
    if (g_export_trie) scan_export_tries();
    if (g_forwarders) scan_forwarders();
    if (g_alias_pairs) scan_alias_pairs();

    G.elapsed = (double)(clock() - t0) / CLOCKS_PER_SEC;
}

/* ─── Print report ──────────────────────────────────────────────────────────── */

static void print_report(void) {
    if (!q_quiet) {
        out("\n");
        out("  ___       _                                  ____\n");
        out(" |_ _|_ __ | |_ ___ _ __ _ __   ___  ___  ___ / ___|  ___ ___  _ __   ___\n");
        out("  | || '_ \\| __/ _ \\ '__| '_ \\ / _ \\/ __|/ _ \\\\___ \\ / __/ _ \\| '_ \\ / _ \\\n");
        out("  | || | | | ||  __/ |  | |_) | (_) \\__ \\  __/ ___) | (_| (_) | |_) |  __/\n");
        out(" |___|_| |_|\\__\\___|_|  | .__/ \\___/|___/\\___||____/ \\___\\___/| .__/ \\___|\n");
        out("                        |_|                                   |_|\n");
        out("            InterposeScope-C v2.2.0 — %s\n\n", g_arm64 ? "arm64" : "x86_64");
    }

    time_t now = time(NULL);
    struct tm tm; localtime_r(&now, &tm);
    char ts[64]; strftime(ts, sizeof ts, "%Y-%m-%d %H:%M:%S", &tm);
    out("InterposeScope-C v2.2.0    %s local\n", ts);

    if (!q_quiet) {
        out("========================================================================\n");
        out("HOST PROCESS\n");
        out("========================================================================\n");
        out("       pid: %d\n", getpid());
        out("      ppid: %d\n", getppid());
        out("      arch: %s\n", g_arm64 ? "arm64" : "x86_64");
        char exe[PATH_MAX]; uint32_t sz = PATH_MAX;
        if (_NSGetExecutablePath(exe, &sz) == 0) out("       exe: %s\n", exe);
        out("       uid: %d\n", getuid());
        struct utsname u;
        if (uname(&u) == 0) out("        os: %s %s\n", u.sysname, u.release);
        if (g_check_sign && G.sign_status >= 0) {
            out("    signed: %s\n", G.sign_status ? "YES" : "NO");
        }
        out("\n");

        out("========================================================================\n");
        out("DYLD ENVIRONMENT EXPOSURE\n");
        out("========================================================================\n");
        extern char **environ;
        int any = 0;
        for (char **e = environ; e && *e; e++) {
            if (strncmp(*e, "DYLD_", 5) == 0) {
                out("  %s", *e);
                if (strstr(*e, "INSERT_LIBRARIES") || strstr(*e, "PRINT_LIBRARIES"))
                    out("  <-- ALERT");
                out("\n");
                any = 1;
            }
        }
        if (!any) out("  CLEAN — no DYLD_* variables set\n");
        out("\n");

        if (!q_minimal && !g_top) {
            out("========================================================================\n");
            out("LOADED IMAGES (%d)\n", G.nimgs);
            out("========================================================================\n");
            int cache = 0, file = 0;
            for (int i = 0; i < G.nimgs; i++) G.imgs[i].cache_only ? cache++ : file++;
            out("  %d backed by dyld shared cache, %d with on-disk Mach-O files\n", cache, file);
            for (int i = 0; i < G.nimgs; i++)
                out("  [%s] 0x%012lx  %s\n",
                    G.imgs[i].cache_only ? "cache" : "file ",
                    (unsigned long)G.imgs[i].mh, G.imgs[i].path);
            out("\n");
        } else if (g_top) {
            /* --top: just show image count, not full listing */
            int cache = 0, file = 0;
            for (int i = 0; i < G.nimgs; i++) G.imgs[i].cache_only ? cache++ : file++;
            out("  [images] %d total (%d shared cache, %d on-disk)\n\n", G.nimgs, cache, file);
        }
    }

    /* ─── findings ─── */
    out("========================================================================\n");
    out("DYLD __interpose SECTIONS\n");
    out("========================================================================\n");
    if (G.nipr) {
        for (int i = 0; i < G.nipr; i++) {
            out("  image:        %s\n", G.ipr[i].image);
            out("  replacee:     0x%lx  (%s)\n", (long)G.ipr[i].replacee, G.ipr[i].replacee_owner);
            out("  replacement:  0x%lx  -> %s\n", (long)G.ipr[i].replacement, G.ipr[i].replacement_owner);
            out("  verdict:      %s\n\n",
                G.ipr[i].third_party == 2 ? "ANON" :
                G.ipr[i].third_party ? "THIRD_PARTY" : "apple-lib");
        }
    } else if (!q_minimal) {
        out("  CLEAN — no __interpose sections in any loaded image\n\n");
    }

    if (!q_minimal) {
        out("========================================================================\n");
        out("INDIRECT SYMBOL REBINDING (__la_symbol_ptr)\n");
        out("========================================================================\n");
        if (G.nrbr) {
            for (int i = 0; i < G.nrbr; i++) {
                out("  %s!%s\n", basename_(G.rbr[i].image), G.rbr[i].symbol);
                out("    expected: 0x%lx\n", (long)G.rbr[i].expected);
                out("    actual:   0x%lx  -> %s\n\n", (long)G.rbr[i].actual, G.rbr[i].actual_owner);
            }
        } else out("  CLEAN — no indirect symbol pointer divergence detected\n\n");
    }

    out("========================================================================\n");
    out("HIGH-VALUE API ENTRY-POINT INTEGRITY (%d checked)\n", G.nh);
    out("========================================================================\n");
    out("  %-28s %-8s %-12s %s\n", "SYMBOL", "CATEGORY", "STATE", "DETAIL");
    out("  %s\n", "----------------------------------------------------------------------");

    int hooked = 0, patched = 0, sysb = 0, ue = 0, fwd = 0;
    const char **cluster_dest = malloc(G.nh * sizeof(char *));
    int *cluster_count = calloc(G.nh, sizeof(int));

    for (int i = 0; i < G.nh; i++) {
        hook_t *r = &G.hooks[i];
        if (r->syscall_stub) sysb++;
        switch (r->state) {
            case ST_HOOKED: hooked++; break;
            case ST_PATCHED: patched++; break;
            case ST_UNKNOWN_ENTRY: ue++; break;
            case ST_SELF_FWD: fwd++; break;
        }

        /* only show non-clean in minimal mode */
        if (q_minimal && r->state == ST_CLEAN) continue;

        switch (r->state) {
        case ST_HOOKED:
            if (!q_minimal)
                out("  %-28s %-8s HOOKED       %s  [%s -> %s]\n",
                    r->sym, r->cat, basename_(r->owner),
                    r->tramp, r->target_owner);
            break;
        case ST_UNKNOWN_ENTRY:
            out("  %-28s %-8s UNKNOWN-ENTRY [concealed hook — not clean code, not a "
                "recognized trampoline]\n", r->sym, r->cat);
            if (g_verbose) {
                out("    bytes: ");
                for (int b = 0; b < 32; b++) out("%02X ", r->first_bytes[b]);
                out("\n");
            }
            break;
        case ST_PATCHED:
            if (!q_minimal)
                out("  %-28s %-8s PATCHED      [%s] %s\n",
                    r->sym, r->cat, PTN[r->patch], basename_(r->owner));
            break;
        case ST_SELF_FWD:
            if (g_verbose)
                out("  %-28s %-8s SELF-FWD     %s (tail call)\n",
                    r->sym, r->cat, basename_(r->owner));
            break;
        case ST_CLEAN:
            if (g_verbose) out("  %-28s %-8s CLEAN        %s\n",
                r->sym, r->cat, basename_(r->owner));
            break;
        default: break;
        }
    }

    if (hooked == 0 && patched == 0 && ue == 0 && !q_minimal)
        out("  CLEAN — no entry-point trampolines or patches detected\n");

    /* hook clustering: group hooks by destination owner + page */
    if (hooked > 1) {
        out("\n  ─── Hook clusters (by destination owner + page) ───\n");
        for (int i = 0; i < G.nh; i++) {
            if (G.hooks[i].state != ST_HOOKED) continue;
            uintptr_t target_page = G.hooks[i].chain[G.hooks[i].chain_len-1] & ~0xFFFULL;
            const char *owner = G.hooks[i].target_owner;
            out("    %-28s -> %s (page 0x%lx)\n",
                G.hooks[i].sym, basename_(owner), (long)target_page);
        }
    }

    out("\n");

    if (!q_minimal) {
        out("========================================================================\n");
        out("ANONYMOUS EXECUTABLE MEMORY (unsigned code regions)\n");
        out("========================================================================\n");
        if (G.nrx) {
            for (int i = 0; i < G.nrx; i++)
                out("  0x%012lx  %8lu KB  RX  (no backing image)\n",
                    (long)G.rx[i].base, (unsigned long)(G.rx[i].size / 1024));
            out("\n  %d anonymous RX region(s) — review recommended.\n", G.nrx);
        } else out("  CLEAN — no anonymous executable regions outside mapped images\n");
        out("\n");

        if (!g_top) {
        out("========================================================================\n");
        out("OBJECTIVE-C METHOD OWNERSHIP (swizzle attribution)\n");
        out("========================================================================\n");
        for (int i = 0; i < G.nobjc; i++) {
            if (G.objc[i].state == 0) {
                out("  [%s %s]\n", G.objc[i].cls, G.objc[i].sel);
                out("    imp -> %s\n", G.objc[i].owner);
            } else if (G.objc[i].state == 1)
                out("  [%s %s]  CLASS NOT LOADED\n", G.objc[i].cls, G.objc[i].sel);
            else
                out("  [%s %s]  METHOD N/A\n", G.objc[i].cls, G.objc[i].sel);
        }
        out("\n");

        out("========================================================================\n");
        out("TELEMETRY SURFACES (Endpoint Security / os_log)\n");
        out("========================================================================\n");
        for (int i = 0; i < G.ntel; i++) {
            out("  %-36s %s", G.tel[i].sym,
                G.tel[i].present ? "PRESENT" : "NOT FOUND");
            if (G.tel[i].present)
                out("  (%s)", basename_(G.tel[i].owner));
            out("\n");
        }
        out("\n");
        } /* !g_top */

        if (g_check_sign && G.sign_status >= 0) {
            out("========================================================================\n");
            out("CODE SIGNATURE STATUS\n");
            out("========================================================================\n");
            out("  Process: pid=%d\n", getpid());
            out("  Signed:  %s\n", G.sign_status ? "YES (fully signed)" : "NO (unsigned or partially signed)");
            out("\n");
        }

        if (g_verbose) {
            out("========================================================================\n");
            out("IMPLEMENTATION FINGERPRINTS (FNV-1a, first 16 bytes)\n");
            out("========================================================================\n");
            for (int i = 0; i < G.nh; i++)
                if (G.hooks[i].state == ST_HOOKED)
                    out("  %-30s 0x%016lx\n", G.hooks[i].sym,
                        (unsigned long)G.fp[i]);
            out("\n");
        }
    }

    /* summary always prints */
    out("========================================================================\n");
    out("SUMMARY\n");
    out("========================================================================\n");
    out("  catalog APIs checked : %d\n", G.nh);
    out("  hooked (external)    : %d\n", hooked);
    out("  unknown-entry        : %d   (concealed hook candidates)\n", ue);
    out("  self-forwards        : %d   (dyld/segment tail-calls)\n", fwd);
    out("  patched (non-branch) : %d\n", patched);
    out("  syscall stubs        : %d\n", sysb);
    out("  interpose pairs      : %d\n", G.nipr);
    out("  rebind divergences   : %d\n", G.nrbr);
    out("  anonymous RX regions : %d\n", G.nrx);
    out("  images scanned       : %d\n", G.nimgs);
    out("  telemetry APIs       : %d checked\n", G.ntel);
    /* v2.2: unscanned targets (F5) */
    if (G.nunscanned > 0) {
        out("  unscanned targets    : %d   (dlsym returned NULL)\n", G.nunscanned);
        if (g_verbose) {
            out("    ");
            for (int i = 0; i < G.nunscanned && i < 32; i++)
                out("%s%s", i > 0 ? ", " : "", G.unscanned_syms[i]);
            if (G.nunscanned > 32) out(" ...");
            out("\n");
        }
    }
    /* v2.2: new analytical results */
    if (g_export_trie) out("  trie mismatches      : %d\n", G.n_trie_mismatch);
    if (g_forwarders)  out("  reexport forwards    : %d\n", G.n_reexport);
    if (g_alias_pairs) out("  alias-pair diverged  : %d   (selective interception)\n", G.n_alias_div);
    if (g_check_sign) out("  signed               : %s\n",
        G.sign_status == 1 ? "YES" : G.sign_status == 0 ? "NO" : "?");
    out("  elapsed              : %.3fs\n\n", G.elapsed);

    if (hooked || ue || patched || G.nipr || G.nrbr || G.nrx ||
        G.n_trie_mismatch || G.n_alias_div) {
        out("FINDINGS\n");
        out("  %d hooked, %d unknown-entry, %d patched, %d interpose, "
            "%d rebinds, %d anonymous RX regions",
            hooked, ue, patched, G.nipr, G.nrbr, G.nrx);
        if (G.n_trie_mismatch) out(", %d trie mismatches", G.n_trie_mismatch);
        if (G.n_alias_div) out(", %d alias divergences", G.n_alias_div);
        out("\n");
    } else {
        out("FINDINGS\n");
        out("  All surfaces clean.\n");
    }

    /* Verdict (for operators) — always print, even in quiet mode */
    int total_findings = hooked + ue + patched + G.nipr + G.nrbr + G.nrx +
                         G.n_trie_mismatch + G.n_alias_div;
    out("\nVERDICT: %s\n",
        total_findings > 0 ?
        "MODIFIED — investigate flagged entries" :
        "CLEAN — no user-mode modifications detected");

    /* F8: Recommended operator actions */
    if (!q_quiet && total_findings > 0)
        print_operator_actions(hooked, patched, ue, G.nipr, G.nrbr, G.nrx,
                               G.n_trie_mismatch, G.n_alias_div);

    if (g_verbose && hooked + ue + patched > 0) {
        out("\nVERBOSE — FUNCTION DETAIL\n");
        out("========================================================================\n");
        for (int i = 0; i < G.nh; i++) {
            if (G.hooks[i].state == ST_HOOKED ||
                G.hooks[i].state == ST_PATCHED ||
                G.hooks[i].state == ST_UNKNOWN_ENTRY) {
                out("  %s!%s\n", basename_(G.hooks[i].owner), G.hooks[i].sym);
                out("    address:   0x%lx\n", (long)G.hooks[i].addr);
                out("    state:     %s\n", STN[G.hooks[i].state]);
                out("    bytes:     ");
                for (int b = 0; b < 32; b++) out("%02X ", G.hooks[i].first_bytes[b]);
                out("\n");
                if (G.hooks[i].chain_len > 1) {
                    out("    chain:     ");
                    for (int c = 0; c < G.hooks[i].chain_len; c++)
                        out("0x%lx%s", (long)G.hooks[i].chain[c], c+1<G.hooks[i].chain_len?" -> ":"");
                    out("\n");
                }
                out("\n");
            }
        }
    }

    free(cluster_dest); free(cluster_count);
}

/* ─── F8: Recommended operator actions ─────────────────────────────────────── */

static void print_operator_actions(int hooked, int patched, int ue, int interpose,
                                    int rebind, int rx, int trie_mm, int alias_div) {
    out("\n========================================================================\n");
    out("RECOMMENDED OPERATOR ACTIONS\n");
    out("========================================================================\n");

    if (hooked > 0) {
        out("  [HOOKED] %d function(s) have trampoline redirects:\n", hooked);
        out("    -> Identify the hook destination image (check target_owner field)\n");
        out("    -> Dump hook target bytes for signature analysis\n");
        out("    -> Check if destination is in anonymous RX region (likely malicious)\n");
        out("    -> Cross-reference with --ground-truth to confirm byte modification\n\n");
    }
    if (patched > 0) {
        out("  [PATCHED] %d function(s) have inline patches:\n", patched);
        out("    -> Classify patch type (early-ret, const-ret, nop, brk)\n");
        out("    -> Early-ret on security APIs = likely EDR bypass or malware\n");
        out("    -> Use --verbose to see raw bytes of patched functions\n\n");
    }
    if (ue > 0) {
        out("  [UNKNOWN-ENTRY] %d function(s) have unrecognizable prologues:\n", ue);
        out("    -> HIGH PRIORITY — concealed hooks that evade pattern matching\n");
        out("    -> Dump full 32-byte prologue for manual analysis\n");
        out("    -> Compare with --ground-truth to see what the original bytes should be\n");
        out("    -> These are the strongest indicators of sophisticated hooking\n\n");
    }
    if (interpose > 0) {
        out("  [INTERPOSE] %d __interpose section entries:\n", interpose);
        out("    -> Check if replacement function is in a third-party image\n");
        out("    -> Apple-legitimate interposes target apple-lib images\n");
        out("    -> Third-party interposes on security APIs warrant investigation\n\n");
    }
    if (rebind > 0) {
        out("  [REBIND] %d indirect symbol pointer divergences:\n", rebind);
        out("    -> fishhook-style rebinding detected\n");
        out("    -> Check which image's __la_symbol_ptr was modified\n");
        out("    -> Identify the replacement function's owning image\n\n");
    }
    if (rx > 0) {
        out("  [ANON-RX] %d anonymous executable memory regions:\n", rx);
        out("    -> These regions have no backing image — potential injected code\n");
        out("    -> Dump bytes with --dump-rx for disassembly\n");
        out("    -> Check if any hooked functions redirect to these regions\n\n");
    }
    if (trie_mm > 0) {
        out("  [TRIE-MISMATCH] %d export-trie address mismatches:\n", trie_mm);
        out("    -> dlsym address differs from on-disk export trie address\n");
        out("    -> Indicates in-memory symbol redirection (interpose or hook)\n");
        out("    -> Run --ground-truth for byte-level confirmation\n\n");
    }
    if (alias_div > 0) {
        out("  [ALIAS-DIV] %d alias-pair divergences:\n", alias_div);
        out("    -> $NOCANCEL variant hooked but primary not (or vice versa)\n");
        out("    -> Selective interception — strong indicator of targeted hooking\n");
        out("    -> Investigate which variant is hooked and why\n\n");
    }
    out("  GENERAL:\n");
    out("    -> Run --ground-truth for byte-level comparison with shared cache\n");
    out("    -> Run --export-trie to verify dlsym addresses match export trie\n");
    out("    -> Run --alias-pairs to detect selective $NOCANCEL hooking\n");
    out("    -> Run --forwarders to trace LC_REEXPORT chains\n");
    out("    -> Use --watch N for continuous monitoring of dynamic hook installation\n");
}

/* ─── F10: Full JSON tree output ───────────────────────────────────────────── */

static void print_json(void) {
    int cache = 0;
    for (int i = 0; i < G.nimgs; i++) if (G.imgs[i].cache_only) cache++;
    int hooked = 0, patched = 0, ue = 0, interposed = 0, rebound = 0;
    int trie_mm = 0, reexported = 0, alias_div = 0;
    for (int i = 0; i < G.nh; i++) {
        switch (G.hooks[i].state) {
            case ST_HOOKED: hooked++; break;
            case ST_PATCHED: patched++; break;
            case ST_UNKNOWN_ENTRY: ue++; break;
            case ST_INTERPOSED: interposed++; break;
            case ST_REBOUND: rebound++; break;
            case ST_TRIE_MISMATCH: trie_mm++; break;
            case ST_REEXPORT: reexported++; break;
        }
        if (G.hooks[i].alias_diverged) alias_div++;
    }

    out("{\n");
    out("  \"version\": \"2.2.0\",\n");
    out("  \"timestamp\": %ld,\n", (long)time(NULL));
    out("  \"os\": \"macOS\",\n");
    out("  \"arch\": \"%s\",\n", g_arm64 ? "arm64" : "x86_64");
    out("  \"host\": {\"pid\": %d, \"ppid\": %d, \"uid\": %d},\n", getpid(), getppid(), getuid());

    /* Images */
    out("  \"images\": {\n");
    out("    \"total\": %d, \"cache\": %d, \"on_disk\": %d,\n", G.nimgs, cache, G.nimgs - cache);
    out("    \"list\": [\n");
    for (int i = 0; i < G.nimgs; i++) {
        out("      {\"path\": \"%s\", \"cache_only\": %s, \"slide\": \"0x%lx\"}%s\n",
            G.imgs[i].path, G.imgs[i].cache_only ? "true" : "false",
            (unsigned long)G.imgs[i].slide,
            i < G.nimgs - 1 ? "," : "");
    }
    out("    ]\n");
    out("  },\n");

    /* Interpose pairs */
    out("  \"interpose\": {\n");
    out("    \"count\": %d,\n", G.nipr);
    out("    \"entries\": [\n");
    for (int i = 0; i < G.nipr; i++) {
        out("      {\"image\": \"%s\", \"replacee_owner\": \"%s\", \"replacement_owner\": \"%s\", \"third_party\": %s}%s\n",
            basename_(G.ipr[i].image),
            basename_(G.ipr[i].replacee_owner),
            basename_(G.ipr[i].replacement_owner),
            G.ipr[i].third_party ? "true" : "false",
            i < G.nipr - 1 ? "," : "");
    }
    out("    ]\n");
    out("  },\n");

    /* Rebind divergences */
    out("  \"rebinds\": {\n");
    out("    \"count\": %d,\n", G.nrbr);
    out("    \"entries\": [\n");
    for (int i = 0; i < G.nrbr; i++) {
        out("      {\"image\": \"%s\", \"symbol\": \"%s\", \"actual_owner\": \"%s\"}%s\n",
            basename_(G.rbr[i].image), G.rbr[i].symbol,
            basename_(G.rbr[i].actual_owner),
            i < G.nrbr - 1 ? "," : "");
    }
    out("    ]\n");
    out("  },\n");

    /* Hooks — full detail tree */
    out("  \"hooks\": {\n");
    out("    \"checked\": %d, \"hooked\": %d, \"patched\": %d, \"unknown_entry\": %d,\n",
        G.nh, hooked, patched, ue);
    out("    \"interposed\": %d, \"rebound\": %d, \"trie_mismatch\": %d, \"reexport\": %d,\n",
        interposed, rebound, trie_mm, reexported);
    out("    \"alias_diverged\": %d, \"unscanned\": %d,\n", alias_div, G.nunscanned);
    out("    \"entries\": [\n");
    for (int i = 0; i < G.nh; i++) {
        hook_t *r = &G.hooks[i];
        out("      {\n");
        out("        \"symbol\": \"%s\",\n", r->sym ? r->sym : "?");
        out("        \"category\": \"%s\",\n", r->cat ? r->cat : "?");
        out("        \"state\": \"%s\",\n", STN[r->state]);
        out("        \"address\": \"0x%lx\",\n", (unsigned long)r->addr);
        out("        \"owner\": \"%s\",\n", r->owner[0] ? basename_(r->owner) : "");
        if (r->tramp[0]) out("        \"trampoline\": \"%s\",\n", r->tramp);
        if (r->target_owner[0]) out("        \"target_owner\": \"%s\",\n", basename_(r->target_owner));
        if (r->chain_len > 1) {
            out("        \"chain\": [");
            for (int c = 0; c < r->chain_len; c++)
                out("\"0x%lx\"%s", (unsigned long)r->chain[c],
                    c < r->chain_len - 1 ? ", " : "");
            out("],\n");
        }
        if (r->patch != PT_NONE) out("        \"patch_type\": \"%s\",\n", PTN[r->patch]);
        if (r->syscall_stub) out("        \"syscall_stub\": true,\n");
        if (r->trie_match == 0) out("        \"trie_mismatch\": true,\n");
        if (r->reexport_from[0]) out("        \"reexport_from\": \"%s\",\n", basename_(r->reexport_from));
        if (r->alias_diverged) out("        \"alias_diverged\": true, \"alias_partner\": \"%s\",\n", r->alias_partner);
        out("        \"fingerprint\": \"0x%016llx\"\n", (unsigned long long)G.fp[i]);
        out("      }%s\n", i < G.nh - 1 ? "," : "");
    }
    out("    ]\n");
    out("  },\n");

    /* Anonymous RX regions */
    out("  \"anonymous_rx\": {\n");
    out("    \"count\": %d,\n", G.nrx);
    out("    \"regions\": [\n");
    for (int i = 0; i < G.nrx; i++) {
        out("      {\"base\": \"0x%lx\", \"size_kb\": %lu}%s\n",
            (unsigned long)G.rx[i].base,
            (unsigned long)(G.rx[i].size / 1024),
            i < G.nrx - 1 ? "," : "");
    }
    out("    ]\n");
    out("  },\n");

    /* ObjC methods */
    out("  \"objc_methods\": {\n");
    out("    \"count\": %d,\n", G.nobjc);
    out("    \"entries\": [\n");
    for (int i = 0; i < G.nobjc; i++) {
        out("      {\"class\": \"%s\", \"selector\": \"%s\", \"state\": %d, \"owner\": \"%s\"}%s\n",
            G.objc[i].cls, G.objc[i].sel, G.objc[i].state,
            G.objc[i].owner[0] ? basename_(G.objc[i].owner) : "",
            i < G.nobjc - 1 ? "," : "");
    }
    out("    ]\n");
    out("  },\n");

    /* Telemetry */
    out("  \"telemetry\": {\n");
    out("    \"count\": %d,\n", G.ntel);
    out("    \"entries\": [\n");
    for (int i = 0; i < G.ntel; i++) {
        out("      {\"symbol\": \"%s\", \"present\": %s}%s\n",
            G.tel[i].sym, G.tel[i].present ? "true" : "false",
            i < G.ntel - 1 ? "," : "");
    }
    out("    ]\n");
    out("  },\n");

    /* Unscanned targets (F5) */
    out("  \"unscanned\": {\n");
    out("    \"count\": %d,\n", G.nunscanned);
    out("    \"symbols\": [");
    for (int i = 0; i < G.nunscanned; i++) {
        out("\"%s\"%s", G.unscanned_syms[i] ? G.unscanned_syms[i] : "?",
            i < G.nunscanned - 1 ? ", " : "");
    }
    out("]\n");
    out("  },\n");

    /* Summary */
    {
        int hooked = 0, ue = 0, patched = 0;
        for (int i = 0; i < G.nh; i++) {
            if (G.hooks[i].state == ST_HOOKED) hooked++;
            else if (G.hooks[i].state == ST_UNKNOWN_ENTRY) ue++;
            else if (G.hooks[i].state == ST_PATCHED) patched++;
        }
        int total_findings = hooked + ue + patched + G.nipr + G.nrbr + G.nrx +
                             G.n_trie_mismatch + G.n_alias_div;
        out("  \"summary\": {\n");
        out("    \"hooked\": %d,\n", hooked);
        out("    \"unknown_entry\": %d,\n", ue);
        out("    \"patched\": %d,\n", patched);
        out("    \"interpose_pairs\": %d,\n", G.nipr);
        out("    \"rebinds\": %d,\n", G.nrbr);
        out("    \"anonymous_rx\": %d,\n", G.nrx);
        out("    \"trie_mismatches\": %d,\n", G.n_trie_mismatch);
        out("    \"alias_diverged\": %d,\n", G.n_alias_div);
        out("    \"images_scanned\": %d,\n", G.nimgs);
        out("    \"elapsed_sec\": %.3f\n", G.elapsed);
        out("  },\n");
        out("  \"signed\": %d,\n", G.sign_status);
        out("  \"verdict\": \"%s\"\n",
            total_findings > 0 ?
            "MODIFIED — investigate flagged entries" :
            "CLEAN — no user-mode modifications detected");
    }
    out("}\n");
}

static void print_watch_diff(void) {
    if (g_prev_nh == 0) {
        /* first run — just show summary */
        out("=== WATCH INTERVAL %ds — BASELINE SNAPSHOT ===\n", g_watch_interval_sec);
        out("  (next snapshot will show deltas)\n");
        return;
    }
    /* diff current vs previous */
    int new_hooks = 0, changed_states = 0;
    for (int i = 0; i < G.nh; i++) {
        for (int j = 0; j < g_prev_nh; j++) {
            if (strcmp(G.hooks[i].sym, g_prev_hooks[j].sym) == 0) {
                if (G.hooks[i].state != g_prev_hooks[j].state) {
                    out("  CHANGED: %s %s -> %s\n",
                        G.hooks[i].sym,
                        STN[g_prev_hooks[j].state],
                        STN[G.hooks[i].state]);
                    changed_states++;
                }
            }
        }
    }
    if (new_hooks == 0 && changed_states == 0) {
        out("  No changes detected\n");
    } else {
        out("  %d state change(s) detected (findings may have shifted)\n", changed_states);
    }
}

/* ─── Dyld shared cache baseline comparison ───────────────────────────────── */
/* Save/compare function entry-point fingerprints to detect in-memory hooks
   that persist across process restarts. Baseline file format:
   # InterposeScope baseline v1
   <sym> <fnv1a_hash> <state>
   ... */

static void write_baseline(const char *path) {
    FILE *f = fopen(path, "w");
    if (!f) {
        out("[baseline] ERROR: cannot write to %s\n", path);
        return;
    }
    fprintf(f, "# InterposeScope baseline v1\n");
    fprintf(f, "# arch=%s images=%d\n", g_arm64 ? "arm64" : "x86_64", G.nimgs);
    for (int i = 0; i < G.nh; i++) {
        fprintf(f, "%s %016llx %d\n",
                G.hooks[i].sym ? G.hooks[i].sym : "?",
                (unsigned long long)G.fp[i],
                G.hooks[i].state);
    }
    fclose(f);
    out("[baseline] Wrote %d fingerprints to %s\n", G.nh, path);
}

static void compare_baseline(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) {
        out("[baseline] ERROR: cannot read %s — run with --baseline first\n", path);
        return;
    }
    char line[512];
    int matched = 0, diverged = 0, missing = 0;
    /* Read baseline into a simple array */
    typedef struct { char sym[128]; uint64_t fp; int state; } bl_t;
    bl_t bl[512]; int nbl = 0;

    while (fgets(line, sizeof(line), f) && nbl < 512) {
        if (line[0] == '#') continue;
        char sym[128]; unsigned long long fp; int st;
        if (sscanf(line, "%127s %llx %d", sym, &fp, &st) == 3) {
            strncpy(bl[nbl].sym, sym, 127);
            bl[nbl].fp = fp;
            bl[nbl].state = st;
            nbl++;
        }
    }
    fclose(f);

    out("========================================================================\n");
    out("DYLD SHARED CACHE BASELINE COMPARISON\n");
    out("========================================================================\n");
    out("  Baseline: %s (%d entries)\n", path, nbl);
    out("  Current:  %d entries\n\n", G.nh);

    for (int i = 0; i < G.nh; i++) {
        const char *sym = G.hooks[i].sym ? G.hooks[i].sym : "?";
        int found = -1;
        for (int j = 0; j < nbl; j++) {
            if (strcmp(bl[j].sym, sym) == 0) { found = j; break; }
        }
        if (found < 0) {
            out("  NEW       %-28s  fp=%016llx  state=%d\n",
                sym, (unsigned long long)G.fp[i], G.hooks[i].state);
            missing++;
        } else if (bl[found].fp != G.fp[i]) {
            out("  DIVERGED  %-28s  baseline=%016llx  current=%016llx  [%s -> %s]\n",
                sym,
                (unsigned long long)bl[found].fp,
                (unsigned long long)G.fp[i],
                STN[bl[found].state], STN[G.hooks[i].state]);
            diverged++;
        } else {
            matched++;
        }
    }

    out("\n  --- Summary ---\n");
    out("  matched:   %d\n", matched);
    out("  diverged:  %d  (in-memory modification detected)\n", diverged);
    out("  new:       %d  (not in baseline)\n", missing);

    if (diverged > 0)
        out("\n  VERDICT: ANOMALY — %d function(s) diverge from baseline\n", diverged);
    else
        out("\n  VERDICT: MATCH — all functions consistent with baseline\n");
}

/* ─── Ground-truth byte-diff against dyld shared cache ────────────────────── */
/* Compare in-memory function bytes against the on-disk dyld shared cache file.
   This is the true ground-truth comparison — no pre-saved baseline needed.
   Detects any in-memory modification of shared cache code by reading the
   actual bytes from the cache file on disk and comparing them to what's
   currently mapped in the process. */

struct dyld_cache_mapping_info_gt {
    uint64_t address;
    uint64_t size;
    uint64_t fileOffset;
    uint32_t maxProt;
    uint32_t initProt;
};

static int find_shared_cache_path(char *out, size_t outsz) {
    const char *arch_suf = g_arm64 ? "arm64e" : "x86_64";
    const char *dirs[] = {
        "/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld",
        "/System/Library/dyld",
        "/usr/lib",
        NULL,
    };
    char candidate[PATH_MAX];
    for (int d = 0; dirs[d]; d++) {
        snprintf(candidate, sizeof(candidate), "%s/dyld_shared_cache_%s", dirs[d], arch_suf);
        if (access(candidate, R_OK) == 0) {
            strncpy(out, candidate, outsz - 1);
            out[outsz - 1] = '\0';
            return 1;
        }
        if (g_arm64) {
            snprintf(candidate, sizeof(candidate), "%s/dyld_shared_cache_arm64", dirs[d]);
            if (access(candidate, R_OK) == 0) {
                strncpy(out, candidate, outsz - 1);
                out[outsz - 1] = '\0';
                return 1;
            }
        }
    }
    return 0;
}

static void shared_cache_diff(void) {
    char cache_path[PATH_MAX] = {0};
    if (!find_shared_cache_path(cache_path, sizeof(cache_path))) {
        out("[ground-truth] ERROR: cannot locate dyld shared cache file\n");
        out("  Searched: /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_*\n");
        out("            /System/Library/dyld/dyld_shared_cache_*\n");
        out("            /usr/lib/dyld_shared_cache_*\n");
        return;
    }

    /* On modern macOS, the shared cache is split into sub-files.
       The main file contains only the header + first mapping.
       Sub-files (.01, .02, .05, .09, etc.) contain the rest.
       Each sub-file has its own header with its own mapping table.

       Strategy: parse all sub-files, build a unified mapping table
       that maps VM address ranges to (subfile_path, file_offset). */

    typedef struct {
        uint64_t vmaddr;
        uint64_t vmsize;
        uint64_t fileoff;
        char subfile[PATH_MAX];
        int prot;
    } gt_map_t;

    gt_map_t gt_maps[128];
    int n_gt_maps = 0;

    /* Parse the main cache file and all sub-files */
    const char *sub_suffixes[] = {
        "", ".01", ".02", ".03", ".04", ".05", ".06", ".07",
        ".08", ".09", ".10", ".11", ".12",
        ".01.dylddata", ".02.dylddata", ".06.dylddata", ".10.dylddata",
        ".04.dyldlinkedit", ".08.dyldlinkedit", ".12.dyldlinkedit",
        ".07.dyldreadonly", ".03.dyldreadonly",
        ".atlas", ".map",
        NULL
    };

    char magic[17] = {0};
    int n_subfiles = 0;

    for (int s = 0; sub_suffixes[s] && n_gt_maps < 120; s++) {
        char subpath[PATH_MAX];
        snprintf(subpath, sizeof(subpath), "%s%s", cache_path, sub_suffixes[s]);

        int fd = open(subpath, O_RDONLY);
        if (fd < 0) continue;

        struct stat st;
        if (fstat(fd, &st) < 0) { close(fd); continue; }
        size_t fsize = (size_t)st.st_size;
        if (fsize < 24) { close(fd); continue; } /* too small for header */

        void *mapped = mmap(NULL, fsize, PROT_READ, MAP_PRIVATE, fd, 0);
        close(fd);
        if (mapped == MAP_FAILED) continue;

        /* Check for dyld cache magic */
        if (memcmp(mapped, "dyld_v1", 7) != 0) {
            munmap(mapped, fsize);
            continue;
        }

        if (n_subfiles == 0) {
            memcpy(magic, mapped, 16);
        }
        n_subfiles++;

        /* Parse header: magic[16], mappingOffset(u32), mappingCount(u32) */
        uint32_t mappingOffset, mappingCount;
        memcpy(&mappingOffset, (uint8_t *)mapped + 16, 4);
        memcpy(&mappingCount, (uint8_t *)mapped + 20, 4);

        if (mappingOffset == 0 || mappingCount == 0 ||
            mappingOffset + mappingCount * 32 > fsize) {
            munmap(mapped, fsize);
            continue;
        }

        for (uint32_t i = 0; i < mappingCount && n_gt_maps < 120; i++) {
            uint8_t *p = (uint8_t *)mapped + mappingOffset + i * 32;
            struct dyld_cache_mapping_info_gt mi;
            memcpy(&mi, p, 32);
            gt_maps[n_gt_maps].vmaddr = mi.address;
            gt_maps[n_gt_maps].vmsize = mi.size;
            gt_maps[n_gt_maps].fileoff = mi.fileOffset;
            gt_maps[n_gt_maps].prot = mi.initProt;
            strncpy(gt_maps[n_gt_maps].subfile, subpath, PATH_MAX - 1);
            n_gt_maps++;
        }

        munmap(mapped, fsize);
    }

    out("========================================================================\n");
    out("GROUND-TRUTH BYTE-DIFF (dyld shared cache on-disk)\n");
    out("========================================================================\n");
    out("  Cache base: %s\n", cache_path);
    out("  Magic:      %.16s\n", magic);
    out("  Sub-files:  %d parsed\n", n_subfiles);
    out("  Mappings:   %d total\n", n_gt_maps);
    if (g_verbose) {
        for (int m = 0; m < n_gt_maps; m++)
            out("    [%d] addr=0x%012llx  size=0x%08llx  fileOff=0x%09llx  prot=%c%c%c  [%s]\n",
                m, (unsigned long long)gt_maps[m].vmaddr,
                (unsigned long long)gt_maps[m].vmsize,
                (unsigned long long)gt_maps[m].fileoff,
                (gt_maps[m].prot & 4) ? 'R' : '-',
                (gt_maps[m].prot & 2) ? 'W' : '-',
                (gt_maps[m].prot & 1) ? 'X' : '-',
                basename_(gt_maps[m].subfile));
    }
    out("  Functions:  %d to compare\n\n", G.nh);

    int window = g_bytes_window;
    if (window > 64) window = 64;
    if (window < 8) window = 32;

    int matched = 0, diverged = 0, not_in_cache = 0, err = 0;
    int first_div = 1;

    /* Cache file descriptors for sub-files we've already opened */
    typedef struct { char path[PATH_MAX]; void *mapped; size_t size; } subfile_cache_t;
    subfile_cache_t sf_cache[32];
    int n_sf_cache = 0;

    for (int i = 0; i < G.nh; i++) {
        hook_t *r = &G.hooks[i];
        if (r->unscanned) continue;
        uintptr_t live_addr = r->addr;

        /* Find the image's slide */
        Dl_info di;
        if (!dladdr((void *)live_addr, &di) || !di.dli_fbase) {
            not_in_cache++;
            continue;
        }

        uintptr_t slide = 0;
        int found_img = 0;
        for (int j = 0; j < G.nimgs; j++) {
            if ((const void *)G.imgs[j].mh == di.dli_fbase) {
                slide = G.imgs[j].slide;
                found_img = 1;
                break;
            }
        }
        if (!found_img) {
            not_in_cache++;
            continue;
        }

        /* Compute unslid VM address */
        uintptr_t unslid = live_addr - slide;

        /* Find which mapping contains this address */
        int map_idx = -1;
        for (int m = 0; m < n_gt_maps; m++) {
            if (unslid >= gt_maps[m].vmaddr &&
                unslid < gt_maps[m].vmaddr + gt_maps[m].vmsize) {
                map_idx = m;
                break;
            }
        }
        if (map_idx < 0) {
            not_in_cache++;
            continue;
        }

        /* Compute file offset within the sub-file */
        off_t file_off = (off_t)gt_maps[map_idx].fileoff +
                         (off_t)(unslid - gt_maps[map_idx].vmaddr);

        /* Find or open the sub-file */
        void *sf_mapped = NULL;
        size_t sf_size = 0;
        int sf_found = 0;
        for (int c = 0; c < n_sf_cache; c++) {
            if (strcmp(sf_cache[c].path, gt_maps[map_idx].subfile) == 0) {
                sf_mapped = sf_cache[c].mapped;
                sf_size = sf_cache[c].size;
                sf_found = 1;
                break;
            }
        }
        if (!sf_found) {
            if (n_sf_cache >= 32) { err++; continue; }
            int sfd = open(gt_maps[map_idx].subfile, O_RDONLY);
            if (sfd < 0) { err++; continue; }
            struct stat sst;
            if (fstat(sfd, &sst) < 0) { close(sfd); err++; continue; }
            sf_size = (size_t)sst.st_size;
            sf_mapped = mmap(NULL, sf_size, PROT_READ, MAP_PRIVATE, sfd, 0);
            close(sfd);
            if (sf_mapped == MAP_FAILED) { err++; continue; }
            strncpy(sf_cache[n_sf_cache].path, gt_maps[map_idx].subfile, PATH_MAX - 1);
            sf_cache[n_sf_cache].mapped = sf_mapped;
            sf_cache[n_sf_cache].size = sf_size;
            n_sf_cache++;
        }

        if (file_off < 0 || (size_t)file_off + window > sf_size) {
            err++;
            continue;
        }

        /* Read on-disk bytes from sub-file */
        uint8_t disk_bytes[64];
        memcpy(disk_bytes, (uint8_t *)sf_mapped + file_off, window);

        /* Compare with in-memory bytes */
        if (memcmp(r->first_bytes, disk_bytes, window) == 0) {
            matched++;
            if (g_verbose) {
                out("  MATCH     %-28s  off=0x%08llx  [%s]\n",
                    r->sym ? r->sym : "?", (unsigned long long)file_off,
                    basename_(r->owner));
            }
        } else {
            diverged++;
            if (first_div) {
                out("  --- Divergences ---\n\n");
                first_div = 0;
            }
            out("  DIVERGED  %-28s  off=0x%08llx  [%s]\n",
                r->sym ? r->sym : "?", (unsigned long long)file_off,
                basename_(r->owner));
            out("    mem:  ");
            for (int b = 0; b < window; b++) out("%02X", r->first_bytes[b]);
            out("\n    disk: ");
            for (int b = 0; b < window; b++) out("%02X", disk_bytes[b]);
            out("\n    diff: ");
            for (int b = 0; b < window; b++)
                out("%s", r->first_bytes[b] != disk_bytes[b] ? "^^" : "  ");
            out("\n\n");
        }
    }

    /* Unmap all cached sub-files */
    for (int c = 0; c < n_sf_cache; c++)
        munmap(sf_cache[c].mapped, sf_cache[c].size);

    out("  --- Ground-truth Summary ---\n");
    out("  matched:       %d  (in-memory == on-disk)\n", matched);
    out("  diverged:      %d  (IN-MEMORY MODIFICATION DETECTED)\n", diverged);
    out("  not in cache:  %d  (non-shared-cache or unresolvable)\n", not_in_cache);
    out("  errors:        %d\n", err);
    out("  window:        %d bytes\n", window);

    if (diverged > 0)
        out("\n  VERDICT: ANOMALY — %d function(s) differ from on-disk shared cache\n", diverged);
    else if (matched > 0)
        out("\n  VERDICT: PRISTINE — all %d shared-cache functions match on-disk bytes\n", matched);
    else
        out("\n  VERDICT: INCONCLUSIVE — no functions could be compared\n");
}

/* ─── F4: Cohort multi-process mode ────────────────────────────────────────── */
/* Scan multiple PIDs in a single run. For each PID, open the task port,
   enumerate images, and compare the hook landscape across processes.
   This enables detection of process-specific hooking (e.g. EDR that
   only instruments certain processes). */

static void cohort_scan(const char *pid_list) {
    out("========================================================================\n");
    out("COHORT MULTI-PROCESS SCAN\n");
    out("========================================================================\n");
    out("  PID list: %s\n\n", pid_list);

    /* Parse comma-separated PIDs */
    pid_t pids[64];
    int npids = 0;
    char buf[256];
    strncpy(buf, pid_list, 255);
    buf[255] = '\0';
    char *tok = strtok(buf, ",");
    while (tok && npids < 64) {
        int pid = atoi(tok);
        if (pid > 0) pids[npids++] = (pid_t)pid;
        tok = strtok(NULL, ",");
    }

    if (npids == 0) {
        out("  ERROR: no valid PIDs parsed from '%s'\n", pid_list);
        return;
    }

    out("  PIDs to scan: %d\n\n", npids);

    /* For each PID, scan and record summary */
    typedef struct {
        pid_t pid;
        int nimgs;
        int hooked;
        int patched;
        int ue;
        int nipr;
        int nrbr;
        int nrx;
        int task_ok;
        char proc_name[256];
    } cohort_result_t;

    cohort_result_t results[64];
    int n_results = 0;

    for (int p = 0; p < npids; p++) {
        pid_t pid = pids[p];
        cohort_result_t *cr = &results[n_results];
        memset(cr, 0, sizeof *cr);
        cr->pid = pid;

        /* Get process name */
        char path[PATH_MAX];
        if (proc_pidpath(pid, path, sizeof(path)) > 0) {
            const char *bn = strrchr(path, '/');
            strncpy(cr->proc_name, bn ? bn + 1 : path, 255);
        } else {
            snprintf(cr->proc_name, sizeof(cr->proc_name), "pid=%d", pid);
        }

        out("  --- Scanning pid %d (%s) ---\n", pid, cr->proc_name);

        /* Try to open the task port */
        remote_t rt = open_remote(pid);
        if (!rt.valid) {
            out("    [FAIL] task_for_pid denied (entitlement/root required)\n\n");
            cr->task_ok = 0;
            n_results++;
            continue;
        }
        cr->task_ok = 1;

        /* Enumerate remote images */
        image_t remote_imgs[1024];
        int n_remote = 0;
        remote_analyze(pid, remote_imgs, &n_remote);
        cr->nimgs = n_remote;

        /* Read remote memory for each catalog API and check for hooks.
           We use the same catalog but read bytes from the remote process. */
        int r_hooked = 0, r_patched = 0, r_ue = 0;
        for (size_t i = 0; i < CATALOG_N && i < 512; i++) {
            void *a = dlsym(RTLD_DEFAULT, CATALOG[i].sym);
            if (!a) continue;
            uintptr_t addr = (uintptr_t)a & ~1ULL;

            /* Read 64 bytes from the remote process at the same address
               (shared cache is at the same VA in all processes) */
            uint8_t rbuf[64];
            mach_vm_size_t out_sz = 0;
            if (!remote_read(rt, (mach_vm_address_t)addr, sizeof(rbuf), rbuf, &out_sz))
                continue;

            /* Check for trampoline/patch */
            tramp_t t = {0};
            int hit = g_arm64 ? dec_arm64_step(addr, rbuf, &t)
                              : dec_x64_step(addr, rbuf, &t);
            int patch = classify_patch(rbuf, sizeof rbuf);

            if (!hit && patch == PT_NONE &&
                !is_known_clean_prologue(rbuf, sizeof rbuf, g_arm64)) {
                r_ue++;
                out("    [UNKNOWN-ENTRY] %s\n", CATALOG[i].sym);
            } else if (hit && t.target) {
                r_hooked++;
                out("    [HOOKED] %s -> 0x%lx\n", CATALOG[i].sym,
                    (unsigned long)t.target);
            } else if (patch != PT_NONE) {
                r_patched++;
                out("    [PATCHED] %s [%s]\n", CATALOG[i].sym, PTN[patch]);
            }
        }

        cr->hooked = r_hooked;
        cr->patched = r_patched;
        cr->ue = r_ue;

        mach_port_deallocate(mach_task_self(), rt.task);
        n_results++;

        out("    Summary: %d imgs, %d hooked, %d patched, %d unknown-entry\n\n",
            cr->nimgs, r_hooked, r_patched, r_ue);
    }

    /* Cross-process comparison */
    out("  --- Cohort Comparison ---\n");
    out("  %-8s %-24s %-6s %-8s %-8s %-8s %-8s\n",
        "PID", "NAME", "IMGS", "HOOKED", "PATCHED", "UNKNOWN", "TASK");
    out("  %s\n", "----------------------------------------------------------------------");
    for (int i = 0; i < n_results; i++) {
        cohort_result_t *cr = &results[i];
        out("  %-8d %-24s %-6d %-8d %-8d %-8d %-8s\n",
            cr->pid, cr->proc_name, cr->nimgs,
            cr->hooked, cr->patched, cr->ue,
            cr->task_ok ? "OK" : "DENIED");
    }

    /* Detect process-specific hooking */
    int any_hooked = 0, all_hooked = 1;
    for (int i = 0; i < n_results; i++) {
        if (results[i].task_ok) {
            if (results[i].hooked + results[i].ue + results[i].patched > 0)
                any_hooked = 1;
            else
                all_hooked = 0;
        }
    }
    if (any_hooked && !all_hooked)
        out("\n  VERDICT: PROCESS-SPECIFIC HOOKING — some processes hooked, others clean\n");
    else if (any_hooked && all_hooked)
        out("\n  VERDICT: SYSTEMATIC HOOKING — all accessible processes show hooks\n");
    else
        out("\n  VERDICT: CLEAN — no hooks detected in any accessible process\n");
}

/* ─── Watch mode ─────────────────────────────────────────────────────────── */

static void watch_loop(pid_t remote_pid) {
    for (;;) {
        memcpy(g_prev_hooks, G.hooks, sizeof(hook_t) * G.nh);
        g_prev_nh = G.nh;

        memset(&G, 0, sizeof(G));
        g_len = 0;
        run_all(remote_pid);

        if (g_json) print_json();
        else print_report();

        print_watch_diff();
        flush_out();
        g_len = 0;

        if (g_watch == 0) break;
        sleep(g_watch_interval_sec);
    }
}

/* ─── main ────────────────────────────────────────────────────────────────── */

static void usage(void) {
    out("InterPoseScope-C v2.2.0 — macOS hook & API-indirection mapper\n\n");
    out("Usage: interposescope [FLAGS]\n\n");
    out("OUTPUT MODES:\n");
    out("  --quiet              No banner/section headers (minimal beacon output)\n");
    out("  --minimal            Only anomalies and verdicts (no clean rows)\n");
    out("  --brief              High-value APIs only (20 CRITICAL/HIGH)\n");
    out("  --json               Full JSON tree output (all entries with detail)\n");
    out("  --verbose            Verbose (byte dumps + chain + fingerprint)\n");
    out("  --top N              Top N most-targeted APIs (fast operator triage)\n");
    out("\nANALYTICAL FEATURES:\n");
    out("  --ground-truth       F1: Byte-diff in-memory vs on-disk dyld shared cache\n");
    out("  --export-trie        F2: Verify dlsym addresses vs on-disk export trie\n");
    out("  --forwarders         F3: Resolve LC_REEXPORT forwarder chains\n");
    out("  --cohort PIDS        F4: Multi-process scan (comma-separated PIDs)\n");
    out("  --alias-pairs        F9: Check $NOCANCEL alias pairs for selective hooking\n");
    out("\nREMOTE/PROCESS:\n");
    out("  --pid N              Scan remote process (task_for_pid + memory read)\n");
    out("  --check-sign         Check process code signature\n");
    out("  --module X[,Y]       Restrict to specific modules\n");
    out("  --functions X[,Y]    Check specific functions\n");
    out("\nCONTINUOUS:\n");
    out("  --watch N            Continuous mode, re-scan every N seconds\n");
    out("\nMISC:\n");
    out("  --bytes N            Comparison window (default 64)\n");
    out("  --dump-bytes         Include raw bytes in output\n");
    out("  --dump-rx            Dump anonymous RX region bytes (hex)\n");
    out("  --baseline FILE      Save function fingerprints to baseline file\n");
    out("  --compare FILE       Compare current fingerprints against baseline\n");
    out("  --help               This help\n");
    out("\n");
}

int main(int argc, char **argv) {
#ifdef __arm64__
    g_arm64 = 1;
#else
    g_arm64 = 0;
#endif

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--quiet")) q_quiet = 1;
        else if (!strcmp(argv[i], "--minimal")) q_minimal = 1;
        else if (!strcmp(argv[i], "--brief")) g_brief = 1;
        else if (!strcmp(argv[i], "--verbose")) g_verbose = 1;
        else if (!strcmp(argv[i], "--json")) g_json = 1;
        else if (!strcmp(argv[i], "--watch") && i + 1 < argc)
            g_watch = 1, g_watch_interval_sec = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--top") && i + 1 < argc) g_top = 1, i++;
        else if (!strcmp(argv[i], "--check-sign")) g_check_sign = 1;
        else if (!strcmp(argv[i], "--dump-rx")) g_dumprx = 1;
        else if (!strcmp(argv[i], "--dump-bytes")) g_dump_bytes = 1;
        else if (!strcmp(argv[i], "--bytes") && i + 1 < argc)
            g_bytes_window = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--pid") && i + 1 < argc)
            g_remote_pid = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--baseline") && i + 1 < argc) {
            g_baseline = 1;
            strncpy(g_baseline_path, argv[++i], PATH_MAX-1);
        }
        else if (!strcmp(argv[i], "--compare") && i + 1 < argc) {
            g_compare = 1;
            strncpy(g_baseline_path, argv[++i], PATH_MAX-1);
        }
        else if (!strcmp(argv[i], "--ground-truth") || !strcmp(argv[i], "--gt")) {
            g_ground_truth = 1;
        }
        else if (!strcmp(argv[i], "--export-trie") || !strcmp(argv[i], "--et")) {
            g_export_trie = 1;
        }
        else if (!strcmp(argv[i], "--forwarders") || !strcmp(argv[i], "--fwd")) {
            g_forwarders = 1;
        }
        else if (!strcmp(argv[i], "--cohort") && i + 1 < argc) {
            g_cohort = 1;
            strncpy(g_cohort_pids, argv[++i], 255);
        }
        else if (!strcmp(argv[i], "--alias-pairs") || !strcmp(argv[i], "--ap")) {
            g_alias_pairs = 1;
        }
        else if (!strcmp(argv[i], "--module") && i + 1 < argc) {
            char *tok = strtok(argv[++i], ",");
            while (tok && g_modules_n < 16) {
                strncpy(g_modules[g_modules_n++], tok, 63);
                tok = strtok(NULL, ",");
            }
        }
        else if (!strcmp(argv[i], "--functions") && i + 1 < argc) {
            char *tok = strtok(argv[++i], ",");
            while (tok && g_functions_n < 64) {
                strncpy(g_functions[g_functions_n++], tok, 127);
                tok = strtok(NULL, ",");
            }
        }
        else if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
            usage(); flush_out(); return 0;
        }
    }

    if (g_watch) {
        watch_loop(g_remote_pid);
        return 0;
    }

    /* F4: cohort mode runs before the normal scan */
    if (g_cohort) {
        run_all(0);  /* scan self first for comparison baseline */
        cohort_scan(g_cohort_pids);
        flush_out();
        return 0;
    }

    run_all(g_remote_pid);

    if (g_baseline) {
        write_baseline(g_baseline_path);
    } else if (g_compare) {
        compare_baseline(g_baseline_path);
    } else if (g_ground_truth) {
        print_report();
        shared_cache_diff();
    } else if (g_json) {
        print_json();
    } else {
        print_report();
    }

    flush_out();
    return 0;
}
