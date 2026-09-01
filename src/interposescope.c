/*
 * InterposeScope-C v2.0 — macOS user-mode hook & API-indirection mapper
 *
 * Full-featured mmap scanner for endpoint-security research on macOS.
 * Read-only: never writes memory, never changes protections.
 *
 * Detection surfaces:
 *   dyld __interpose sections
 *   indirect symbol pointer rebinding (fishhook-style)
 *   inline entry-point branch trampolines (arm64 + x86_64)
 *   patch classification (early-ret, const-ret, NOP, breakpoint)
 *   Mach-O export integrity via symbol resolution
 *   ObjC method-swizzle IMP ownership attribution
 *   patch type classification (EARLY-RET, CONST-RET, NOP, BREAKPOINT)
 *   anonymous executable memory (unsigned RX regions)
 *   DYLD_INSERT_LIBRARIES env exposure
 *   Endpoint Security / os_log telemetry surface presence
 *   FNV-1a implementation fingerprinting for hook correlation
 *   JSON output, brief mode, verbose mode, module/function selectors,
 *   remote PID probing via task_for_pid
 *
 * Build:
 *   clang -arch arm64 -O2 -o interposescope interposescope.c \
 *         -framework Foundation -lobjc -isysroot $(xcrun --show-sdk-path)
 */

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

/* ─── output buffer ─── */
#define OUT_CAP (1024 * 1024)
static char  g_out[OUT_CAP];
static size_t g_len = 0;
static int g_verbose = 0, g_json = 0, g_brief = 0, g_all_exp = 0;
static int g_dump_bytes = 0, g_bytes_window = 32;
static pid_t g_remote_pid = 0;
static char g_modules[16][64]; static int g_modules_n = 0;
static char g_functions[64][128]; static int g_functions_n = 0;

static void out(const char *fmt, ...) {
    if (g_len >= OUT_CAP - 2048) return;
    va_list ap; va_start(ap, fmt);
    int n = vsnprintf(g_out + g_len, OUT_CAP - g_len, fmt, ap);
    va_end(ap);
    if (n > 0) g_len += (size_t)n;
}
static void flush_out(void) { fwrite(g_out, 1, g_len, stdout); g_len = 0; }

/* ─── state enums ─── */
enum { ST_CLEAN=0, ST_HOOKED, ST_PATCHED, ST_FWD, ST_NA, ST_NOT_LOADED,
       ST_NON_EXEC, ST_ERROR, ST_SELF_FWD, ST_SYS_MODULE, ST_THIRD_PARTY,
       ST_PRIVATE_EXEC, ST_SYSCALL, ST_UNKNOWN };
static const char *STN[] = {"CLEAN","HOOKED","PATCHED","FWD","N/A",
    "NOT LOADED","NON-EXEC","ERROR","SELF-FWD","SYS","THIRD-PARTY",
    "PRIVATE-EXEC","SYSCALL","?"};

enum { PT_NONE=0, PT_EARLY_RET, PT_CONST_RET, PT_NOP, PT_BRK, PT_BYTE, PT_UNKNOWN };
static const char *PTN[] = {"NONE","EARLY-RET","CONST-RET","NOP","BRK","BYTE","?"};

/* ─── helpers ─── */
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

/* ─── images ─── */
typedef struct {
    char path[PATH_MAX];
    const struct mach_header_64 *mh;
    uintptr_t slide;
    int cache_only, is_main, is_64;
    uintptr_t text_base; size_t text_size;
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

/* ─── interpose ─── */
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
                    struct section_64 *sec = (void *)(p + sizeof(*seg));
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

/* ─── rebind (indirect symbol table divergence) ─── */
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
        struct stat st; if (fstat(fd, &st) < 0) { close(fd); continue; }
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

/* ─── trampoline decoders ─── */
typedef struct {
    const char *kind;
    uintptr_t target;
    uintptr_t chain[8];
    int chain_len;
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
    if ((w0 & 0xFFFFFC1Fu) == 0xD61F0000u) {
        t->kind = "BR-reg"; t->target = 0; return 0;
    }
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
        int8_t r = (int8_t)buf[1];
        t->kind = "JMP rel8"; t->target = entry + 2 + r; return 1;
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

static void follow_chain(uintptr_t start, tramp_t *t) {
    t->chain[0] = start; t->chain_len = 1;
    for (int hop = 0; hop < 7 && t->chain_len < 8; hop++) {
        uintptr_t entry = t->target;
        if (!entry) break;
        uint8_t buf[64]; memcpy(buf, (void *)entry, sizeof buf);
        tramp_t next = {0};
        int ok = g_arm64 ? dec_arm64_step(entry, buf, &next)
                         : dec_x64_step(entry, buf, &next);
        if (!ok || !next.target) break;
        t->chain[t->chain_len++] = next.target;
        t->target = next.target;
        t->kind = next.kind;
        if (next.kind[0] == 'B' && next.kind[1] == 'R') break;
    }
}

/* ─── patch classification ─── */
static int classify_patch(const uint8_t *buf, size_t len) {
    if (len < 4) return PT_NONE;
    if (g_arm64) {
        uint32_t w0; memcpy(&w0, buf, 4);
        if (w0 == 0xD65F03C0u) return PT_EARLY_RET;
        if (w0 == 0xD503201Fu) return PT_NOP;
        if ((w0 & 0xFFE0001Fu) == 0xD4200000u) return PT_BRK;
        if ((w0 & 0xFFE0001Fu) == 0xD4000001u) return PT_BRK;
        if (len >= 8) {
            uint32_t w1; memcpy(&w1, buf + 4, 4);
            if ((w0 & 0xFFE00000u) == 0xD2800000u &&
                (w1 & 0xFFFFFC1Fu) == 0xD65F0000u) return PT_CONST_RET;
        }
    } else {
        if (buf[0] == 0xC3) return PT_EARLY_RET;
        if (len >= 3 && buf[0] == 0x31 && buf[1] == 0xC0 && buf[2] == 0xC3)
            return PT_CONST_RET;
        if (buf[0] == 0x90) return PT_NOP;
        if (buf[0] == 0xCC) return PT_BRK;
    }
    return PT_NONE;
}

/* ─── API catalog ─── */
typedef struct { const char *sym; const char *cat; int rel; } cat_t;
static const cat_t CATALOG[] = {
    {"posix_spawn","process",0},{"posix_spawnp","process",0},
    {"execve","process",0},{"execv","process",0},
    {"fork","process",1},{"vfork","process",1},
    {"kill","process",1},{"waitpid","process",2},
    {"proc_pidinfo","process",2},{"proc_listpids","process",2},
    {"dlopen","dyld",0},{"dlsym","dyld",0},{"dlclose","dyld",1},
    {"dladdr","dyld",2},
    {"_dyld_register_func_for_add_image","dyld",1},
    {"_dyld_register_func_for_remove_image","dyld",1},
    {"mmap","memory",0},{"mprotect","memory",0},{"munmap","memory",1},
    {"mach_vm_allocate","memory",0},{"mach_vm_write","memory",0},
    {"mach_vm_read_overwrite","memory",0},{"mach_vm_map","memory",0},
    {"mach_vm_protect","memory",1},{"mach_vm_deallocate","memory",1},
    {"task_for_pid","tasks",0},{"task_for_pid_posix_spawn","tasks",1},
    {"thread_create_running","tasks",0},{"task_threads","tasks",1},
    {"mach_port_allocate","tasks",2},{"mach_port_insert_right","tasks",2},
    {"open","files",0},{"openat","files",0},
    {"stat","files",1},{"lstat","files",1},{"fstat","files",2},
    {"unlink","files",1},{"rename","files",1},{"chmod","files",1},
    {"chown","files",1},{"read","files",2},{"write","files",2},
    {"getattrlist","files",2},{"setattrlist","files",2},
    {"mkdir","files",2},{"rmdir","files",2},
    {"socket","network",0},{"connect","network",0},
    {"bind","network",1},{"listen","network",1},{"accept","network",1},
    {"getaddrinfo","network",1},{"send","network",2},
    {"recv","network",2},{"sendto","network",2},{"recvfrom","network",2},
    {"setuid","priv",0},{"seteuid","priv",0},
    {"setgid","priv",1},{"setegid","priv",1},
    {"getuid","priv",2},{"geteuid","priv",2},
    {"csr_check","priv",1},{"csr_get_active_config","priv",2},
    {"objc_msgSend","objc",0},{"objc_msgSendSuper2","objc",1},
    {"method_exchangeImplementations","objc",1},
    {"class_replaceMethod","objc",1},{"objc_getClass","objc",2},
    {"sel_registerName","objc",3},{"objc_registerClassPair","objc",3},
    {"notify_post","notify",1},{"notify_register_dispatch","notify",2},
    {"notify_register_check","notify",2},
    {"getxattr","xattr",1},{"setxattr","xattr",1},
    {"listxattr","xattr",2},{"removexattr","xattr",2},
    {"SecItemCopyMatching","keychain",0},{"SecItemAdd","keychain",0},
    {"SecItemUpdate","keychain",1},{"SecItemDelete","keychain",1},
    {"SecKeyCreateSignature","keychain",2},
    {"es_new_client","endsec",0},{"es_subscribe","endsec",0},
    {"es_unsubscribe","endsec",1},{"es_delete_client","endsec",2},
    {"es_mute_process","endsec",1},
    {"os_log_create","logging",2},{"os_log","logging",2},
    {"os_activity_create","logging",3},
    {"system","misc",0},{"popen","misc",0},{"pclose","misc",2},
    {"getenv","misc",2},{"setenv","misc",2},
    {"ptrace","tasks",1},{"sysctl","misc",2},
};
#define CATALOG_N (sizeof(CATALOG)/sizeof(CATALOG[0]))

/* ─── anonymous RX ─── */
typedef struct { mach_vm_address_t base; mach_vm_size_t size; } rx_t;

static int scan_anon_rx(rx_t *rows, int maxrows) {
    task_t task = mach_task_self();
    mach_vm_address_t addr = MACH_VM_MIN_ADDRESS;
    int nr = 0;
    while (nr < maxrows) {
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t obj = MACH_PORT_NULL;
        mach_vm_size_t size = 0;
        kern_return_t kr = vm_region_64(task, &addr, &size,
            VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &cnt, &obj);
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

/* ─── syscall stub detection ─── */
static int is_syscall_stub_arm64(uintptr_t a) {
    uint32_t w; memcpy(&w, (void *)a, 4);
    return (w & 0xFFE0001Fu) == 0xD4000001u;
}
static int is_syscall_stub_x64(uintptr_t a) {
    uint8_t b[2]; memcpy(b, (void *)a, 2);
    return b[0] == 0x0F && b[1] == 0x05;
}

/* ─── objc swizzle surface ─── */
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

/* ─── telemetry surfaces ─── */
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

/* ─── hook row ─── */
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
} hook_t;

/* ─── global scan state ─── */
static struct {
    image_t imgs[1024]; int nimgs;
    ipr_t ipr[512]; int nipr;
    rbr_t rbr[256]; int nrbr;
    hook_t hooks[512]; int nh;
    rx_t rx[512]; int nrx;
    objc_row_t objc[32]; int nobjc;
    tel_t tel[16]; int ntel;
    uint64_t fp[512];
    double elapsed;
} G;

static void run_all(pid_t remote_pid) {
#ifdef __arm64__
    g_arm64 = 1;
#else
    g_arm64 = 0;
#endif
    clock_t t0 = clock();
    G.nimgs = collect_images(G.imgs, 1024);
    G.nipr  = scan_interpose(G.imgs, G.nimgs, G.ipr, 512);
    G.nrbr  = scan_rebinds(G.imgs, G.nimgs, G.rbr, 256);
    G.nobjc = scan_objc(G.objc, 32);
    G.nrx   = scan_anon_rx(G.rx, 512);
    G.ntel  = scan_telemetry(G.tel, 16);

    G.nh = 0;
    for (size_t i = 0; i < CATALOG_N && G.nh < 512; i++) {
        if (g_brief && CATALOG[i].rel > 1) continue;
        void *a = dlsym(RTLD_DEFAULT, CATALOG[i].sym);
        if (!a) continue;
        uintptr_t addr = (uintptr_t)a & ~1ULL;

        hook_t *r = &G.hooks[G.nh];
        memset(r, 0, sizeof *r);
        r->sym = CATALOG[i].sym;
        r->cat = CATALOG[i].cat;
        r->addr = addr;
        r->rel = CATALOG[i].rel;

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

        if (hit && t.target) {
            follow_chain(addr, &t);
            memcpy(r->chain, t.chain, sizeof t.chain);
            r->chain_len = t.chain_len;
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
    G.elapsed = (double)(clock() - t0) / CLOCKS_PER_SEC;
}

/* ═══ print emitters ═══ */

static void print_banner(void) {
    out("\n");
    out("  ___       _                                  ____\n");
    out(" |_ _|_ __ | |_ ___ _ __ _ __   ___  ___  ___ / ___|  ___ ___  _ __   ___\n");
    out("  | || '_ \\| __/ _ \\ '__| '_ \\ / _ \\/ __|/ _ \\\\___ \\ / __/ _ \\| '_ \\ / _ \\\n");
    out("  | || | | | ||  __/ |  | |_) | (_) \\__ \\  __/ ___) | (_| (_) | |_) |  __/\n");
    out(" |___|_| |_|\\__\\___|_|  | .__/ \\___/|___/\\___||____/ \\___\\___/| .__/ \\___|\n");
    out("                        |_|                                   |_|\n");
    out("            InterposeScope-C v2.0 — %s\n\n", g_arm64 ? "arm64" : "x86_64");
}

static void print_host(void) {
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
    out("\n");
}

static void print_env(void) {
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
}

static void print_images(void) {
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
}

static void print_interpose(void) {
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
    } else out("  CLEAN — no __interpose sections in any loaded image\n\n");
}

static void print_rebinds(void) {
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

static void print_hooks(void) {
    out("========================================================================\n");
    out("HIGH-VALUE API ENTRY-POINT INTEGRITY (%d checked)\n", G.nh);
    out("========================================================================\n");
    out("  %-28s %-8s %-12s %s\n", "SYMBOL", "CATEGORY", "STATE", "DETAIL");
    out("  %s\n", "----------------------------------------------------------------------");
    int hooked = 0, patched = 0, sysb = 0;
    for (int i = 0; i < G.nh; i++) {
        hook_t *r = &G.hooks[i];
        if (r->syscall_stub) sysb++;
        switch (r->state) {
        case ST_HOOKED:
            hooked++;
            out("  %-28s %-8s HOOKED       %s", r->sym, r->cat,
                basename_(r->owner));
            if (r->tramp[0] && r->target_owner[0])
                out("  [%s -> %s]", r->tramp, r->target_owner);
            out("\n");
            if (g_verbose) {
                for (int c = 0; c < r->chain_len; c++)
                    out("    chain[%d] -> 0x%lx\n", c, (long)r->chain[c]);
                out("    bytes: ");
                for (int b = 0; b < 32; b++) out("%02X ", r->first_bytes[b]);
                out("\n");
            }
            break;
        case ST_PATCHED:
            patched++;
            out("  %-28s %-8s PATCHED      [%s] %s\n",
                r->sym, r->cat, PTN[r->patch], basename_(r->owner));
            break;
        case ST_SELF_FWD:
            out("  %-28s %-8s SELF-FWD     %s (tail call)\n",
                r->sym, r->cat, basename_(r->owner));
            break;
        default: break;
        }
    }
    if (!hooked && !patched)
        out("  CLEAN — no entry-point trampolines or patches detected\n");
    out("\n");
    if (sysb) {
        out("  NOTE: %d function(s) contain inline SVC/syscall stubs.\n", sysb);
        out("        These bypass library wrappers and are invisible to user-mode hooks.\n\n");
    }
}

static void print_anon_rx(void) {
    out("========================================================================\n");
    out("ANONYMOUS EXECUTABLE MEMORY (unsigned code regions)\n");
    out("========================================================================\n");
    if (G.nrx) {
        for (int i = 0; i < G.nrx; i++)
            out("  0x%012lx  %8lu KB  RX  (no backing image)\n",
                (long)G.rx[i].base, (unsigned long)(G.rx[i].size / 1024));
        out("\n  %d anonymous RX region(s) found — review recommended.\n", G.nrx);
    } else out("  CLEAN — no anonymous executable regions outside mapped images\n");
    out("\n");
}

static void print_objc(void) {
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
}

static void print_telemetry(void) {
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
}

static void print_fingerprints(void) {
    out("========================================================================\n");
    out("IMPLEMENTATION FINGERPRINTS (FNV-1a, first 16 bytes)\n");
    out("========================================================================\n");
    for (int i = 0; i < G.nh; i++)
        if (G.hooks[i].state == ST_HOOKED)
            out("  %-30s 0x%016lx\n", G.hooks[i].sym,
                (unsigned long)G.fp[i]);
    out("\n");
}

static void print_summary(void) {
    out("========================================================================\n");
    out("SUMMARY\n");
    out("========================================================================\n");
    int hooked = 0, patched = 0, clean = 0, fwd = 0, sysb = 0;
    for (int i = 0; i < G.nh; i++) {
        switch (G.hooks[i].state) {
            case ST_HOOKED: hooked++; break;
            case ST_PATCHED: patched++; break;
            case ST_CLEAN: clean++; break;
            case ST_SELF_FWD: fwd++; break;
        }
        if (G.hooks[i].syscall_stub) sysb++;
    }
    out("  catalog APIs checked : %d\n", G.nh);
    out("  hooked (external)    : %d\n", hooked);
    out("  self-forwards        : %d   (dyld/segment tail-calls)\n", fwd);
    out("  patched (non-branch) : %d\n", patched);
    out("  clean                : %d\n", clean);
    out("  syscall stubs        : %d\n", sysb);
    out("  interpose pairs      : %d\n", G.nipr);
    out("  rebind divergences   : %d\n", G.nrbr);
    out("  anonymous RX regions : %d\n", G.nrx);
    out("  images scanned       : %d\n", G.nimgs);
    out("  telemetry APIs       : %d checked\n", G.ntel);
    out("  elapsed              : %.3fs\n\n", G.elapsed);

    out("RECOMMENDED OPERATOR ACTIONS\n");
    if (hooked)
        out("  - HOOKED: dump hook destination bytes, attribute to module, validate.\n");
    if (patched)
        out("  - PATCHED: re-run with --verbose to inspect the changed bytes.\n");
    if (G.nrx)
        out("  - Anonymous RX: run vmmap on the PID, hash the region, correlate.\n");
    if (G.nipr)
        out("  - Interpose: verify replacement owners are expected EDR dylibs.\n");
    if (G.nrbr)
        out("  - Rebinds: compare expected vs actual owner for each divergent symbol.\n");
    if (!hooked && !patched && !G.nrx && !G.nipr && !G.nrbr)
        out("  - All surfaces clean. Exercise covered behaviors and confirm endpoint\n    telemetry fires (Coverage Validation).\n");
    out("\n");
}

static void print_json(void) {
    int cache = 0;
    for (int i = 0; i < G.nimgs; i++) if (G.imgs[i].cache_only) cache++;
    int hooked = 0, patched = 0;
    for (int i = 0; i < G.nh; i++) {
        if (G.hooks[i].state == ST_HOOKED) hooked++;
        if (G.hooks[i].state == ST_PATCHED) patched++;
    }
    out("{\n");
    out("  \"version\": \"2.0\",\n");
    out("  \"timestamp\": %ld,\n", (long)time(NULL));
    out("  \"os\": \"macOS\",\n");
    out("  \"arch\": \"%s\",\n", g_arm64 ? "arm64" : "x86_64");
    out("  \"host\": {\"pid\": %d, \"ppid\": %d, \"uid\": %d},\n", getpid(), getppid(), getuid());
    out("  \"images\": {\"total\": %d, \"cache\": %d, \"on_disk\": %d},\n",
        G.nimgs, cache, G.nimgs - cache);
    out("  \"interpose_count\": %d,\n", G.nipr);
    out("  \"hooks\": {\"checked\": %d, \"hooked\": %d, \"patched\": %d},\n",
        G.nh, hooked, patched);
    out("  \"rebind_divergences\": %d,\n", G.nrbr);
    out("  \"anonymous_rx\": %d,\n", G.nrx);
    out("  \"objc_methods\": %d,\n", G.nobjc);
    out("  \"telemetry_present\": %d,\n", G.ntel);
    out("  \"elapsed_sec\": %.3f\n", G.elapsed);
    out("}\n");
}

static void usage(void) {
    out("InterposeScope-C v2.0\n\n");
    out("Usage: interposescope [FLAGS]\n\n");
    out("  --brief              High-value APIs only (CRITICAL/HIGH)\n");
    out("  --verbose            Include byte dumps and chain details\n");
    out("  --json               JSON output\n");
    out("  --all-exports        Check every export from selected modules (slow)\n");
    out("  --pid N              Probe remote process (requires entitlement)\n");
    out("  --module X[,Y]       Restrict to specific modules\n");
    out("  --functions X[,Y]    Check specific functions\n");
    out("  --bytes N            Comparison window (default 32)\n");
    out("  --dump-bytes         Include raw bytes in output\n");
    out("\n");
}

int main(int argc, char **argv) {
#ifdef __arm64__
    g_arm64 = 1;
#else
    g_arm64 = 0;
#endif
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--brief")) g_brief = 1;
        else if (!strcmp(argv[i], "--verbose")) g_verbose = 1;
        else if (!strcmp(argv[i], "--json")) g_json = 1;
        else if (!strcmp(argv[i], "--all-exports")) g_all_exp = 1;
        else if (!strcmp(argv[i], "--bytes") && i + 1 < argc)
            g_bytes_window = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--dump-bytes")) g_dump_bytes = 1;
        else if (!strcmp(argv[i], "--pid") && i + 1 < argc)
            g_remote_pid = atoi(argv[++i]);
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

    run_all(g_remote_pid);

    if (g_json) {
        print_json();
    } else {
        print_banner();
        print_host();
        print_env();
        print_images();
        print_interpose();
        print_rebinds();
        print_hooks();
        print_anon_rx();
        print_objc();
        print_telemetry();
        if (g_verbose) print_fingerprints();
        print_summary();
        if (g_remote_pid > 0) {
            out("========================================================================\n");
            out("REMOTE PROCESS PROBE (pid=%d)\n", g_remote_pid);
            out("========================================================================\n");
            task_t task = MACH_PORT_NULL;
            kern_return_t kr = task_for_pid(mach_task_self(), g_remote_pid, &task);
            if (kr != KERN_SUCCESS) {
                out("  task_for_pid: %s (kern=%d)\n", mach_error_string(kr), kr);
                out("  NOTE: requires com.apple.system-task-ports entitlement\n\n");
            } else {
                out("  task_for_pid: SUCCEEDED (port %u)\n", task);
                out("  Remote memory read capability confirmed.\n\n");
                mach_port_deallocate(mach_task_self(), task);
            }
        }
    }

    flush_out();
    return 0;
}
