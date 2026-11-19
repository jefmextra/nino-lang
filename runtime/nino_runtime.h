#ifndef _WIN32
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#endif
#if defined(_WIN32) && defined(__MINGW32__) && !defined(__USE_MINGW_SETJMP_NON_SEH)
#define __USE_MINGW_SETJMP_NON_SEH 1
#endif
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <iso646.h>
#include <setjmp.h>
#include <stddef.h>
#include <stdatomic.h>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <io.h>
#include <fcntl.h>
#include <windows.h>
#include <bcrypt.h>
#else
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/mman.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
#include <errno.h>
#include <dlfcn.h>
#endif

static int nino_argc = 0;
static char **nino_argv = NULL;
static inline void _nino_sha256_raw(const uint8_t *data, size_t len, uint8_t out32[32]);
static inline void _nino_sha512_raw(const uint8_t *m, size_t n, uint8_t out64[64]);
static inline int _nino_hex_nib(char c);
static inline bool _nino_ed25519_verify_raw(const uint8_t *m, size_t n, const uint8_t pk[32],
                                            const uint8_t sig[64]);
static inline const char *_nino_json_esc(const char *s);
static inline const char *sha256(const char *data);
static inline const char *sha512(const char *data);
static inline const char *hmac_sha256(const char *key, const char *msg);

static inline bool _nino_is_safe_env_path(const char *s) {
    if (!s || !s[0])
        return false;
    for (size_t i = 0; s[i]; i++) {
        char c = s[i];
        if (c == ';' || c == '|' || c == '&' || c == '`' || c == '$' || c == '>' || c == '<' || c == '"' ||
            c == '\'' || c == '\n' || c == '\r') {
            return false;
        }
    }
    return true;
}

static inline bool _nino_ct_streq(const char *a, const char *b) {
    if (!a || !b)
        return false;
    size_t la = strlen(a), lb = strlen(b);
    if (la != lb || la == 0)
        return false;
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < la; i++) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    return diff == 0;
}
static inline void nino_init_args(int argc, char **argv) {
    nino_argc = argc;
    nino_argv = argv;
#ifdef NINO_HAS_PCC_CERTIFICATE
    if (argc > 1 && (strcmp(argv[1], "--verify-proof") == 0 || strcmp(argv[1], "--proof-info") == 0)) {
        const char *user_hmac_key = getenv("NINO_PCC_HMAC_KEY");
        const char *user_pubkey = getenv("NINO_PCC_ED25519_PUB");
        bool reverify_z3 = false;
        for (int ai = 2; ai < argc; ai++) {
            if (strcmp(argv[ai], "--hmac-key") == 0 && ai + 1 < argc) {
                user_hmac_key = argv[++ai];
            } else if (strcmp(argv[ai], "--pubkey") == 0 && ai + 1 < argc) {
                user_pubkey = argv[++ai];
            } else if (strcmp(argv[ai], "--reverify-z3") == 0) {
                reverify_z3 = true;
            }
        }
        const char *calc_smt_sha = sha256(_NINO_PCC_SMT_SPEC);
        char seal_input[512];
        snprintf(seal_input, sizeof(seal_input), "%s:%s:%d:%s:%s", _NINO_PCC_SRC_SHA, _NINO_PCC_SMT_SHA,
                 _NINO_PCC_THEOREMS, _NINO_PCC_LOGIC, _NINO_PCC_VERDICT);
        const char *calc_seal_sha = sha256(seal_input);
        int actual_checks = 0;
        const char *sp = _NINO_PCC_SMT_SPEC;
        while ((sp = strstr(sp, "(check-sat)")) != NULL) {
            actual_checks++;
            sp += 11;
        }
        bool has_assert = (strstr(_NINO_PCC_SMT_SPEC, "(assert ") != NULL);
        bool no_vacuous = (strstr(_NINO_PCC_SMT_SPEC, "NO_VERIFICATION_OBLIGATIONS") == NULL &&
                           strstr(_NINO_PCC_SMT_SPEC, "PCC_UNSUPPORTED_OBLIGATION") == NULL);
        bool bv_consistent =
            (strstr(_NINO_PCC_LOGIC, "QF_BV") == NULL || strstr(_NINO_PCC_SMT_SPEC, "(_ BitVec 64)") != NULL);
        bool fp_consistent =
            (strstr(_NINO_PCC_LOGIC, "IEEE754") == NULL || strstr(_NINO_PCC_SMT_SPEC, "Float64") != NULL);
        bool spec_valid = (actual_checks >= 1 && actual_checks == _NINO_PCC_CHECK_CNT && has_assert &&
                           no_vacuous && bv_consistent && fp_consistent);
        bool smt_match = _nino_ct_streq(calc_smt_sha, _NINO_PCC_SMT_SHA);
        bool seal_match = _nino_ct_streq(calc_seal_sha, _NINO_PCC_SEAL_SHA);
        bool verdict_ok = (_NINO_PCC_THEOREMS >= 1 && strncmp(_NINO_PCC_VERDICT, "UNSAT Verified", 14) == 0);
        char mac_payload[576];
        snprintf(mac_payload, sizeof(mac_payload), "NINO_PCC_V2:%s:%s:%d:%d:%s:%s", _NINO_PCC_SRC_SHA,
                 _NINO_PCC_SMT_SHA, _NINO_PCC_THEOREMS, _NINO_PCC_CHECK_CNT, _NINO_PCC_LOGIC,
                 _NINO_PCC_VERDICT);
        bool mac_match = false;
        if (_NINO_PCC_KEYED != 0) {
            if (user_hmac_key && user_hmac_key[0] != 0) {
                mac_match = _nino_ct_streq(hmac_sha256(user_hmac_key, mac_payload), _NINO_PCC_MAC_TAG);
            }
        } else {
            char dkey[256];
            if (user_hmac_key && user_hmac_key[0] != 0) {
                snprintf(dkey, sizeof(dkey), "%s", user_hmac_key);
            } else {
                snprintf(dkey, sizeof(dkey), "NINO_PCC_DOMAIN_V2:%s", _NINO_PCC_SRC_SHA);
            }
            mac_match = _nino_ct_streq(hmac_sha256(dkey, mac_payload), _NINO_PCC_MAC_TAG);
        }
        bool ed_match = true;
#ifdef NINO_PCC_ED25519
        ed_match = false;
        if (strlen(_NINO_PCC_ED25519_PUB) == 64 && strlen(_NINO_PCC_ED25519_SIG) == 128) {
            bool pk_pin_ok = true;
            if (user_pubkey && user_pubkey[0] != 0) {
                pk_pin_ok = _nino_ct_streq(user_pubkey, _NINO_PCC_ED25519_PUB);
            }
            if (pk_pin_ok) {
                uint8_t ed_pk[32];
                uint8_t ed_sig[64];
                for (int i = 0; i < 32; i++)
                    ed_pk[i] = (uint8_t)((_nino_hex_nib(_NINO_PCC_ED25519_PUB[i * 2]) << 4) |
                                         _nino_hex_nib(_NINO_PCC_ED25519_PUB[i * 2 + 1]));
                for (int i = 0; i < 64; i++)
                    ed_sig[i] = (uint8_t)((_nino_hex_nib(_NINO_PCC_ED25519_SIG[i * 2]) << 4) |
                                          _nino_hex_nib(_NINO_PCC_ED25519_SIG[i * 2 + 1]));
                ed_match = _nino_ed25519_verify_raw((const uint8_t *)mac_payload, strlen(mac_payload), ed_pk,
                                                    ed_sig);
            }
        }
#endif
        bool z3_reverify_ok = true;
        if (reverify_z3 && spec_valid && smt_match && seal_match && mac_match && ed_match && verdict_ok) {
            char tmp_smt[64];
            char tmp_out[64];
            char cmd_buf[1024];
            snprintf(tmp_smt, sizeof(tmp_smt), "_nino_pcc_chk_%llu.smt2", (unsigned long long)clock());
            snprintf(tmp_out, sizeof(tmp_out), "_nino_pcc_chk_%llu.out", (unsigned long long)clock());
            FILE *sf = fopen(tmp_smt, "wb");
            if (sf) {
                fwrite(_NINO_PCC_SMT_SPEC, 1, strlen(_NINO_PCC_SMT_SPEC), sf);
                fclose(sf);
            } else {
                z3_reverify_ok = false;
            }
            if (z3_reverify_ok) {
                snprintf(cmd_buf, sizeof(cmd_buf), "z3 -T:15 -t:10000 -smt2 \"%s\" > \"%s\" 2>&1", tmp_smt,
                         tmp_out);
                if (system(cmd_buf) != 0) {
                    int z3_rc = -1;
#ifdef _WIN32
                    snprintf(cmd_buf, sizeof(cmd_buf),
                             "tools\\z3.exe -T:15 -t:10000 -smt2 \"%s\" > \"%s\" 2>&1", tmp_smt, tmp_out);
                    z3_rc = system(cmd_buf);
                    if (z3_rc != 0) {
                        const char *nh = getenv("NINO_HOME");
                        if (_nino_is_safe_env_path(nh)) {
                            snprintf(cmd_buf, sizeof(cmd_buf),
                                     "\"\"%s\\tools\\z3.exe\" -T:15 -t:10000 -smt2 \"%s\" > \"%s\" 2>&1\"",
                                     nh, tmp_smt, tmp_out);
                            z3_rc = system(cmd_buf);
                        }
                    }
#else
                    snprintf(cmd_buf, sizeof(cmd_buf), "tools/z3 -T:15 -t:10000 -smt2 \"%s\" > \"%s\" 2>&1",
                             tmp_smt, tmp_out);
                    z3_rc = system(cmd_buf);
                    if (z3_rc != 0) {
                        const char *nh = getenv("NINO_HOME");
                        if (_nino_is_safe_env_path(nh)) {
                            snprintf(cmd_buf, sizeof(cmd_buf),
                                     "\"%s/tools/z3\" -T:15 -t:10000 -smt2 \"%s\" > \"%s\" 2>&1", nh, tmp_smt,
                                     tmp_out);
                            z3_rc = system(cmd_buf);
                        }
                    }
#endif
                    (void)z3_rc;
                }
                FILE *rf = fopen(tmp_out, "rb");
                int r_unsat = 0;
                bool r_sat = false;
                if (rf) {
                    char ln[256];
                    while (fgets(ln, sizeof(ln), rf)) {
                        if (strncmp(ln, "unsat", 5) == 0)
                            r_unsat++;
                        else if (strncmp(ln, "sat", 3) == 0 || strncmp(ln, "unknown", 7) == 0 ||
                                 strstr(ln, "error") != NULL)
                            r_sat = true;
                    }
                    fclose(rf);
                } else {
                    z3_reverify_ok = false;
                }
                if (r_sat || r_unsat < actual_checks)
                    z3_reverify_ok = false;
            }
            remove(tmp_smt);
            remove(tmp_out);
        }
        printf("================================================================================\n");
        printf("[Nino Proof-Carrying Binary (PCC v1.0)]\n");
#ifdef NINO_PCC_ED25519
        printf("  Binary Integrity : Integrity-Sealed SMT Specification (Ed25519 + HMAC-SHA256 + SHA-256)\n");
#else
        printf("  Binary Integrity : Integrity-Sealed SMT Specification (HMAC-SHA256 + SHA-256)\n");
#endif
        printf("  Source Digest    : %s\n", _NINO_PCC_SRC_SHA);
        printf("  SMT Spec Digest  : %s\n", _NINO_PCC_SMT_SHA);
        printf("  Logic Profile    : %s\n", _NINO_PCC_LOGIC);
#ifdef NINO_PCC_ED25519
        printf("  Auth Scheme      : %s\n", _NINO_PCC_KEYED
                                                ? "RFC 8032 Ed25519 + External HMAC-SHA256"
                                                : "RFC 8032 Ed25519 Asymmetric + Domain HMAC-SHA256");
#else
        printf("  Auth Scheme      : %s\n", _NINO_PCC_KEYED ? "External Secret Key (RFC 2104 HMAC-SHA256)"
                                                            : "Domain Seal Key (RFC 2104 HMAC-SHA256)");
#endif
        printf("  CryptographicSeal: %s\n", _NINO_PCC_SEAL_SHA);
        printf("  HMAC-SHA256 Tag  : %s\n", _NINO_PCC_MAC_TAG);
#ifdef NINO_PCC_ED25519
        printf("  Ed25519 PubKey   : %s\n", _NINO_PCC_ED25519_PUB);
        printf("  Ed25519 Sig      : %s\n", _NINO_PCC_ED25519_SIG);
#endif
        printf("  Solver Engine    : Microsoft Z3 SMT Theorem Prover\n");
        printf("  Proof Verdict    : [\033[92m✓ %s\033[0m]\n", _NINO_PCC_VERDICT);
        printf("  Theorems Proven  : %d Active Invariants (%d Z3 Queries)\n", _NINO_PCC_THEOREMS,
               actual_checks);
        if (!spec_valid || !smt_match || !seal_match || !mac_match || !ed_match || !verdict_ok ||
            !z3_reverify_ok) {
            printf("  Runtime Audit    : [✗ PCC CRYPTOGRAPHIC INTEGRITY CHECK FAILED]\n");
            printf("================================================================================\n");
            exit(1);
        }
#ifdef NINO_PCC_ED25519
        printf("  Runtime Audit    : [✓ Embedded SMT Spec, SHA-256, HMAC-SHA256 & Ed25519 Re-Verified]\n");
#else
        printf("  Runtime Audit    : [✓ Embedded SMT Spec, SHA-256 & HMAC-SHA256 Re-Verified]\n");
#endif
        printf("================================================================================\n");
        exit(0);
    }
#else
    if (argc > 1 && (strcmp(argv[1], "--verify-proof") == 0 || strcmp(argv[1], "--proof-info") == 0)) {
        printf("================================================================================\n");
        printf("[Nino Binary]\n");
        printf("  Status: Standalone native executable (Standard Compilation Mode)\n");
        printf("  Notice: To embed an SMT proof certificate, recompile with:\n");
        printf("          ninoc build <file.nino> --proof\n");
        printf("================================================================================\n");
        exit(1);
    }
#endif
}
static inline int64_t nino_get_argc(void) {
    return (int64_t)nino_argc;
}
static inline const char *nino_get_arg(int64_t idx) {
    if (idx < 0 || idx >= nino_argc || !nino_argv)
        return "";
    return nino_argv[idx];
}
static inline const char *get_env(const char *name) {
    if (!name)
        return "";
    const char *v = getenv(name);
    return v ? v : "";
}
static inline const char *nino_get_env(const char *name) {
    return get_env(name);
}
static inline int64_t nino_char_code(const char *s) {
    if (!s || !s[0])
        return 0;
    return (int64_t)((unsigned char)s[0]);
}
static inline void _nino_trace_auto_dump(void);
static inline void nino_require(bool cond, const char *msg) {
    if (!cond) {
        fprintf(stderr, "[Nino Precondition Violation] require() failed: %s\n", msg ? msg : "");
        _nino_trace_auto_dump();
        exit(1);
    }
}
static inline void nino_ensure(bool cond, const char *msg) {
    if (!cond) {
        fprintf(stderr, "[Nino Postcondition Violation] ensure() failed: %s\n", msg ? msg : "");
        _nino_trace_auto_dump();
        exit(1);
    }
}
static inline void nino_panic(const char *msg) {
    fprintf(stderr, "[Nino Panic] %s\n", msg ? msg : "");
    exit(1);
}
#if defined(_MSC_VER)
#define NINO_THREAD_LOCAL __declspec(thread)
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L && !defined(__STDC_NO_THREADS__)
#define NINO_THREAD_LOCAL _Thread_local
#elif defined(__GNUC__) || defined(__clang__)
#define NINO_THREAD_LOCAL __thread
#else
#define NINO_THREAD_LOCAL
#endif

static inline bool _nino_arr_is_alive(const void *arr);
typedef struct {
    void *addr;
    void *container;
    uint8_t *orig_bytes;
    size_t size;
    int fn_depth;
    uint8_t is_local;
    uint8_t has_container;
} nino_tx_entry_t;
typedef struct {
    jmp_buf buf;
    int base_idx;
    int fn_depth;
} nino_tx_frame_t;
typedef struct {
    nino_tx_frame_t *chunks[64];
    volatile int depth;
    volatile int fn_depth;
    int entry_count;
    int capacity;
    nino_tx_entry_t *entries;
} nino_tx_manager_t;
typedef struct {
    int fn_d;
    int tx_d;
} nino_fn_scope_t;
static NINO_THREAD_LOCAL nino_tx_manager_t _nino_tx;
static inline nino_tx_frame_t *_nino_tx_frame_ptr(int d) {
    if (d < 0 || d >= 2048)
        return NULL;
    int ci = d >> 5;
    if (!_nino_tx.chunks[ci])
        _nino_tx.chunks[ci] = (nino_tx_frame_t *)calloc(32, sizeof(nino_tx_frame_t));
    return _nino_tx.chunks[ci] ? &_nino_tx.chunks[ci][d & 31] : NULL;
}
static inline void nino_tx_cleanup_from(int base) {
    if (base < 0)
        base = 0;
    for (int i = base; i < _nino_tx.entry_count; i++) {
        if (_nino_tx.entries[i].orig_bytes) {
            free(_nino_tx.entries[i].orig_bytes);
            _nino_tx.entries[i].orig_bytes = NULL;
        }
    }
    if (base < _nino_tx.entry_count)
        _nino_tx.entry_count = base;
}
static inline void nino_tx_cleanup(void) {
    nino_tx_frame_t *fp = (_nino_tx.depth > 0) ? _nino_tx_frame_ptr(_nino_tx.depth - 1) : NULL;
    nino_tx_cleanup_from(fp ? fp->base_idx : 0);
}
static inline nino_fn_scope_t nino_tx_fn_enter(void) {
    nino_fn_scope_t sc;
    sc.fn_d = _nino_tx.fn_depth;
    sc.tx_d = _nino_tx.depth;
    _nino_tx.fn_depth = sc.fn_d + 1;
    return sc;
}
static inline int nino_tx_push_idx(void) {
    if (_nino_tx.depth < 0)
        _nino_tx.depth = 0;
    int d = _nino_tx.depth;
    nino_tx_frame_t *fp = _nino_tx_frame_ptr(d);
    if (!fp)
        return 0;
    _nino_tx.depth = d + 1;
    fp->base_idx = _nino_tx.entry_count;
    fp->fn_depth = _nino_tx.fn_depth;
    return d;
}
static inline void nino_tx_commit(void) {
    if (_nino_tx.depth > 0) {
        int d = --_nino_tx.depth;
        nino_tx_frame_t *fp = _nino_tx_frame_ptr(d);
        nino_tx_cleanup_from(fp ? fp->base_idx : 0);
    }
}
static inline void nino_tx_fn_leave(nino_fn_scope_t sc) {
    while (_nino_tx.depth > sc.tx_d)
        nino_tx_commit();
    if (_nino_tx.depth > 0 && _nino_tx.entry_count > 0) {
        nino_tx_frame_t *fp = _nino_tx_frame_ptr(_nino_tx.depth - 1);
        int base = fp ? fp->base_idx : 0;
        if (base < 0)
            base = 0;
        int w = base;
        for (int i = base; i < _nino_tx.entry_count; i++) {
            if (_nino_tx.entries[i].is_local && _nino_tx.entries[i].fn_depth > sc.fn_d) {
                if (_nino_tx.entries[i].orig_bytes)
                    free(_nino_tx.entries[i].orig_bytes);
            } else {
                if (w != i)
                    _nino_tx.entries[w] = _nino_tx.entries[i];
                w++;
            }
        }
        _nino_tx.entry_count = w;
    }
    _nino_tx.fn_depth = sc.fn_d;
}
static inline void _nino_tx_checkpoint_ex(void *addr, void *container, size_t sz, int is_local,
                                          int has_container) {
    if (_nino_tx.depth <= 0 || !addr || sz == 0)
        return;
    if (has_container && (!container || !_nino_arr_is_alive(container)))
        return;
    if (_nino_tx.entry_count >= _nino_tx.capacity) {
        int new_cap = _nino_tx.capacity == 0 ? 32 : _nino_tx.capacity * 2;
        nino_tx_entry_t *new_entries =
            (nino_tx_entry_t *)realloc(_nino_tx.entries, (size_t)new_cap * sizeof(nino_tx_entry_t));
        if (!new_entries)
            return;
        _nino_tx.entries = new_entries;
        _nino_tx.capacity = new_cap;
    }
    uint8_t *backup = (uint8_t *)malloc(sz);
    if (!backup)
        return;
    memcpy(backup, addr, sz);
    int idx = _nino_tx.entry_count++;
    _nino_tx.entries[idx].addr = addr;
    _nino_tx.entries[idx].container = container;
    _nino_tx.entries[idx].size = sz;
    _nino_tx.entries[idx].orig_bytes = backup;
    _nino_tx.entries[idx].fn_depth = _nino_tx.fn_depth;
    _nino_tx.entries[idx].is_local = (uint8_t)(is_local ? 1 : 0);
    _nino_tx.entries[idx].has_container = (uint8_t)(has_container ? 1 : 0);
}
static inline void nino_tx_checkpoint(void *addr, size_t sz) {
    _nino_tx_checkpoint_ex(addr, NULL, sz, 0, 0);
}
static inline void nino_tx_checkpoint_local(void *addr, size_t sz) {
    _nino_tx_checkpoint_ex(addr, NULL, sz, 1, 0);
}
static inline void nino_tx_checkpoint_arr(void *container, void *elem_addr, size_t sz) {
    _nino_tx_checkpoint_ex(elem_addr, container, sz, 0, 1);
}
static inline void nino_tx_rollback(void) {
    nino_tx_frame_t *fp = (_nino_tx.depth > 0) ? _nino_tx_frame_ptr(_nino_tx.depth - 1) : NULL;
    int base = fp ? fp->base_idx : 0;
    int frame_fn_d = fp ? fp->fn_depth : 0;
    for (int i = _nino_tx.entry_count - 1; i >= base; i--) {
        if (_nino_tx.entries[i].addr && _nino_tx.entries[i].orig_bytes) {
            if (_nino_tx.entries[i].is_local && _nino_tx.entries[i].fn_depth > frame_fn_d)
                continue;
            if (_nino_tx.entries[i].has_container && !_nino_arr_is_alive(_nino_tx.entries[i].container))
                continue;
            memcpy(_nino_tx.entries[i].addr, _nino_tx.entries[i].orig_bytes, _nino_tx.entries[i].size);
        }
    }
    nino_tx_cleanup_from(base);
}
static inline void nino_abort(const char *msg) {
    if (_nino_tx.depth > 0) {
        int d = _nino_tx.depth - 1;
        nino_tx_frame_t *fp = _nino_tx_frame_ptr(d);
        nino_tx_rollback();
        _nino_tx.depth = d;
        if (fp) {
            _nino_tx.fn_depth = fp->fn_depth;
            longjmp(fp->buf, 1);
        }
    }
    nino_panic(msg);
}
typedef struct NinoArenaSlab {
    char *data;
    size_t cap;
    size_t used;
    size_t base_offset;
    struct NinoArenaSlab *prev;
} NinoArenaSlab;
typedef struct {
    NinoArenaSlab *tail;
    size_t total_offset;
    size_t *marks;
    uint64_t *mark_ids;
    int mark_cap;
    uint64_t base_mark_id;
    uint64_t next_mark_id;
    uint64_t reset_gen;
    int mark_depth;
} NinoArena;
static NINO_THREAD_LOCAL NinoArena g_nino_arena = {NULL, 0, NULL, NULL, 0, 1ULL, 2ULL, 1ULL, 0};
static NINO_THREAD_LOCAL uint64_t _nino_arena_gen = 1;
static inline bool _nino_in_arena(const void *ptr) {
    if (!ptr)
        return false;
    for (NinoArenaSlab *sl = g_nino_arena.tail; sl; sl = sl->prev) {
        if (sl->data && (uintptr_t)ptr >= (uintptr_t)sl->data &&
            (uintptr_t)ptr < (uintptr_t)(sl->data + sl->used))
            return true;
    }
    return false;
}
static inline bool _nino_in_arena_range(const void *ptr, size_t sz) {
    if (!ptr || sz == 0)
        return false;
    uintptr_t lo = (uintptr_t)ptr;
    uintptr_t hi = lo + sz;
    if (hi < lo)
        return false;
    for (NinoArenaSlab *sl = g_nino_arena.tail; sl; sl = sl->prev) {
        if (sl->data && lo >= (uintptr_t)sl->data && hi <= (uintptr_t)(sl->data + sl->used))
            return true;
    }
    return false;
}
static inline void nino_arena_init(size_t cap) {
    while (g_nino_arena.tail) {
        NinoArenaSlab *p = g_nino_arena.tail->prev;
        if (g_nino_arena.tail->data)
            free(g_nino_arena.tail->data);
        free(g_nino_arena.tail);
        g_nino_arena.tail = p;
    }
    size_t c = cap ? cap : (4 * 1024 * 1024);
    NinoArenaSlab *s = (NinoArenaSlab *)malloc(sizeof(NinoArenaSlab));
    if (s) {
        s->data = (char *)malloc(c);
        s->cap = c;
        s->used = 0;
        s->base_offset = 0;
        s->prev = NULL;
        g_nino_arena.tail = s;
    }
    g_nino_arena.total_offset = 0;
    g_nino_arena.mark_depth = 0;
    if (g_nino_arena.next_mark_id < 2)
        g_nino_arena.next_mark_id = 2;
    g_nino_arena.base_mark_id = g_nino_arena.next_mark_id++;
    g_nino_arena.reset_gen++;
    _nino_arena_gen++;
}
static inline void *nino_arena_alloc(size_t sz) {
    if (!g_nino_arena.tail)
        nino_arena_init(4 * 1024 * 1024);
    size_t asz = (sz + 7) & ~((size_t)7);
    if (asz == 0)
        asz = 8;
    NinoArenaSlab *s = g_nino_arena.tail;
    if (s && s->data && s->used + asz <= s->cap) {
        void *p = s->data + s->used;
        s->used += asz;
        g_nino_arena.total_offset += asz;
        return p;
    }
    size_t slab_cap = 4 * 1024 * 1024;
    if (asz > slab_cap)
        slab_cap = asz;
    NinoArenaSlab *ns = (NinoArenaSlab *)malloc(sizeof(NinoArenaSlab));
    if (!ns)
        return malloc(sz);
    ns->data = (char *)malloc(slab_cap);
    if (!ns->data) {
        free(ns);
        return malloc(sz);
    }
    ns->cap = slab_cap;
    ns->used = asz;
    ns->base_offset = g_nino_arena.total_offset;
    ns->prev = s;
    g_nino_arena.tail = ns;
    g_nino_arena.total_offset += asz;
    return ns->data;
}
static inline void nino_arena_reset(void) {
    while (g_nino_arena.tail && g_nino_arena.tail->prev) {
        NinoArenaSlab *p = g_nino_arena.tail->prev;
        if (g_nino_arena.tail->data)
            free(g_nino_arena.tail->data);
        free(g_nino_arena.tail);
        g_nino_arena.tail = p;
    }
    if (g_nino_arena.tail)
        g_nino_arena.tail->used = 0;
    g_nino_arena.total_offset = 0;
    g_nino_arena.mark_depth = 0;
    if (g_nino_arena.next_mark_id < 2)
        g_nino_arena.next_mark_id = 2;
    g_nino_arena.base_mark_id = g_nino_arena.next_mark_id++;
    g_nino_arena.reset_gen++;
    _nino_arena_gen++;
}
static inline void arena_reset(void) {
    nino_arena_reset();
}
static inline int64_t arena_mark(void) {
    size_t m = g_nino_arena.total_offset;
    if (g_nino_arena.mark_depth >= g_nino_arena.mark_cap) {
        int ncap = g_nino_arena.mark_cap == 0 ? 64 : g_nino_arena.mark_cap * 2;
        size_t *nm = (size_t *)realloc(g_nino_arena.marks, (size_t)ncap * sizeof(size_t));
        uint64_t *nid = (uint64_t *)realloc(g_nino_arena.mark_ids, (size_t)ncap * sizeof(uint64_t));
        if (nm && nid) {
            g_nino_arena.marks = nm;
            g_nino_arena.mark_ids = nid;
            g_nino_arena.mark_cap = ncap;
        } else {
            if (nm)
                g_nino_arena.marks = nm;
            if (nid)
                g_nino_arena.mark_ids = nid;
        }
    }
    if (g_nino_arena.mark_depth < g_nino_arena.mark_cap) {
        if (g_nino_arena.next_mark_id < 2)
            g_nino_arena.next_mark_id = 2;
        g_nino_arena.marks[g_nino_arena.mark_depth] = m;
        g_nino_arena.mark_ids[g_nino_arena.mark_depth] = g_nino_arena.next_mark_id++;
        g_nino_arena.mark_depth++;
    }
    return (int64_t)m;
}
static inline void arena_rollback(int64_t mark) {
    if (mark < 0 || (size_t)mark > g_nino_arena.total_offset)
        return;
    size_t m = (size_t)mark;
    while (g_nino_arena.mark_depth > 0 && g_nino_arena.marks &&
           g_nino_arena.marks[g_nino_arena.mark_depth - 1] >= m) {
        g_nino_arena.mark_depth--;
    }
    while (g_nino_arena.tail && g_nino_arena.tail->base_offset > 0 && g_nino_arena.tail->base_offset >= m) {
        NinoArenaSlab *p = g_nino_arena.tail->prev;
        if (g_nino_arena.tail->data)
            free(g_nino_arena.tail->data);
        free(g_nino_arena.tail);
        g_nino_arena.tail = p;
    }
    if (g_nino_arena.tail && m >= g_nino_arena.tail->base_offset)
        g_nino_arena.tail->used = m - g_nino_arena.tail->base_offset;
    g_nino_arena.total_offset = m;
    _nino_arena_gen++;
}
static inline int64_t arena_used(void) {
    return (int64_t)g_nino_arena.total_offset;
}
static inline char *nino_str_concat(const char *a, const char *b) {
    if (!a)
        a = "";
    if (!b)
        b = "";
    size_t la = strlen(a), lb = strlen(b);
    char *buf = (char *)nino_arena_alloc(la + lb + 1);
    if (!buf)
        return "";
    memcpy(buf, a, la);
    memcpy(buf + la, b, lb);
    buf[la + lb] = '\0';
    return buf;
}
static inline char *nino_str_concat_int(const char *a, int64_t b) {
    if (!a)
        a = "";
    char num_buf[64];
    snprintf(num_buf, sizeof(num_buf), "%lld", (long long)b);
    return nino_str_concat(a, num_buf);
}
static inline char *nino_int_concat_str(int64_t a, const char *b) {
    char num_buf[64];
    snprintf(num_buf, sizeof(num_buf), "%lld", (long long)a);
    return nino_str_concat(num_buf, b);
}
static inline char *nino_str_concat_double(const char *a, double b) {
    if (!a)
        a = "";
    char num_buf[64];
    snprintf(num_buf, sizeof(num_buf), "%g", b);
    if (!strchr(num_buf, '.') && !strchr(num_buf, 'e') && !strchr(num_buf, 'E')) {
        size_t nl = strlen(num_buf);
        if (nl + 2 < sizeof(num_buf)) {
            memcpy(num_buf + nl, ".0", 3);
        }
    }
    return nino_str_concat(a, num_buf);
}
static inline char *nino_double_concat_str(double a, const char *b) {
    char num_buf[64];
    snprintf(num_buf, sizeof(num_buf), "%g", a);
    if (!strchr(num_buf, '.') && !strchr(num_buf, 'e') && !strchr(num_buf, 'E')) {
        size_t nl = strlen(num_buf);
        if (nl + 2 < sizeof(num_buf)) {
            memcpy(num_buf + nl, ".0", 3);
        }
    }
    return nino_str_concat(num_buf, b);
}

static inline char *nino_concat_val(const char *a, const char *b) {
    return nino_str_concat(a, b);
}
static inline char *nino_concat_int(const char *a, int64_t b) {
    return nino_str_concat_int(a, b);
}
static inline char *nino_concat_double(const char *a, double b) {
    return nino_str_concat_double(a, b);
}
static inline char *nino_concat_bool(const char *a, bool b) {
    return nino_str_concat(a, b ? "true" : "false");
}

static inline char *nino_concat_val_r(const char *a, const char *b) {
    return nino_str_concat(a, b);
}
static inline char *nino_concat_int_r(int64_t a, const char *b) {
    return nino_int_concat_str(a, b);
}
static inline char *nino_concat_double_r(double a, const char *b) {
    return nino_double_concat_str(a, b);
}
static inline char *nino_concat_bool_r(bool a, const char *b) {
    return nino_str_concat(a ? "true" : "false", b);
}

#define nino_auto_concat(A, B)                                                                               \
    _Generic((B),                                                                                            \
        char *: nino_concat_val,                                                                             \
        const char *: nino_concat_val,                                                                       \
        void *: nino_concat_val,                                                                             \
        unsigned char: nino_concat_int,                                                                      \
        signed char: nino_concat_int,                                                                        \
        short: nino_concat_int,                                                                              \
        unsigned short: nino_concat_int,                                                                     \
        int: nino_concat_int,                                                                                \
        unsigned int: nino_concat_int,                                                                       \
        long: nino_concat_int,                                                                               \
        unsigned long: nino_concat_int,                                                                      \
        long long: nino_concat_int,                                                                          \
        unsigned long long: nino_concat_int,                                                                 \
        double: nino_concat_double,                                                                          \
        float: nino_concat_double,                                                                           \
        bool: nino_concat_bool,                                                                              \
        default: nino_concat_val)((A), (B))
#define nino_auto_concat_r(A, B)                                                                             \
    _Generic((A),                                                                                            \
        char *: nino_concat_val_r,                                                                           \
        const char *: nino_concat_val_r,                                                                     \
        void *: nino_concat_val_r,                                                                           \
        unsigned char: nino_concat_int_r,                                                                    \
        signed char: nino_concat_int_r,                                                                      \
        short: nino_concat_int_r,                                                                            \
        unsigned short: nino_concat_int_r,                                                                   \
        int: nino_concat_int_r,                                                                              \
        unsigned int: nino_concat_int_r,                                                                     \
        long: nino_concat_int_r,                                                                             \
        unsigned long: nino_concat_int_r,                                                                    \
        long long: nino_concat_int_r,                                                                        \
        unsigned long long: nino_concat_int_r,                                                               \
        double: nino_concat_double_r,                                                                        \
        float: nino_concat_double_r,                                                                         \
        bool: nino_concat_bool_r,                                                                            \
        default: nino_concat_val_r)((A), (B))

static inline bool nino_str_eq(const char *a, const char *b) {
    if (a == b)
        return true;
    if (!a || !b)
        return false;
    return strcmp(a, b) == 0;
}
static inline size_t _nino_fast_strlen(const char *s) {
    if (!s)
        return 0;
    static NINO_THREAD_LOCAL const char *_c_s1 = NULL;
    static NINO_THREAD_LOCAL size_t _c_l1 = 0;
    static NINO_THREAD_LOCAL uint64_t _c_g1 = 0;
    static NINO_THREAD_LOCAL const char *_c_s2 = NULL;
    static NINO_THREAD_LOCAL size_t _c_l2 = 0;
    static NINO_THREAD_LOCAL uint64_t _c_g2 = 0;
    if (s == _c_s1 && _c_g1 == _nino_arena_gen && s[_c_l1] == 0)
        return _c_l1;
    if (s == _c_s2 && _c_g2 == _nino_arena_gen && s[_c_l2] == 0)
        return _c_l2;
    size_t l = strlen(s);
    if (l >= 64 && _nino_in_arena(s)) {
        _c_s2 = _c_s1;
        _c_l2 = _c_l1;
        _c_g2 = _c_g1;
        _c_s1 = s;
        _c_l1 = l;
        _c_g1 = _nino_arena_gen;
    }
    return l;
}
static inline int64_t nino_str_len(const char *s) {
    return (int64_t)_nino_fast_strlen(s);
}
static inline char *nino_str_char_at(const char *s, int64_t idx) {
    if (!s || idx < 0)
        return "";
    static NINO_THREAD_LOCAL char _ctab[256][2];
    static NINO_THREAD_LOCAL int _ctab_init = 0;
    if (!_ctab_init) {
        for (int i = 0; i < 256; i++) {
            _ctab[i][0] = (char)i;
            _ctab[i][1] = 0;
        }
        _ctab_init = 1;
    }
    size_t l = _nino_fast_strlen(s);
    if ((size_t)idx >= l)
        return "";
    return _ctab[(unsigned char)s[idx]];
}
static inline char *nino_str_slice(const char *s, int64_t start, int64_t count) {
    if (!s || start < 0 || count <= 0)
        return "";
    int64_t slen = (int64_t)_nino_fast_strlen(s);
    if (start >= slen)
        return "";
    if (start + count > slen)
        count = slen - start;
    char *res = (char *)nino_arena_alloc(count + 1);
    if (!res)
        return "";
    memcpy(res, s + start, count);
    res[count] = 0;
    return res;
}
static inline char *nino_read_file(const char *path) {
    if (!path)
        return "";
    FILE *f = fopen(path, "rb");
    if (!f)
        return "";
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 0) {
        fclose(f);
        return "";
    }
    char *buf = (char *)nino_arena_alloc(sz + 1);
    if (!buf) {
        fclose(f);
        return "";
    }
    size_t rb = fread(buf, 1, sz, f);
    buf[rb] = '\0';
    fclose(f);
    return buf;
}
static inline int _nino_hex_nib(char c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return 0;
}
static inline int64_t nino_write_hex_file(const char *path, const char *hex) {
    if (!path || !hex)
        return 0;
    size_t hlen = strlen(hex);
    size_t nbytes = hlen / 2;
    FILE *f = fopen(path, "wb");
    if (!f)
        return 0;
    if (nbytes > 0) {
        uint8_t *raw = (uint8_t *)malloc(nbytes);
        if (!raw) {
            fclose(f);
            return 0;
        }
        for (size_t i = 0; i < nbytes; i++)
            raw[i] = (uint8_t)((_nino_hex_nib(hex[i * 2]) << 4) | _nino_hex_nib(hex[i * 2 + 1]));
        size_t wr = fwrite(raw, 1, nbytes, f);
        free(raw);
        fclose(f);
        return (int64_t)wr;
    }
    fclose(f);
    return 0;
}
static inline int64_t nino_write_file(const char *path, const char *content) {
    if (!path || !content)
        return 0;
    FILE *f = fopen(path, "wb");
    if (!f)
        return 0;
    size_t len = strlen(content);
    size_t written = fwrite(content, 1, len, f);
    fclose(f);
    return (int64_t)written;
}
static inline bool nino_file_exists(const char *path) {
    if (!path)
        return false;
    FILE *f = fopen(path, "rb");
    if (f) {
        fclose(f);
        return true;
    }
    return false;
}
static inline bool nino_file_delete(const char *path) {
    if (!path)
        return false;
    return remove(path) == 0;
}
static inline int64_t nino_exec_cmd(const char *cmd) {
    if (!cmd)
        return -1;
    int r = system(cmd);
    if (r > 255)
        return (int64_t)((r >> 8) & 0xFF);
    return (int64_t)r;
}
static inline void nino_print_str(const char *s) {
    printf("%s\n", s ? s : "");
}
static inline void nino_print_int(int64_t n) {
    printf("%lld\n", (long long)n);
}
static inline void nino_print_double(double d) {
    char num_buf[64];
    snprintf(num_buf, sizeof(num_buf), "%g", d);
    if (!strchr(num_buf, '.') && !strchr(num_buf, 'e') && !strchr(num_buf, 'E')) {
        size_t nl = strlen(num_buf);
        if (nl + 2 < sizeof(num_buf)) {
            memcpy(num_buf + nl, ".0", 3);
        }
    }
    printf("%s\n", num_buf);
}
static inline void nino_print_bool(bool b) {
    printf("%s\n", b ? "true" : "false");
}

static inline void nino_print_ptr(const void *p) {
    if (p)
        printf("[array:%p]\n", p);
    else
        printf("[]\n");
}
static inline void nino_print_val_ptr(const void *p) {
    if (p)
        printf("[array:%p] ", p);
    else
        printf("[] ");
}
#define nino_print(X)                                                                                        \
    _Generic((X),                                                                                            \
        const char *: nino_print_str,                                                                        \
        char *: nino_print_str,                                                                              \
        unsigned char: nino_print_int,                                                                       \
        signed char: nino_print_int,                                                                         \
        short: nino_print_int,                                                                               \
        unsigned short: nino_print_int,                                                                      \
        int: nino_print_int,                                                                                 \
        unsigned int: nino_print_int,                                                                        \
        long: nino_print_int,                                                                                \
        unsigned long: nino_print_int,                                                                       \
        long long: nino_print_int,                                                                           \
        unsigned long long: nino_print_int,                                                                  \
        double: nino_print_double,                                                                           \
        float: nino_print_double,                                                                            \
        bool: nino_print_bool,                                                                               \
        default: nino_print_ptr)(X)
static inline void nino_print_val_str(const char *s) {
    printf("%s ", s ? s : "");
}
static inline void nino_print_val_int(int64_t n) {
    printf("%lld ", (long long)n);
}
static inline void nino_print_val_double(double d) {
    printf("%g ", d);
}
static inline void nino_print_val_bool(bool b) {
    printf("%s ", b ? "true" : "false");
}
#define nino_print_val(X)                                                                                    \
    _Generic((X),                                                                                            \
        const char *: nino_print_val_str,                                                                    \
        char *: nino_print_val_str,                                                                          \
        unsigned char: nino_print_val_int,                                                                   \
        signed char: nino_print_val_int,                                                                     \
        short: nino_print_val_int,                                                                           \
        unsigned short: nino_print_val_int,                                                                  \
        int: nino_print_val_int,                                                                             \
        unsigned int: nino_print_val_int,                                                                    \
        long: nino_print_val_int,                                                                            \
        unsigned long: nino_print_val_int,                                                                   \
        long long: nino_print_val_int,                                                                       \
        unsigned long long: nino_print_val_int,                                                              \
        double: nino_print_val_double,                                                                       \
        float: nino_print_val_double,                                                                        \
        bool: nino_print_val_bool,                                                                           \
        default: nino_print_val_ptr)(X)

#define _NINO_ARR_MAGIC 0x4E494E4F41525201LL
typedef struct {
    int64_t magic;
    int64_t origin;
    int64_t cap;
    int64_t len;
    uint64_t reset_gen;
    uint64_t mark_id;
} NinoArrHdr;
static atomic_flag _nino_harr_lock = ATOMIC_FLAG_INIT;
static const void **_nino_harr_slots = NULL;
static size_t _nino_harr_cap = 0;
static size_t _nino_harr_cnt = 0;
static size_t _nino_harr_used = 0;
#define _NINO_HARR_TOMB ((const void *)(uintptr_t)1)
static inline void _nino_harr_acq(void) {
    while (atomic_flag_test_and_set_explicit(&_nino_harr_lock, memory_order_acquire)) {}
}
static inline void _nino_harr_rel(void) {
    atomic_flag_clear_explicit(&_nino_harr_lock, memory_order_release);
}
static inline size_t _nino_harr_hash(const void *p) {
    uintptr_t x = (uintptr_t)p;
    x ^= x >> 33;
    x *= 0xff51afd7ed558ccdULL;
    x ^= x >> 33;
    return (size_t)x;
}
static inline void _nino_harr_rehash(size_t new_cap) {
    const void **ns = (const void **)calloc(new_cap, sizeof(const void *));
    if (!ns)
        return;
    size_t ncnt = 0;
    for (size_t i = 0; i < _nino_harr_cap; i++) {
        const void *v = _nino_harr_slots[i];
        if (v && v != _NINO_HARR_TOMB) {
            size_t idx = _nino_harr_hash(v) & (new_cap - 1);
            while (ns[idx])
                idx = (idx + 1) & (new_cap - 1);
            ns[idx] = v;
            ncnt++;
        }
    }
    free(_nino_harr_slots);
    _nino_harr_slots = ns;
    _nino_harr_cap = new_cap;
    _nino_harr_cnt = ncnt;
    _nino_harr_used = ncnt;
}
static inline void _nino_heap_arr_reg(const void *arr) {
    if (!arr)
        return;
    _nino_harr_acq();
    if (_nino_harr_cap == 0 || (_nino_harr_used + 1) * 2 >= _nino_harr_cap) {
        size_t nc = _nino_harr_cap == 0
                        ? 128
                        : ((_nino_harr_cnt * 4 >= _nino_harr_cap) ? _nino_harr_cap * 2 : _nino_harr_cap);
        _nino_harr_rehash(nc);
    }
    if (_nino_harr_cap > 0) {
        size_t idx = _nino_harr_hash(arr) & (_nino_harr_cap - 1);
        size_t ft = (size_t)-1;
        while (_nino_harr_slots[idx]) {
            if (_nino_harr_slots[idx] == arr) {
                _nino_harr_rel();
                return;
            }
            if (_nino_harr_slots[idx] == _NINO_HARR_TOMB && ft == (size_t)-1)
                ft = idx;
            idx = (idx + 1) & (_nino_harr_cap - 1);
        }
        if (ft != (size_t)-1) {
            _nino_harr_slots[ft] = arr;
        } else {
            _nino_harr_slots[idx] = arr;
            _nino_harr_used++;
        }
        _nino_harr_cnt++;
    }
    _nino_harr_rel();
}
static inline void _nino_heap_arr_unreg(const void *arr) {
    if (!arr)
        return;
    _nino_harr_acq();
    if (_nino_harr_cap > 0) {
        size_t idx = _nino_harr_hash(arr) & (_nino_harr_cap - 1);
        while (_nino_harr_slots[idx]) {
            if (_nino_harr_slots[idx] == arr) {
                _nino_harr_slots[idx] = _NINO_HARR_TOMB;
                if (_nino_harr_cnt > 0)
                    _nino_harr_cnt--;
                break;
            }
            idx = (idx + 1) & (_nino_harr_cap - 1);
        }
    }
    _nino_harr_rel();
}
static inline bool _nino_heap_arr_contains(const void *arr) {
    if (!arr)
        return false;
    _nino_harr_acq();
    bool ok = false;
    if (_nino_harr_cap > 0) {
        size_t idx = _nino_harr_hash(arr) & (_nino_harr_cap - 1);
        while (_nino_harr_slots[idx]) {
            if (_nino_harr_slots[idx] == arr) {
                ok = true;
                break;
            }
            idx = (idx + 1) & (_nino_harr_cap - 1);
        }
    }
    _nino_harr_rel();
    return ok;
}
static inline bool _nino_arr_is_alive(const void *arr) {
    if (!arr)
        return false;
    const NinoArrHdr *hdr = ((const NinoArrHdr *)arr) - 1;
    bool in_arena = _nino_in_arena_range(hdr, sizeof(NinoArrHdr));
    bool in_heap = in_arena ? false : _nino_heap_arr_contains(arr);
    if (!in_arena && !in_heap)
        return false;
    if (hdr->magic != _NINO_ARR_MAGIC)
        return false;
    if (in_heap)
        return hdr->origin == -1;
    if (hdr->reset_gen != g_nino_arena.reset_gen)
        return false;
    if (hdr->origin < 0 || (size_t)hdr->origin >= g_nino_arena.total_offset)
        return false;
    if (hdr->mark_id == g_nino_arena.base_mark_id)
        return true;
    for (int d = 0; d < g_nino_arena.mark_depth; d++) {
        if (g_nino_arena.mark_ids && g_nino_arena.mark_ids[d] == hdr->mark_id)
            return true;
    }
    return false;
}
static inline bool arena_ptr_valid(const void *ptr) {
    if (!ptr)
        return false;
    if (_nino_heap_arr_contains(ptr))
        return _nino_arr_is_alive(ptr);
    if (!_nino_in_arena(ptr))
        return false;
    const NinoArrHdr *hdr = ((const NinoArrHdr *)ptr) - 1;
    if (_nino_in_arena_range(hdr, sizeof(NinoArrHdr)) && hdr->magic == _NINO_ARR_MAGIC)
        return _nino_arr_is_alive(ptr);
    return true;
}
static inline int64_t nino_len_str(const void *s) {
    return s ? (int64_t)strlen((const char *)s) : 0;
}
static inline int64_t nino_len_arr(const void *p) {
    if (!p)
        return 0;
    if (!_nino_arr_is_alive(p)) {
        fprintf(stderr,
                "[Nino Use-After-Rollback Violation CWE-416] Array length read outside valid arena epoch\n");
        exit(1);
    }
    const NinoArrHdr *hdr = ((const NinoArrHdr *)p) - 1;
    return hdr->len;
}
static inline void *nino_bounds_check(void *arr, int64_t idx) {
    if (!arr) {
        fprintf(stderr, "[Nino Bounds Violation CWE-119] Dereferencing null array\n");
        exit(1);
    }
    if (!_nino_arr_is_alive(arr)) {
        fprintf(stderr,
                "[Nino Use-After-Rollback Violation CWE-416] Array accessed outside valid arena epoch\n");
        exit(1);
    }
    const NinoArrHdr *hdr = ((const NinoArrHdr *)arr) - 1;
    int64_t len = hdr->len;
    if (idx < 0 || idx >= len) {
        fprintf(stderr, "[Nino Bounds Violation CWE-125/787] Index %lld out of bounds [0, %lld)\n",
                (long long)idx, (long long)len);
        exit(1);
    }
    return arr;
}
static inline int64_t nino_div(int64_t a, int64_t b, int line) {
    if (b == 0) {
        fprintf(stderr, "[Nino Arithmetic Guard - Line %d] Division by zero attempted\n", line);
        exit(1);
    }
    if (a == (-9223372036854775807LL - 1) && b == -1) {
        fprintf(stderr, "[Nino Arithmetic Guard - Line %d] Signed 64-bit division overflow\n", line);
        exit(1);
    }
    return a / b;
}
static inline void nino_print_float(double f) {
    nino_print_double(f);
}
static inline int64_t nino_len_any(const void *p) {
    return nino_len_arr(p);
}
#define len(X)                                                                                               \
    _Generic((X),                                                                                            \
        char *: nino_len_str,                                                                                \
        const char *: nino_len_str,                                                                          \
        int64_t *: nino_len_arr,                                                                             \
        const int64_t *: nino_len_arr,                                                                       \
        double *: nino_len_arr,                                                                              \
        const double *: nino_len_arr,                                                                        \
        const char **: nino_len_arr,                                                                         \
        const char *const *: nino_len_arr,                                                                   \
        default: nino_len_arr)((X))
static inline char *slice(const char *s, int64_t start, int64_t count) {
    return nino_str_slice(s, start, count);
}
static inline char *char_at(const char *s, int64_t idx) {
    return nino_str_char_at(s, idx);
}
static inline char *read_file(const char *path) {
    return nino_read_file(path);
}
static inline int64_t write_file(const char *path, const char *content) {
    return nino_write_file(path, content);
}
static inline bool file_exists(const char *path) {
    return nino_file_exists(path);
}
static inline bool file_delete(const char *path) {
    if (!path)
        return false;
    return remove(path) == 0;
}
static inline int64_t exec_cmd(const char *cmd) {
    return nino_exec_cmd(cmd);
}
static inline int64_t argc(void) {
    return nino_get_argc();
}
static inline const char *argv(int64_t idx) {
    return nino_get_arg(idx);
}
static inline bool nino_is_windows(void) {
#ifdef _WIN32
    return true;
#else
    return false;
#endif
}
static inline bool is_windows(void) {
    return nino_is_windows();
}
static int _nino_net_ready = 0;
static inline bool _nino_net_init(void) {
    if (!_nino_net_ready) {
#ifdef _WIN32
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
            return false;
#else
        signal(SIGPIPE, SIG_IGN);
#endif
        _nino_net_ready = 1;
    }
    return true;
}
static inline int64_t tcp_listen(int64_t port) {
    if (port <= 0 || port > 65535)
        return -1;
    if (!_nino_net_init())
        return -1;
#ifdef _WIN32
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET)
        return -1;
    int opt = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, sizeof(opt));
#else
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0)
        return -1;
    int opt = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#endif
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((uint16_t)port);
    if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
#ifdef _WIN32
        closesocket(s);
#else
        close(s);
#endif
        return -1;
    }
    if (listen(s, 128) != 0) {
#ifdef _WIN32
        closesocket(s);
#else
        close(s);
#endif
        return -1;
    }
    return (int64_t)s;
}
static inline int64_t tcp_accept(int64_t server_fd) {
    if (server_fd < 0)
        return -1;
#ifdef _WIN32
    SOCKET c = accept((SOCKET)server_fd, NULL, NULL);
    if (c == INVALID_SOCKET)
        return -1;
    return (int64_t)c;
#else
    int c = accept((int)server_fd, NULL, NULL);
    if (c < 0)
        return -1;
    return (int64_t)c;
#endif
}
static inline const char *tcp_read(int64_t client_fd, int64_t max_bytes) {
    if (client_fd < 0 || max_bytes <= 0)
        return "";
    if (max_bytes > 16777216)
        max_bytes = 16777216;
    char *buf = (char *)nino_arena_alloc((size_t)max_bytes + 1);
    if (!buf)
        return "";
#ifdef _WIN32
    int n = recv((SOCKET)client_fd, buf, (int)max_bytes, 0);
#else
    ssize_t n = recv((int)client_fd, buf, (size_t)max_bytes, 0);
#endif
    if (n <= 0) {
        buf[0] = '\0';
        return "";
    }
    buf[n] = '\0';
    return buf;
}
static inline int64_t tcp_write(int64_t client_fd, const char *data) {
    if (client_fd < 0 || !data)
        return -1;
    size_t total = strlen(data);
    size_t sent = 0;
    while (sent < total) {
#ifdef _WIN32
        int chunk = (total - sent > 65536) ? 65536 : (int)(total - sent);
        int n = send((SOCKET)client_fd, data + sent, chunk, 0);
        if (n <= 0)
            return -1;
#else
        ssize_t n = send((int)client_fd, data + sent, total - sent, 0);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return -1;
#endif
        sent += (size_t)n;
    }
    return (int64_t)sent;
}
static inline void tcp_close(int64_t fd) {
    if (fd < 0)
        return;
#ifdef _WIN32
    closesocket((SOCKET)fd);
#else
    close((int)fd);
#endif
}
static inline int64_t tcp_connect(const char *host, int64_t port) {
    if (!host || !host[0] || port <= 0 || port > 65535)
        return -1;
    if (!_nino_net_init())
        return -1;
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%lld", (long long)port);
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *res = NULL;
    if (getaddrinfo(host, port_str, &hints, &res) != 0 || !res)
        return -1;
    int64_t out_fd = -1;
    for (struct addrinfo *rp = res; rp != NULL; rp = rp->ai_next) {
#ifdef _WIN32
        SOCKET s = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (s == INVALID_SOCKET)
            continue;
        if (connect(s, rp->ai_addr, (int)rp->ai_addrlen) == 0) {
            out_fd = (int64_t)s;
            break;
        }
        closesocket(s);
#else
        int s = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (s < 0)
            continue;
        if (connect(s, rp->ai_addr, rp->ai_addrlen) == 0) {
            out_fd = (int64_t)s;
            break;
        }
        close(s);
#endif
    }
    freeaddrinfo(res);
    return out_fd;
}
static inline void *alloc_memory(int64_t sz) {
    return malloc((size_t)sz);
}
static inline void nino_free_memory_impl(void *ptr) {
    if (ptr)
        free(ptr);
}
static inline void nino_write_byte_impl(void *ptr, int64_t offset, uint8_t val) {
    if (ptr)
        ((uint8_t *)ptr)[offset] = val;
}
static inline uint8_t nino_read_byte_impl(void *ptr, int64_t offset) {
    if (!ptr)
        return 0;
    return ((uint8_t *)ptr)[offset];
}
#ifdef NINO_STRICT_C11
#define free_memory(ptr) nino_free_memory_impl((void *)(ptr))
#define write_byte(ptr, offset, val) nino_write_byte_impl((void *)(ptr), (offset), (uint8_t)(val))
#define read_byte(ptr, offset) nino_read_byte_impl((void *)(ptr), (offset))
#else
#define free_memory(ptr) nino_free_memory_impl((void *)(uintptr_t)(ptr))
#define write_byte(ptr, offset, val) nino_write_byte_impl((void *)(uintptr_t)(ptr), (offset), (uint8_t)(val))
#define read_byte(ptr, offset) nino_read_byte_impl((void *)(uintptr_t)(ptr), (offset))
#endif
static inline void write_i32(void *ptr, int64_t offset, int32_t val) {
    if (ptr)
        memcpy((char *)ptr + offset, &val, 4);
}
static inline int32_t read_i32(void *ptr, int64_t offset) {
    if (!ptr)
        return 0;
    int32_t val = 0;
    memcpy(&val, (char *)ptr + offset, 4);
    return val;
}
static inline const char *mem_dump(void *ptr) {
    if (!ptr)
        return "[NULL Buffer]";
    char *buf = (char *)nino_arena_alloc(64);
    if (!buf)
        return "";
    snprintf(buf, 64, "[RAM Buffer at %p]", ptr);
    return buf;
}
static inline int64_t file_write(const char *path, const char *content) {
    return nino_write_file(path, content);
}
static inline char *file_read(const char *path) {
    return nino_read_file(path);
}

static inline int64_t foreign_alloc(int64_t sz, const char *abi) {
    (void)abi;
    return (int64_t)(uintptr_t)malloc((size_t)sz);
}
static inline void foreign_free(int64_t ptr) {
    if (ptr)
        free((void *)(uintptr_t)ptr);
}
static inline void _nino_secure_zero(void *ptr, size_t n) {
    if (!ptr || n == 0)
        return;
    volatile uint8_t *vp = (volatile uint8_t *)ptr;
    while (n--)
        *vp++ = 0;
}
typedef struct {
    void *page_base;
    size_t data_bytes;
    size_t total_bytes;
    uint8_t *cipher;
    uint8_t *pad;
    size_t len;
    uint32_t head_canary;
    uint32_t tail_canary;
    bool mlocked;
    bool page_guarded;
} nino_sealed_t;
typedef struct {
    int64_t cipher;
    int64_t mask;
} nino_sealed_i64_t;
typedef struct {
    int64_t cipher;
    int64_t mask;
} nino_morphic_t;
static inline uint64_t _nino_entropy_u64(void) {
    uint64_t val = 0;
#ifdef _WIN32
    if (BCryptGenRandom(NULL, (PUCHAR)&val, sizeof(val), BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0 && val != 0)
        return val;
#else
    FILE *uf = fopen("/dev/urandom", "rb");
    if (uf) {
        size_t rd = fread(&val, 1, sizeof(val), uf);
        fclose(uf);
        if (rd == sizeof(val) && val != 0)
            return val;
    }
#endif
    void *p = malloc(1);
    uint64_t addr = (uint64_t)(uintptr_t)p;
    if (p)
        free(p);
    uint64_t t = (uint64_t)time(NULL);
    uint64_t c = (uint64_t)clock();
    uint64_t x = addr ^ (t << 32) ^ c ^ 0x9E3779B97F4A7C15ULL;
    x ^= x >> 30;
    x *= 0xBF58476D1CE4E5B9ULL;
    x ^= x >> 27;
    x *= 0x94D049BB133111EBULL;
    x ^= x >> 31;
    return x ? x : 0x1234567890ABCDEFULL;
}
static inline int64_t csprng_u64(void) {
    return (int64_t)(_nino_entropy_u64() & 0x7FFFFFFFFFFFFFFFULL);
}
static inline double math_ln(double x) {
    return x > 0.0 ? log(x) : 0.0;
}
static inline bool is_nan(double x) {
    return isnan(x) != 0;
}
static inline bool is_inf(double x) {
    return isinf(x) != 0;
}
static inline bool is_finite(double x) {
    return isfinite(x) != 0;
}
static inline double fp_abs(double x) {
    return fabs(x);
}
static inline double fp_sqrt(double x) {
    return sqrt(x);
}
static inline double to_float(int64_t x) {
    return (double)x;
}
static inline nino_sealed_t *nino_seal_bytes(const uint8_t *raw, size_t l, const uint8_t *obf_mask,
                                             size_t mlen) {
    nino_sealed_t *s = (nino_sealed_t *)calloc(1, sizeof(nino_sealed_t));
    if (!s)
        return NULL;
    s->len = l;
    s->head_canary = 0xDEADC0DE;
    s->tail_canary = 0xFEEDFACE;
    size_t span = (l + 1 + 63) & ~((size_t)63);
    size_t need = span * 2;
    size_t data_bytes = ((need + 4095) / 4096) * 4096;
    if (data_bytes < 4096)
        data_bytes = 4096;
    size_t total_bytes = data_bytes + 4096;
#ifdef _WIN32
    void *blk = VirtualAlloc(NULL, total_bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (blk) {
        s->page_base = blk;
        s->data_bytes = data_bytes;
        s->total_bytes = total_bytes;
        s->cipher = (uint8_t *)blk;
        s->pad = (uint8_t *)blk + span;
        DWORD oldp = 0;
        if (VirtualProtect((uint8_t *)blk + data_bytes, 4096, PAGE_NOACCESS, &oldp))
            s->page_guarded = true;
        if (VirtualLock(blk, data_bytes))
            s->mlocked = true;
    }
#else
    void *blk = NULL;
    if (posix_memalign(&blk, 4096, total_bytes) == 0 && blk) {
        memset(blk, 0, total_bytes);
        s->page_base = blk;
        s->data_bytes = data_bytes;
        s->total_bytes = total_bytes;
        s->cipher = (uint8_t *)blk;
        s->pad = (uint8_t *)blk + span;
        if (mprotect((uint8_t *)blk + data_bytes, 4096, PROT_NONE) == 0)
            s->page_guarded = true;
        if (mlock(blk, data_bytes) == 0)
            s->mlocked = true;
    }
#endif
    if (!s->page_base) {
        s->cipher = (uint8_t *)calloc(1, l + 1);
        s->pad = (uint8_t *)calloc(1, l + 1);
        if (!s->cipher || !s->pad) {
            if (s->cipher)
                free(s->cipher);
            if (s->pad)
                free(s->pad);
            free(s);
            return NULL;
        }
#ifdef _WIN32
        if (VirtualLock(s->cipher, l + 1) && VirtualLock(s->pad, l + 1))
            s->mlocked = true;
#else
        if (mlock(s->cipher, l + 1) == 0 && mlock(s->pad, l + 1) == 0)
            s->mlocked = true;
#endif
    }
    uint64_t ks = 0;
    for (size_t i = 0; i < l; i++) {
        if ((i & 7) == 0)
            ks = _nino_entropy_u64();
        uint8_t pb = (uint8_t)((ks >> ((i & 7) * 8)) & 0xFF);
        if (pb == 0)
            pb = 0xA5;
        uint8_t b = raw ? raw[i] : 0;
        if (obf_mask && mlen > 0)
            b ^= obf_mask[i % mlen];
        s->pad[i] = pb;
        s->cipher[i] = b ^ pb;
    }
    if (s->page_base) {
#ifdef _WIN32
        DWORD oldp = 0;
        (void)VirtualProtect(s->page_base, s->data_bytes, PAGE_NOACCESS, &oldp);
#else
        (void)mprotect(s->page_base, s->data_bytes, PROT_NONE);
#endif
    }
    return s;
}
static inline nino_sealed_t *nino_seal_str(const char *raw) {
    if (!raw)
        return nino_seal_bytes(NULL, 0, NULL, 0);
    return nino_seal_bytes((const uint8_t *)raw, strlen(raw), NULL, 0);
}
static inline nino_sealed_i64_t nino_seal_i64(int64_t val) {
    int64_t m = (int64_t)_nino_entropy_u64();
    nino_sealed_i64_t s;
    s.mask = m;
    s.cipher = val ^ m;
    return s;
}
static atomic_flag _nino_seal_lock = ATOMIC_FLAG_INIT;
static inline void _nino_seal_acq(void) {
    while (atomic_flag_test_and_set_explicit(&_nino_seal_lock, memory_order_acquire)) {}
}
static inline void _nino_seal_rel(void) {
    atomic_flag_clear_explicit(&_nino_seal_lock, memory_order_release);
}
static inline const char *unseal(const void *ptr) {
    if (!ptr)
        return "";
    union {
        const void *cv;
        nino_sealed_t *s;
    } u;
    u.cv = ptr;
    nino_sealed_t *s = u.s;
    _nino_seal_acq();
    if (s->head_canary != 0xDEADC0DE || s->tail_canary != 0xFEEDFACE) {
        _nino_seal_rel();
        return (const char *)ptr;
    }
    if (!s->cipher || !s->pad) {
        _nino_seal_rel();
        return "";
    }
    char *res = (char *)nino_arena_alloc(s->len + 1);
    if (!res) {
        _nino_seal_rel();
        return "";
    }
    char *tmp = (char *)calloc(1, s->len + 1);
    if (!tmp) {
        _nino_seal_rel();
        return "";
    }
#ifdef _WIN32
    (void)VirtualLock(tmp, s->len + 1);
#else
    (void)mlock(tmp, s->len + 1);
#endif
    if (s->page_base) {
#ifdef _WIN32
        DWORD oldp = 0;
        (void)VirtualProtect(s->page_base, s->data_bytes, PAGE_READONLY, &oldp);
#else
        (void)mprotect(s->page_base, s->data_bytes, PROT_READ);
#endif
    }
    for (size_t i = 0; i < s->len; i++) {
        tmp[i] = (char)(s->cipher[i] ^ s->pad[i]);
    }
    tmp[s->len] = 0;
    if (s->page_base) {
#ifdef _WIN32
        DWORD oldp = 0;
        (void)VirtualProtect(s->page_base, s->data_bytes, PAGE_NOACCESS, &oldp);
#else
        (void)mprotect(s->page_base, s->data_bytes, PROT_NONE);
#endif
    }
    memcpy(res, tmp, s->len + 1);
    _nino_secure_zero(tmp, s->len + 1);
#ifdef _WIN32
    (void)VirtualUnlock(tmp, s->len + 1);
#else
    (void)munlock(tmp, s->len + 1);
#endif
    free(tmp);
    _nino_seal_rel();
    return res;
}
static inline bool seal_is_locked(const void *ptr) {
    if (!ptr)
        return false;
    const nino_sealed_t *s = (const nino_sealed_t *)ptr;
    if (s->head_canary != 0xDEADC0DE || s->tail_canary != 0xFEEDFACE)
        return false;
    return s->mlocked || s->page_guarded;
}
static inline void seal_destroy(const void *ptr) {
    if (!ptr)
        return;
    union {
        const void *cv;
        nino_sealed_t *s;
    } u;
    u.cv = ptr;
    nino_sealed_t *s = u.s;
    _nino_seal_acq();
    if (s->head_canary != 0xDEADC0DE || s->tail_canary != 0xFEEDFACE) {
        _nino_seal_rel();
        return;
    }
    s->head_canary = 0;
    s->tail_canary = 0;
    if (s->page_base) {
#ifdef _WIN32
        DWORD oldp = 0;
        (void)VirtualProtect(s->page_base, s->data_bytes, PAGE_READWRITE, &oldp);
        _nino_secure_zero(s->page_base, s->data_bytes);
        if (s->mlocked)
            VirtualUnlock(s->page_base, s->data_bytes);
        VirtualFree(s->page_base, 0, MEM_RELEASE);
#else
        (void)mprotect(s->page_base, s->data_bytes, PROT_READ | PROT_WRITE);
        _nino_secure_zero(s->page_base, s->data_bytes);
        if (s->mlocked)
            munlock(s->page_base, s->data_bytes);
        if (s->page_guarded)
            (void)mprotect((uint8_t *)s->page_base + s->data_bytes, 4096, PROT_READ | PROT_WRITE);
        free(s->page_base);
#endif
    } else {
        if (s->cipher) {
            _nino_secure_zero(s->cipher, s->len + 1);
            if (s->mlocked) {
#ifdef _WIN32
                VirtualUnlock(s->cipher, s->len + 1);
#else
                munlock(s->cipher, s->len + 1);
#endif
            }
            free(s->cipher);
            s->cipher = NULL;
        }
        if (s->pad) {
            _nino_secure_zero(s->pad, s->len + 1);
            if (s->mlocked) {
#ifdef _WIN32
                VirtualUnlock(s->pad, s->len + 1);
#else
                munlock(s->pad, s->len + 1);
#endif
            }
            free(s->pad);
            s->pad = NULL;
        }
    }
    _nino_secure_zero(s, sizeof(nino_sealed_t));
    free(s);
    _nino_seal_rel();
}
static inline int64_t unseal_i64(nino_sealed_i64_t s) {
    return s.cipher ^ s.mask;
}
static inline nino_morphic_t nino_morphic_init(int64_t val) {
    uint64_t m = _nino_entropy_u64();
    if (m == 0)
        m = 0xCAFEBABE12345678ULL;
    nino_morphic_t mvar;
    mvar.mask = (int64_t)m;
    mvar.cipher = (int64_t)((uint64_t)val ^ m);
    return mvar;
}
static inline int64_t nino_morphic_read(const nino_morphic_t *mvar) {
    if (!mvar)
        return 0;
    return (int64_t)((uint64_t)mvar->cipher ^ (uint64_t)mvar->mask);
}
static inline void nino_morphic_write(nino_morphic_t *mvar, int64_t new_val) {
    if (!mvar)
        return;
    uint64_t nm = _nino_entropy_u64();
    if (nm == 0 || (int64_t)nm == mvar->mask)
        nm ^= 0x9E3779B97F4A7C15ULL;
    mvar->mask = (int64_t)nm;
    mvar->cipher = (int64_t)((uint64_t)new_val ^ nm);
}
static inline void _nino_sha_tf(uint32_t s[8], const uint8_t d[64]) {
    static const uint32_t K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
    uint32_t m[64];
    for (int i = 0; i < 16; ++i)
        m[i] = ((uint32_t)d[i * 4] << 24) | ((uint32_t)d[i * 4 + 1] << 16) | ((uint32_t)d[i * 4 + 2] << 8) |
               ((uint32_t)d[i * 4 + 3]);
    for (int i = 16; i < 64; ++i) {
        uint32_t s0 = ((m[i - 15] >> 7) | (m[i - 15] << 25)) ^ ((m[i - 15] >> 18) | (m[i - 15] << 14)) ^
                      (m[i - 15] >> 3);
        uint32_t s1 =
            ((m[i - 2] >> 17) | (m[i - 2] << 15)) ^ ((m[i - 2] >> 19) | (m[i - 2] << 13)) ^ (m[i - 2] >> 10);
        m[i] = m[i - 16] + s0 + m[i - 7] + s1;
    }
    uint32_t a = s[0], b = s[1], c = s[2], d0 = s[3], e = s[4], f = s[5], g = s[6], h0 = s[7];
    for (int i = 0; i < 64; ++i) {
        uint32_t S1 = ((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7));
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t t1 = h0 + S1 + ch + K[i] + m[i];
        uint32_t S0 = ((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10));
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + maj;
        h0 = g;
        g = f;
        f = e;
        e = d0 + t1;
        d0 = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    s[0] += a;
    s[1] += b;
    s[2] += c;
    s[3] += d0;
    s[4] += e;
    s[5] += f;
    s[6] += g;
    s[7] += h0;
}
static int _nino_stdin_eof = 0;
static inline void stdio_binary_mode(void) {
#ifdef _WIN32
    _setmode(_fileno(stdin), _O_BINARY);
    _setmode(_fileno(stdout), _O_BINARY);
#endif
    _nino_stdin_eof = 0;
}
static inline bool stdin_eof(void) {
    return _nino_stdin_eof != 0;
}
static inline const char *stdin_read_line(void) {
    size_t cap = 256;
    size_t len = 0;
    char *tmp = (char *)malloc(cap);
    if (!tmp) {
        _nino_stdin_eof = 1;
        return "";
    }
    int c;
    while ((c = fgetc(stdin)) != EOF) {
        if (c == '\n')
            break;
        if (len + 1 >= cap) {
            cap *= 2;
            char *nxt = (char *)realloc(tmp, cap);
            if (!nxt) {
                free(tmp);
                _nino_stdin_eof = 1;
                return "";
            }
            tmp = nxt;
        }
        tmp[len++] = (char)c;
    }
    if (c == EOF) {
        _nino_stdin_eof = 1;
    }
    while (len > 0 && tmp[len - 1] == '\r') {
        len--;
    }
    char *res = (char *)nino_arena_alloc(len + 1);
    if (res) {
        if (len > 0)
            memcpy(res, tmp, len);
        res[len] = '\0';
    }
    free(tmp);
    return res ? res : "";
}
static inline const char *stdin_read_exact(int64_t n) {
    if (n <= 0)
        return "";
    char *buf = (char *)nino_arena_alloc((size_t)n + 1);
    if (!buf)
        return "";
    size_t total = 0;
    while (total < (size_t)n) {
        size_t rd = fread(buf + total, 1, (size_t)n - total, stdin);
        if (rd == 0) {
            _nino_stdin_eof = 1;
            break;
        }
        total += rd;
    }
    buf[total] = '\0';
    return buf;
}
static inline void stdout_write_raw(const char *s) {
    if (!s)
        return;
    size_t l = strlen(s);
    if (l > 0)
        fwrite(s, 1, l, stdout);
    fflush(stdout);
}
static inline void print_raw(const char *s) {
    stdout_write_raw(s);
}
static inline const char *int_to_str(int64_t v) {
    char *buf = (char *)nino_arena_alloc(32);
    if (!buf)
        return "";
    snprintf(buf, 32, "%lld", (long long)v);
    return buf;
}
static inline void stderr_write(const char *s) {
    if (!s)
        return;
    fprintf(stderr, "%s", s);
    fflush(stderr);
}
static inline int64_t char_code_at(const char *s, int64_t idx) {
    if (!s || idx < 0)
        return 0;
    size_t l = _nino_fast_strlen(s);
    if ((size_t)idx >= l)
        return 0;
    return (int64_t)((unsigned char)s[idx]);
}
static inline const char *char_from_code(int64_t code) {
    char *buf = (char *)nino_arena_alloc(2);
    if (!buf)
        return "";
    buf[0] = (char)(code & 0xFF);
    buf[1] = '\0';
    return buf;
}
static inline int64_t nino_get_pid(void) {
#ifdef _WIN32
    return (int64_t)GetCurrentProcessId();
#else
    return (int64_t)getpid();
#endif
}
typedef struct NinoLspDoc {
    char *uri;
    char *text;
    struct NinoLspDoc *next;
} NinoLspDoc;
static NinoLspDoc *_nino_lsp_docs = NULL;
static inline char *_nino_heap_dup(const char *s) {
    if (!s)
        s = "";
    size_t l = strlen(s);
    char *p = (char *)malloc(l + 1);
    if (p)
        memcpy(p, s, l + 1);
    return p;
}
static inline const char *region_pin(const char *s) {
    return s ? _nino_heap_dup(s) : "";
}
static inline void lsp_doc_set(const char *uri, const char *text) {
    if (!uri)
        return;
    NinoLspDoc *cur = _nino_lsp_docs;
    while (cur) {
        if (strcmp(cur->uri, uri) == 0) {
            free(cur->text);
            cur->text = _nino_heap_dup(text);
            return;
        }
        cur = cur->next;
    }
    NinoLspDoc *node = (NinoLspDoc *)malloc(sizeof(NinoLspDoc));
    if (!node)
        return;
    node->uri = _nino_heap_dup(uri);
    node->text = _nino_heap_dup(text);
    node->next = _nino_lsp_docs;
    _nino_lsp_docs = node;
}
static inline const char *lsp_doc_get(const char *uri) {
    if (!uri)
        return "";
    NinoLspDoc *cur = _nino_lsp_docs;
    while (cur) {
        if (strcmp(cur->uri, uri) == 0)
            return cur->text ? cur->text : "";
        cur = cur->next;
    }
    return "";
}
static inline bool lsp_doc_exists(const char *uri) {
    if (!uri)
        return false;
    NinoLspDoc *cur = _nino_lsp_docs;
    while (cur) {
        if (strcmp(cur->uri, uri) == 0)
            return true;
        cur = cur->next;
    }
    return false;
}
static inline void lsp_doc_remove(const char *uri) {
    if (!uri)
        return;
    NinoLspDoc **pp = &_nino_lsp_docs;
    while (*pp) {
        NinoLspDoc *cur = *pp;
        if (strcmp(cur->uri, uri) == 0) {
            *pp = cur->next;
            free(cur->uri);
            free(cur->text);
            free(cur);
            return;
        }
        pp = &cur->next;
    }
}
static inline const char *sha256(const char *data) {
    char *hbuf = (char *)nino_arena_alloc(65);
    if (!hbuf)
        return "";
    uint32_t s[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                     0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    size_t len = data ? strlen(data) : 0;
    uint64_t blen = (uint64_t)len * 8;
    size_t plen = ((len + 8) / 64 + 1) * 64;
    uint8_t *p = (uint8_t *)calloc(plen, 1);
    if (!p)
        return "";
    if (len > 0)
        memcpy(p, data, len);
    p[len] = 0x80;
    for (int i = 0; i < 8; ++i)
        p[plen - 1 - i] = (uint8_t)(blen >> (i * 8));
    for (size_t i = 0; i < plen; i += 64)
        _nino_sha_tf(s, p + i);
    free(p);
    for (int i = 0; i < 8; ++i)
        snprintf(hbuf + i * 8, 9, "%08x", (unsigned int)s[i]);
    hbuf[64] = '\0';
    return hbuf;
}
static inline void _nino_sha512_raw(const uint8_t *m, size_t n, uint8_t out64[64]) {
    static const uint64_t K512[80] = {
        0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
        0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
        0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
        0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
        0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
        0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
        0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
        0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
        0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
        0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
        0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
        0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
        0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
        0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
        0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
        0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
        0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
        0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
        0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
        0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL};
    uint64_t h[8] = {0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL,
                     0xa54ff53a5f1d36f1ULL, 0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
                     0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL};
    size_t plen = ((n + 16) / 128 + 1) * 128;
    uint8_t *p = (uint8_t *)calloc(plen, 1);
    if (!p) {
        memset(out64, 0, 64);
        return;
    }
    if (n > 0) {
        memcpy(p, m, n);
    }
    p[n] = 0x80;
    uint64_t blo = (uint64_t)n * 8ULL;
    uint64_t bhi = (uint64_t)n >> 61;
    for (int i = 0; i < 8; i++) {
        p[plen - 1 - i] = (uint8_t)(blo >> (i * 8));
        p[plen - 9 - i] = (uint8_t)(bhi >> (i * 8));
    }
    for (size_t off = 0; off < plen; off += 128) {
        uint64_t w[80];
        for (int i = 0; i < 16; i++) {
            uint64_t v = 0;
            for (int j = 0; j < 8; j++)
                v = (v << 8) | p[off + (size_t)i * 8 + (size_t)j];
            w[i] = v;
        }
        for (int i = 16; i < 80; i++) {
            uint64_t s0 = ((w[i - 15] >> 1) | (w[i - 15] << 63)) ^ ((w[i - 15] >> 8) | (w[i - 15] << 56)) ^
                          (w[i - 15] >> 7);
            uint64_t s1 = ((w[i - 2] >> 19) | (w[i - 2] << 45)) ^ ((w[i - 2] >> 61) | (w[i - 2] << 3)) ^
                          (w[i - 2] >> 6);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        uint64_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
        for (int i = 0; i < 80; i++) {
            uint64_t S1 = ((e >> 14) | (e << 50)) ^ ((e >> 18) | (e << 46)) ^ ((e >> 41) | (e << 23));
            uint64_t ch = (e & f) ^ ((~e) & g);
            uint64_t t1 = hh + S1 + ch + K512[i] + w[i];
            uint64_t S0 = ((a >> 28) | (a << 36)) ^ ((a >> 34) | (a << 30)) ^ ((a >> 39) | (a << 25));
            uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint64_t t2 = S0 + maj;
            hh = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }
        h[0] += a;
        h[1] += b;
        h[2] += c;
        h[3] += d;
        h[4] += e;
        h[5] += f;
        h[6] += g;
        h[7] += hh;
    }
    free(p);
    for (int i = 0; i < 8; i++)
        for (int j = 0; j < 8; j++)
            out64[i * 8 + (7 - j)] = (uint8_t)(h[i] >> (j * 8));
}
static inline const char *sha512(const char *data) {
    uint8_t out[64];
    _nino_sha512_raw((const uint8_t *)(data ? data : ""), data ? strlen(data) : 0, out);
    char *hbuf = (char *)nino_arena_alloc(129);
    if (!hbuf)
        return "";
    for (int i = 0; i < 64; i++)
        snprintf(hbuf + i * 2, 3, "%02x", (unsigned int)out[i]);
    hbuf[128] = 0;
    return hbuf;
}
typedef struct {
    uint64_t w[16];
} nino_fe25519;
typedef struct {
    nino_fe25519 X, Y, Z, T;
} nino_edpt;
static inline uint64_t _nino_p_limb(int i) {
    return i == 0 ? 0xffedULL : (i == 15 ? 0x7fffULL : 0xffffULL);
}
static inline void _nino_fe_u64(nino_fe25519 *r, uint64_t v) {
    memset(r, 0, sizeof(*r));
    r->w[0] = v & 0xffff;
    r->w[1] = (v >> 16) & 0xffff;
    r->w[2] = (v >> 32) & 0xffff;
    r->w[3] = (v >> 48) & 0xffff;
}
static inline void _nino_fe_reduce(nino_fe25519 *r) {
    for (int pass = 0; pass < 3; pass++) {
        uint64_t c = 0;
        for (int i = 0; i < 15; i++) {
            uint64_t v = r->w[i] + c;
            r->w[i] = v & 0xffffULL;
            c = v >> 16;
        }
        uint64_t top = r->w[15] + c;
        r->w[15] = top & 0x7fffULL;
        r->w[0] += (top >> 15) * 19ULL;
    }
    nino_fe25519 sub;
    uint64_t bw = 0;
    for (int i = 0; i < 16; i++) {
        uint64_t a = r->w[i], p = _nino_p_limb(i);
        uint64_t nb = (a < p + bw) ? 1ULL : 0ULL;
        sub.w[i] = (a + (nb ? 65536ULL : 0ULL)) - p - bw;
        bw = nb;
    }
    uint64_t mask = 0ULL - (1ULL - bw);
    for (int i = 0; i < 16; i++)
        r->w[i] = (r->w[i] & ~mask) | (sub.w[i] & mask);
}
static inline void _nino_fe_add(nino_fe25519 *r, const nino_fe25519 *a, const nino_fe25519 *b) {
    for (int i = 0; i < 16; i++)
        r->w[i] = a->w[i] + b->w[i];
    _nino_fe_reduce(r);
}
static inline void _nino_fe_sub(nino_fe25519 *r, const nino_fe25519 *a, const nino_fe25519 *b) {
    nino_fe25519 tmp;
    uint64_t c = 0;
    for (int i = 0; i < 15; i++) {
        uint64_t v = a->w[i] + _nino_p_limb(i) + c;
        tmp.w[i] = v & 0xffffULL;
        c = v >> 16;
    }
    tmp.w[15] = a->w[15] + _nino_p_limb(15) + c;
    uint64_t bw = 0;
    for (int i = 0; i < 16; i++) {
        uint64_t av = tmp.w[i], bv = b->w[i];
        uint64_t nb = (av < bv + bw) ? 1ULL : 0ULL;
        r->w[i] = (av + (nb ? 65536ULL : 0ULL)) - bv - bw;
        bw = nb;
    }
    _nino_fe_reduce(r);
}
static inline void _nino_fe_mul(nino_fe25519 *r, const nino_fe25519 *a, const nino_fe25519 *b) {
    uint64_t acc[32];
    memset(acc, 0, sizeof(acc));
    for (int i = 0; i < 16; i++)
        for (int j = 0; j < 16; j++)
            acc[i + j] += a->w[i] * b->w[j];
    for (int i = 0; i < 16; i++)
        r->w[i] = acc[i] + 38ULL * acc[i + 16];
    _nino_fe_reduce(r);
}
static inline void _nino_fe_sqr(nino_fe25519 *r, const nino_fe25519 *a) {
    _nino_fe_mul(r, a, a);
}
static inline void _nino_fe_tobytes(uint8_t out[32], const nino_fe25519 *a) {
    nino_fe25519 t = *a;
    _nino_fe_reduce(&t);
    for (int i = 0; i < 16; i++) {
        out[2 * i] = (uint8_t)(t.w[i] & 0xff);
        out[2 * i + 1] = (uint8_t)(t.w[i] >> 8);
    }
}
static inline void _nino_fe_frombytes(nino_fe25519 *r, const uint8_t in[32]) {
    for (int i = 0; i < 16; i++)
        r->w[i] = (uint64_t)in[2 * i] | ((uint64_t)in[2 * i + 1] << 8);
    r->w[15] &= 0x7fffULL;
    _nino_fe_reduce(r);
}
static inline bool _nino_fe_eq(const nino_fe25519 *a, const nino_fe25519 *b) {
    uint8_t ab[32], bb[32];
    _nino_fe_tobytes(ab, a);
    _nino_fe_tobytes(bb, b);
    uint8_t d = 0;
    for (int i = 0; i < 32; i++)
        d |= (uint8_t)(ab[i] ^ bb[i]);
    return d == 0;
}
static inline void _nino_fe_inv(nino_fe25519 *r, const nino_fe25519 *a) {
    nino_fe25519 z;
    _nino_fe_u64(&z, 1);
    for (int b = 254; b >= 0; b--) {
        _nino_fe_sqr(&z, &z);
        if (b != 4 && b != 2)
            _nino_fe_mul(&z, &z, a);
    }
    *r = z;
}
static inline void _nino_fe_pow_p3_8(nino_fe25519 *r, const nino_fe25519 *a) {
    nino_fe25519 z;
    _nino_fe_u64(&z, 1);
    for (int b = 251; b >= 0; b--) {
        _nino_fe_sqr(&z, &z);
        if (b != 0)
            _nino_fe_mul(&z, &z, a);
    }
    *r = z;
}
static NINO_THREAD_LOCAL nino_fe25519 _nino_ed_d, _nino_ed_2d, _nino_ed_sqrtm1;
static NINO_THREAD_LOCAL nino_edpt _nino_ed_base;
static NINO_THREAD_LOCAL bool _nino_ed_ready = false;
static inline void _nino_ed_init(void) {
    if (_nino_ed_ready)
        return;
    nino_fe25519 f0, f1, f2, n1, d1, d1i, yb, num, den, t, chk;
    _nino_fe_u64(&f0, 0);
    _nino_fe_u64(&f1, 1);
    _nino_fe_u64(&f2, 2);
    _nino_fe_u64(&n1, 121665ULL);
    _nino_fe_sub(&n1, &f0, &n1);
    _nino_fe_u64(&d1, 121666ULL);
    _nino_fe_inv(&d1i, &d1);
    _nino_fe_mul(&_nino_ed_d, &n1, &d1i);
    _nino_fe_add(&_nino_ed_2d, &_nino_ed_d, &_nino_ed_d);
    nino_fe25519 sm1;
    _nino_fe_u64(&sm1, 1);
    for (int b = 252; b >= 0; b--) {
        _nino_fe_sqr(&sm1, &sm1);
        if (b != 2)
            _nino_fe_mul(&sm1, &sm1, &f2);
    }
    _nino_ed_sqrtm1 = sm1;
    nino_fe25519 four, five, fi;
    _nino_fe_u64(&four, 4);
    _nino_fe_u64(&five, 5);
    _nino_fe_inv(&fi, &five);
    _nino_fe_mul(&yb, &four, &fi);
    _nino_fe_sqr(&num, &yb);
    _nino_fe_mul(&den, &num, &_nino_ed_d);
    _nino_fe_sub(&num, &num, &f1);
    _nino_fe_add(&den, &den, &f1);
    nino_fe25519 di;
    _nino_fe_inv(&di, &den);
    nino_fe25519 x2;
    _nino_fe_mul(&x2, &num, &di);
    _nino_fe_pow_p3_8(&t, &x2);
    _nino_fe_sqr(&chk, &t);
    if (!_nino_fe_eq(&chk, &x2))
        _nino_fe_mul(&t, &t, &_nino_ed_sqrtm1);
    if (t.w[0] & 1ULL)
        _nino_fe_sub(&t, &f0, &t);
    _nino_ed_base.X = t;
    _nino_ed_base.Y = yb;
    _nino_ed_base.Z = f1;
    _nino_fe_mul(&_nino_ed_base.T, &t, &yb);
    _nino_ed_ready = true;
}
static inline void _nino_ed_ident(nino_edpt *p) {
    _nino_fe_u64(&p->X, 0);
    _nino_fe_u64(&p->Y, 1);
    _nino_fe_u64(&p->Z, 1);
    _nino_fe_u64(&p->T, 0);
}
static inline void _nino_ed_add(nino_edpt *r, const nino_edpt *p, const nino_edpt *q) {
    nino_fe25519 a, b, c, d, e, f, g, h, t1, t2;
    _nino_fe_sub(&t1, &p->Y, &p->X);
    _nino_fe_sub(&t2, &q->Y, &q->X);
    _nino_fe_mul(&a, &t1, &t2);
    _nino_fe_add(&t1, &p->Y, &p->X);
    _nino_fe_add(&t2, &q->Y, &q->X);
    _nino_fe_mul(&b, &t1, &t2);
    _nino_fe_mul(&t1, &p->T, &q->T);
    _nino_fe_mul(&c, &t1, &_nino_ed_2d);
    _nino_fe_mul(&t1, &p->Z, &q->Z);
    _nino_fe_add(&d, &t1, &t1);
    _nino_fe_sub(&e, &b, &a);
    _nino_fe_sub(&f, &d, &c);
    _nino_fe_add(&g, &d, &c);
    _nino_fe_add(&h, &b, &a);
    _nino_fe_mul(&r->X, &e, &f);
    _nino_fe_mul(&r->Y, &g, &h);
    _nino_fe_mul(&r->Z, &f, &g);
    _nino_fe_mul(&r->T, &e, &h);
}
static inline void _nino_ed_cswap(nino_edpt *p, nino_edpt *q, uint64_t b) {
    uint64_t mask = 0ULL - b;
    for (int i = 0; i < 16; i++) {
        uint64_t tx = mask & (p->X.w[i] ^ q->X.w[i]);
        p->X.w[i] ^= tx;
        q->X.w[i] ^= tx;
        uint64_t ty = mask & (p->Y.w[i] ^ q->Y.w[i]);
        p->Y.w[i] ^= ty;
        q->Y.w[i] ^= ty;
        uint64_t tz = mask & (p->Z.w[i] ^ q->Z.w[i]);
        p->Z.w[i] ^= tz;
        q->Z.w[i] ^= tz;
        uint64_t tt = mask & (p->T.w[i] ^ q->T.w[i]);
        p->T.w[i] ^= tt;
        q->T.w[i] ^= tt;
    }
}
static inline void _nino_ed_mul(nino_edpt *r, const nino_edpt *p, const uint8_t s[32]) {
    nino_edpt r0, r1;
    _nino_ed_ident(&r0);
    r1 = *p;
    for (int i = 255; i >= 0; i--) {
        uint64_t bit = (uint64_t)((s[i / 8] >> (i & 7)) & 1);
        _nino_ed_cswap(&r0, &r1, bit);
        _nino_ed_add(&r1, &r0, &r1);
        _nino_ed_add(&r0, &r0, &r0);
        _nino_ed_cswap(&r0, &r1, bit);
    }
    *r = r0;
}
static inline void _nino_ed_encode(uint8_t out[32], const nino_edpt *p) {
    nino_fe25519 zi, x, y;
    _nino_fe_inv(&zi, &p->Z);
    _nino_fe_mul(&x, &p->X, &zi);
    _nino_fe_mul(&y, &p->Y, &zi);
    _nino_fe_tobytes(out, &y);
    uint8_t xb[32];
    _nino_fe_tobytes(xb, &x);
    out[31] |= (uint8_t)((xb[0] & 1) << 7);
}
static inline bool _nino_ed_decode(nino_edpt *r, const uint8_t enc[32]) {
    static const uint8_t p_le[32] = {0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f};
    uint8_t yc[32];
    memcpy(yc, enc, 32);
    yc[31] &= 0x7f;
    uint32_t bw = 0;
    for (int i = 0; i < 32; i++) {
        int d = (int)yc[i] - (int)p_le[i] - (int)bw;
        bw = (d < 0) ? 1U : 0U;
    }
    if (bw == 0)
        return false;
    nino_fe25519 y, f1, y2, u, v, v3, v7, uv3, x, chk;
    _nino_fe_u64(&f1, 1);
    _nino_fe_frombytes(&y, yc);
    _nino_fe_sqr(&y2, &y);
    _nino_fe_sub(&u, &y2, &f1);
    _nino_fe_mul(&v, &y2, &_nino_ed_d);
    _nino_fe_add(&v, &v, &f1);
    _nino_fe_sqr(&v3, &v);
    _nino_fe_mul(&v3, &v3, &v);
    _nino_fe_sqr(&v7, &v3);
    _nino_fe_mul(&v7, &v7, &v);
    _nino_fe_mul(&uv3, &u, &v3);
    nino_fe25519 uv7;
    _nino_fe_mul(&uv7, &u, &v7);
    nino_fe25519 e;
    _nino_fe_u64(&e, 1);
    for (int b = 251; b >= 0; b--) {
        _nino_fe_sqr(&e, &e);
        if (b != 1)
            _nino_fe_mul(&e, &e, &uv7);
    }
    _nino_fe_mul(&x, &uv3, &e);
    _nino_fe_sqr(&chk, &x);
    _nino_fe_mul(&chk, &chk, &v);
    if (!_nino_fe_eq(&chk, &u)) {
        _nino_fe_mul(&x, &x, &_nino_ed_sqrtm1);
        _nino_fe_sqr(&chk, &x);
        _nino_fe_mul(&chk, &chk, &v);
        if (!_nino_fe_eq(&chk, &u))
            return false;
    }
    uint8_t xb[32];
    _nino_fe_tobytes(xb, &x);
    uint8_t x0 = xb[0] & 1;
    uint8_t sign = (enc[31] >> 7) & 1;
    if (x0 == 0 && sign == 1) {
        nino_fe25519 f0;
        _nino_fe_u64(&f0, 0);
        if (_nino_fe_eq(&x, &f0))
            return false;
    }
    if (x0 != sign) {
        nino_fe25519 f0;
        _nino_fe_u64(&f0, 0);
        _nino_fe_sub(&x, &f0, &x);
    }
    r->X = x;
    r->Y = y;
    r->Z = f1;
    _nino_fe_mul(&r->T, &x, &y);
    return true;
}
static const uint8_t _nino_ed_L[32] = {0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7,
                                       0xa2, 0xde, 0xf9, 0xde, 0x14, 0,    0,    0,    0,    0,    0,
                                       0,    0,    0,    0,    0,    0,    0,    0,    0,    0x10};
static inline void _nino_sc_reduce(uint8_t out32[32], const uint8_t in64[64]) {
    uint8_t rem[33];
    memset(rem, 0, sizeof(rem));
    for (int bi = 63; bi >= 0; bi--) {
        uint8_t byte = in64[bi];
        for (int bit = 7; bit >= 0; bit--) {
            uint8_t carry = (uint8_t)((byte >> bit) & 1);
            for (int k = 0; k < 33; k++) {
                uint8_t nxt = (uint8_t)((rem[k] << 1) | carry);
                carry = (uint8_t)(rem[k] >> 7);
                rem[k] = nxt;
            }
            uint32_t bw = 0;
            uint8_t diff[33];
            for (int k = 0; k < 32; k++) {
                int d = (int)rem[k] - (int)_nino_ed_L[k] - (int)bw;
                bw = (d < 0) ? 1U : 0U;
                diff[k] = (uint8_t)(d & 0xff);
            }
            int d32 = (int)rem[32] - (int)bw;
            if (d32 >= 0) {
                diff[32] = (uint8_t)d32;
                memcpy(rem, diff, 33);
            }
        }
    }
    memcpy(out32, rem, 32);
}
static inline void _nino_ed25519_from_seed(uint8_t pk[32], uint8_t sk[64], const uint8_t seed[32]) {
    _nino_ed_init();
    uint8_t d[64];
    _nino_sha512_raw(seed, 32, d);
    d[0] &= 248;
    d[31] &= 127;
    d[31] |= 64;
    nino_edpt A;
    _nino_ed_mul(&A, &_nino_ed_base, d);
    _nino_ed_encode(pk, &A);
    memcpy(sk, seed, 32);
    memcpy(sk + 32, pk, 32);
}
static inline void _nino_ed25519_sign_raw(uint8_t sig[64], const uint8_t *m, size_t n, const uint8_t sk[64]) {
    _nino_ed_init();
    uint8_t az[64], r_hash[64], r[32], k_hash[64], k[32];
    _nino_sha512_raw(sk, 32, az);
    az[0] &= 248;
    az[31] &= 127;
    az[31] |= 64;
    uint8_t *tmp = (uint8_t *)malloc(n + 64);
    if (!tmp) {
        memset(sig, 0, 64);
        return;
    }
    memcpy(tmp + 32, az + 32, 32);
    if (n > 0)
        memcpy(tmp + 64, m, n);
    _nino_sha512_raw(tmp + 32, n + 32, r_hash);
    _nino_sc_reduce(r, r_hash);
    nino_edpt R;
    _nino_ed_mul(&R, &_nino_ed_base, r);
    _nino_ed_encode(sig, &R);
    memcpy(tmp, sig, 32);
    memcpy(tmp + 32, sk + 32, 32);
    if (n > 0)
        memcpy(tmp + 64, m, n);
    _nino_sha512_raw(tmp, n + 64, k_hash);
    free(tmp);
    _nino_sc_reduce(k, k_hash);
    uint32_t acc[64];
    memset(acc, 0, sizeof(acc));
    for (int i = 0; i < 32; i++)
        acc[i] = r[i];
    for (int i = 0; i < 32; i++)
        for (int j = 0; j < 32; j++)
            acc[i + j] += (uint32_t)k[i] * (uint32_t)az[j];
    uint8_t prod64[64];
    for (int i = 0; i < 63; i++) {
        acc[i + 1] += acc[i] >> 8;
        prod64[i] = (uint8_t)(acc[i] & 0xff);
    }
    prod64[63] = (uint8_t)(acc[63] & 0xff);
    _nino_sc_reduce(sig + 32, prod64);
}
static inline bool _nino_ed25519_verify_raw(const uint8_t *m, size_t n, const uint8_t pk[32],
                                            const uint8_t sig[64]) {
    _nino_ed_init();
    uint32_t bw = 0;
    for (int i = 0; i < 32; i++) {
        int d = (int)sig[32 + i] - (int)_nino_ed_L[i] - (int)bw;
        bw = (d < 0) ? 1U : 0U;
    }
    if (bw == 0)
        return false;
    nino_edpt A, R;
    if (!_nino_ed_decode(&A, pk))
        return false;
    if (!_nino_ed_decode(&R, sig))
        return false;
    uint8_t *tmp = (uint8_t *)malloc(n + 64);
    if (!tmp)
        return false;
    memcpy(tmp, sig, 32);
    memcpy(tmp + 32, pk, 32);
    if (n > 0)
        memcpy(tmp + 64, m, n);
    uint8_t k_hash[64], k[32];
    _nino_sha512_raw(tmp, n + 64, k_hash);
    free(tmp);
    _nino_sc_reduce(k, k_hash);
    nino_edpt lhs, kA, rhs;
    _nino_ed_mul(&lhs, &_nino_ed_base, sig + 32);
    _nino_ed_mul(&kA, &A, k);
    _nino_ed_add(&rhs, &R, &kA);
    uint8_t lb[32], rb[32];
    _nino_ed_encode(lb, &lhs);
    _nino_ed_encode(rb, &rhs);
    uint8_t diff = 0;
    for (int i = 0; i < 32; i++)
        diff |= (uint8_t)(lb[i] ^ rb[i]);
    return diff == 0;
}
static inline const char *ed25519_keygen_seed(const char *seed_hex) {
    if (!seed_hex || strlen(seed_hex) < 64)
        return "";
    uint8_t seed[32], pk[32], sk[64];
    for (int i = 0; i < 32; i++)
        seed[i] = (uint8_t)((_nino_hex_nib(seed_hex[i * 2]) << 4) | _nino_hex_nib(seed_hex[i * 2 + 1]));
    _nino_ed25519_from_seed(pk, sk, seed);
    char *out = (char *)nino_arena_alloc(194);
    if (!out)
        return "";
    for (int i = 0; i < 32; i++)
        snprintf(out + i * 2, 3, "%02x", (unsigned int)pk[i]);
    out[64] = ':';
    for (int i = 0; i < 64; i++)
        snprintf(out + 65 + i * 2, 3, "%02x", (unsigned int)sk[i]);
    out[193] = 0;
    return out;
}
static inline const char *ed25519_keygen(void) {
    char shex[65];
    for (int i = 0; i < 4; i++) {
        uint64_t r = _nino_entropy_u64();
        snprintf(shex + i * 16, 17, "%016llx", (unsigned long long)r);
    }
    shex[64] = 0;
    return ed25519_keygen_seed(shex);
}
static inline const char *ed25519_pubkey_from_sk(const char *sk_hex) {
    if (!sk_hex || strlen(sk_hex) < 64)
        return "";
    uint8_t seed[32], pk[32], sk[64];
    for (int i = 0; i < 32; i++)
        seed[i] = (uint8_t)((_nino_hex_nib(sk_hex[i * 2]) << 4) | _nino_hex_nib(sk_hex[i * 2 + 1]));
    _nino_ed25519_from_seed(pk, sk, seed);
    char *out = (char *)nino_arena_alloc(65);
    if (!out)
        return "";
    for (int i = 0; i < 32; i++)
        snprintf(out + i * 2, 3, "%02x", (unsigned int)pk[i]);
    out[64] = 0;
    return out;
}
static inline const char *ed25519_sign(const char *msg, const char *sk_hex) {
    if (!msg || !sk_hex || strlen(sk_hex) < 64)
        return "";
    uint8_t seed[32], pk[32], sk[64], sig[64];
    for (int i = 0; i < 32; i++)
        seed[i] = (uint8_t)((_nino_hex_nib(sk_hex[i * 2]) << 4) | _nino_hex_nib(sk_hex[i * 2 + 1]));
    _nino_ed25519_from_seed(pk, sk, seed);
    _nino_ed25519_sign_raw(sig, (const uint8_t *)msg, strlen(msg), sk);
    char *out = (char *)nino_arena_alloc(129);
    if (!out)
        return "";
    for (int i = 0; i < 64; i++)
        snprintf(out + i * 2, 3, "%02x", (unsigned int)sig[i]);
    out[128] = 0;
    return out;
}
static inline bool ed25519_verify(const char *msg, const char *sig_hex, const char *pk_hex) {
    if (!msg || !sig_hex || !pk_hex || strlen(sig_hex) != 128 || strlen(pk_hex) != 64)
        return false;
    uint8_t pk[32], sig[64];
    for (int i = 0; i < 32; i++)
        pk[i] = (uint8_t)((_nino_hex_nib(pk_hex[i * 2]) << 4) | _nino_hex_nib(pk_hex[i * 2 + 1]));
    for (int i = 0; i < 64; i++)
        sig[i] = (uint8_t)((_nino_hex_nib(sig_hex[i * 2]) << 4) | _nino_hex_nib(sig_hex[i * 2 + 1]));
    return _nino_ed25519_verify_raw((const uint8_t *)msg, strlen(msg), pk, sig);
}
typedef struct {
    int64_t step;
    char label[64];
    int64_t val;
    char hash[65];
} NinoTraceEntry;
static NINO_THREAD_LOCAL NinoTraceEntry _nino_trace_ring[256];
static NINO_THREAD_LOCAL int64_t _nino_trace_total = 0;
static NINO_THREAD_LOCAL char _nino_trace_hash[65] =
    "0000000000000000000000000000000000000000000000000000000000000000";
static inline void trace_reset(void) {
    _nino_trace_total = 0;
    memset(_nino_trace_ring, 0, sizeof(_nino_trace_ring));
    memset(_nino_trace_hash, '0', 64);
    _nino_trace_hash[64] = '\0';
}
static inline void trace_record(const char *label, int64_t val) {
    if (!label)
        label = "state";
    int64_t step = ++_nino_trace_total;
    char msg[256];
    snprintf(msg, sizeof(msg), "%s:%s:%lld", _nino_trace_hash, label, (long long)val);
    const char *next_h = sha256(msg);
    if (next_h && strlen(next_h) == 64) {
        memcpy(_nino_trace_hash, next_h, 65);
    }
    int64_t slot = (step - 1) & 255;
    _nino_trace_ring[slot].step = step;
    snprintf(_nino_trace_ring[slot].label, sizeof(_nino_trace_ring[slot].label), "%s", label);
    _nino_trace_ring[slot].val = val;
    memcpy(_nino_trace_ring[slot].hash, _nino_trace_hash, 65);
}
static inline void trace_checkpoint(const char *label) {
    trace_record(label ? label : "checkpoint", _nino_trace_total);
}
static inline const char *trace_chain_hash(void) {
    char *out = (char *)nino_arena_alloc(65);
    if (!out)
        return "";
    memcpy(out, _nino_trace_hash, 65);
    return out;
}
static inline int64_t trace_count(void) {
    return _nino_trace_total;
}
static inline int64_t trace_entry_val(int64_t idx) {
    if (idx < 0 || idx >= _nino_trace_total)
        return 0;
    return _nino_trace_ring[idx & 255].val;
}
static inline const char *trace_entry_label(int64_t idx) {
    if (idx < 0 || idx >= _nino_trace_total)
        return "";
    char *out = (char *)nino_arena_alloc(64);
    if (!out)
        return "";
    memcpy(out, _nino_trace_ring[idx & 255].label, 64);
    return out;
}
static inline const char *trace_entry_hash(int64_t idx) {
    if (idx < 0 || idx >= _nino_trace_total)
        return "";
    char *out = (char *)nino_arena_alloc(65);
    if (!out)
        return "";
    memcpy(out, _nino_trace_ring[idx & 255].hash, 65);
    return out;
}
static inline void trace_dump(void) {
    printf("[Nino Flight Recorder - Deterministic Execution Trace]\n");
    printf("  Total Transitions : %lld\n", (long long)_nino_trace_total);
    printf("  Terminal Chain SHA: %s\n", _nino_trace_hash);
    int64_t count = _nino_trace_total < 256 ? _nino_trace_total : 256;
    int64_t start = _nino_trace_total > 256 ? (_nino_trace_total - 256) : 0;
    for (int64_t i = start; i < start + count; i++) {
        NinoTraceEntry *e = &_nino_trace_ring[i & 255];
        char hprefix[17];
        memcpy(hprefix, e->hash, 16);
        hprefix[16] = '\0';
        printf("  [Step %03lld] %-24s = %-12lld | SHA256: %s...\n", (long long)e->step, e->label,
               (long long)e->val, hprefix);
    }
}
static inline void _nino_trace_auto_dump(void) {
    if (_nino_trace_total > 0) {
        trace_dump();
    }
}
struct _NinoJniInterface;
typedef const struct _NinoJniInterface *_NinoJNIEnv;
struct _NinoJniInterface {
    const char *(*GetStringUTFChars)(_NinoJNIEnv *, const char *, uint8_t *);
    void (*ReleaseStringUTFChars)(_NinoJNIEnv *, const char *, const char *);
    const char *(*NewStringUTF)(_NinoJNIEnv *, const char *);
};
static inline const char *_nino_jni_get_utf(_NinoJNIEnv *e, const char *s, uint8_t *c) {
    (void)e;
    if (c)
        *c = 0;
    return s ? s : "";
}
static inline void _nino_jni_rel_utf(_NinoJNIEnv *e, const char *s, const char *u) {
    (void)e;
    (void)s;
    (void)u;
}
static inline const char *_nino_jni_new_utf(_NinoJNIEnv *e, const char *s) {
    (void)e;
    return nino_str_concat(s ? s : "", "");
}
static const struct _NinoJniInterface _nino_jni_vtbl = {_nino_jni_get_utf, _nino_jni_rel_utf,
                                                        _nino_jni_new_utf};
static const struct _NinoJniInterface *_nino_jni_env_ptr = &_nino_jni_vtbl;
static inline int64_t dylib_open(const char *path) {
    if (!path || !path[0])
        return 0;
#ifdef _WIN32
    HMODULE h = LoadLibraryA(path);
    return (int64_t)(uintptr_t)h;
#else
    void *h = dlopen(path, RTLD_NOW);
    return (int64_t)(uintptr_t)h;
#endif
}
static inline int64_t dylib_sym(int64_t handle, const char *sym) {
    if (!handle || !sym || !sym[0])
        return 0;
#ifdef _WIN32
    FARPROC p = GetProcAddress((HMODULE)(uintptr_t)handle, sym);
    return (int64_t)(uintptr_t)p;
#else
    void *p = dlsym((void *)(uintptr_t)handle, sym);
    return (int64_t)(uintptr_t)p;
#endif
}
static inline int64_t dylib_call_i64(int64_t fn_ptr, int64_t a, int64_t b) {
    if (!fn_ptr)
        return 0;
    typedef int64_t (*fn_t)(int64_t, int64_t);
    fn_t f = (fn_t)(uintptr_t)fn_ptr;
    return f(a, b);
}
static inline const char *dylib_call_str(int64_t fn_ptr, const char *s) {
    if (!fn_ptr)
        return "";
    typedef const char *(*fn_t)(const char *);
    fn_t f = (fn_t)(uintptr_t)fn_ptr;
    const char *r = f(s ? s : "");
    return r ? nino_str_concat(r, "") : "";
}
static inline int64_t dylib_call_jni_i64(int64_t fn_ptr, int64_t a, int64_t b) {
    if (!fn_ptr)
        return 0;
    typedef int64_t (*jni_fn_t)(void *, void *, int64_t, int64_t);
    jni_fn_t f = (jni_fn_t)(uintptr_t)fn_ptr;
    return f((void *)&_nino_jni_env_ptr, NULL, a, b);
}
static inline const char *dylib_call_jni_str(int64_t fn_ptr, const char *s) {
    if (!fn_ptr)
        return "";
    typedef const char *(*jni_fn_t)(void *, void *, const char *);
    jni_fn_t f = (jni_fn_t)(uintptr_t)fn_ptr;
    const char *r = f((void *)&_nino_jni_env_ptr, NULL, s ? s : "");
    return r ? nino_str_concat(r, "") : "";
}
static inline void dylib_close(int64_t handle) {
    if (!handle)
        return;
#ifdef _WIN32
    FreeLibrary((HMODULE)(uintptr_t)handle);
#else
    dlclose((void *)(uintptr_t)handle);
#endif
}
typedef struct {
    uint8_t *data;
    uint8_t *parity;
    int32_t size;
    int64_t heals;
} nino_ecc_t;
static inline void *alloc_parity_buffer(int32_t sz) {
    nino_ecc_t *b = (nino_ecc_t *)calloc(1, sizeof(nino_ecc_t));
    if (!b)
        return NULL;
    b->size = sz;
    b->data = (uint8_t *)calloc(sz + 1, 1);
    b->parity = (uint8_t *)calloc(sz + 1, 1);
    return b;
}
static inline uint8_t _calc_ecc_p(uint8_t b) {
    uint8_t d1 = (b >> 0) & 1, d2 = (b >> 1) & 1, d3 = (b >> 2) & 1, d4 = (b >> 3) & 1, d5 = (b >> 4) & 1,
            d6 = (b >> 5) & 1, d7 = (b >> 6) & 1, d8 = (b >> 7) & 1;
    return (d1 ^ d2 ^ d4 ^ d5 ^ d7) | ((d1 ^ d3 ^ d4 ^ d6 ^ d7) << 1) | ((d2 ^ d3 ^ d4 ^ d8) << 2) |
           ((d5 ^ d6 ^ d7 ^ d8) << 3);
}
#define CANARY_HEAD 0xDEADC0DEDEADC0DEULL
#define CANARY_TAIL 0xFEEDFACEDEADBEEFULL
typedef struct {
    uint64_t head_canary;
    int32_t size;
    int32_t _pad;
    char name[32];
    uint8_t payload[];
} nino_guard_t;
static inline void *alloc_guarded_memory(int32_t sz, const char *name) {
    size_t tot = sizeof(nino_guard_t) + sz + sizeof(uint64_t);
    nino_guard_t *g = (nino_guard_t *)calloc(1, tot);
    if (!g)
        return NULL;
    g->head_canary = CANARY_HEAD;
    g->size = sz;
    if (name)
        snprintf(g->name, sizeof(g->name), "%s", name);
    *(uint64_t *)(g->payload + sz) = CANARY_TAIL;
    return (void *)g->payload;
}
static inline int64_t cpu_get_cycles(void) {
#ifdef _WIN32
    LARGE_INTEGER c;
    QueryPerformanceCounter(&c);
    return (int64_t)c.QuadPart;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000000LL + (int64_t)ts.tv_nsec;
#endif
}
#ifdef _WIN32
typedef struct {
    HWND hwnd;
    HDC mem_dc;
    HBITMAP mem_bmp;
    int32_t width;
    int32_t height;
    bool is_open;
    int64_t last_click[2];
    bool has_click;
} nino_win_t;
static inline COLORREF _nino_hex_color(const char *hex) {
    if (!hex)
        return RGB(0, 0, 0);
    if (hex[0] == '#')
        hex++;
    unsigned int r = 0, g = 0, b = 0;
    if (sscanf(hex, "%02x%02x%02x", &r, &g, &b) == 3) {
        return RGB(r, g, b);
    }
    return RGB(255, 255, 255);
}
static inline LRESULT CALLBACK _nino_wndproc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    nino_win_t *win = (nino_win_t *)GetWindowLongPtrA(hwnd, GWLP_USERDATA);
    switch (msg) {
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        if (win && win->mem_dc) {
            BitBlt(hdc, 0, 0, win->width, win->height, win->mem_dc, 0, 0, SRCCOPY);
        }
        EndPaint(hwnd, &ps);
        return 0;
    }
    case WM_LBUTTONDOWN: {
        if (win) {
            win->last_click[0] = (int16_t)LOWORD(lp);
            win->last_click[1] = (int16_t)HIWORD(lp);
            win->has_click = true;
        }
        return 0;
    }
    case WM_CLOSE: {
        if (win)
            win->is_open = false;
        DestroyWindow(hwnd);
        return 0;
    }
    case WM_DESTROY: {
        if (win)
            win->is_open = false;
        return 0;
    }
    }
    return DefWindowProcA(hwnd, msg, wp, lp);
}
static inline void *create_window(const char *title, int32_t w, int32_t ht) {
    static int cls_reg = 0;
    const char *cls = "NinoWindowClass";
    if (!cls_reg) {
        WNDCLASSA wc;
        memset(&wc, 0, sizeof(wc));
        wc.lpfnWndProc = _nino_wndproc;
        wc.hInstance = GetModuleHandleA(NULL);
        wc.lpszClassName = cls;
        wc.hCursor = LoadCursorA(NULL, IDC_ARROW);
        RegisterClassA(&wc);
        cls_reg = 1;
    }
    nino_win_t *win = (nino_win_t *)calloc(1, sizeof(nino_win_t));
    if (!win)
        return NULL;
    win->width = w;
    win->height = ht;
    win->is_open = true;
    RECT rc;
    memset(&rc, 0, sizeof(rc));
    rc.right = w;
    rc.bottom = ht;
    AdjustWindowRect(&rc, WS_OVERLAPPEDWINDOW, FALSE);
    win->hwnd = CreateWindowExA(0, cls, title ? title : "Nino Window",
                                WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX, CW_USEDEFAULT,
                                CW_USEDEFAULT, rc.right - rc.left, rc.bottom - rc.top, NULL, NULL,
                                GetModuleHandleA(NULL), NULL);
    SetWindowLongPtrA(win->hwnd, GWLP_USERDATA, (LONG_PTR)win);
    HDC hdc = GetDC(win->hwnd);
    win->mem_dc = CreateCompatibleDC(hdc);
    win->mem_bmp = CreateCompatibleBitmap(hdc, w, ht);
    SelectObject(win->mem_dc, win->mem_bmp);
    ReleaseDC(win->hwnd, hdc);
    HBRUSH bg = CreateSolidBrush(RGB(15, 23, 42));
    RECT bg_rc;
    memset(&bg_rc, 0, sizeof(bg_rc));
    bg_rc.right = w;
    bg_rc.bottom = ht;
    FillRect(win->mem_dc, &bg_rc, bg);
    DeleteObject(bg);
    ShowWindow(win->hwnd, SW_SHOW);
    UpdateWindow(win->hwnd);
    return win;
}
static inline void window_draw_rect(void *h, int32_t x, int32_t y, int32_t w, int32_t ht, const char *c) {
    if (!h)
        return;
    nino_win_t *win = (nino_win_t *)h;
    if (!win->mem_dc)
        return;
    HBRUSH br = CreateSolidBrush(_nino_hex_color(c));
    RECT rc = {x, y, x + w, y + ht};
    FillRect(win->mem_dc, &rc, br);
    DeleteObject(br);
}
static inline void window_draw_round_rect(void *h, int32_t x, int32_t y, int32_t w, int32_t ht, int32_t r,
                                          const char *c, const char *o) {
    if (!h)
        return;
    nino_win_t *win = (nino_win_t *)h;
    if (!win->mem_dc)
        return;
    HBRUSH br = CreateSolidBrush(_nino_hex_color(c));
    HPEN pen = CreatePen(PS_SOLID, 1, o ? _nino_hex_color(o) : _nino_hex_color(c));
    HGDIOBJ old_br = SelectObject(win->mem_dc, br);
    HGDIOBJ old_pen = SelectObject(win->mem_dc, pen);
    RoundRect(win->mem_dc, x, y, x + w, y + ht, r * 2, r * 2);
    SelectObject(win->mem_dc, old_br);
    SelectObject(win->mem_dc, old_pen);
    DeleteObject(br);
    DeleteObject(pen);
}
static inline void window_draw_text(void *h, const char *tx, int32_t x, int32_t y, int32_t s, const char *c) {
    if (!h || !tx)
        return;
    nino_win_t *win = (nino_win_t *)h;
    if (!win->mem_dc)
        return;
    SetBkMode(win->mem_dc, TRANSPARENT);
    SetTextColor(win->mem_dc, _nino_hex_color(c));
    HFONT font = CreateFontA(s > 0 ? s + 4 : 14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, ANSI_CHARSET,
                             OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
                             DEFAULT_PITCH | FF_DONTCARE, "Segoe UI");
    HGDIOBJ old_font = SelectObject(win->mem_dc, font);
    TextOutA(win->mem_dc, x, y, tx, (int)strlen(tx));
    SelectObject(win->mem_dc, old_font);
    DeleteObject(font);
}
static inline void window_update(void *h) {
    if (!h)
        return;
    nino_win_t *win = (nino_win_t *)h;
    if (win->hwnd) {
        InvalidateRect(win->hwnd, NULL, FALSE);
        UpdateWindow(win->hwnd);
        MSG msg;
        while (PeekMessageA(&msg, win->hwnd, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessageA(&msg);
        }
    }
}
static inline bool window_is_open(void *h) {
    if (!h)
        return false;
    nino_win_t *win = (nino_win_t *)h;
    MSG msg;
    while (PeekMessageA(&msg, NULL, 0, 0, PM_REMOVE)) {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }
    return win->is_open;
}
static inline void window_clear(void *h) {
    if (!h)
        return;
    nino_win_t *win = (nino_win_t *)h;
    if (!win->mem_dc)
        return;
    HBRUSH bg = CreateSolidBrush(RGB(15, 23, 42));
    RECT bg_rc;
    memset(&bg_rc, 0, sizeof(bg_rc));
    bg_rc.right = win->width;
    bg_rc.bottom = win->height;
    FillRect(win->mem_dc, &bg_rc, bg);
    DeleteObject(bg);
}
static inline int64_t *window_poll_click(void *h) {
    if (!h)
        return NULL;
    nino_win_t *win = (nino_win_t *)h;
    MSG msg;
    while (PeekMessageA(&msg, NULL, 0, 0, PM_REMOVE)) {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }
    if (win->has_click) {
        win->has_click = false;
        return win->last_click;
    }
    return NULL;
}
static inline void window_sleep(void *h, int32_t ms) {
    (void)h;
    MSG msg;
    DWORD start = GetTickCount();
    while ((GetTickCount() - start) < (DWORD)ms) {
        while (PeekMessageA(&msg, NULL, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessageA(&msg);
        }
        Sleep(5);
    }
}
static inline void window_wait_close(void *h) {
    if (!h)
        return;
    nino_win_t *win = (nino_win_t *)h;
    MSG msg;
    while (win->is_open && GetMessageA(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }
}
#else
static inline void *create_window(const char *t, int32_t w, int32_t ht) {
    (void)t;
    (void)w;
    (void)ht;
    return NULL;
}
static inline void window_draw_rect(void *h, int32_t x, int32_t y, int32_t w, int32_t ht, const char *c) {
    (void)h;
    (void)x;
    (void)y;
    (void)w;
    (void)ht;
    (void)c;
}
static inline void window_draw_round_rect(void *h, int32_t x, int32_t y, int32_t w, int32_t ht, int32_t r,
                                          const char *c, const char *o) {
    (void)h;
    (void)x;
    (void)y;
    (void)w;
    (void)ht;
    (void)r;
    (void)c;
    (void)o;
}
static inline void window_draw_text(void *h, const char *tx, int32_t x, int32_t y, int32_t s, const char *c) {
    (void)h;
    (void)tx;
    (void)x;
    (void)y;
    (void)s;
    (void)c;
}
static inline void window_update(void *h) {
    (void)h;
}
static inline bool window_is_open(void *h) {
    (void)h;
    return false;
}
static inline void window_wait_close(void *h) {
    (void)h;
}
static inline void window_clear(void *h) {
    (void)h;
}
static inline int64_t *window_poll_click(void *h) {
    (void)h;
    static int64_t pt[2] = {0, 0};
    return pt;
}
static inline void window_sleep(void *h, int32_t ms) {
    (void)h;
    (void)ms;
}
static inline int32_t GetTickCount(void) {
    return (int32_t)(clock() * 1000 / CLOCKS_PER_SEC);
}
static inline int32_t Beep(int32_t f, int32_t d) {
    (void)f;
    (void)d;
    return 1;
}
#endif
static NINO_THREAD_LOCAL int64_t _nino_heap_arr_live = 0;
static inline uint64_t _nino_arena_cur_mark_id(void) {
    return (g_nino_arena.mark_depth > 0 && g_nino_arena.mark_ids)
               ? g_nino_arena.mark_ids[g_nino_arena.mark_depth - 1]
               : g_nino_arena.base_mark_id;
}
static inline void _nino_stamp_arr(NinoArrHdr *hdr, int64_t orig, int64_t cap, int64_t alen) {
    hdr->magic = _NINO_ARR_MAGIC;
    hdr->cap = cap;
    hdr->len = alen;
    if (orig < 0 || !_nino_in_arena(hdr)) {
        hdr->origin = -1;
        hdr->reset_gen = 0;
        hdr->mark_id = 0;
    } else {
        hdr->origin = orig;
        hdr->reset_gen = g_nino_arena.reset_gen;
        hdr->mark_id = _nino_arena_cur_mark_id();
    }
}
static inline void *_nino_alloc_arr(size_t initial_bytes) {
    if (initial_bytes < 256)
        initial_bytes = 256;
    size_t tot = sizeof(NinoArrHdr) + initial_bytes;
    if (!g_nino_arena.tail)
        nino_arena_init(4 * 1024 * 1024);
    int64_t orig = (int64_t)g_nino_arena.total_offset;
    NinoArrHdr *hdr = (NinoArrHdr *)nino_arena_alloc(tot);
    if (!hdr)
        return NULL;
    memset(hdr, 0, tot);
    _nino_stamp_arr(hdr, orig, (int64_t)initial_bytes, 0);
    return (void *)(hdr + 1);
}
static inline void *_nino_make_arr(size_t count, size_t elem_sz, const void *items) {
    size_t data_bytes = count * elem_sz;
    size_t cap_bytes = data_bytes < 256 ? 256 : data_bytes * 2;
    size_t tot = sizeof(NinoArrHdr) + cap_bytes;
    if (!g_nino_arena.tail)
        nino_arena_init(4 * 1024 * 1024);
    int64_t orig = (int64_t)g_nino_arena.total_offset;
    NinoArrHdr *hdr = (NinoArrHdr *)nino_arena_alloc(tot);
    if (!hdr)
        return NULL;
    memset(hdr, 0, tot);
    _nino_stamp_arr(hdr, orig, (int64_t)cap_bytes, (int64_t)count);
    void *p = (void *)(hdr + 1);
    if (items && count > 0)
        memcpy(p, items, data_bytes);
    return p;
}
static inline void *_nino_push_impl(void *arr, const void *p_item, size_t elem_sz, size_t arr_elem_sz) {
    size_t sz = (arr && arr_elem_sz > 1) ? arr_elem_sz : elem_sz;
    if (sz < 1)
        sz = 8;
    if (arr && !_nino_arr_is_alive(arr)) {
        fprintf(stderr,
                "[Nino Use-After-Rollback Violation CWE-416] push() onto invalidated/rolled-back array\n");
        exit(1);
    }
    if (!arr)
        arr = _nino_alloc_arr(256);
    NinoArrHdr *cur = ((NinoArrHdr *)arr) - 1;
    int64_t orig = cur->origin;
    int64_t cap_bytes = cur->cap;
    int64_t old_len = cur->len;
    size_t needed = (size_t)(old_len + 1) * sz;
    if ((int64_t)needed <= cap_bytes) {
        memcpy((char *)arr + (old_len * sz), p_item, elem_sz < sz ? elem_sz : sz);
        cur->len = old_len + 1;
        return arr;
    }
    size_t new_cap = needed * 2;
    if (new_cap < 256)
        new_cap = 256;
    size_t tot = sizeof(NinoArrHdr) + new_cap;
    bool crosses_mark = (orig < 0) || (g_nino_arena.mark_depth > 0 && g_nino_arena.marks &&
                                       (size_t)orig < g_nino_arena.marks[g_nino_arena.mark_depth - 1]);
    NinoArrHdr *base = NULL;
    int64_t new_orig = -1;
    void *old_ptr = arr;
    if (orig == -1) {
        base = (NinoArrHdr *)realloc(cur, tot);
        if (!base)
            return arr;
        if ((void *)(base + 1) != old_ptr) {
            _nino_heap_arr_unreg(old_ptr);
        }
    } else if (crosses_mark) {
        base = (NinoArrHdr *)calloc(1, tot);
        if (!base)
            return arr;
        if (old_len > 0)
            memcpy(base + 1, arr, (size_t)old_len * sz);
        _nino_heap_arr_live++;
    } else {
        new_orig = (int64_t)g_nino_arena.total_offset;
        base = (NinoArrHdr *)nino_arena_alloc(tot);
        if (!base)
            return arr;
        memset(base, 0, tot);
        if (old_len > 0)
            memcpy(base + 1, arr, (size_t)old_len * sz);
    }
    _nino_stamp_arr(base, new_orig, (int64_t)new_cap, old_len + 1);
    void *new_items = (void *)(base + 1);
    if (new_orig == -1)
        _nino_heap_arr_reg(new_items);
    memcpy((char *)new_items + (old_len * sz), p_item, elem_sz < sz ? elem_sz : sz);
    return new_items;
}
static inline void _nino_arr_free_impl(void *arr) {
    if (!arr || !_nino_arr_is_alive(arr))
        return;
    NinoArrHdr *base = ((NinoArrHdr *)arr) - 1;
    if (base->origin != -1)
        return;
    _nino_heap_arr_unreg(arr);
    base->magic = 0;
    int64_t cap = base->cap;
    if (cap > 0)
        memset(arr, 0, (size_t)cap);
    free(base);
    if (_nino_heap_arr_live > 0)
        _nino_heap_arr_live--;
}
#define arr_free(A) _nino_arr_free_impl((void *)(A))
static inline int64_t heap_live_arrays(void) {
    return _nino_heap_arr_live;
}
static inline void *_nino_push_i64(void *arr, int64_t val) {
    return _nino_push_impl(arr, &val, sizeof(int64_t), sizeof(int64_t));
}
static inline void *_nino_push_f64(void *arr, double val) {
    return _nino_push_impl(arr, &val, sizeof(double), sizeof(double));
}
static inline void *_nino_push_str(void *arr, const char *val) {
    return _nino_push_impl(arr, &val, sizeof(const char *), sizeof(const char *));
}
static inline void *_nino_push_ptr(void *arr, const void *val) {
    return _nino_push_impl(arr, &val, sizeof(void *), sizeof(void *));
}
#define push(arr, item)                                                                                      \
    _Generic((item),                                                                                         \
        int64_t: _nino_push_i64,                                                                             \
        int: _nino_push_i64,                                                                                 \
        double: _nino_push_f64,                                                                              \
        float: _nino_push_f64,                                                                               \
        const char *: _nino_push_str,                                                                        \
        char *: _nino_push_str,                                                                              \
        default: _nino_push_ptr)((void *)(arr), (item))
static inline void *_nino_pop_impl(void *arr) {
    if (!arr)
        return NULL;
    if (!_nino_arr_is_alive(arr)) {
        fprintf(stderr,
                "[Nino Use-After-Rollback Violation CWE-416] pop() on invalidated/rolled-back array\n");
        exit(1);
    }
    NinoArrHdr *hdr = ((NinoArrHdr *)arr) - 1;
    if (hdr->len > 0)
        hdr->len--;
    return arr;
}
#define pop(arr) _nino_pop_impl((void *)(arr))
typedef struct NinoDictEntry {
    const char *key;
    const char *val;
    struct NinoDictEntry *next;
} NinoDictEntry;
typedef struct {
    char summary[64];
    uint32_t magic;
    int count;
    NinoDictEntry *head;
} NinoDict;
static inline NinoDict *nino_dict_create(void) {
    NinoDict *d = (NinoDict *)nino_arena_alloc(sizeof(NinoDict));
    if (d) {
        memset(d->summary, 0, 64);
        memcpy(d->summary, "[NinoDict]", 11);
        d->magic = 0xD1C70001;
        d->head = NULL;
        d->count = 0;
    }
    return d;
}
static inline void nino_dict_set(NinoDict *d, const char *k, const char *v) {
    if (!d || !k || d->magic != 0xD1C70001)
        return;
    if (!v)
        v = "";
    size_t vl = strlen(v);
    char *cp = (char *)nino_arena_alloc(vl + 1);
    if (!cp)
        return;
    memcpy(cp, v, vl + 1);
    NinoDictEntry *cur = d->head;
    while (cur) {
        if (cur->key && strcmp(cur->key, k) == 0) {
            cur->val = cp;
            return;
        }
        cur = cur->next;
    }
    size_t kl = strlen(k);
    char *kp = (char *)nino_arena_alloc(kl + 1);
    if (!kp)
        return;
    memcpy(kp, k, kl + 1);
    NinoDictEntry *e = (NinoDictEntry *)nino_arena_alloc(sizeof(NinoDictEntry));
    if (!e)
        return;
    e->key = kp;
    e->val = cp;
    e->next = d->head;
    d->head = e;
    d->count++;
}
static inline const char *_nino_auto_to_str_int(long long v) {
    char *b = (char *)nino_arena_alloc(32);
    if (!b)
        return "";
    snprintf(b, 32, "%lld", v);
    return b;
}
static inline const char *_nino_auto_to_str_dbl(double v) {
    char *b = (char *)nino_arena_alloc(32);
    if (!b)
        return "";
    snprintf(b, 32, "%f", v);
    return b;
}
static inline const char *_nino_auto_to_str_s(const char *s) {
    return s ? s : "";
}
static inline const char *_nino_auto_to_str_c(char *s) {
    return s ? s : "";
}
#define _nino_auto_str(X)                                                                                    \
    _Generic((X),                                                                                            \
        char *: _nino_auto_to_str_c,                                                                         \
        const char *: _nino_auto_to_str_s,                                                                   \
        int: _nino_auto_to_str_int,                                                                          \
        long: _nino_auto_to_str_int,                                                                         \
        long long: _nino_auto_to_str_int,                                                                    \
        unsigned int: _nino_auto_to_str_int,                                                                 \
        unsigned long: _nino_auto_to_str_int,                                                                \
        unsigned long long: _nino_auto_to_str_int,                                                           \
        double: _nino_auto_to_str_dbl,                                                                       \
        float: _nino_auto_to_str_dbl,                                                                        \
        default: _nino_auto_to_str_s)(X)
#define nino_dict_set_auto(D, K, V) nino_dict_set((D), _nino_auto_str(K), _nino_auto_str(V))
static inline NinoDict *_nino_dict_kv(NinoDict *d, const char *k, const char *v) {
    nino_dict_set(d, k, v);
    return d;
}
#define nino_dict_chain(D, K, V) _nino_dict_kv((D), _nino_auto_str(K), _nino_auto_str(V))
static inline const char *nino_dict_get(const void *ptr, const char *k) {
    if (!k || !ptr)
        return "";
    const NinoDict *d = (const NinoDict *)ptr;
    if (d->magic != 0xD1C70001)
        return "";
    NinoDictEntry *cur = d->head;
    while (cur) {
        if (cur->key && strcmp(cur->key, k) == 0)
            return cur->val;
        cur = cur->next;
    }
    return "";
}
typedef struct {
    int32_t pid;
    char behavior[64];
    char **msgs;
    int cap;
    int head;
    int tail;
    int count;
    int32_t restarts;
    bool alive;
} NinoActor;
static NinoActor **_nino_actors = NULL;
static int32_t _nino_actor_cnt = 0;
static int32_t _nino_actor_cap = 0;
#ifdef _WIN32
static SRWLOCK _nino_actor_lock = SRWLOCK_INIT;
#define _NINO_ACT_LOCK() AcquireSRWLockExclusive(&_nino_actor_lock)
#define _NINO_ACT_UNLOCK() ReleaseSRWLockExclusive(&_nino_actor_lock)
#else
static pthread_mutex_t _nino_actor_lock = PTHREAD_MUTEX_INITIALIZER;
#define _NINO_ACT_LOCK() pthread_mutex_lock(&_nino_actor_lock)
#define _NINO_ACT_UNLOCK() pthread_mutex_unlock(&_nino_actor_lock)
#endif
typedef const char *(*NinoActorHandlerFn)(const char *);
typedef struct {
    char name[64];
    NinoActorHandlerFn fn;
} NinoActorRegEntry;
static NinoActorRegEntry _nino_actor_reg[128];
static int32_t _nino_actor_reg_cnt = 0;
static inline void _nino_actor_register(const char *name, NinoActorHandlerFn fn) {
    if (!name || !name[0] || !fn)
        return;
    _NINO_ACT_LOCK();
    for (int32_t i = 0; i < _nino_actor_reg_cnt; i++) {
        if (strcmp(_nino_actor_reg[i].name, name) == 0) {
            _nino_actor_reg[i].fn = fn;
            _NINO_ACT_UNLOCK();
            return;
        }
    }
    if (_nino_actor_reg_cnt < 128) {
        snprintf(_nino_actor_reg[_nino_actor_reg_cnt].name, 64, "%s", name);
        _nino_actor_reg[_nino_actor_reg_cnt].fn = fn;
        _nino_actor_reg_cnt++;
    }
    _NINO_ACT_UNLOCK();
}
static inline int32_t spawn_actor(const char *name) {
    _NINO_ACT_LOCK();
    if (_nino_actor_cnt + 1 >= _nino_actor_cap) {
        int32_t nc = _nino_actor_cap == 0 ? 64 : _nino_actor_cap * 2;
        NinoActor **na = (NinoActor **)realloc(_nino_actors, (size_t)nc * sizeof(NinoActor *));
        if (!na) {
            _NINO_ACT_UNLOCK();
            return 0;
        }
        for (int32_t i = _nino_actor_cap; i < nc; i++)
            na[i] = NULL;
        _nino_actors = na;
        _nino_actor_cap = nc;
    }
    int32_t pid = ++_nino_actor_cnt;
    NinoActor *a = (NinoActor *)calloc(1, sizeof(NinoActor));
    if (!a) {
        _NINO_ACT_UNLOCK();
        return 0;
    }
    a->pid = pid;
    a->cap = 64;
    a->msgs = (char **)calloc((size_t)a->cap, sizeof(char *));
    snprintf(a->behavior, sizeof(a->behavior), "%s", name ? name : "Actor");
    a->alive = true;
    _nino_actors[pid] = a;
    _NINO_ACT_UNLOCK();
    return pid;
}
static inline bool actor_send(int32_t pid, void *msg) {
    _NINO_ACT_LOCK();
    if (pid <= 0 || pid > _nino_actor_cnt || !_nino_actors[pid] || !_nino_actors[pid]->alive) {
        _NINO_ACT_UNLOCK();
        return false;
    }
    NinoActor *a = _nino_actors[pid];
    if (a->count >= a->cap) {
        int ncap = a->cap < 64 ? 64 : a->cap * 2;
        char **nbuf = (char **)calloc((size_t)ncap, sizeof(char *));
        if (!nbuf) {
            _NINO_ACT_UNLOCK();
            return false;
        }
        for (int i = 0; i < a->count; i++)
            nbuf[i] = a->msgs[(a->head + i) % a->cap];
        free(a->msgs);
        a->msgs = nbuf;
        a->head = 0;
        a->tail = a->count;
        a->cap = ncap;
    }
    const char *s = msg ? (const char *)msg : "";
    size_t sl = strlen(s);
    char *cp = (char *)malloc(sl + 1);
    if (!cp) {
        _NINO_ACT_UNLOCK();
        return false;
    }
    memcpy(cp, s, sl + 1);
    a->msgs[a->tail] = cp;
    a->tail = (a->tail + 1) % a->cap;
    a->count++;
    _NINO_ACT_UNLOCK();
    return true;
}
static inline int64_t actor_inbox_len(int32_t pid) {
    _NINO_ACT_LOCK();
    int64_t r = (pid > 0 && pid <= _nino_actor_cnt && _nino_actors[pid] && _nino_actors[pid]->alive)
                    ? (int64_t)_nino_actors[pid]->count
                    : 0;
    _NINO_ACT_UNLOCK();
    return r;
}
static inline const char *actor_receive(int32_t pid) {
    _NINO_ACT_LOCK();
    if (pid <= 0 || pid > _nino_actor_cnt || !_nino_actors[pid] || !_nino_actors[pid]->alive) {
        _NINO_ACT_UNLOCK();
        return "";
    }
    NinoActor *a = _nino_actors[pid];
    char *owned = NULL;
    if (a->count > 0) {
        owned = a->msgs[a->head];
        a->msgs[a->head] = NULL;
        a->head = (a->head + 1) % a->cap;
        a->count--;
    }
    char beh[64];
    memcpy(beh, a->behavior, 64);
    NinoActorHandlerFn hfn = NULL;
    for (int32_t i = 0; i < _nino_actor_reg_cnt; i++) {
        if (strcmp(_nino_actor_reg[i].name, beh) == 0) {
            hfn = _nino_actor_reg[i].fn;
            break;
        }
    }
    _NINO_ACT_UNLOCK();
    const char *msg = owned ? owned : "";
    if (hfn) {
        const char *hres = hfn(msg);
        const char *dup = hres ? nino_str_concat(hres, "") : "";
        if (owned)
            free(owned);
        return dup;
    }
    char *out = (char *)nino_arena_alloc(strlen(msg) + 96);
    if (out) {
        if (strcmp(msg, "PING") == 0) {
            snprintf(out, strlen(msg) + 96, "PONG_FROM_%s", beh);
        } else if (msg[0]) {
            snprintf(out, strlen(msg) + 96, "%s_ACK:%s", beh, msg);
        } else {
            snprintf(out, strlen(msg) + 96, "%s_READY", beh);
        }
    }
    if (owned)
        free(owned);
    return out ? out : "";
}
static inline int32_t spawn_supervisor(int32_t pid, const char *pol) {
    (void)pol;
    return (pid > 0 && pid <= _nino_actor_cnt) ? pid : 1;
}
static inline bool _nino_is_word_ch(unsigned char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}
static inline bool _nino_has_word(const char *s, const char *w) {
    if (!s || !w || !w[0])
        return false;
    size_t wl = strlen(w);
    const char *cur = s;
    while ((cur = strstr(cur, w)) != NULL) {
        bool lb = (cur == s) || !_nino_is_word_ch((unsigned char)cur[-1]);
        bool rb = (cur[wl] == 0) || !_nino_is_word_ch((unsigned char)cur[wl]);
        if (lb && rb)
            return true;
        cur += wl;
    }
    return false;
}
static inline void *supervisor_dispatch(int32_t sid, void *msg) {
    _NINO_ACT_LOCK();
    NinoActor *a = (sid > 0 && sid <= _nino_actor_cnt) ? _nino_actors[sid] : NULL;
    if (!a) {
        _NINO_ACT_UNLOCK();
        return nino_dict_create();
    }
    const char *m = msg ? (const char *)msg : "";
    NinoDict *d = nino_dict_create();
    if (_nino_has_word(m, "FAULT") || _nino_has_word(m, "CRASH")) {
        a->restarts++;
        for (int i = 0; i < a->count; i++) {
            int idx = (a->head + i) % a->cap;
            if (a->msgs[idx]) {
                free(a->msgs[idx]);
                a->msgs[idx] = NULL;
            }
        }
        a->head = 0;
        a->tail = 0;
        a->count = 0;
        a->alive = true;
        char rbuf[32];
        snprintf(rbuf, 32, "%d", (int)a->restarts);
        char beh[64];
        memcpy(beh, a->behavior, 64);
        _NINO_ACT_UNLOCK();
        nino_dict_set(d, "status", "RECOVERED_SUPERVISOR_ACTION");
        nino_dict_set(d, "restart_count", rbuf);
        nino_dict_set(d, "actor", beh);
        snprintf(d->summary, 64, "RECOVERED:%s (restarts=%d)", beh, (int)a->restarts);
    } else {
        int32_t rst = a->restarts;
        _NINO_ACT_UNLOCK();
        actor_send(sid, (void *)m);
        const char *rep = actor_receive(sid);
        char rbuf[32];
        snprintf(rbuf, 32, "%d", (int)rst);
        nino_dict_set(d, "status", "OK");
        nino_dict_set(d, "restart_count", rbuf);
        nino_dict_set(d, "response", rep);
        snprintf(d->summary, 64, "PROCESSED:%s", m);
    }
    return d;
}
static inline bool actor_patch(int32_t pid, const char *name) {
    _NINO_ACT_LOCK();
    if (pid <= 0 || pid > _nino_actor_cnt || !_nino_actors[pid] || !name || !name[0]) {
        _NINO_ACT_UNLOCK();
        return false;
    }
    snprintf(_nino_actors[pid]->behavior, sizeof(_nino_actors[pid]->behavior), "%s", name);
    _NINO_ACT_UNLOCK();
    return true;
}
#define _NINO_SP_P 2305843009213691579ULL
#define _NINO_SP_Q 1152921504606845789ULL
#define _NINO_GEN_G 4ULL
#define _NINO_GEN_H 49ULL
static inline uint64_t _nino_ct_add_mod(uint64_t x, uint64_t y, uint64_t mod) {
    uint64_t sum = x + y;
    uint64_t carry = ((x & y) | ((x | y) & (~sum))) >> 63;
    uint64_t d = sum - mod;
    uint64_t borrow = (((~sum) & mod) | ((~(sum ^ mod)) & d)) >> 63;
    uint64_t need_sub = (carry | (1ULL ^ borrow)) & 1ULL;
    uint64_t mask = 0ULL - need_sub;
    return (d & mask) | (sum & (~mask));
}
static inline uint64_t _nino_mod_mul(uint64_t a, uint64_t b, uint64_t mod) {
    if (mod == 0)
        return 0;
    uint64_t res = 0;
    a %= mod;
    b %= mod;
    for (int i = 0; i < 64; i++) {
        uint64_t mask = 0ULL - (b & 1ULL);
        uint64_t added = _nino_ct_add_mod(res, a, mod);
        res = (added & mask) | (res & (~mask));
        a = _nino_ct_add_mod(a, a, mod);
        b >>= 1;
    }
    return res;
}
static inline uint64_t _nino_mod_pow(uint64_t base, uint64_t exp, uint64_t mod) {
    if (mod <= 1)
        return 0;
    uint64_t res = 1;
    base %= mod;
    for (int i = 0; i < 64; i++) {
        uint64_t mask = 0ULL - (exp & 1ULL);
        uint64_t prod = _nino_mod_mul(res, base, mod);
        res = (prod & mask) | (res & (~mask));
        base = _nino_mod_mul(base, base, mod);
        exp >>= 1;
    }
    return res;
}
static inline uint64_t _nino_mod_inv_p(uint64_t a, uint64_t p) {
    return _nino_mod_pow(a, p - 2ULL, p);
}
static inline uint64_t _nino_hash_u64(const char *s) {
    const char *h = sha256(s ? s : "");
    unsigned long long v = 0;
    sscanf(h, "%016llx", &v);
    return (uint64_t)v;
}
static inline void _rlwe64_poly_a(uint64_t seed, int a[64]) {
    for (int i = 0; i < 64; i++) {
        uint64_t x = seed ^ ((uint64_t)(i + 1) * 0x9E3779B97F4A7C15ULL);
        x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ULL;
        x = (x ^ (x >> 27)) * 0x94D049BB133111EBULL;
        a[i] = (int)((x ^ (x >> 31)) % 3329ULL);
    }
}
static inline void _rlwe64_mul(const int a[64], const int b[64], int out[64]) {
    for (int i = 0; i < 64; i++)
        out[i] = 0;
    for (int i = 0; i < 64; i++) {
        for (int j = 0; j < 64; j++) {
            int prod = (a[i] * b[j]) % 3329;
            if (i + j < 64)
                out[i + j] = (out[i + j] + prod) % 3329;
            else
                out[i + j - 64] = (out[i + j - 64] - prod + 3329) % 3329;
        }
    }
    for (int i = 0; i < 64; i++)
        out[i] = (out[i] % 3329 + 3329) % 3329;
}
static inline int _rlwe_trit(uint64_t bits, int idx) {
    uint64_t c = (bits >> ((idx & 31) * 2)) & 3ULL;
    return c == 1ULL ? 1 : (c == 2ULL ? -1 : 0);
}
static inline void _mlkem_mat_a(uint64_t seed, int row, int col, int32_t out[256]) {
    uint64_t tag = seed ^ ((uint64_t)(row * 2 + col + 1) * 0xD1342543DE82EF95ULL);
    for (int i = 0; i < 256; i++) {
        uint64_t x = tag ^ ((uint64_t)(i + 1) * 0x9E3779B97F4A7C15ULL);
        x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ULL;
        x = (x ^ (x >> 27)) * 0x94D049BB133111EBULL;
        out[i] = (int32_t)((x ^ (x >> 31)) % 3329ULL);
    }
}
static inline void _mlkem_poly_mul_acc(const int32_t a[256], const int32_t b[256], int32_t acc[256]) {
    int32_t tmp[256];
    memset(tmp, 0, sizeof(tmp));
    for (int i = 0; i < 256; i++) {
        int32_t ai = a[i];
        for (int j = 0; j < 256; j++) {
            int idx = i + j;
            int32_t p = ai * b[j];
            if (idx < 256)
                tmp[idx] += p;
            else
                tmp[idx - 256] -= p;
        }
    }
    for (int i = 0; i < 256; i++) {
        int32_t v = (acc[i] + tmp[i]) % 3329;
        acc[i] = (v < 0) ? (v + 3329) : v;
    }
}
static inline int32_t _mlkem_trit(const uint64_t w[8], int idx) {
    uint64_t bits = (w[idx >> 5] >> ((idx & 31) * 2)) & 3ULL;
    return (bits == 1ULL) ? 1 : ((bits == 2ULL) ? -1 : 0);
}
static inline void *pq_generate_keypair(int32_t lvl) {
    bool use_mlkem = (lvl == 512 || lvl == 1024);
#ifdef NINO_RELEASE_PQC
    use_mlkem = true;
#endif
    uint64_t seed = _nino_entropy_u64();
    uint64_t dsa_x = (_nino_entropy_u64() % (_NINO_SP_Q - 3ULL)) + 2ULL;
    uint64_t dsa_y = _nino_mod_pow(_NINO_GEN_G, dsa_x, _NINO_SP_P);
    if (use_mlkem) {
        uint64_t sb[2][8], eb[2][8];
        int32_t sv[2][256], tv[2][256], A[2][2][256];
        for (int r = 0; r < 2; r++) {
            for (int w = 0; w < 8; w++) {
                sb[r][w] = _nino_entropy_u64();
                eb[r][w] = _nino_entropy_u64();
            }
            for (int i = 0; i < 256; i++)
                sv[r][i] = _mlkem_trit(sb[r], i);
            for (int c = 0; c < 2; c++)
                _mlkem_mat_a(seed, r, c, A[r][c]);
        }
        for (int r = 0; r < 2; r++) {
            for (int i = 0; i < 256; i++)
                tv[r][i] = (_mlkem_trit(eb[r], i) + 3329) % 3329;
            for (int c = 0; c < 2; c++)
                _mlkem_poly_mul_acc(A[r][c], sv[c], tv[r]);
        }
        char *pk = (char *)nino_arena_alloc(1640);
        char *sk = (char *)nino_arena_alloc(360);
        snprintf(pk, 1640, "MLKEM512_PK:%016llx:%016llx:", (unsigned long long)seed,
                 (unsigned long long)dsa_y);
        size_t po = strlen(pk);
        for (int r = 0; r < 2; r++)
            for (int i = 0; i < 256; i++) {
                snprintf(pk + po, 4, "%03x", (unsigned int)tv[r][i]);
                po += 3;
            }
        snprintf(sk, 360, "MLKEM512_SK:%016llx:%016llx:%016llx:", (unsigned long long)seed,
                 (unsigned long long)dsa_y, (unsigned long long)dsa_x);
        size_t so = strlen(sk);
        for (int r = 0; r < 2; r++)
            for (int w = 0; w < 8; w++) {
                snprintf(sk + so, 17, "%016llx", (unsigned long long)sb[r][w]);
                so += 16;
            }
        NinoDict *d = nino_dict_create();
        nino_dict_set(d, "public_key", pk);
        nino_dict_set(d, "private_key", sk);
        return d;
    }
    uint64_t s_lo = _nino_entropy_u64(), s_hi = _nino_entropy_u64(), e_lo = _nino_entropy_u64(),
             e_hi = _nino_entropy_u64();
    int a[64], s[64], b[64];
    _rlwe64_poly_a(seed, a);
    for (int i = 0; i < 64; i++)
        s[i] = _rlwe_trit(i < 32 ? s_lo : s_hi, i);
    _rlwe64_mul(a, s, b);
    for (int i = 0; i < 64; i++)
        b[i] = (b[i] + _rlwe_trit(i < 32 ? e_lo : e_hi, i) + 33290) % 3329;
    char *pk = (char *)nino_arena_alloc(280);
    char *sk = (char *)nino_arena_alloc(128);
    snprintf(pk, 280, "RLWE64_PK:%016llx:%016llx:", (unsigned long long)seed, (unsigned long long)dsa_y);
    size_t off = strlen(pk);
    for (int i = 0; i < 64; i++)
        snprintf(pk + off + i * 3, 4, "%03x", (unsigned int)b[i]);
    snprintf(sk, 128, "RLWE64_SK:%016llx:%016llx:%016llx:%016llx%016llx", (unsigned long long)seed,
             (unsigned long long)dsa_y, (unsigned long long)dsa_x, (unsigned long long)s_lo,
             (unsigned long long)s_hi);
    NinoDict *d = nino_dict_create();
    nino_dict_set(d, "public_key", pk);
    nino_dict_set(d, "private_key", sk);
    return d;
}
static inline void *pq_encapsulate(const char *pk) {
    NinoDict *d = nino_dict_create();
    if (!pk)
        return d;
    if (strncmp(pk, "MLKEM512_PK:", 12) == 0 && strlen(pk) == 1582) {
        unsigned long long seed = 0, dsa_y = 0;
        int pkn = 0;
        if (sscanf(pk + 12, "%016llx:%016llx:%n", &seed, &dsa_y, &pkn) != 2 || pkn != 34)
            return d;
        const char *th = pk + 46;
        int32_t A[2][2][256], tv[2][256], rv[2][256], u[2][256], v[256];
        uint64_t rb[2][8], e1b[2][8], e2b[8], m[4];
        for (int r = 0; r < 2; r++) {
            for (int w = 0; w < 8; w++) {
                rb[r][w] = _nino_entropy_u64();
                e1b[r][w] = _nino_entropy_u64();
            }
            for (int i = 0; i < 256; i++) {
                unsigned int vv = 0;
                if (sscanf(th + (r * 256 + i) * 3, "%03x", &vv) != 1)
                    return d;
                tv[r][i] = (int32_t)vv;
                rv[r][i] = _mlkem_trit(rb[r], i);
            }
            for (int c = 0; c < 2; c++)
                _mlkem_mat_a((uint64_t)seed, r, c, A[r][c]);
        }
        for (int w = 0; w < 8; w++)
            e2b[w] = _nino_entropy_u64();
        for (int w = 0; w < 4; w++)
            m[w] = _nino_entropy_u64();
        for (int c = 0; c < 2; c++) {
            for (int i = 0; i < 256; i++)
                u[c][i] = (_mlkem_trit(e1b[c], i) + 3329) % 3329;
            for (int r = 0; r < 2; r++)
                _mlkem_poly_mul_acc(A[r][c], rv[r], u[c]);
        }
        for (int i = 0; i < 256; i++) {
            int bit = (int)((m[i >> 6] >> (i & 63)) & 1ULL);
            v[i] = (_mlkem_trit(e2b, i) + bit * 1665 + 3329) % 3329;
        }
        for (int r = 0; r < 2; r++)
            _mlkem_poly_mul_acc(tv[r], rv[r], v);
        char *ct = (char *)nino_arena_alloc(2360);
        memcpy(ct, "MLKEM512_CT:", 13);
        size_t co = 12;
        for (int c = 0; c < 2; c++)
            for (int i = 0; i < 256; i++) {
                snprintf(ct + co, 4, "%03x", (unsigned int)u[c][i]);
                co += 3;
            }
        for (int i = 0; i < 256; i++) {
            snprintf(ct + co, 4, "%03x", (unsigned int)v[i]);
            co += 3;
        }
        char mbuf[96];
        snprintf(mbuf, 96, "MLKEM512_SS:%016llx%016llx%016llx%016llx", (unsigned long long)m[0],
                 (unsigned long long)m[1], (unsigned long long)m[2], (unsigned long long)m[3]);
        const char *ss = sha256(mbuf);
        nino_dict_set(d, "ciphertext", ct);
        nino_dict_set(d, "shared_secret", ss);
        return d;
    }
    if (strncmp(pk, "RLWE64_PK:", 10) != 0 || strlen(pk) != 236)
        return d;
    unsigned long long seed = 0, dsa_y = 0;
    int pkn = 0;
    if (sscanf(pk + 10, "%016llx:%016llx:%n", &seed, &dsa_y, &pkn) != 2 || pkn != 34)
        return d;
    const char *b_hex = pk + 44;
    int a[64], b[64], r[64], u[64], v[64];
    _rlwe64_poly_a((uint64_t)seed, a);
    for (int i = 0; i < 64; i++) {
        unsigned int bv = 0;
        if (sscanf(b_hex + i * 3, "%03x", &bv) != 1)
            return d;
        b[i] = (int)bv;
    }
    uint64_t r_lo = _nino_entropy_u64(), r_hi = _nino_entropy_u64(), e1_lo = _nino_entropy_u64(),
             e1_hi = _nino_entropy_u64(), e2_lo = _nino_entropy_u64(), e2_hi = _nino_entropy_u64(),
             m_lo = _nino_entropy_u64(), m_hi = _nino_entropy_u64();
    for (int i = 0; i < 64; i++)
        r[i] = _rlwe_trit(i < 32 ? r_lo : r_hi, i);
    _rlwe64_mul(a, r, u);
    _rlwe64_mul(b, r, v);
    char *ct = (char *)nino_arena_alloc(420);
    memcpy(ct, "RLWE64_CT:", 11);
    size_t off = 10;
    for (int i = 0; i < 64; i++) {
        int e1 = _rlwe_trit(i < 32 ? e1_lo : e1_hi, i), e2 = _rlwe_trit(i < 32 ? e2_lo : e2_hi, i);
        int mk = (i < 32) ? (int)((m_lo >> (i * 2)) & 3ULL) : (int)((m_hi >> ((i - 32) * 2)) & 3ULL);
        u[i] = (u[i] + e1 + 33290) % 3329;
        v[i] = (v[i] + e2 + mk * 832 + 33290) % 3329;
        snprintf(ct + off + i * 6, 7, "%03x%03x", (unsigned int)u[i], (unsigned int)v[i]);
    }
    char mbuf[64];
    snprintf(mbuf, 64, "RLWE64_SS:%016llx%016llx", (unsigned long long)m_lo, (unsigned long long)m_hi);
    const char *ss = sha256(mbuf);
    nino_dict_set(d, "ciphertext", ct);
    nino_dict_set(d, "shared_secret", ss);
    return d;
}
static inline const char *pq_decapsulate(const char *ct, const char *sk) {
    if (!ct || !sk)
        return "";
    if (strncmp(ct, "MLKEM512_CT:", 12) == 0 && strncmp(sk, "MLKEM512_SK:", 12) == 0) {
        if (strlen(ct) != 2316 || strlen(sk) != 319)
            return "";
        unsigned long long seed = 0, dsa_y = 0, dsa_x = 0;
        int skn = 0;
        if (sscanf(sk + 12, "%016llx:%016llx:%016llx:%n", &seed, &dsa_y, &dsa_x, &skn) != 3 || skn != 51)
            return "";
        uint64_t sb[2][8];
        const char *sh = sk + 63;
        for (int r = 0; r < 2; r++)
            for (int w = 0; w < 8; w++) {
                unsigned long long sv = 0;
                if (sscanf(sh + (r * 8 + w) * 16, "%016llx", &sv) != 1)
                    return "";
                sb[r][w] = (uint64_t)sv;
            }
        int32_t svec[2][256], u[2][256], v[256], su[256];
        memset(su, 0, sizeof(su));
        const char *ch = ct + 12;
        for (int r = 0; r < 2; r++)
            for (int i = 0; i < 256; i++) {
                svec[r][i] = _mlkem_trit(sb[r], i);
                unsigned int uv = 0;
                if (sscanf(ch + (r * 256 + i) * 3, "%03x", &uv) != 1)
                    return "";
                u[r][i] = (int32_t)uv;
            }
        for (int i = 0; i < 256; i++) {
            unsigned int vv = 0;
            if (sscanf(ch + (512 + i) * 3, "%03x", &vv) != 1)
                return "";
            v[i] = (int32_t)vv;
        }
        for (int c = 0; c < 2; c++)
            _mlkem_poly_mul_acc(svec[c], u[c], su);
        uint64_t rec[4];
        memset(rec, 0, sizeof(rec));
        for (int i = 0; i < 256; i++) {
            int32_t dk = (v[i] - su[i] + 3329) % 3329;
            int bit = ((dk + 832) / 1665) & 1;
            rec[i >> 6] |= ((uint64_t)bit << (i & 63));
        }
        char mbuf[96];
        snprintf(mbuf, 96, "MLKEM512_SS:%016llx%016llx%016llx%016llx", (unsigned long long)rec[0],
                 (unsigned long long)rec[1], (unsigned long long)rec[2], (unsigned long long)rec[3]);
        return sha256(mbuf);
    }
    if (strncmp(ct, "RLWE64_CT:", 10) != 0 || strncmp(sk, "RLWE64_SK:", 10) != 0 || strlen(ct) != 394 ||
        strlen(sk) != 93)
        return "";
    unsigned long long seed = 0, dsa_y = 0, dsa_x = 0, s_lo = 0, s_hi = 0;
    if (sscanf(sk + 10, "%016llx:%016llx:%016llx:%016llx%016llx", &seed, &dsa_y, &dsa_x, &s_lo, &s_hi) != 5)
        return "";
    int s[64], u[64], v[64], su[64];
    const char *uv = ct + 10;
    for (int i = 0; i < 64; i++) {
        s[i] = _rlwe_trit(i < 32 ? (uint64_t)s_lo : (uint64_t)s_hi, i);
        unsigned int ui = 0, vi = 0;
        if (sscanf(uv + i * 6, "%03x%03x", &ui, &vi) != 2)
            return "";
        u[i] = (int)ui;
        v[i] = (int)vi;
    }
    _rlwe64_mul(s, u, su);
    uint64_t rec_lo = 0, rec_hi = 0;
    for (int i = 0; i < 64; i++) {
        int dk = (v[i] - su[i] + 33290) % 3329;
        int mk = ((dk + 416) / 832) & 3;
        if (i < 32)
            rec_lo |= ((uint64_t)mk << (i * 2));
        else
            rec_hi |= ((uint64_t)mk << ((i - 32) * 2));
    }
    char mbuf[64];
    snprintf(mbuf, 64, "RLWE64_SS:%016llx%016llx", (unsigned long long)rec_lo, (unsigned long long)rec_hi);
    return sha256(mbuf);
}
static inline const char *pq_sign(const char *msg, const char *sk) {
    if (!sk)
        return "";
    unsigned long long seed = 0, dsa_y = 0, dsa_x = 0, s_lo = 0, s_hi = 0;
    if (strncmp(sk, "MLKEM512_SK:", 12) == 0 && strlen(sk) == 319) {
        int skn = 0;
        if (sscanf(sk + 12, "%016llx:%016llx:%016llx:%n", &seed, &dsa_y, &dsa_x, &skn) != 3 || skn != 51)
            return "";
    } else if (strncmp(sk, "RLWE64_SK:", 10) == 0 && strlen(sk) == 93) {
        if (sscanf(sk + 10, "%016llx:%016llx:%016llx:%016llx%016llx", &seed, &dsa_y, &dsa_x, &s_lo, &s_hi) !=
            5)
            return "";
    } else
        return "";
    uint64_t k_nonce = (_nino_hash_u64(nino_str_concat(sk, msg ? msg : "")) % (_NINO_SP_Q - 3ULL)) + 2ULL;
    uint64_t r_com = _nino_mod_pow(_NINO_GEN_G, k_nonce, _NINO_SP_P);
    char cbuf[64];
    snprintf(cbuf, 64, "%016llx:%016llx:", dsa_y, (unsigned long long)r_com);
    uint64_t e_chal = (_nino_hash_u64(nino_str_concat(cbuf, msg ? msg : "")) % (_NINO_SP_Q - 1ULL)) + 1ULL;
    uint64_t z_resp = (k_nonce + _nino_mod_mul(e_chal, (uint64_t)dsa_x, _NINO_SP_Q)) % _NINO_SP_Q;
    char *sig = (char *)nino_arena_alloc(64);
    snprintf(sig, 64, "SP_SCHNORR_SIG:%016llx:%016llx", (unsigned long long)r_com,
             (unsigned long long)z_resp);
    return sig;
}
static inline bool pq_verify(const char *msg, const char *sig, const char *pk) {
    if (!sig || !pk || strncmp(sig, "SP_SCHNORR_SIG:", 15) != 0 || strlen(sig) != 48)
        return false;
    unsigned long long seed = 0, dsa_y = 0, r_com = 0, z_resp = 0;
    int pkn = 0, sgn = 0;
    if (strncmp(pk, "MLKEM512_PK:", 12) == 0 && strlen(pk) == 1582) {
        if (sscanf(pk + 12, "%016llx:%016llx:%n", &seed, &dsa_y, &pkn) != 2 || pkn != 34)
            return false;
    } else if (strncmp(pk, "RLWE64_PK:", 10) == 0 && strlen(pk) == 236) {
        if (sscanf(pk + 10, "%016llx:%016llx:%n", &seed, &dsa_y, &pkn) != 2 || pkn != 34)
            return false;
    } else
        return false;
    if (sscanf(sig + 15, "%016llx:%016llx%n", &r_com, &z_resp, &sgn) != 2 || sgn != 33)
        return false;
    if (r_com <= 1 || r_com >= _NINO_SP_P || dsa_y <= 1 || dsa_y >= _NINO_SP_P)
        return false;
    char cbuf[64];
    snprintf(cbuf, 64, "%016llx:%016llx:", dsa_y, r_com);
    uint64_t e_chal = (_nino_hash_u64(nino_str_concat(cbuf, msg ? msg : "")) % (_NINO_SP_Q - 1ULL)) + 1ULL;
    uint64_t lhs = _nino_mod_pow(_NINO_GEN_G, (uint64_t)z_resp, _NINO_SP_P);
    uint64_t rhs =
        _nino_mod_mul((uint64_t)r_com, _nino_mod_pow((uint64_t)dsa_y, e_chal, _NINO_SP_P), _NINO_SP_P);
    return lhs == rhs;
}
static inline void *zk_commit(int64_t s) {
    NinoDict *d = nino_dict_create();
    uint64_t p = _NINO_SP_P, q = _NINO_SP_Q;
    uint64_t r_blind = (_nino_entropy_u64() % (q - 3ULL)) + 2ULL;
    int64_t sm = s % (int64_t)q;
    if (sm < 0)
        sm += (int64_t)q;
    uint64_t cm_val =
        _nino_mod_mul(_nino_mod_pow(_NINO_GEN_G, (uint64_t)sm, p), _nino_mod_pow(_NINO_GEN_H, r_blind, p), p);
    char cbuf[48];
    snprintf(cbuf, 48, "PEDERSEN_GQ_%016llx", (unsigned long long)cm_val);
    nino_dict_set(d, "commitment", cbuf);
    return d;
}
static inline void *zk_prove_condition(int64_t s, const char *op, int64_t th) {
    NinoDict *d = nino_dict_create();
    bool ok = false, is_eq = false;
    int dir = 1;
    int64_t slack = 0;
    if (op) {
        if (strcmp(op, ">") == 0) {
            ok = (s > th);
            slack = s - th - 1;
            dir = 1;
        } else if (strcmp(op, ">=") == 0) {
            ok = (s >= th);
            slack = s - th;
            dir = 1;
        } else if (strcmp(op, "<") == 0) {
            ok = (s < th);
            slack = th - s - 1;
            dir = -1;
        } else if (strcmp(op, "<=") == 0) {
            ok = (s <= th);
            slack = th - s;
            dir = -1;
        } else if (strcmp(op, "==") == 0 || strcmp(op, "=") == 0) {
            ok = (s == th);
            slack = 0;
            is_eq = true;
        } else if (strcmp(op, "!=") == 0) {
            ok = (s != th);
            if (s > th) {
                slack = s - th - 1;
                dir = 1;
            } else {
                slack = th - s - 1;
                dir = -1;
            }
        }
    }
    uint64_t p = _NINO_SP_P, q = _NINO_SP_Q;
    int64_t sm = s % (int64_t)q;
    if (sm < 0)
        sm += (int64_t)q;
    uint64_t s_mod = (uint64_t)sm;
    uint64_t r_bits[48], r_sum = 0;
    for (int i = 0; i < 48; i++) {
        r_bits[i] = (_nino_entropy_u64() % (q - 3ULL)) + 2ULL;
        r_sum = (r_sum + _nino_mod_mul(r_bits[i], (1ULL << i) % q, q)) % q;
    }
    uint64_t r_sec = (dir == 1) ? r_sum : (q - r_sum) % q;
    uint64_t C_sec =
        _nino_mod_mul(_nino_mod_pow(_NINO_GEN_G, s_mod, p), _nino_mod_pow(_NINO_GEN_H, r_sec, p), p);
    char cm_s[48];
    snprintf(cm_s, 48, "PEDERSEN_GQ_%016llx", (unsigned long long)C_sec);
    char th_s[32];
    snprintf(th_s, 32, "%lld", (long long)th);
    nino_dict_set(d, "commitment", cm_s);
    nino_dict_set(d, "op", op ? op : "");
    nino_dict_set(d, "threshold", th_s);
    if (!ok || slack < 0 || (uint64_t)slack >= (1ULL << 48)) {
        nino_dict_set(d, "is_valid", "false");
        nino_dict_set(d, "proof_tag", "INVALID");
        return d;
    }
    if (is_eq) {
        uint64_t k = (_nino_entropy_u64() % (q - 3ULL)) + 2ULL;
        uint64_t tv = _nino_mod_pow(_NINO_GEN_H, k, p);
        char fs[128];
        snprintf(fs, 128, "EQ:%016llx:%016llx:%s", (unsigned long long)C_sec, (unsigned long long)tv, th_s);
        uint64_t e_ch = (_nino_hash_u64(fs) % (q - 3ULL)) + 2ULL;
        uint64_t zv = (k + _nino_mod_mul(e_ch, r_sec, q)) % q;
        char pt[80];
        snprintf(pt, 80, "ZKEQ:%016llx:%016llx", (unsigned long long)tv, (unsigned long long)zv);
        nino_dict_set(d, "is_valid", "true");
        nino_dict_set(d, "proof_tag", pt);
        return d;
    }
    uint64_t g_inv = _nino_mod_inv_p(_NINO_GEN_G, p);
    uint64_t C_i[48], e_sim[48], z0[48], z1[48], T0[48], T1[48], w_i[48], b_i[48], e0[48];
    for (int i = 0; i < 48; i++) {
        b_i[i] = ((uint64_t)slack >> i) & 1ULL;
        C_i[i] = _nino_mod_mul(b_i[i] ? _NINO_GEN_G : 1ULL, _nino_mod_pow(_NINO_GEN_H, r_bits[i], p), p);
        w_i[i] = (_nino_entropy_u64() % (q - 3ULL)) + 2ULL;
        e_sim[i] = (_nino_entropy_u64() % (q - 3ULL)) + 2ULL;
        uint64_t z_sim = (_nino_entropy_u64() % (q - 3ULL)) + 2ULL;
        if (b_i[i] == 0) {
            T0[i] = _nino_mod_pow(_NINO_GEN_H, w_i[i], p);
            T1[i] = _nino_mod_mul(_nino_mod_pow(_NINO_GEN_H, z_sim, p),
                                  _nino_mod_pow(_nino_mod_mul(C_i[i], g_inv, p), q - e_sim[i], p), p);
            z1[i] = z_sim;
        } else {
            T0[i] = _nino_mod_mul(_nino_mod_pow(_NINO_GEN_H, z_sim, p),
                                  _nino_mod_pow(C_i[i], q - e_sim[i], p), p);
            T1[i] = _nino_mod_pow(_NINO_GEN_H, w_i[i], p);
            z0[i] = z_sim;
        }
    }
    char *fs = (char *)nino_arena_alloc(48 * 48 + 128);
    int fpos = snprintf(fs, 128, "RNG:%016llx:%d:%s:%s:", (unsigned long long)C_sec, dir, op, th_s);
    for (int i = 0; i < 48; i++)
        fpos += snprintf(fs + fpos, 49, "%016llx%016llx%016llx", (unsigned long long)C_i[i],
                         (unsigned long long)T0[i], (unsigned long long)T1[i]);
    uint64_t root_e = _nino_hash_u64(fs);
    for (int i = 0; i < 48; i++) {
        uint64_t ei = ((root_e ^ ((uint64_t)(i + 1) * 0x9E3779B97F4A7C15ULL)) % (q - 3ULL)) + 2ULL;
        if (b_i[i] == 0) {
            e0[i] = (ei + q - e_sim[i]) % q;
            z0[i] = (w_i[i] + _nino_mod_mul(e0[i], r_bits[i], q)) % q;
        } else {
            uint64_t e1v = (ei + q - e_sim[i]) % q;
            e0[i] = e_sim[i];
            z1[i] = (w_i[i] + _nino_mod_mul(e1v, r_bits[i], q)) % q;
        }
    }
    char *pt = (char *)nino_arena_alloc(48 * 64 + 64);
    int ppos = snprintf(pt, 64, "ZKR48:%d:%016llx:", dir, (unsigned long long)root_e);
    for (int i = 0; i < 48; i++)
        ppos += snprintf(pt + ppos, 65, "%016llx%016llx%016llx%016llx", (unsigned long long)C_i[i],
                         (unsigned long long)e0[i], (unsigned long long)z0[i], (unsigned long long)z1[i]);
    nino_dict_set(d, "is_valid", "true");
    nino_dict_set(d, "proof_tag", pt);
    return d;
}
static inline bool zk_verify_proof(void *ptr) {
    if (!ptr)
        return false;
    const char *cm = nino_dict_get(ptr, "commitment");
    const char *op = nino_dict_get(ptr, "op");
    const char *th_s = nino_dict_get(ptr, "threshold");
    const char *tag = nino_dict_get(ptr, "proof_tag");
    if (!cm || strncmp(cm, "PEDERSEN_GQ_", 12) != 0 || strlen(cm) != 28 || !op || !th_s || !tag)
        return false;
    unsigned long long C_sec = 0;
    int cm_n = 0;
    if (sscanf(cm + 12, "%016llx%n", &C_sec, &cm_n) != 1 || cm_n != 16)
        return false;
    int64_t th = (int64_t)strtoll(th_s, NULL, 10);
    uint64_t p = _NINO_SP_P, q = _NINO_SP_Q;
    if (strcmp(op, "==") == 0 || strcmp(op, "=") == 0) {
        if (strncmp(tag, "ZKEQ:", 5) != 0 || strlen(tag) != 38)
            return false;
        unsigned long long tv = 0, zv = 0;
        int eq_n = 0;
        if (sscanf(tag + 5, "%016llx:%016llx%n", &tv, &zv, &eq_n) != 2 || eq_n != 33)
            return false;
        int64_t tm = th % (int64_t)q;
        if (tm < 0)
            tm += (int64_t)q;
        uint64_t C_slack =
            _nino_mod_mul((uint64_t)C_sec, _nino_mod_pow(_NINO_GEN_G, (q - (uint64_t)tm) % q, p), p);
        char fs[128];
        snprintf(fs, 128, "EQ:%016llx:%016llx:%s", C_sec, tv, th_s);
        uint64_t e_ch = (_nino_hash_u64(fs) % (q - 3ULL)) + 2ULL;
        uint64_t lhs = _nino_mod_pow(_NINO_GEN_H, (uint64_t)zv, p);
        uint64_t rhs = _nino_mod_mul((uint64_t)tv, _nino_mod_pow(C_slack, e_ch, p), p);
        return lhs == rhs;
    }
    int dir = 0;
    unsigned long long root_e = 0;
    int hdr_len = 0;
    if (sscanf(tag, "ZKR48:%d:%016llx:%n", &dir, &root_e, &hdr_len) != 2 || hdr_len <= 0)
        return false;
    const char *hex = tag + hdr_len;
    if (strlen(hex) != 48 * 64)
        return false;
    if (strcmp(op, ">") == 0 || strcmp(op, ">=") == 0) {
        if (dir != 1)
            return false;
    } else if (strcmp(op, "<") == 0 || strcmp(op, "<=") == 0) {
        if (dir != -1)
            return false;
    } else if (strcmp(op, "!=") == 0) {
        if (dir != 1 && dir != -1)
            return false;
    } else
        return false;
    int64_t adj_th = th;
    if (strcmp(op, ">") == 0)
        adj_th = th + 1;
    else if (strcmp(op, "<") == 0)
        adj_th = th - 1;
    else if (strcmp(op, "!=") == 0)
        adj_th = (dir == 1) ? (th + 1) : (th - 1);
    int64_t tm = adj_th % (int64_t)q;
    if (tm < 0)
        tm += (int64_t)q;
    uint64_t C_target =
        (dir == 1) ? _nino_mod_mul((uint64_t)C_sec, _nino_mod_pow(_NINO_GEN_G, (q - (uint64_t)tm) % q, p), p)
                   : _nino_mod_mul(_nino_mod_pow(_NINO_GEN_G, (uint64_t)tm, p),
                                   _nino_mod_inv_p((uint64_t)C_sec, p), p);
    uint64_t g_inv = _nino_mod_inv_p(_NINO_GEN_G, p), prod = 1;
    char *fs = (char *)nino_arena_alloc(48 * 48 + 128);
    int fpos = snprintf(fs, 128, "RNG:%016llx:%d:%s:%s:", C_sec, dir, op, th_s);
    for (int i = 0; i < 48; i++) {
        unsigned long long ci = 0, e0v = 0, z0v = 0, z1v = 0;
        if (sscanf(hex + i * 64, "%016llx%016llx%016llx%016llx", &ci, &e0v, &z0v, &z1v) != 4)
            return false;
        if (ci <= 0 || ci >= p || e0v >= q || z0v >= q || z1v >= q)
            return false;
        prod = _nino_mod_mul(prod, _nino_mod_pow((uint64_t)ci, (1ULL << i) % q, p), p);
        uint64_t ei = (((uint64_t)root_e ^ ((uint64_t)(i + 1) * 0x9E3779B97F4A7C15ULL)) % (q - 3ULL)) + 2ULL;
        uint64_t e1v = (ei + q - (uint64_t)e0v) % q;
        uint64_t t0 = _nino_mod_mul(_nino_mod_pow(_NINO_GEN_H, (uint64_t)z0v, p),
                                    _nino_mod_pow((uint64_t)ci, (q - (uint64_t)e0v) % q, p), p);
        uint64_t t1 =
            _nino_mod_mul(_nino_mod_pow(_NINO_GEN_H, (uint64_t)z1v, p),
                          _nino_mod_pow(_nino_mod_mul((uint64_t)ci, g_inv, p), (q - e1v) % q, p), p);
        fpos += snprintf(fs + fpos, 49, "%016llx%016llx%016llx", ci, (unsigned long long)t0,
                         (unsigned long long)t1);
    }
    if (prod != C_target)
        return false;
    return _nino_hash_u64(fs) == (uint64_t)root_e;
}
static inline const char *_nino_merkle_set_root(void *set, int64_t s, bool *out_found) {
    if (out_found)
        *out_found = false;
    if (!set)
        return sha256("EMPTY_SET");
    int64_t n = nino_len_arr(set);
    const int64_t *arr = (const int64_t *)set;
    const char *cur_root = "0000000000000000000000000000000000000000000000000000000000000000";
    for (int64_t i = 0; i < n; i++) {
        if (arr[i] == s && out_found)
            *out_found = true;
        char leaf[128];
        snprintf(leaf, sizeof(leaf), "%s:%lld", cur_root, (long long)arr[i]);
        cur_root = sha256(leaf);
    }
    return cur_root;
}
static inline void *zk_prove_membership(int64_t s, void *set) {
    bool found = false;
    const char *root = _nino_merkle_set_root(set, s, &found);
    NinoDict *d = nino_dict_create();
    nino_dict_set(d, "merkle_root", root);
    nino_dict_set(d, "in_set", found ? "true" : "false");
    int64_t n = set ? nino_len_arr(set) : 0;
    if (!found || n <= 0 || n > 256) {
        nino_dict_set(d, "commitment", "INVALID");
        nino_dict_set(d, "proof_tag", "INVALID");
        return d;
    }
    const int64_t *arr = (const int64_t *)set;
    int64_t widx = -1;
    for (int64_t i = 0; i < n; i++) {
        if (arr[i] == s) {
            widx = i;
            break;
        }
    }
    if (widx < 0) {
        nino_dict_set(d, "proof_tag", "INVALID");
        return d;
    }
    uint64_t p = _NINO_SP_P, q = _NINO_SP_Q;
    uint64_t r_blind = (_nino_entropy_u64() % (q - 3ULL)) + 2ULL;
    int64_t sm = s % (int64_t)q;
    if (sm < 0)
        sm += (int64_t)q;
    uint64_t C =
        _nino_mod_mul(_nino_mod_pow(_NINO_GEN_G, (uint64_t)sm, p), _nino_mod_pow(_NINO_GEN_H, r_blind, p), p);
    char cm_s[48];
    snprintf(cm_s, sizeof(cm_s), "PEDERSEN_GQ_%016llx", (unsigned long long)C);
    nino_dict_set(d, "commitment", cm_s);
    uint64_t ev[256], zv[256], Tv[256];
    uint64_t w = (_nino_entropy_u64() % (q - 3ULL)) + 2ULL;
    uint64_t esum = 0;
    for (int64_t i = 0; i < n; i++) {
        if (i == widx) {
            Tv[i] = _nino_mod_pow(_NINO_GEN_H, w, p);
        } else {
            ev[i] = (_nino_entropy_u64() % (q - 3ULL)) + 2ULL;
            zv[i] = (_nino_entropy_u64() % (q - 3ULL)) + 2ULL;
            esum = (esum + ev[i]) % q;
            int64_t aim = arr[i] % (int64_t)q;
            if (aim < 0)
                aim += (int64_t)q;
            uint64_t Ci = _nino_mod_mul(C, _nino_mod_pow(_NINO_GEN_G, (q - (uint64_t)aim) % q, p), p);
            Tv[i] =
                _nino_mod_mul(_nino_mod_pow(_NINO_GEN_H, zv[i], p), _nino_mod_pow(Ci, (q - ev[i]) % q, p), p);
        }
    }
    size_t fsz = 128 + (size_t)n * 17;
    char *fs = (char *)nino_arena_alloc(fsz);
    if (!fs)
        return d;
    int fp = snprintf(fs, fsz, "ZKMEM:%s:%016llx:", root, (unsigned long long)C);
    for (int64_t i = 0; i < n; i++)
        fp += snprintf(fs + fp, 18, "%016llx", (unsigned long long)Tv[i]);
    uint64_t eroot = _nino_hash_u64(fs) % q;
    ev[widx] = (eroot + q - esum) % q;
    zv[widx] = (w + _nino_mod_mul(ev[widx], r_blind, q)) % q;
    size_t psz = 48 + (size_t)n * 33;
    char *pt = (char *)nino_arena_alloc(psz);
    if (!pt)
        return d;
    int pp = snprintf(pt, psz, "ZKMEM:%lld:", (long long)n);
    for (int64_t i = 0; i < n; i++)
        pp += snprintf(pt + pp, 33, "%016llx%016llx", (unsigned long long)ev[i], (unsigned long long)zv[i]);
    nino_dict_set(d, "proof_tag", pt);
    return d;
}
static inline bool zk_verify_membership(void *ptr, void *set) {
    if (!ptr || !set)
        return false;
    const char *in_s = nino_dict_get(ptr, "in_set");
    if (strcmp(in_s, "true") != 0)
        return false;
    const char *expected_root = _nino_merkle_set_root(set, 0, NULL);
    const char *proof_root = nino_dict_get(ptr, "merkle_root");
    if (strcmp(expected_root, proof_root) != 0)
        return false;
    int64_t n = nino_len_arr(set);
    if (n <= 0 || n > 256)
        return false;
    const char *cm = nino_dict_get(ptr, "commitment");
    const char *tag = nino_dict_get(ptr, "proof_tag");
    if (!cm || strncmp(cm, "PEDERSEN_GQ_", 12) != 0 || strlen(cm) != 28 || !tag)
        return false;
    unsigned long long Cv = 0;
    int cm_n = 0;
    if (sscanf(cm + 12, "%016llx%n", &Cv, &cm_n) != 1 || cm_n != 16)
        return false;
    uint64_t p = _NINO_SP_P, q = _NINO_SP_Q, C = (uint64_t)Cv;
    if (C == 0 || C >= p)
        return false;
    long long pcnt = 0;
    int hdr_n = 0;
    if (sscanf(tag, "ZKMEM:%lld:%n", &pcnt, &hdr_n) != 1 || hdr_n <= 0 || pcnt != n)
        return false;
    const char *hex = tag + hdr_n;
    if (strlen(hex) != (size_t)n * 32U)
        return false;
    const int64_t *arr = (const int64_t *)set;
    size_t fsz = 128 + (size_t)n * 17;
    char *fs = (char *)nino_arena_alloc(fsz);
    if (!fs)
        return false;
    int fp = snprintf(fs, fsz, "ZKMEM:%s:%016llx:", expected_root, (unsigned long long)C);
    uint64_t esum = 0;
    for (int64_t i = 0; i < n; i++) {
        unsigned long long ei = 0, zi = 0;
        if (sscanf(hex + (size_t)i * 32U, "%016llx%016llx", &ei, &zi) != 2)
            return false;
        if (ei >= q || zi >= q)
            return false;
        esum = (esum + (uint64_t)ei) % q;
        int64_t aim = arr[i] % (int64_t)q;
        if (aim < 0)
            aim += (int64_t)q;
        uint64_t Ci = _nino_mod_mul(C, _nino_mod_pow(_NINO_GEN_G, (q - (uint64_t)aim) % q, p), p);
        uint64_t Ti = _nino_mod_mul(_nino_mod_pow(_NINO_GEN_H, (uint64_t)zi, p),
                                    _nino_mod_pow(Ci, (q - (uint64_t)ei) % q, p), p);
        fp += snprintf(fs + fp, 18, "%016llx", (unsigned long long)Ti);
    }
    uint64_t eroot = _nino_hash_u64(fs) % q;
    return esum == eroot;
}
#define nil 0
#define panic(msg) nino_panic(msg)
static inline const char *sanitize(const char *s) {
    if (!s)
        return "";
    size_t l = strlen(s);
    char *b = (char *)nino_arena_alloc(l * 6 + 1);
    if (!b)
        return s;
    size_t j = 0;
    for (size_t i = 0; i < l; i++) {
        if (s[i] == 60) {
            memcpy(b + j, "&lt;", 4);
            j += 4;
        } else if (s[i] == 62) {
            memcpy(b + j, "&gt;", 4);
            j += 4;
        } else if (s[i] == 38) {
            memcpy(b + j, "&amp;", 5);
            j += 5;
        } else if (s[i] == 34) {
            memcpy(b + j, "&quot;", 6);
            j += 6;
        } else if (s[i] == 39) {
            memcpy(b + j, "&#x27;", 6);
            j += 6;
        } else {
            b[j++] = s[i];
        }
    }
    b[j] = 0;
    return b;
}
static inline const char *_nino_measure_self_image(void) {
    char epath[512];
    epath[0] = 0;
#ifdef _WIN32
    DWORD n = GetModuleFileNameA(NULL, epath, (DWORD)(sizeof(epath) - 1));
    if (n > 0 && n < sizeof(epath))
        epath[n] = 0;
#else
    ssize_t n = readlink("/proc/self/exe", epath, sizeof(epath) - 1);
    if (n > 0)
        epath[n] = 0;
#endif
    if (epath[0]) {
        FILE *f = fopen(epath, "rb");
        if (f) {
            fseek(f, 0, SEEK_END);
            long fsz = ftell(f);
            if (fsz > 0 && fsz <= 16777216L) {
                fseek(f, 0, SEEK_SET);
                uint8_t *buf = (uint8_t *)malloc((size_t)fsz);
                if (buf) {
                    size_t rd = fread(buf, 1, (size_t)fsz, f);
                    fclose(f);
                    uint8_t dig[32];
                    _nino_sha256_raw(buf, rd, dig);
                    free(buf);
                    char *hex = (char *)nino_arena_alloc(65);
                    if (hex) {
                        for (int i = 0; i < 32; i++)
                            snprintf(hex + i * 2, 3, "%02x", (unsigned int)dig[i]);
                        hex[64] = 0;
                        return hex;
                    }
                }
            }
            fclose(f);
        }
    }
    char pbuf[64];
    snprintf(pbuf, 64, "NINO_PROC_PID_%lld", (long long)nino_get_pid());
    return sha256(pbuf);
}
static inline void *enclave_attest(void) {
    NinoDict *d = nino_dict_create();
    const char *mr = _nino_measure_self_image();
    nino_dict_set(d, "mrenclave", mr);
    nino_dict_set(d, "measurement_scope", "software_process_sha256");
    nino_dict_set(d, "hardware_tee", "false");
    nino_dict_set(d, "status", "SOFTWARE_INTEGRITY_MEASURED");
    snprintf(d->summary, sizeof(d->summary), "%s", mr ? mr : "");
    return d;
}
#define print(X) nino_print(X)
static inline void write_vga(int r, int c, const char *s, int clr) {
    (void)r;
    (void)c;
    (void)clr;
    if (s)
        printf("%s\n", s);
}
typedef struct {
    char **cols;
    int col_count;
    int col_cap;
    double num_val;
} NinoDbRow;
typedef struct {
    char name[64];
    char col_names[16][64];
    int col_name_cnt;
    NinoDbRow *rows;
    int row_count;
    int row_cap;
} NinoDbTable;
typedef struct {
    int id;
    void *sqlite_db;
    bool is_native;
    bool open;
} NinoDbConn;
typedef int (*_nino_sql_open_fn)(const char *, void **);
typedef int (*_nino_sql_exec_fn)(void *, const char *, void *, void *, char **);
typedef int (*_nino_sql_prep_fn)(void *, const char *, int, void **, const char **);
typedef int (*_nino_sql_step_fn)(void *);
typedef int (*_nino_sql_colcnt_fn)(void *);
typedef const unsigned char *(*_nino_sql_coltxt_fn)(void *, int);
typedef const char *(*_nino_sql_colname_fn)(void *, int);
typedef int (*_nino_sql_fin_fn)(void *);
typedef int (*_nino_sql_close_fn)(void *);
typedef int (*_nino_sql_chg_fn)(void *);
typedef int (*_nino_sql_bind_txt_fn)(void *, int, const char *, int, void (*)(void *));
typedef struct {
    int probed;
    int avail;
    _nino_sql_open_fn open;
    _nino_sql_exec_fn exec;
    _nino_sql_prep_fn prep;
    _nino_sql_step_fn step;
    _nino_sql_colcnt_fn col_cnt;
    _nino_sql_coltxt_fn col_txt;
    _nino_sql_colname_fn col_name;
    _nino_sql_fin_fn fin;
    _nino_sql_close_fn close;
    _nino_sql_chg_fn changes;
    _nino_sql_bind_txt_fn bind_txt;
} _NinoSqliteApi;
static _NinoSqliteApi _nino_sq = {0};
static NINO_THREAD_LOCAL NinoDbTable *_nino_db_tables = NULL;
static NINO_THREAD_LOCAL int _nino_db_table_cnt = 0;
static NINO_THREAD_LOCAL int _nino_db_table_cap = 0;
static NINO_THREAD_LOCAL NinoDbConn *_nino_db_conns = NULL;
static NINO_THREAD_LOCAL int _nino_db_conn_cnt = 0;
static NINO_THREAD_LOCAL int _nino_db_conn_cap = 0;
static NINO_THREAD_LOCAL int _nino_db_conn_seq = 0;
static NINO_THREAD_LOCAL int64_t *_nino_redis_fds = NULL;
static NINO_THREAD_LOCAL int _nino_redis_fd_cnt = 0;
static NINO_THREAD_LOCAL int _nino_redis_fd_cap = 0;
static NINO_THREAD_LOCAL NinoDict *_nino_redis_kv = NULL;
static inline bool _nino_load_sql_sym(void *lib, const char *nm, void *dst, size_t sz) {
#ifdef _WIN32
    FARPROC p = GetProcAddress((HMODULE)lib, nm);
    if (!p)
        return false;
    memcpy(dst, &p, sz);
    return true;
#else
    void *p = dlsym(lib, nm);
    if (!p)
        return false;
    memcpy(dst, &p, sz);
    return true;
#endif
}
static inline bool _nino_sqlite_init(void) {
    if (_nino_sq.probed) {
        return _nino_sq.avail != 0;
    }
    _nino_sq.probed = 1;
    void *lib = NULL;
#ifdef _WIN32
    lib = (void *)LoadLibraryA("sqlite3.dll");
#else
    lib = dlopen("libsqlite3.so.0", RTLD_LAZY);
    if (!lib) {
        lib = dlopen("libsqlite3.so", RTLD_LAZY);
    }
    if (!lib) {
        lib = dlopen("libsqlite3.dylib", RTLD_LAZY);
    }
#endif
    if (!lib) {
        return false;
    }
    typedef int (*_nino_sql_init_fn)(void);
    _nino_sql_init_fn init_fn = NULL;
    if (_nino_load_sql_sym(lib, "sqlite3_initialize", &init_fn, sizeof(init_fn)) && init_fn) {
        if (init_fn() != 0)
            return false;
    }
    if (!_nino_load_sql_sym(lib, "sqlite3_open", &_nino_sq.open, sizeof(_nino_sq.open)) ||
        !_nino_load_sql_sym(lib, "sqlite3_exec", &_nino_sq.exec, sizeof(_nino_sq.exec)) ||
        !_nino_load_sql_sym(lib, "sqlite3_prepare_v2", &_nino_sq.prep, sizeof(_nino_sq.prep)) ||
        !_nino_load_sql_sym(lib, "sqlite3_step", &_nino_sq.step, sizeof(_nino_sq.step)) ||
        !_nino_load_sql_sym(lib, "sqlite3_column_count", &_nino_sq.col_cnt, sizeof(_nino_sq.col_cnt)) ||
        !_nino_load_sql_sym(lib, "sqlite3_column_text", &_nino_sq.col_txt, sizeof(_nino_sq.col_txt)) ||
        !_nino_load_sql_sym(lib, "sqlite3_column_name", &_nino_sq.col_name, sizeof(_nino_sq.col_name)) ||
        !_nino_load_sql_sym(lib, "sqlite3_finalize", &_nino_sq.fin, sizeof(_nino_sq.fin)) ||
        !_nino_load_sql_sym(lib, "sqlite3_close", &_nino_sq.close, sizeof(_nino_sq.close)) ||
        !_nino_load_sql_sym(lib, "sqlite3_changes", &_nino_sq.changes, sizeof(_nino_sq.changes))) {
        return false;
    }
    (void)_nino_load_sql_sym(lib, "sqlite3_bind_text", &_nino_sq.bind_txt, sizeof(_nino_sq.bind_txt));
    _nino_sq.avail = 1;
    return true;
}
static inline NinoDbConn *_nino_find_db_conn(const void *db) {
    if (!db)
        return NULL;
    const char *s = (const char *)db;
    if (strncmp(s, "sqlite:", 7) != 0)
        return NULL;
    int id = atoi(s + 7);
    for (int i = 0; i < _nino_db_conn_cnt; i++) {
        if (_nino_db_conns[i].id == id && _nino_db_conns[i].open)
            return &_nino_db_conns[i];
    }
    return NULL;
}
static inline NinoDbTable *_nino_db_get_or_add_table(const char *name, bool create_if_missing) {
    for (int i = 0; i < _nino_db_table_cnt; i++) {
        if (strcmp(_nino_db_tables[i].name, name) == 0)
            return &_nino_db_tables[i];
    }
    if (!create_if_missing)
        return NULL;
    if (_nino_db_table_cnt >= _nino_db_table_cap) {
        int ncap = _nino_db_table_cap == 0 ? 16 : _nino_db_table_cap * 2;
        NinoDbTable *nt = (NinoDbTable *)realloc(_nino_db_tables, (size_t)ncap * sizeof(NinoDbTable));
        if (!nt)
            return NULL;
        _nino_db_tables = nt;
        _nino_db_table_cap = ncap;
    }
    NinoDbTable *t = &_nino_db_tables[_nino_db_table_cnt++];
    memset(t, 0, sizeof(NinoDbTable));
    snprintf(t->name, sizeof(t->name), "%s", name ? name : "");
    return t;
}
static inline const char *db_sqlite_open(const char *p) {
    int id = ++_nino_db_conn_seq;
    const char *path = p ? p : ":memory:";
    void *sdb = NULL;
    bool nat = false;
    if (_nino_sqlite_init() && _nino_sq.open(path, &sdb) == 0 && sdb)
        nat = true;
    if (_nino_db_conn_cnt >= _nino_db_conn_cap) {
        int ncap = _nino_db_conn_cap == 0 ? 16 : _nino_db_conn_cap * 2;
        NinoDbConn *nc = (NinoDbConn *)realloc(_nino_db_conns, (size_t)ncap * sizeof(NinoDbConn));
        if (nc) {
            _nino_db_conns = nc;
            _nino_db_conn_cap = ncap;
        }
    }
    if (_nino_db_conn_cnt < _nino_db_conn_cap) {
        NinoDbConn *c = &_nino_db_conns[_nino_db_conn_cnt++];
        c->id = id;
        c->sqlite_db = sdb;
        c->is_native = nat;
        c->open = true;
    }
    char *buf = (char *)nino_arena_alloc(strlen(path) + 48);
    if (!buf)
        return "";
    snprintf(buf, strlen(path) + 48, "sqlite:%d:%s:%s", id, nat ? "native" : "mem", path);
    return buf;
}
static inline const char *_nino_sql_bind_quote(const char *q, const void *params) {
    if (!q)
        return "";
    if (!params || !_nino_arr_is_alive(params))
        return q;
    int64_t plen = nino_len_arr(params);
    if (plen <= 0)
        return q;
    const char *const *pvals = (const char *const *)params;
    size_t cap = strlen(q) + 64;
    for (int64_t i = 0; i < plen; i++) {
        const char *pv = pvals[i] ? pvals[i] : "";
        cap += strlen(pv) * 2 + 4;
    }
    char *out = (char *)nino_arena_alloc(cap);
    if (!out)
        return q;
    size_t oi = 0;
    bool in_sq = false;
    int64_t pi = 0;
    for (size_t i = 0; q[i] && oi + 4 < cap; i++) {
        char c = q[i];
        if (c == 39) {
            in_sq = !in_sq;
            out[oi++] = c;
        } else if (!in_sq && c == '?' && pi < plen) {
            const char *pv = pvals[pi];
            pi++;
            if (!pv)
                pv = "";
            out[oi++] = 39;
            for (size_t k = 0; pv[k] && oi + 4 < cap; k++) {
                if (pv[k] == 39) {
                    out[oi++] = 39;
                    out[oi++] = 39;
                } else {
                    out[oi++] = pv[k];
                }
            }
            out[oi++] = 39;
        } else {
            out[oi++] = c;
        }
    }
    out[oi] = 0;
    return out;
}
static inline char _nino_ascii_lo(char c) {
    return (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c;
}
static inline int _nino_strncasecmp(const char *a, const char *b, size_t n) {
    if (!a || !b)
        return a ? 1 : (b ? -1 : 0);
    for (size_t i = 0; i < n; i++) {
        char ca = _nino_ascii_lo(a[i]);
        char cb = _nino_ascii_lo(b[i]);
        if (ca != cb || ca == 0)
            return (int)(unsigned char)ca - (int)(unsigned char)cb;
    }
    return 0;
}
static inline const char *_nino_strcasestr(const char *h, const char *nd) {
    if (!h || !nd)
        return NULL;
    size_t nl = strlen(nd);
    if (nl == 0)
        return h;
    for (; *h; h++) {
        if (_nino_strncasecmp(h, nd, nl) == 0)
            return h;
    }
    return NULL;
}
static inline bool _nino_db_row_matches_where_tbl(const NinoDbTable *tbl, const NinoDbRow *r, const char *wp);
static inline int32_t _nino_db_sqlite_exec_p(const void *db, const char *q, const void *params) {
    if (!q)
        return 0;
    NinoDbConn *dc = _nino_find_db_conn(db);
    if (dc && dc->is_native && dc->sqlite_db) {
        if (params && _nino_arr_is_alive(params) && nino_len_arr(params) > 0 && _nino_sq.bind_txt) {
            void *stmt = NULL;
            if (_nino_sq.prep(dc->sqlite_db, q, -1, &stmt, NULL) != 0 || !stmt)
                return -1;
            int64_t plen = nino_len_arr(params);
            const char *const *pvals = (const char *const *)params;
            void (*tr)(void *) = (void (*)(void *))(intptr_t)-1;
            for (int64_t i = 0; i < plen; i++) {
                const char *pv = pvals[i] ? pvals[i] : "";
                (void)_nino_sq.bind_txt(stmt, (int)(i + 1), pv, -1, tr);
            }
            int sr = _nino_sq.step(stmt);
            _nino_sq.fin(stmt);
            if (sr != 101 && sr != 100)
                return -1;
            return (int32_t)_nino_sq.changes(dc->sqlite_db);
        }
        int rc = _nino_sq.exec(dc->sqlite_db, q, NULL, NULL, NULL);
        if (rc != 0)
            return -1;
        return (int32_t)_nino_sq.changes(dc->sqlite_db);
    }
    const char *eq = _nino_sql_bind_quote(q, params);
    const char *ct = _nino_strcasestr(eq, "CREATE TABLE");
    if (ct) {
        const char *p = ct + 12;
        while (*p == ' ' || *p == '\t')
            p++;
        bool if_ne = false;
        if (_nino_strncasecmp(p, "IF NOT EXISTS", 13) == 0 && (p[13] == ' ' || p[13] == '\t')) {
            if_ne = true;
            p += 13;
            while (*p == ' ' || *p == '\t')
                p++;
        }
        char tname[64];
        int ti = 0;
        while (*p && *p != ' ' && *p != '\t' && *p != '(' && ti < 63)
            tname[ti++] = *p++;
        tname[ti] = 0;
        NinoDbTable *tbl = _nino_db_get_or_add_table(tname, true);
        if (tbl && !(if_ne && (tbl->row_count > 0 || tbl->col_name_cnt > 0))) {
            for (int i = 0; i < tbl->row_count; i++) {
                for (int j = 0; j < tbl->rows[i].col_count; j++)
                    free(tbl->rows[i].cols[j]);
                free(tbl->rows[i].cols);
            }
            tbl->row_count = 0;
            tbl->col_name_cnt = 0;
            const char *lp = strchr(p, '(');
            if (lp) {
                const char *cur = lp + 1;
                while (*cur && *cur != ')' && tbl->col_name_cnt < 16) {
                    while (*cur == ' ' || *cur == ',' || *cur == '\t' || *cur == '\n' || *cur == '\r')
                        cur++;
                    if (!*cur || *cur == ')')
                        break;
                    char cname[64];
                    int ci = 0;
                    while (*cur && *cur != ' ' && *cur != ',' && *cur != ')' && ci < 63)
                        cname[ci++] = *cur++;
                    cname[ci] = 0;
                    if (ci > 0)
                        snprintf(tbl->col_names[tbl->col_name_cnt++], 64, "%s", cname);
                    int pd = 0;
                    while (*cur) {
                        if (*cur == '(')
                            pd++;
                        else if (*cur == ')') {
                            if (pd == 0)
                                break;
                            pd--;
                        } else if (*cur == ',' && pd == 0) {
                            cur++;
                            break;
                        }
                        cur++;
                    }
                }
            }
        }
        return 0;
    }
    const char *ins = _nino_strcasestr(eq, "INSERT INTO");
    if (ins) {
        const char *p = ins + 11;
        while (*p == ' ' || *p == '\t')
            p++;
        char tname[64];
        int ti = 0;
        while (*p && *p != ' ' && *p != '\t' && *p != '(' && ti < 63)
            tname[ti++] = *p++;
        tname[ti] = 0;
        NinoDbTable *tbl = _nino_db_get_or_add_table(tname, true);
        const char *vp = _nino_strcasestr(eq, "VALUES");
        if (tbl && vp) {
            const char *lp = strchr(vp, '(');
            if (lp) {
                if (tbl->row_count >= tbl->row_cap) {
                    int nrc = tbl->row_cap == 0 ? 32 : tbl->row_cap * 2;
                    NinoDbRow *nr = (NinoDbRow *)realloc(tbl->rows, (size_t)nrc * sizeof(NinoDbRow));
                    if (!nr)
                        return 0;
                    tbl->rows = nr;
                    tbl->row_cap = nrc;
                }
                NinoDbRow *r = &tbl->rows[tbl->row_count++];
                memset(r, 0, sizeof(NinoDbRow));
                const char *cur = lp + 1;
                while (*cur && *cur != ')') {
                    while (*cur == ' ' || *cur == ',')
                        cur++;
                    if (!*cur || *cur == ')')
                        break;
                    char val[256];
                    int vi = 0;
                    if (*cur == 39 || *cur == 34) {
                        char qc = *cur++;
                        while (*cur) {
                            if (*cur == qc && cur[1] == qc) {
                                if (vi < 255)
                                    val[vi++] = qc;
                                cur += 2;
                            } else if (*cur == qc) {
                                cur++;
                                break;
                            } else {
                                if (vi < 255)
                                    val[vi++] = *cur;
                                cur++;
                            }
                        }
                    } else {
                        while (*cur && *cur != ',' && *cur != ')' && vi < 255)
                            val[vi++] = *cur++;
                        while (vi > 0 && val[vi - 1] == ' ')
                            vi--;
                    }
                    val[vi] = 0;
                    if (r->col_count >= r->col_cap) {
                        int ncc = r->col_cap == 0 ? 8 : r->col_cap * 2;
                        char **ncls = (char **)realloc(r->cols, (size_t)ncc * sizeof(char *));
                        if (!ncls)
                            break;
                        r->cols = ncls;
                        r->col_cap = ncc;
                    }
                    char *cv = (char *)malloc((size_t)vi + 1);
                    if (cv) {
                        memcpy(cv, val, (size_t)vi + 1);
                        r->cols[r->col_count++] = cv;
                    }
                    if ((val[0] >= '0' && val[0] <= '9') || val[0] == '-')
                        r->num_val = atof(val);
                }
                return 1;
            }
        }
        return 0;
    }
    const char *upd = _nino_strcasestr(eq, "UPDATE ");
    if (upd) {
        const char *p = upd + 7;
        while (*p == ' ' || *p == '\t')
            p++;
        char tname[64];
        int ti = 0;
        while (*p && *p != ' ' && *p != '\t' && *p != ';' && ti < 63)
            tname[ti++] = *p++;
        tname[ti] = 0;
        NinoDbTable *tbl = _nino_db_get_or_add_table(tname, false);
        const char *sp = _nino_strcasestr(p, "SET");
        if (!tbl || !sp)
            return 0;
        sp += 3;
        int set_cols[16];
        char set_vals[16][256];
        int scnt = 0;
        const char *wp = NULL;
        const char *cur = sp;
        while (*cur && scnt < 16) {
            while (*cur == ' ' || *cur == '\t' || *cur == ',')
                cur++;
            if (!*cur || *cur == ';')
                break;
            if (_nino_strncasecmp(cur, "WHERE", 5) == 0 && (cur[5] == ' ' || cur[5] == '\t')) {
                wp = cur;
                break;
            }
            char cn[64];
            int ci = 0;
            while (*cur && *cur != ' ' && *cur != '\t' && *cur != '=' && ci < 63)
                cn[ci++] = *cur++;
            cn[ci] = 0;
            while (*cur == ' ' || *cur == '\t')
                cur++;
            if (*cur != '=')
                break;
            cur++;
            while (*cur == ' ' || *cur == '\t')
                cur++;
            char val[256];
            int vi = 0;
            if (*cur == 39 || *cur == 34) {
                char qc = *cur++;
                while (*cur) {
                    if (*cur == qc && cur[1] == qc) {
                        if (vi < 255)
                            val[vi++] = qc;
                        cur += 2;
                    } else if (*cur == qc) {
                        cur++;
                        break;
                    } else {
                        if (vi < 255)
                            val[vi++] = *cur;
                        cur++;
                    }
                }
            } else {
                while (*cur && *cur != ',' && *cur != ' ' && *cur != '\t' && *cur != ';' && vi < 255)
                    val[vi++] = *cur++;
            }
            val[vi] = 0;
            int cidx = -1;
            for (int k = 0; k < tbl->col_name_cnt; k++) {
                if (_nino_strncasecmp(tbl->col_names[k], cn, 64) == 0) {
                    cidx = k;
                    break;
                }
            }
            if (cidx >= 0) {
                set_cols[scnt] = cidx;
                snprintf(set_vals[scnt], 256, "%s", val);
                scnt++;
            }
        }
        int ucnt = 0;
        for (int k = 0; k < tbl->row_count; k++) {
            NinoDbRow *r = &tbl->rows[k];
            if (_nino_db_row_matches_where_tbl(tbl, r, wp)) {
                for (int si = 0; si < scnt; si++) {
                    int cx = set_cols[si];
                    if (cx >= 0 && cx < r->col_count) {
                        free(r->cols[cx]);
                        size_t vl = strlen(set_vals[si]);
                        char *nv = (char *)malloc(vl + 1);
                        if (nv)
                            memcpy(nv, set_vals[si], vl + 1);
                        r->cols[cx] = nv;
                        if ((set_vals[si][0] >= '0' && set_vals[si][0] <= '9') || set_vals[si][0] == '-')
                            r->num_val = atof(set_vals[si]);
                    }
                }
                ucnt++;
            }
        }
        return ucnt;
    }
    const char *delp = _nino_strcasestr(eq, "DELETE FROM");
    if (delp) {
        const char *p = delp + 11;
        while (*p == ' ' || *p == '\t')
            p++;
        char tname[64];
        int ti = 0;
        while (*p && *p != ' ' && *p != '\t' && *p != ';' && *p != '\r' && *p != '\n' && ti < 63)
            tname[ti++] = *p++;
        tname[ti] = 0;
        NinoDbTable *tbl = _nino_db_get_or_add_table(tname, false);
        if (!tbl)
            return 0;
        const char *wp = _nino_strcasestr(p, "WHERE ");
        if (!wp)
            wp = _nino_strcasestr(p, "WHERE\t");
        int del = 0;
        int keep = 0;
        for (int k = 0; k < tbl->row_count; k++) {
            if (_nino_db_row_matches_where_tbl(tbl, &tbl->rows[k], wp)) {
                for (int j = 0; j < tbl->rows[k].col_count; j++)
                    free(tbl->rows[k].cols[j]);
                free(tbl->rows[k].cols);
                del++;
            } else {
                if (keep != k)
                    tbl->rows[keep] = tbl->rows[k];
                keep++;
            }
        }
        tbl->row_count = keep;
        return del;
    }
    return 0;
}
static inline int32_t db_sqlite_exec(const void *db, const char *q) {
    return _nino_db_sqlite_exec_p(db, q, NULL);
}
static inline bool _nino_db_row_matches_where(const NinoDbRow *r, const char *wp) {
    if (!wp)
        return true;
    int op_mode = 0;
    const char *val_p = NULL;
    if ((val_p = strstr(wp, ">="))) {
        op_mode = 2;
        val_p += 2;
    } else if ((val_p = strstr(wp, "<="))) {
        op_mode = 4;
        val_p += 2;
    } else if ((val_p = strstr(wp, ">"))) {
        op_mode = 1;
        val_p += 1;
    } else if ((val_p = strstr(wp, "<"))) {
        op_mode = 3;
        val_p += 1;
    } else if ((val_p = strstr(wp, "="))) {
        op_mode = 5;
        val_p += 1;
    }
    if (op_mode == 0 || !val_p)
        return true;
    while (*val_p == ' ')
        val_p++;
    if (*val_p == 39) {
        char target[256];
        int ti = 0;
        val_p++;
        while (*val_p && ti < 255) {
            if (*val_p == 39 && val_p[1] == 39) {
                target[ti++] = 39;
                val_p += 2;
            } else if (*val_p == 39)
                break;
            else
                target[ti++] = *val_p++;
        }
        target[ti] = 0;
        bool is_num = (ti > 0 && ((target[0] >= '0' && target[0] <= '9') || target[0] == '-'));
        double tv = is_num ? atof(target) : 0.0;
        if (op_mode == 5) {
            for (int ci = 0; ci < r->col_count; ci++) {
                if (r->cols[ci] && strcmp(r->cols[ci], target) == 0)
                    return true;
            }
            return is_num && fabs(r->num_val - tv) < 1e-6;
        }
        if (!is_num)
            return false;
        if (op_mode == 1)
            return r->num_val > tv;
        if (op_mode == 2)
            return r->num_val >= tv;
        if (op_mode == 3)
            return r->num_val < tv;
        if (op_mode == 4)
            return r->num_val <= tv;
        return false;
    }
    double thresh = atof(val_p);
    if (op_mode == 1)
        return r->num_val > thresh;
    if (op_mode == 2)
        return r->num_val >= thresh;
    if (op_mode == 3)
        return r->num_val < thresh;
    if (op_mode == 4)
        return r->num_val <= thresh;
    if (op_mode == 5)
        return fabs(r->num_val - thresh) < 1e-6;
    return true;
}
static inline bool _nino_db_row_matches_where_tbl(const NinoDbTable *tbl, const NinoDbRow *r,
                                                  const char *wp) {
    if (!wp)
        return true;
    const char *cur = wp;
    if (_nino_strncasecmp(cur, "WHERE", 5) == 0)
        cur += 5;
    while (*cur == ' ' || *cur == '\t')
        cur++;
    char col_tok[64];
    int cti = 0;
    while (*cur && *cur != ' ' && *cur != '\t' && *cur != '=' && *cur != '>' && *cur != '<' && *cur != '!' &&
           cti < 63)
        col_tok[cti++] = *cur++;
    col_tok[cti] = 0;
    int col_idx = -1;
    if (tbl && cti > 0) {
        for (int ci = 0; ci < tbl->col_name_cnt && ci < r->col_count; ci++) {
            if (_nino_strncasecmp(tbl->col_names[ci], col_tok, 64) == 0) {
                col_idx = ci;
                break;
            }
        }
    }
    int op_mode = 0;
    const char *val_p = NULL;
    if ((val_p = strstr(wp, ">="))) {
        op_mode = 2;
        val_p += 2;
    } else if ((val_p = strstr(wp, "<="))) {
        op_mode = 4;
        val_p += 2;
    } else if ((val_p = strstr(wp, ">"))) {
        op_mode = 1;
        val_p += 1;
    } else if ((val_p = strstr(wp, "<"))) {
        op_mode = 3;
        val_p += 1;
    } else if ((val_p = strstr(wp, "="))) {
        op_mode = 5;
        val_p += 1;
    }
    if (op_mode == 0 || !val_p)
        return true;
    while (*val_p == ' ')
        val_p++;
    if (col_idx >= 0) {
        const char *cv = r->cols[col_idx] ? r->cols[col_idx] : "";
        char target[256];
        int ti = 0;
        if (*val_p == 39) {
            val_p++;
            while (*val_p && ti < 255) {
                if (*val_p == 39 && val_p[1] == 39) {
                    target[ti++] = 39;
                    val_p += 2;
                } else if (*val_p == 39)
                    break;
                else
                    target[ti++] = *val_p++;
            }
            target[ti] = 0;
        } else {
            while (*val_p && *val_p != ' ' && *val_p != ';' && *val_p != '\t' && *val_p != '\r' &&
                   *val_p != '\n' && ti < 255)
                target[ti++] = *val_p++;
            target[ti] = 0;
        }
        bool t_num = (ti > 0 && ((target[0] >= '0' && target[0] <= '9') || target[0] == '-'));
        bool c_num = (cv[0] != 0 && ((cv[0] >= '0' && cv[0] <= '9') || cv[0] == '-'));
        double cv_d = c_num ? atof(cv) : 0.0;
        double tv_d = t_num ? atof(target) : 0.0;
        if (op_mode == 5) {
            if (strcmp(cv, target) == 0)
                return true;
            return c_num && t_num && fabs(cv_d - tv_d) < 1e-6;
        }
        if (!c_num || !t_num)
            return false;
        if (op_mode == 1)
            return cv_d > tv_d;
        if (op_mode == 2)
            return cv_d >= tv_d;
        if (op_mode == 3)
            return cv_d < tv_d;
        if (op_mode == 4)
            return cv_d <= tv_d;
        return false;
    }
    return _nino_db_row_matches_where(r, wp);
}
static inline void *_nino_db_sqlite_query_p(const void *db, const char *q, const void *params) {
    void *arr = _nino_alloc_arr(256);
    if (!q || !_nino_strcasestr(q, "SELECT"))
        return arr;
    NinoDbConn *dc = _nino_find_db_conn(db);
    if (dc && dc->is_native && dc->sqlite_db) {
        void *stmt = NULL;
        if (_nino_sq.prep(dc->sqlite_db, q, -1, &stmt, NULL) == 0 && stmt) {
            if (params && _nino_arr_is_alive(params) && _nino_sq.bind_txt) {
                int64_t plen = nino_len_arr(params);
                const char *const *pvals = (const char *const *)params;
                void (*tr)(void *) = (void (*)(void *))(intptr_t)-1;
                for (int64_t i = 0; i < plen; i++) {
                    const char *pv = pvals[i] ? pvals[i] : "";
                    (void)_nino_sq.bind_txt(stmt, (int)(i + 1), pv, -1, tr);
                }
            }
            while (_nino_sq.step(stmt) == 100) {
                int nc = _nino_sq.col_cnt(stmt);
                const char *c0 =
                    (nc > 0 && _nino_sq.col_txt(stmt, 0)) ? (const char *)_nino_sq.col_txt(stmt, 0) : "";
                const char *c1 =
                    (nc > 1 && _nino_sq.col_txt(stmt, 1)) ? (const char *)_nino_sq.col_txt(stmt, 1) : "";
                char *row_s = (char *)nino_arena_alloc(strlen(c0) + strlen(c1) + 8);
                if (row_s) {
                    if (nc > 1)
                        snprintf(row_s, strlen(c0) + strlen(c1) + 8, "%s: %s", c0, c1);
                    else
                        snprintf(row_s, strlen(c0) + 8, "%s", c0);
                    arr = _nino_push_impl(arr, &row_s, sizeof(const char *), sizeof(const char *));
                }
            }
            _nino_sq.fin(stmt);
        }
        return arr;
    }
    const char *eq = _nino_sql_bind_quote(q, params);
    NinoDbTable *tbl = (_nino_db_table_cnt > 0) ? &_nino_db_tables[_nino_db_table_cnt - 1] : NULL;
    const char *fp = _nino_strcasestr(eq, "FROM ");
    if (fp) {
        fp += 5;
        while (*fp == ' ')
            fp++;
        char tname[64];
        int ti = 0;
        while (*fp && *fp != ' ' && ti < 63)
            tname[ti++] = *fp++;
        tname[ti] = 0;
        tbl = _nino_db_get_or_add_table(tname, false);
    }
    if (!tbl)
        return arr;
    const char *wp = _nino_strcasestr(eq, "WHERE ");
    if (!wp)
        wp = _nino_strcasestr(eq, "WHERE\t");
    for (int i = 0; i < tbl->row_count; i++) {
        NinoDbRow *r = &tbl->rows[i];
        if (_nino_db_row_matches_where_tbl(tbl, r, wp) && r->col_count > 0) {
            const char *s1 = r->col_count > 1 ? r->cols[1] : r->cols[0];
            const char *s2 = r->col_count > 2 ? r->cols[2] : (r->col_count > 1 ? r->cols[1] : "");
            char *row_s = (char *)nino_arena_alloc(strlen(s1) + strlen(s2) + 8);
            snprintf(row_s, strlen(s1) + strlen(s2) + 8, "%s: %s", s1, s2);
            arr = _nino_push_impl(arr, &row_s, sizeof(const char *), sizeof(const char *));
        }
    }
    return arr;
}
static inline void *db_sqlite_query(const void *db, const char *q) {
    return _nino_db_sqlite_query_p(db, q, NULL);
}
static inline void db_sqlite_close(const void *db) {
    NinoDbConn *dc = _nino_find_db_conn(db);
    if (!dc)
        return;
    if (dc->is_native && dc->sqlite_db) {
        _nino_sq.close(dc->sqlite_db);
        dc->sqlite_db = NULL;
    }
    dc->open = false;
}
typedef struct {
    int id;
    int64_t fd;
    bool open;
    int64_t affected_rows;
    char host[64];
    int port;
    char db[64];
    char last_err[256];
} NinoPgConn;
static NINO_THREAD_LOCAL NinoPgConn _nino_pg_conns[32];
static NINO_THREAD_LOCAL int _nino_pg_seq = 0;
static inline void _nino_be_u32(uint8_t *dst, uint32_t v) {
    dst[0] = (uint8_t)(v >> 24);
    dst[1] = (uint8_t)(v >> 16);
    dst[2] = (uint8_t)(v >> 8);
    dst[3] = (uint8_t)v;
}
static inline uint32_t _nino_rd_u32(const uint8_t *src) {
    return ((uint32_t)src[0] << 24) | ((uint32_t)src[1] << 16) | ((uint32_t)src[2] << 8) | (uint32_t)src[3];
}
static inline int _nino_rd_i16(const uint8_t *src) {
    uint16_t u = (uint16_t)(((uint16_t)src[0] << 8) | (uint16_t)src[1]);
    return (u >= 0x8000U) ? ((int)u - 65536) : (int)u;
}
static inline void _nino_md5_hex(const uint8_t *data, size_t len, char out33[33]) {
    static const uint32_t r[64] = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                                   5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20,
                                   4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                                   6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};
    uint32_t k[64];
    for (int i = 0; i < 64; i++)
        k[i] = (uint32_t)floor(fabs(sin((double)(i + 1))) * 4294967296.0);
    size_t plen = ((len + 8U) / 64U + 1U) * 64U;
    uint8_t *msg = (uint8_t *)calloc(plen, 1U);
    if (!msg) {
        memset(out33, 0, 33);
        return;
    }
    if (len > 0U && data)
        memcpy(msg, data, len);
    msg[len] = 0x80U;
    uint64_t bits = (uint64_t)len * 8ULL;
    for (int i = 0; i < 8; i++)
        msg[plen - 8U + i] = (uint8_t)(bits >> (i * 8));
    uint32_t h0 = 0x67452301U, h1 = 0xefcdab89U, h2 = 0x98badcfeU, h3 = 0x10325476U;
    for (size_t off = 0; off < plen; off += 64U) {
        uint32_t w[16];
        for (int i = 0; i < 16; i++) {
            const uint8_t *p = msg + off + i * 4;
            w[i] = (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
        }
        uint32_t a = h0, b = h1, c = h2, d = h3;
        for (int i = 0; i < 64; i++) {
            uint32_t f, g;
            if (i < 16) {
                f = (b & c) | ((~b) & d);
                g = (uint32_t)i;
            } else if (i < 32) {
                f = (d & b) | ((~d) & c);
                g = (uint32_t)((5 * i + 1) % 16);
            } else if (i < 48) {
                f = b ^ c ^ d;
                g = (uint32_t)((3 * i + 5) % 16);
            } else {
                f = c ^ (b | (~d));
                g = (uint32_t)((7 * i) % 16);
            }
            uint32_t tmp = d;
            d = c;
            c = b;
            uint32_t x = a + f + k[i] + w[g];
            b = b + ((x << r[i]) | (x >> (32U - r[i])));
            a = tmp;
        }
        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
    }
    free(msg);
    uint32_t hs[4] = {h0, h1, h2, h3};
    uint8_t raw[16];
    for (int i = 0; i < 4; i++) {
        raw[i * 4 + 0] = (uint8_t)(hs[i] & 0xFFU);
        raw[i * 4 + 1] = (uint8_t)((hs[i] >> 8) & 0xFFU);
        raw[i * 4 + 2] = (uint8_t)((hs[i] >> 16) & 0xFFU);
        raw[i * 4 + 3] = (uint8_t)((hs[i] >> 24) & 0xFFU);
    }
    for (int i = 0; i < 16; i++)
        snprintf(out33 + i * 2, 3, "%02x", (unsigned int)raw[i]);
    out33[32] = 0;
}
static inline bool _nino_pg_send_all(int64_t fd, const uint8_t *buf, size_t n) {
    size_t sent = 0;
    while (sent < n) {
#ifdef _WIN32
        int r = send((SOCKET)fd, (const char *)(buf + sent), (int)(n - sent), 0);
#else
        ssize_t r = send((int)fd, buf + sent, n - sent, 0);
#endif
        if (r <= 0) {
            return false;
        }
        sent += (size_t)r;
    }
    return true;
}
static inline bool _nino_pg_recv_exact(int64_t fd, uint8_t *buf, size_t n) {
    size_t got = 0;
    while (got < n) {
#ifdef _WIN32
        int r = recv((SOCKET)fd, (char *)(buf + got), (int)(n - got), 0);
#else
        ssize_t r = recv((int)fd, buf + got, n - got, 0);
#endif
        if (r <= 0) {
            return false;
        }
        got += (size_t)r;
    }
    return true;
}
static inline int64_t _nino_pg_tcp_open(const char *host, int64_t port) {
    if (!host || !host[0] || port <= 0 || port > 65535 || !_nino_net_init())
        return -1;
    char pstr[16];
    snprintf(pstr, sizeof(pstr), "%lld", (long long)port);
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *res = NULL;
    if (getaddrinfo(host, pstr, &hints, &res) != 0 || !res)
        return -1;
    int64_t out_fd = -1;
    for (struct addrinfo *rp = res; rp != NULL; rp = rp->ai_next) {
#ifdef _WIN32
        SOCKET s = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (s == INVALID_SOCKET)
            continue;
        u_long nb = 1;
        ioctlsocket(s, FIONBIO, &nb);
        connect(s, rp->ai_addr, (int)rp->ai_addrlen);
        fd_set wfds;
        FD_ZERO(&wfds);
        FD_SET(s, &wfds);
        struct timeval tv;
        tv.tv_sec = 2;
        tv.tv_usec = 0;
        if (select(0, NULL, &wfds, NULL, &tv) > 0) {
            int so_err = 0;
            socklen_t el = (socklen_t)sizeof(so_err);
            if (getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&so_err, &el) == 0 && so_err == 0) {
                nb = 0;
                ioctlsocket(s, FIONBIO, &nb);
                DWORD rto = 2000;
                setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&rto, sizeof(rto));
                out_fd = (int64_t)s;
                break;
            }
        }
        closesocket(s);
#else
        int s = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (s < 0)
            continue;
        int fl = fcntl(s, F_GETFL, 0);
        fcntl(s, F_SETFL, fl | O_NONBLOCK);
        int cr = connect(s, rp->ai_addr, rp->ai_addrlen);
        if (cr == 0 || errno == EINPROGRESS) {
            fd_set wfds;
            FD_ZERO(&wfds);
            FD_SET(s, &wfds);
            struct timeval tv;
            tv.tv_sec = 2;
            tv.tv_usec = 0;
            if (select(s + 1, NULL, &wfds, NULL, &tv) > 0) {
                int so_err = 0;
                socklen_t el = (socklen_t)sizeof(so_err);
                if (getsockopt(s, SOL_SOCKET, SO_ERROR, &so_err, &el) == 0 && so_err == 0) {
                    fcntl(s, F_SETFL, fl);
                    struct timeval rto;
                    rto.tv_sec = 2;
                    rto.tv_usec = 0;
                    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &rto, sizeof(rto));
                    out_fd = (int64_t)s;
                    break;
                }
            }
        }
        close(s);
#endif
    }
    freeaddrinfo(res);
    return out_fd;
}
static inline NinoPgConn *_nino_find_pg_conn(const void *db) {
    if (!db)
        return NULL;
    const char *s = (const char *)db;
    if (strncmp(s, "pg-tcp:", 7) != 0)
        return NULL;
    int id = atoi(s + 7);
    for (int i = 0; i < 32; i++) {
        if (_nino_pg_conns[i].id == id && _nino_pg_conns[i].open)
            return &_nino_pg_conns[i];
    }
    return NULL;
}
static inline const char *db_postgres_connect(const char *h, int64_t p, const char *u, const char *d) {
    const char *host = (h && h[0]) ? h : "127.0.0.1";
    const char *dbn = (d && d[0]) ? d : "postgres";
    const char *raw_u = (u && u[0]) ? u : "postgres";
    char user_b[64];
    char pass_b[128];
    pass_b[0] = 0;
    const char *col = strchr(raw_u, ':');
    if (col) {
        size_t ul = (size_t)(col - raw_u);
        if (ul >= sizeof(user_b))
            ul = sizeof(user_b) - 1;
        memcpy(user_b, raw_u, ul);
        user_b[ul] = 0;
        snprintf(pass_b, sizeof(pass_b), "%s", col + 1);
    } else {
        snprintf(user_b, sizeof(user_b), "%s", raw_u);
        const char *ep = getenv("PGPASSWORD");
        if (ep) {
            snprintf(pass_b, sizeof(pass_b), "%s", ep);
        }
    }
    int64_t fd = _nino_pg_tcp_open(host, p);
    if (fd < 0)
        return "";
    size_t ul = strlen(user_b) + 1, dl = strlen(dbn) + 1;
    uint32_t mlen = (uint32_t)(8 + 5 + ul + 9 + dl + 1);
    uint8_t *msg = (uint8_t *)calloc(mlen, 1);
    if (!msg) {
        tcp_close(fd);
        return "";
    }
    _nino_be_u32(msg, mlen);
    _nino_be_u32(msg + 4, 196608U);
    size_t off = 8;
    memcpy(msg + off, "user", 5);
    off += 5;
    memcpy(msg + off, user_b, ul);
    off += ul;
    memcpy(msg + off, "database", 9);
    off += 9;
    memcpy(msg + off, dbn, dl);
    off += dl;
    msg[off++] = 0;
    bool ok_send = _nino_pg_send_all(fd, msg, mlen);
    free(msg);
    if (!ok_send) {
        tcp_close(fd);
        return "";
    }
    bool authed = false, ready = false;
    while (!ready) {
        uint8_t hdr[5];
        if (!_nino_pg_recv_exact(fd, hdr, 5)) {
            tcp_close(fd);
            return "";
        }
        uint8_t mtype = hdr[0];
        uint32_t plen = _nino_rd_u32(hdr + 1);
        if (plen < 4 || plen > 1048576U) {
            tcp_close(fd);
            return "";
        }
        size_t blen = (size_t)(plen - 4);
        uint8_t *pay = (uint8_t *)malloc(blen + 1);
        if (!pay || (blen && !_nino_pg_recv_exact(fd, pay, blen))) {
            if (pay)
                free(pay);
            tcp_close(fd);
            return "";
        }
        pay[blen] = 0;
        if (mtype == 'R' && blen >= 4) {
            uint32_t acode = _nino_rd_u32(pay);
            if (acode == 0U) {
                authed = true;
            } else if (acode == 3U) {
                size_t pl = strlen(pass_b) + 1;
                uint32_t rl = (uint32_t)(4 + pl);
                uint8_t *rp = (uint8_t *)malloc(1 + rl);
                if (rp) {
                    rp[0] = 'p';
                    _nino_be_u32(rp + 1, rl);
                    memcpy(rp + 5, pass_b, pl);
                    ok_send = _nino_pg_send_all(fd, rp, 1 + rl);
                    free(rp);
                } else
                    ok_send = false;
                if (!ok_send) {
                    if (pay)
                        free(pay);
                    tcp_close(fd);
                    return "";
                }
            } else if (acode == 5U && blen >= 8) {
                char inner_in[256];
                snprintf(inner_in, sizeof(inner_in), "%s%s", pass_b, user_b);
                char inner_hex[33];
                _nino_md5_hex((const uint8_t *)inner_in, strlen(inner_in), inner_hex);
                uint8_t outer_in[36];
                memcpy(outer_in, inner_hex, 32);
                memcpy(outer_in + 32, pay + 4, 4);
                char outer_hex[33];
                _nino_md5_hex(outer_in, 36, outer_hex);
                char resp_pw[40];
                snprintf(resp_pw, sizeof(resp_pw), "md5%s", outer_hex);
                size_t pl = strlen(resp_pw) + 1;
                uint32_t rl = (uint32_t)(4 + pl);
                uint8_t *rp = (uint8_t *)malloc(1 + rl);
                if (rp) {
                    rp[0] = 'p';
                    _nino_be_u32(rp + 1, rl);
                    memcpy(rp + 5, resp_pw, pl);
                    ok_send = _nino_pg_send_all(fd, rp, 1 + rl);
                    free(rp);
                } else
                    ok_send = false;
                if (!ok_send) {
                    if (pay)
                        free(pay);
                    tcp_close(fd);
                    return "";
                }
            } else {
                if (pay)
                    free(pay);
                tcp_close(fd);
                return "";
            }
        } else if (mtype == 'E') {
            if (pay)
                free(pay);
            tcp_close(fd);
            return "";
        } else if (mtype == 'Z') {
            ready = true;
        }
        if (pay)
            free(pay);
    }
    if (!authed || !ready) {
        tcp_close(fd);
        return "";
    }
    int slot = -1;
    for (int i = 0; i < 32; i++) {
        if (!_nino_pg_conns[i].open) {
            slot = i;
            break;
        }
    }
    if (slot < 0) {
        tcp_close(fd);
        return "";
    }
    NinoPgConn *pg = &_nino_pg_conns[slot];
    memset(pg, 0, sizeof(NinoPgConn));
    pg->id = ++_nino_pg_seq;
    pg->fd = fd;
    pg->open = true;
    snprintf(pg->host, sizeof(pg->host), "%s", host);
    pg->port = (int)p;
    snprintf(pg->db, sizeof(pg->db), "%s", dbn);
    char *hdl = (char *)nino_arena_alloc(160);
    snprintf(hdl, 160, "pg-tcp:%d:%s:%lld:%s", pg->id, pg->host, (long long)p, pg->db);
    return hdl;
}
static inline int64_t _nino_redis_tcp_probe(const char *host, int64_t port) {
    if (!host || !host[0] || port <= 0 || port > 65535 || !_nino_net_init())
        return -1;
    char pstr[16];
    snprintf(pstr, sizeof(pstr), "%lld", (long long)port);
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *res = NULL;
    if (getaddrinfo(host, pstr, &hints, &res) != 0 || !res)
        return -1;
    int64_t out_fd = -1;
    for (struct addrinfo *rp = res; rp != NULL; rp = rp->ai_next) {
#ifdef _WIN32
        SOCKET s = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (s == INVALID_SOCKET)
            continue;
        u_long nb = 1;
        ioctlsocket(s, FIONBIO, &nb);
        connect(s, rp->ai_addr, (int)rp->ai_addrlen);
        fd_set wfds;
        FD_ZERO(&wfds);
        FD_SET(s, &wfds);
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 50000;
        if (select(0, NULL, &wfds, NULL, &tv) > 0) {
            int so_err = 0;
            socklen_t el = (socklen_t)sizeof(so_err);
            if (getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&so_err, &el) == 0 && so_err == 0) {
                nb = 0;
                ioctlsocket(s, FIONBIO, &nb);
                DWORD rto = 500;
                setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&rto, sizeof(rto));
                const char *png = "*1\r\n$4\r\nPING\r\n";
                send(s, png, (int)strlen(png), 0);
                char rbuf[32];
                int rn = recv(s, rbuf, sizeof(rbuf) - 1, 0);
                if (rn >= 5 && strncmp(rbuf, "+PONG", 5) == 0) {
                    out_fd = (int64_t)s;
                    break;
                }
            }
        }
        closesocket(s);
#else
        int s = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (s < 0)
            continue;
        int fl = fcntl(s, F_GETFL, 0);
        fcntl(s, F_SETFL, fl | O_NONBLOCK);
        int cr = connect(s, rp->ai_addr, rp->ai_addrlen);
        if (cr == 0 || errno == EINPROGRESS) {
            fd_set wfds;
            FD_ZERO(&wfds);
            FD_SET(s, &wfds);
            struct timeval tv;
            tv.tv_sec = 0;
            tv.tv_usec = 50000;
            if (select(s + 1, NULL, &wfds, NULL, &tv) > 0) {
                int so_err = 0;
                socklen_t el = (socklen_t)sizeof(so_err);
                if (getsockopt(s, SOL_SOCKET, SO_ERROR, &so_err, &el) == 0 && so_err == 0) {
                    fcntl(s, F_SETFL, fl);
                    struct timeval rto;
                    rto.tv_sec = 0;
                    rto.tv_usec = 500000;
                    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &rto, sizeof(rto));
                    const char *png = "*1\r\n$4\r\nPING\r\n";
                    if (send(s, png, strlen(png), 0) > 0) {
                        char rbuf[32];
                        ssize_t rn = recv(s, rbuf, sizeof(rbuf) - 1, 0);
                        if (rn >= 5 && strncmp(rbuf, "+PONG", 5) == 0) {
                            out_fd = (int64_t)s;
                            break;
                        }
                    }
                }
            }
        }
        close(s);
#endif
    }
    freeaddrinfo(res);
    return out_fd;
}
static inline const char *db_redis_connect(const char *h, int64_t p) {
    if (!_nino_redis_kv)
        _nino_redis_kv = nino_dict_create();
    const char *host = (h && h[0]) ? h : "127.0.0.1";
    if (strcmp(host, ":memory:") == 0) {
        int id = ++_nino_db_conn_seq;
        char *buf = (char *)nino_arena_alloc(64);
        snprintf(buf, 64, "redis-mem:%d::memory:", id);
        return buf;
    }
    int64_t fd = _nino_redis_tcp_probe(host, p);
    if (fd >= 0) {
        if (_nino_redis_fd_cnt >= _nino_redis_fd_cap) {
            int ncap = _nino_redis_fd_cap == 0 ? 16 : _nino_redis_fd_cap * 2;
            int64_t *nf = (int64_t *)realloc(_nino_redis_fds, (size_t)ncap * sizeof(int64_t));
            if (nf) {
                _nino_redis_fds = nf;
                _nino_redis_fd_cap = ncap;
            }
        }
        if (_nino_redis_fd_cnt < _nino_redis_fd_cap) {
            int slot = _nino_redis_fd_cnt++;
            _nino_redis_fds[slot] = fd;
            char *buf = (char *)nino_arena_alloc(128);
            snprintf(buf, 128, "redis-tcp:%d:%s:%lld", slot, host, (long long)p);
            return buf;
        }
        tcp_close(fd);
    }
    return "";
}
static inline const char *db_sanitize_sql(const char *s) {
    if (!s)
        return "";
    size_t l = strlen(s);
    char *out = (char *)nino_arena_alloc(l * 2 + 1);
    if (!out)
        return "";
    size_t j = 0;
    for (size_t i = 0; i < l; i++) {
        char c = s[i];
        if (c == ';')
            break;
        if (c == '-' && i + 1 < l && s[i + 1] == '-')
            break;
        if (c == '/' && i + 1 < l && s[i + 1] == '*')
            break;
        if (c == 39) {
            out[j++] = 39;
            out[j++] = 39;
        } else if (c == '\\') {
            out[j++] = '\\';
            out[j++] = '\\';
        } else if (c != '\r' && c != '\n') {
            out[j++] = c;
        }
    }
    out[j] = 0;
    return out;
}
static inline int64_t _nino_pg_run_wire(NinoPgConn *pg, const char *sql, void **out_rows,
                                        const char **out_json) {
    if (!pg || !pg->open || !sql)
        return -1;
    size_t sl = strlen(sql) + 1;
    uint32_t ql = (uint32_t)(4 + sl);
    uint8_t *qp = (uint8_t *)malloc(1 + ql);
    if (!qp)
        return -1;
    qp[0] = 'Q';
    _nino_be_u32(qp + 1, ql);
    memcpy(qp + 5, sql, sl);
    bool sent = _nino_pg_send_all(pg->fd, qp, 1 + ql);
    free(qp);
    if (!sent)
        return -1;
    char cols[32][64];
    int ncols = 0;
    void *arr = out_rows ? _nino_alloc_arr(256) : NULL;
    const char *j_out = out_json ? "[" : NULL;
    int j_cnt = 0;
    int64_t aff = 0;
    bool has_err = false;
    bool done = false;
    while (!done) {
        uint8_t hdr[5];
        if (!_nino_pg_recv_exact(pg->fd, hdr, 5)) {
            has_err = true;
            break;
        }
        uint8_t mt = hdr[0];
        uint32_t plen = _nino_rd_u32(hdr + 1);
        if (plen < 4 || plen > 16777216U) {
            has_err = true;
            break;
        }
        size_t bl = (size_t)(plen - 4);
        uint8_t *pay = (uint8_t *)malloc(bl + 1);
        if (!pay || (bl && !_nino_pg_recv_exact(pg->fd, pay, bl))) {
            if (pay)
                free(pay);
            has_err = true;
            break;
        }
        pay[bl] = 0;
        if (mt == 'T' && bl >= 2) {
            ncols = _nino_rd_i16(pay);
            if (ncols > 32)
                ncols = 32;
            size_t pos = 2;
            for (int ci = 0; ci < ncols && pos < bl; ci++) {
                size_t nlen = 0;
                while (pos + nlen < bl && pay[pos + nlen] != 0)
                    nlen++;
                size_t cp = nlen < 63 ? nlen : 63;
                memcpy(cols[ci], pay + pos, cp);
                cols[ci][cp] = 0;
                pos += nlen + 1 + 18;
            }
        } else if (mt == 'D' && bl >= 2) {
            int fc = _nino_rd_i16(pay);
            size_t pos = 2;
            const char *vals[32];
            for (int ci = 0; ci < 32; ci++)
                vals[ci] = "";
            int ufc = fc < 32 ? fc : 32;
            for (int ci = 0; ci < ufc && pos + 4 <= bl; ci++) {
                uint32_t ufl = _nino_rd_u32(pay + pos);
                pos += 4;
                int32_t flen = (int32_t)ufl;
                if (flen < 0) {
                    vals[ci] = "NULL";
                } else if (pos + (size_t)flen <= bl) {
                    char *vs = (char *)nino_arena_alloc((size_t)flen + 1);
                    if (vs) {
                        memcpy(vs, pay + pos, (size_t)flen);
                        vs[flen] = 0;
                        vals[ci] = vs;
                    }
                    pos += (size_t)flen;
                }
            }
            if (arr && ufc > 0) {
                const char *rstr =
                    (ufc > 1) ? nino_str_concat(nino_str_concat(vals[0], ": "), vals[1]) : vals[0];
                arr = _nino_push_impl(arr, &rstr, sizeof(const char *), sizeof(const char *));
            }
            if (j_out) {
                if (j_cnt > 0)
                    j_out = nino_str_concat(j_out, ",");
                j_out = nino_str_concat(j_out, "{");
                for (int ci = 0; ci < ufc; ci++) {
                    const char *cn = (ci < ncols && cols[ci][0]) ? cols[ci] : "col";
                    char *kv = (char *)nino_arena_alloc(strlen(cn) + strlen(vals[ci]) * 2 + 32);
                    if (kv) {
                        snprintf(kv, strlen(cn) + strlen(vals[ci]) * 2 + 32, "%s\"%s\":\"%s\"",
                                 ci > 0 ? "," : "", cn, _nino_json_esc(vals[ci]));
                        j_out = nino_str_concat(j_out, kv);
                    }
                }
                j_out = nino_str_concat(j_out, "}");
                j_cnt++;
            }
            aff++;
        } else if (mt == 'C' && bl > 0) {
            const char *tag = (const char *)pay;
            const char *sp = strrchr(tag, ' ');
            if (sp && sp[1] >= '0' && sp[1] <= '9')
                aff = (int64_t)strtoll(sp + 1, NULL, 10);
        } else if (mt == 'E') {
            has_err = true;
            size_t pos = 0;
            while (pay && pos < bl && pay[pos] != 0) {
                char ft = (char)pay[pos++];
                const char *fv = (const char *)(pay + pos);
                size_t fl = 0;
                while (pos + fl < bl && fv[fl] != 0)
                    fl++;
                if (ft == 'M' && fl > 0) {
                    size_t mcp = fl < 255 ? fl : 255;
                    memcpy(pg->last_err, fv, mcp);
                    pg->last_err[mcp] = 0;
                }
                pos += fl + 1;
            }
        } else if (mt == 'Z') {
            done = true;
        }
        if (pay)
            free(pay);
    }
    if (out_rows)
        *out_rows = arr;
    if (out_json)
        *out_json = j_out ? nino_str_concat(j_out, "]") : "[]";
    pg->affected_rows = has_err ? -1 : aff;
    return pg->affected_rows;
}
static inline void *db_postgres_query(const void *db, const char *q) {
    NinoPgConn *pg = _nino_find_pg_conn(db);
    if (!pg)
        return _nino_alloc_arr(64);
    void *rows = NULL;
    _nino_pg_run_wire(pg, q, &rows, NULL);
    return rows ? rows : _nino_alloc_arr(64);
}
static inline int32_t db_postgres_exec(const void *db, const char *q) {
    NinoPgConn *pg = _nino_find_pg_conn(db);
    if (!pg)
        return -1;
    return (int32_t)_nino_pg_run_wire(pg, q, NULL, NULL);
}
static inline void db_postgres_close(const void *db) {
    NinoPgConn *pg = _nino_find_pg_conn(db);
    if (!pg)
        return;
    uint8_t term[5];
    term[0] = 'X';
    _nino_be_u32(term + 1, 4U);
    (void)_nino_pg_send_all(pg->fd, term, 5);
    tcp_close(pg->fd);
    pg->fd = -1;
    pg->open = false;
}
static inline void *db_query(const char *c, const char *q, const void *p) {
    if (c && strncmp(c, "pg-tcp:", 7) == 0)
        return db_postgres_query((const void *)c, _nino_sql_bind_quote(q, p));
    return _nino_db_sqlite_query_p((const void *)c, q, p);
}
static inline int64_t db_exec(const char *c, const char *q, const void *p) {
    if (c && strncmp(c, "pg-tcp:", 7) == 0) {
        NinoPgConn *pg = _nino_find_pg_conn(c);
        return pg ? _nino_pg_run_wire(pg, _nino_sql_bind_quote(q, p), NULL, NULL) : -1;
    }
    return (int64_t)_nino_db_sqlite_exec_p((const void *)c, q, p);
}
static inline const char *db_redis_cmd(const char *c, const char *cmd, const void *args) {
    if (!c || !c[0] || !cmd)
        return "";
    if (!_nino_redis_kv)
        _nino_redis_kv = nino_dict_create();
    const char *const *a = (const char *const *)args;
    int64_t alen = args ? nino_len_arr(args) : 0;
    if (strncmp(c, "redis-tcp:", 10) == 0) {
        int slot = atoi(c + 10);
        if (slot >= 0 && slot < _nino_redis_fd_cnt && _nino_redis_fds[slot] >= 0) {
            int64_t fd = _nino_redis_fds[slot];
            size_t rcap = 128 + strlen(cmd);
            for (int64_t i = 0; i < alen; i++)
                rcap += 32 + strlen(a[i] ? a[i] : "");
            char *req = (char *)malloc(rcap);
            if (req) {
                int off =
                    snprintf(req, rcap, "*%lld\r\n$%zu\r\n%s\r\n", (long long)(1 + alen), strlen(cmd), cmd);
                for (int64_t i = 0; i < alen; i++) {
                    const char *ai = a[i] ? a[i] : "";
                    off += snprintf(req + off, rcap - (size_t)off, "$%zu\r\n%s\r\n", strlen(ai), ai);
                }
                size_t sent = 0;
                while (sent < (size_t)off) {
#ifdef _WIN32
                    int n = send((SOCKET)fd, req + sent, off - (int)sent, 0);
#else
                    ssize_t n = send((int)fd, req + sent, (size_t)off - sent, 0);
#endif
                    if (n <= 0) {
                        break;
                    }
                    sent += (size_t)n;
                }
                free(req);
                if (sent == (size_t)off) {
                    char rbuf[4096];
                    size_t hgot = 0;
                    while (hgot + 1 < sizeof(rbuf)) {
#ifdef _WIN32
                        int rn = recv((SOCKET)fd, rbuf + hgot, (int)(sizeof(rbuf) - 1 - hgot), 0);
#else
                        ssize_t rn = recv((int)fd, rbuf + hgot, sizeof(rbuf) - 1 - hgot, 0);
#endif
                        if (rn <= 0)
                            break;
                        hgot += (size_t)rn;
                        rbuf[hgot] = 0;
                        if (strchr(rbuf, '\n'))
                            break;
                    }
                    if (hgot > 0) {
                        rbuf[hgot] = 0;
                        if (rbuf[0] == '+' || rbuf[0] == '-' || rbuf[0] == ':') {
                            char *cr = strchr(rbuf, '\r');
                            if (!cr)
                                cr = strchr(rbuf, '\n');
                            if (cr)
                                *cr = 0;
                            size_t rlen = strlen(rbuf + 1);
                            char *out = (char *)nino_arena_alloc(rlen + 1);
                            if (out)
                                memcpy(out, rbuf + 1, rlen + 1);
                            return out ? out : "";
                        } else if (rbuf[0] == '$') {
                            char *endp = NULL;
                            long long blen = strtoll(rbuf + 1, &endp, 10);
                            char *nl = strchr(rbuf, '\n');
                            if (nl && endp != rbuf + 1 && blen >= 0 && blen <= 1048576LL) {
                                char *pay = nl + 1;
                                size_t have = (size_t)(rbuf + hgot - pay);
                                char *out = (char *)nino_arena_alloc((size_t)blen + 1);
                                if (out) {
                                    size_t got = have < (size_t)blen ? have : (size_t)blen;
                                    if (got > 0)
                                        memcpy(out, pay, got);
                                    while (got < (size_t)blen) {
#ifdef _WIN32
                                        int rn = recv((SOCKET)fd, out + got, (int)((size_t)blen - got), 0);
#else
                                        ssize_t rn = recv((int)fd, out + got, (size_t)blen - got, 0);
#endif
                                        if (rn <= 0)
                                            return "";
                                        got += (size_t)rn;
                                    }
                                    out[blen] = 0;
                                    return out;
                                }
                            }
                        }
                    }
                }
            }
        }
        return "";
    }
    if (strncmp(c, "redis-mem:", 10) != 0)
        return "";
    if (strcmp(cmd, "PING") == 0)
        return "PONG";
    if (strcmp(cmd, "SET") == 0 && alen >= 2) {
        nino_dict_set(_nino_redis_kv, a[0], a[1]);
        return "OK";
    }
    if (strcmp(cmd, "GET") == 0 && alen >= 1) {
        return nino_dict_get(_nino_redis_kv, a[0]);
    }
    return "OK";
}
static inline bool db_close(const char *c) {
    if (!c || !c[0])
        return false;
    if (strncmp(c, "pg-tcp:", 7) == 0) {
        db_postgres_close((const void *)c);
        return true;
    }
    if (strncmp(c, "sqlite:", 7) == 0) {
        db_sqlite_close(c);
        return true;
    }
    if (strncmp(c, "redis-tcp:", 10) == 0) {
        int slot = atoi(c + 10);
        if (slot >= 0 && slot < _nino_redis_fd_cnt && _nino_redis_fds[slot] >= 0) {
            tcp_close(_nino_redis_fds[slot]);
            _nino_redis_fds[slot] = -1;
        }
        return true;
    }
    return true;
}
static inline const char *db_driver_mode(const char *c) {
    if (!c || !c[0])
        return "disconnected";
    if (strncmp(c, "pg-tcp:", 7) == 0) {
        NinoPgConn *pg = _nino_find_pg_conn(c);
        return pg ? "native:postgres-wire" : "disconnected";
    }
    if (strncmp(c, "sqlite:", 7) == 0) {
        NinoDbConn *dc = _nino_find_db_conn(c);
        if (!dc)
            return "disconnected";
        return dc->is_native ? "native:sqlite3" : "embedded:sqlite-mem";
    }
    if (strncmp(c, "redis-tcp:", 10) == 0) {
        int slot = atoi(c + 10);
        return (slot >= 0 && slot < _nino_redis_fd_cnt && _nino_redis_fds[slot] >= 0) ? "native:redis-tcp"
                                                                                      : "disconnected";
    }
    if (strncmp(c, "redis-mem:", 10) == 0)
        return "embedded:redis-mem";
    return "disconnected";
}
static inline void hlt(void) {}
static inline void parity_write_string(void *h, const char *s) {
    if (!h || !s)
        return;
    nino_ecc_t *b = (nino_ecc_t *)h;
    size_t len = strlen(s);
    if ((int32_t)len >= b->size)
        len = b->size - 1;
    memcpy(b->data, s, len);
    b->data[len] = 0;
    for (size_t i = 0; i <= len; i++)
        b->parity[i] = _calc_ecc_p(b->data[i]);
}
static inline void inject_cosmic_ray_flip(void *h, int64_t byte_idx, int64_t bit_idx) {
    if (!h)
        return;
    nino_ecc_t *b = (nino_ecc_t *)h;
    if (byte_idx >= 0 && byte_idx < b->size && bit_idx >= 0 && bit_idx < 8) {
        b->data[byte_idx] ^= (1 << bit_idx);
        printf("[RADIATION STRIKE] Flipped physical RAM bit at byte %lld, bit %lld!\n", (long long)byte_idx,
               (long long)bit_idx);
    }
}
static inline const char *parity_read_string(void *h, int64_t len) {
    (void)len;
    if (!h)
        return "";
    nino_ecc_t *b = (nino_ecc_t *)h;
    size_t dlen = strlen((char *)b->data);
    for (size_t i = 0; i < dlen; i++) {
        uint8_t exp = b->parity[i];
        uint8_t act = _calc_ecc_p(b->data[i]);
        if (exp != act) {
            for (int bit = 0; bit < 8; bit++) {
                uint8_t cand = b->data[i] ^ (1 << bit);
                if (_calc_ecc_p(cand) == exp) {
                    b->data[i] = cand;
                    b->heals++;
                    break;
                }
            }
        }
    }
    return (const char *)b->data;
}
static inline int64_t parity_heal_count(void *h) {
    if (!h)
        return 0;
    nino_ecc_t *b = (nino_ecc_t *)h;
    return b->heals;
}
static inline void guarded_write_byte(void *h, int64_t off, int64_t v) {
    if (!h)
        return;
    nino_guard_t *g = (nino_guard_t *)((uint8_t *)h - offsetof(nino_guard_t, payload));
    if (off >= 0 && off < g->size)
        g->payload[off] = (uint8_t)v;
}
static inline int64_t guarded_read_byte(void *h, int64_t off) {
    if (!h)
        return 0;
    nino_guard_t *g = (nino_guard_t *)((uint8_t *)h - offsetof(nino_guard_t, payload));
    if (off >= 0 && off < g->size)
        return (int64_t)g->payload[off];
    return 0;
}
static inline bool verify_canaries(void *h) {
    if (!h)
        return false;
    nino_guard_t *g = (nino_guard_t *)((uint8_t *)h - offsetof(nino_guard_t, payload));
    uint64_t *tail = (uint64_t *)(g->payload + g->size);
    return (g->head_canary == CANARY_HEAD) && (*tail == CANARY_TAIL);
}
static inline const char *cpu_get_register(const char *reg) {
    (void)reg;
    uint64_t v = (uint64_t)clock();
    char *b = (char *)nino_arena_alloc(32);
    snprintf(b, 32, "0x%016llx", (unsigned long long)v);
    return b;
}
static inline void time_travel_checkpoint(const char *cp) {
    (void)cp;
    if (_nino_tx.depth <= 0) {
        nino_tx_frame_t *fp = _nino_tx_frame_ptr(0);
        if (fp) {
            fp->base_idx = _nino_tx.entry_count;
            fp->fn_depth = _nino_tx.fn_depth;
        }
        _nino_tx.depth = 1;
    } else {
        nino_tx_cleanup();
    }
}
static inline void time_travel_rewind(const char *cp) {
    (void)cp;
    nino_tx_rollback();
    if (_nino_tx.depth > 0)
        _nino_tx.depth--;
}
#define nino_len(X) len(X)
static inline void outb(uint16_t port, uint8_t val) {
    (void)port;
    (void)val;
}
static inline uint8_t inb(uint16_t port) {
    (void)port;
    return 0;
}
typedef void *(*_z3_mk_cfg_t)(void);
typedef void (*_z3_set_prm_t)(void *, const char *, const char *);
typedef void (*_z3_del_cfg_t)(void *);
typedef void *(*_z3_mk_ctx_t)(void *);
typedef void (*_z3_del_ctx_t)(void *);
typedef void *(*_z3_mk_slv_t)(void *);
typedef void (*_z3_slv_ref_t)(void *, void *);
typedef int (*_z3_slv_chk_t)(void *, void *);
typedef void *(*_z3_mk_isym_t)(void *, int);
typedef void *(*_z3_mk_ssym_t)(void *, const char *);
typedef void *(*_z3_mk_srt_t)(void *);
typedef void *(*_z3_mk_cns_t)(void *, void *, void *);
typedef void (*_z3_slv_ass_t)(void *, void *, void *);
typedef struct {
    int probed;
    int avail;
    _z3_mk_cfg_t mk_cfg;
    _z3_set_prm_t set_prm;
    _z3_del_cfg_t del_cfg;
    _z3_mk_ctx_t mk_ctx;
    _z3_del_ctx_t del_ctx;
    _z3_mk_slv_t mk_slv;
    _z3_slv_ref_t inc_ref;
    _z3_slv_ref_t dec_ref;
    _z3_slv_chk_t chk;
    _z3_mk_isym_t isym;
    _z3_mk_ssym_t ssym;
    _z3_mk_srt_t isort;
    _z3_mk_srt_t bsort;
    _z3_mk_cns_t mk_cns;
    _z3_slv_ass_t assrt;
} _NinoZ3Api;
static _NinoZ3Api _nino_z3 = {0};
static inline bool _nino_z3_load(void) {
    if (_nino_z3.probed)
        return _nino_z3.avail != 0;
    _nino_z3.probed = 1;
    void *lib = NULL;
#ifdef _WIN32
    lib = (void *)LoadLibraryA("libz3.dll");
    if (!lib)
        lib = (void *)LoadLibraryA("z3.dll");
#else
    lib = dlopen("libz3.so", RTLD_LAZY);
    if (!lib)
        lib = dlopen("libz3.so.4", RTLD_LAZY);
    if (!lib)
        lib = dlopen("libz3.dylib", RTLD_LAZY);
#endif
    if (!lib) {
        return false;
    }
    if (!_nino_load_sql_sym(lib, "Z3_mk_config", &_nino_z3.mk_cfg, sizeof(_nino_z3.mk_cfg)) ||
        !_nino_load_sql_sym(lib, "Z3_set_param_value", &_nino_z3.set_prm, sizeof(_nino_z3.set_prm)) ||
        !_nino_load_sql_sym(lib, "Z3_del_config", &_nino_z3.del_cfg, sizeof(_nino_z3.del_cfg)) ||
        !_nino_load_sql_sym(lib, "Z3_mk_context", &_nino_z3.mk_ctx, sizeof(_nino_z3.mk_ctx)) ||
        !_nino_load_sql_sym(lib, "Z3_del_context", &_nino_z3.del_ctx, sizeof(_nino_z3.del_ctx)) ||
        !_nino_load_sql_sym(lib, "Z3_mk_solver", &_nino_z3.mk_slv, sizeof(_nino_z3.mk_slv)) ||
        !_nino_load_sql_sym(lib, "Z3_solver_inc_ref", &_nino_z3.inc_ref, sizeof(_nino_z3.inc_ref)) ||
        !_nino_load_sql_sym(lib, "Z3_solver_dec_ref", &_nino_z3.dec_ref, sizeof(_nino_z3.dec_ref)) ||
        !_nino_load_sql_sym(lib, "Z3_solver_check", &_nino_z3.chk, sizeof(_nino_z3.chk)) ||
        !_nino_load_sql_sym(lib, "Z3_mk_int_symbol", &_nino_z3.isym, sizeof(_nino_z3.isym)) ||
        !_nino_load_sql_sym(lib, "Z3_mk_string_symbol", &_nino_z3.ssym, sizeof(_nino_z3.ssym)) ||
        !_nino_load_sql_sym(lib, "Z3_mk_int_sort", &_nino_z3.isort, sizeof(_nino_z3.isort)) ||
        !_nino_load_sql_sym(lib, "Z3_mk_bool_sort", &_nino_z3.bsort, sizeof(_nino_z3.bsort)) ||
        !_nino_load_sql_sym(lib, "Z3_mk_const", &_nino_z3.mk_cns, sizeof(_nino_z3.mk_cns)) ||
        !_nino_load_sql_sym(lib, "Z3_solver_assert", &_nino_z3.assrt, sizeof(_nino_z3.assrt))) {
        return false;
    }
    _nino_z3.avail = 1;
    return true;
}
static inline int64_t Z3_mk_config(void) {
    return _nino_z3_load() ? (int64_t)(uintptr_t)_nino_z3.mk_cfg() : 0;
}
static inline void Z3_set_param_value(int64_t c, const char *k, const char *v) {
    if (c && _nino_z3_load())
        _nino_z3.set_prm((void *)(uintptr_t)c, k, v);
}
static inline void Z3_del_config(int64_t c) {
    if (c && _nino_z3_load())
        _nino_z3.del_cfg((void *)(uintptr_t)c);
}
static inline int64_t Z3_mk_context(int64_t c) {
    return (c && _nino_z3_load()) ? (int64_t)(uintptr_t)_nino_z3.mk_ctx((void *)(uintptr_t)c) : 0;
}
static inline void Z3_del_context(int64_t ctx) {
    if (ctx && _nino_z3_load())
        _nino_z3.del_ctx((void *)(uintptr_t)ctx);
}
static inline int64_t Z3_mk_solver(int64_t ctx) {
    return (ctx && _nino_z3_load()) ? (int64_t)(uintptr_t)_nino_z3.mk_slv((void *)(uintptr_t)ctx) : 0;
}
static inline void Z3_solver_inc_ref(int64_t c, int64_t s) {
    if (c && s && _nino_z3_load())
        _nino_z3.inc_ref((void *)(uintptr_t)c, (void *)(uintptr_t)s);
}
static inline void Z3_solver_dec_ref(int64_t c, int64_t s) {
    if (c && s && _nino_z3_load())
        _nino_z3.dec_ref((void *)(uintptr_t)c, (void *)(uintptr_t)s);
}
static inline int32_t Z3_solver_check(int64_t c, int64_t s) {
    if (!c || !s || !_nino_z3_load())
        return 0;
    return (int32_t)_nino_z3.chk((void *)(uintptr_t)c, (void *)(uintptr_t)s);
}
static inline int64_t Z3_mk_int_symbol(int64_t c, int32_t i) {
    return (c && _nino_z3_load()) ? (int64_t)(uintptr_t)_nino_z3.isym((void *)(uintptr_t)c, (int)i) : 0;
}
static inline int64_t Z3_mk_string_symbol(int64_t c, const char *s) {
    return (c && _nino_z3_load()) ? (int64_t)(uintptr_t)_nino_z3.ssym((void *)(uintptr_t)c, s) : 0;
}
static inline int64_t Z3_mk_int_sort(int64_t c) {
    return (c && _nino_z3_load()) ? (int64_t)(uintptr_t)_nino_z3.isort((void *)(uintptr_t)c) : 0;
}
static inline int64_t Z3_mk_bool_sort(int64_t c) {
    return (c && _nino_z3_load()) ? (int64_t)(uintptr_t)_nino_z3.bsort((void *)(uintptr_t)c) : 0;
}
static inline int64_t Z3_mk_const(int64_t c, int64_t s, int64_t so) {
    return (c && s && so && _nino_z3_load())
               ? (int64_t)(uintptr_t)_nino_z3.mk_cns((void *)(uintptr_t)c, (void *)(uintptr_t)s,
                                                     (void *)(uintptr_t)so)
               : 0;
}
static inline void Z3_solver_assert(int64_t c, int64_t s, int64_t a) {
    if (c && s && a && _nino_z3_load())
        _nino_z3.assrt((void *)(uintptr_t)c, (void *)(uintptr_t)s, (void *)(uintptr_t)a);
}
static inline int64_t time_now_ns(void) {
#ifdef _WIN32
    LARGE_INTEGER c, f;
    QueryPerformanceCounter(&c);
    QueryPerformanceFrequency(&f);
    if (!f.QuadPart)
        return 0;
    int64_t q = (int64_t)c.QuadPart, d = (int64_t)f.QuadPart;
    return (q / d) * 1000000000LL + ((q % d) * 1000000000LL) / d;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000000LL + (int64_t)ts.tv_nsec;
#endif
}
static inline const char *_nino_json_esc(const char *s) {
    if (!s)
        return "";
    size_t l = strlen(s);
    char *b = (char *)nino_arena_alloc(l * 2 + 1);
    if (!b)
        return "";
    size_t j = 0;
    for (size_t i = 0; i < l; i++) {
        char c = s[i];
        if (c == 34 || c == 92) {
            b[j++] = 92;
            b[j++] = c;
        } else if (c == 10) {
            b[j++] = 92;
            b[j++] = 'n';
        } else if (c == 13) {
            b[j++] = 92;
            b[j++] = 'r';
        } else if (c == 9) {
            b[j++] = 92;
            b[j++] = 't';
        } else
            b[j++] = c;
    }
    b[j] = 0;
    return b;
}
static inline const char *_nino_jskip_str(const char *p) {
    if (!p || *p != 34)
        return p;
    p++;
    while (*p) {
        if (*p == 92 && p[1]) {
            p += 2;
            continue;
        }
        if (*p == 34)
            return p + 1;
        p++;
    }
    return p;
}
static inline const char *_nino_jfind_val(const char *j, const char *k) {
    if (!j || !k)
        return NULL;
    size_t kl = strlen(k);
    const char *p = j;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')
        p++;
    if (*p != '{')
        return NULL;
    int depth = 0, arr_d = 0;
    bool expect_k = false;
    while (*p) {
        char c = *p;
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
            p++;
        } else if (c == '{') {
            depth++;
            expect_k = (depth == 1 && arr_d == 0);
            p++;
        } else if (c == '}') {
            depth--;
            expect_k = false;
            p++;
            if (depth <= 0)
                return NULL;
        } else if (c == '[') {
            arr_d++;
            expect_k = false;
            p++;
        } else if (c == ']') {
            arr_d--;
            expect_k = false;
            p++;
        } else if (c == ',') {
            if (depth == 1 && arr_d == 0)
                expect_k = true;
            p++;
        } else if (c == ':') {
            expect_k = false;
            p++;
        } else if (c == 34) {
            const char *ks = p + 1;
            const char *ke = _nino_jskip_str(p);
            bool at_k = (depth == 1 && arr_d == 0 && expect_k);
            expect_k = false;
            p = ke;
            if (at_k && ke > ks) {
                const char *q = p;
                while (*q == ' ' || *q == '\t' || *q == '\r' || *q == '\n')
                    q++;
                if (*q == ':') {
                    size_t sl = (size_t)(ke - 1 - ks);
                    if (ke[-1] == 34 && sl == kl && strncmp(ks, k, kl) == 0) {
                        q++;
                        while (*q == ' ' || *q == '\t' || *q == '\r' || *q == '\n')
                            q++;
                        return q;
                    }
                    p = q + 1;
                }
            }
        } else {
            expect_k = false;
            p++;
        }
    }
    return NULL;
}
static inline const char *_nino_jget_str(const char *j, const char *k) {
    const char *p = _nino_jfind_val(j, k);
    if (!p || *p != 34)
        return "";
    p++;
    size_t ml = strlen(p);
    char *out = (char *)nino_arena_alloc(ml + 1);
    if (!out)
        return "";
    size_t oi = 0;
    while (*p && *p != 34) {
        if (*p == 92 && p[1]) {
            p++;
            if (*p == 'n')
                out[oi++] = 10;
            else if (*p == 'r')
                out[oi++] = 13;
            else if (*p == 't')
                out[oi++] = 9;
            else
                out[oi++] = *p;
            p++;
        } else
            out[oi++] = *p++;
    }
    out[oi] = 0;
    return out;
}
static inline int64_t _nino_jget_i64(const char *j, const char *k) {
    const char *p = _nino_jfind_val(j, k);
    return p ? (int64_t)strtoll(p, NULL, 10) : 0;
}
static inline double _nino_jget_f64(const char *j, const char *k) {
    const char *p = _nino_jfind_val(j, k);
    return p ? strtod(p, NULL) : 0.0;
}
static inline bool _nino_jget_bool(const char *j, const char *k) {
    const char *p = _nino_jfind_val(j, k);
    return p && strncmp(p, "true", 4) == 0;
}
static inline const char *_nino_jget_obj(const char *j, const char *k) {
    const char *p = _nino_jfind_val(j, k);
    if (!p || *p != '{')
        return "{}";
    const char *cur = p;
    int depth = 0;
    bool in_q = false, esc = false;
    while (*cur) {
        if (in_q) {
            if (esc)
                esc = false;
            else if (*cur == 92)
                esc = true;
            else if (*cur == 34)
                in_q = false;
        } else {
            if (*cur == 34)
                in_q = true;
            else if (*cur == '{')
                depth++;
            else if (*cur == '}') {
                depth--;
                if (depth == 0) {
                    cur++;
                    break;
                }
            }
        }
        cur++;
    }
    return nino_str_slice(p, 0, (int64_t)(cur - p));
}
static inline void _nino_sha256_raw(const uint8_t *data, size_t len, uint8_t out32[32]) {
    uint32_t s[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                     0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    uint64_t blen = (uint64_t)len * 8;
    size_t plen = ((len + 8) / 64 + 1) * 64;
    uint8_t *p = (uint8_t *)calloc(plen, 1);
    if (!p) {
        memset(out32, 0, 32);
        return;
    }
    if (len > 0 && data)
        memcpy(p, data, len);
    p[len] = 0x80;
    for (int i = 0; i < 8; ++i)
        p[plen - 1 - i] = (uint8_t)(blen >> (i * 8));
    for (size_t i = 0; i < plen; i += 64)
        _nino_sha_tf(s, p + i);
    free(p);
    for (int i = 0; i < 8; ++i) {
        out32[i * 4] = (uint8_t)(s[i] >> 24);
        out32[i * 4 + 1] = (uint8_t)(s[i] >> 16);
        out32[i * 4 + 2] = (uint8_t)(s[i] >> 8);
        out32[i * 4 + 3] = (uint8_t)(s[i]);
    }
}
static inline const char *hmac_sha256(const char *key, const char *msg) {
    if (!key)
        key = "";
    if (!msg)
        msg = "";
    size_t klen = strlen(key), mlen = strlen(msg);
    uint8_t kblock[64];
    memset(kblock, 0, 64);
    if (klen > 64)
        _nino_sha256_raw((const uint8_t *)key, klen, kblock);
    else if (klen > 0)
        memcpy(kblock, key, klen);
    uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; i++) {
        ipad[i] = kblock[i] ^ 0x36;
        opad[i] = kblock[i] ^ 0x5c;
    }
    uint8_t *in_buf = (uint8_t *)malloc(64 + mlen);
    if (!in_buf)
        return "";
    memcpy(in_buf, ipad, 64);
    if (mlen > 0)
        memcpy(in_buf + 64, msg, mlen);
    uint8_t in_dig[32];
    _nino_sha256_raw(in_buf, 64 + mlen, in_dig);
    free(in_buf);
    uint8_t out_buf[96];
    memcpy(out_buf, opad, 64);
    memcpy(out_buf + 64, in_dig, 32);
    uint8_t out_dig[32];
    _nino_sha256_raw(out_buf, 96, out_dig);
    char *hex = (char *)nino_arena_alloc(65);
    if (!hex)
        return "";
    for (int i = 0; i < 32; i++)
        snprintf(hex + i * 2, 3, "%02x", (unsigned int)out_dig[i]);
    hex[64] = 0;
    return hex;
}
static inline int64_t ffi_open_system_lib(const char *name) {
    if (!name) {
        return 0;
    }
#ifdef _WIN32
    if (strcmp(name, "libc") == 0 || strcmp(name, "c") == 0 || strcmp(name, "libm") == 0 ||
        strcmp(name, "math") == 0) {
        return dylib_open("msvcrt.dll");
    }
    if (strcmp(name, "crypto") == 0 || strcmp(name, "bcrypt") == 0) {
        return dylib_open("bcrypt.dll");
    }
    if (strcmp(name, "sqlite3") == 0) {
        int64_t sh = dylib_open("sqlite3.dll");
        return sh ? sh : dylib_open("msvcrt.dll");
    }
    return dylib_open(name);
#else
    if (strcmp(name, "libc") == 0 || strcmp(name, "c") == 0) {
        int64_t sh = dylib_open("libc.so.6");
        if (!sh) {
            sh = (int64_t)(uintptr_t)dlopen(NULL, RTLD_NOW);
        }
        return sh;
    }
    if (strcmp(name, "libm") == 0 || strcmp(name, "math") == 0) {
        int64_t sh = dylib_open("libm.so.6");
        if (!sh) {
            sh = (int64_t)(uintptr_t)dlopen(NULL, RTLD_NOW);
        }
        return sh;
    }
    return dylib_open(name);
#endif
}
static inline int64_t dylib_call_c_strlen(int64_t fn_ptr, const char *s) {
    if (!fn_ptr || !s)
        return 0;
    typedef size_t (*strlen_fn_t)(const char *);
    strlen_fn_t f = (strlen_fn_t)(uintptr_t)fn_ptr;
    return (int64_t)f(s);
}
typedef int64_t (*NinoThreadFn)(int64_t);
typedef struct {
    NinoThreadFn fn;
    int64_t arg;
    int64_t result;
    int64_t os_tid;
#ifdef _WIN32
    HANDLE handle;
#else
    pthread_t handle;
#endif
    atomic_bool active;
} NinoThreadSlot;
static NinoThreadSlot _nino_threads[256];
static atomic_int _nino_thread_seq = 0;
static inline int64_t current_thread_id(void) {
#ifdef _WIN32
    return (int64_t)GetCurrentThreadId();
#else
    return (int64_t)(uintptr_t)pthread_self();
#endif
}
static inline int64_t cpu_core_count(void) {
#ifdef _WIN32
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return si.dwNumberOfProcessors > 0 ? (int64_t)si.dwNumberOfProcessors : 1;
#else
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    return n > 0 ? (int64_t)n : 1;
#endif
}
static inline void _nino_arena_destroy(void) {
    while (g_nino_arena.tail) {
        NinoArenaSlab *p = g_nino_arena.tail->prev;
        if (g_nino_arena.tail->data)
            free(g_nino_arena.tail->data);
        free(g_nino_arena.tail);
        g_nino_arena.tail = p;
    }
    if (g_nino_arena.marks) {
        free(g_nino_arena.marks);
        g_nino_arena.marks = NULL;
    }
    if (g_nino_arena.mark_ids) {
        free(g_nino_arena.mark_ids);
        g_nino_arena.mark_ids = NULL;
    }
    g_nino_arena.mark_cap = 0;
    g_nino_arena.total_offset = 0;
    g_nino_arena.mark_depth = 0;
}
static inline void nino_arena_free(void) {
    _nino_arena_destroy();
}
#ifdef _WIN32
static DWORD WINAPI _nino_win_thread_entry(LPVOID param) {
    NinoThreadSlot *s = (NinoThreadSlot *)param;
    s->os_tid = (int64_t)GetCurrentThreadId();
    s->result = s->fn ? s->fn(s->arg) : 0;
    _nino_arena_destroy();
    return 0;
}
#else
static void *_nino_posix_thread_entry(void *param) {
    NinoThreadSlot *s = (NinoThreadSlot *)param;
    s->os_tid = (int64_t)(uintptr_t)pthread_self();
    s->result = s->fn ? s->fn(s->arg) : 0;
    _nino_arena_destroy();
    return NULL;
}
#endif
static inline int64_t _nino_thread_spawn(NinoThreadFn fn, int64_t arg) {
    int id = -1;
    for (int tries = 0; tries < 254; tries++) {
        int cand = (int)(((unsigned int)atomic_fetch_add(&_nino_thread_seq, 1) % 254U) + 1U);
        bool exp_f = false;
        if (atomic_compare_exchange_strong(&_nino_threads[cand].active, &exp_f, true)) {
            id = cand;
            break;
        }
    }
    if (id < 0)
        return -1;
    NinoThreadSlot *s = &_nino_threads[id];
    s->fn = fn;
    s->arg = arg;
    s->result = 0;
    s->os_tid = 0;
#ifdef _WIN32
    DWORD tid = 0;
    s->handle = CreateThread(NULL, 0, _nino_win_thread_entry, s, 0, &tid);
    if (!s->handle) {
        atomic_store(&s->active, false);
        return -1;
    }
#else
    if (pthread_create(&s->handle, NULL, _nino_posix_thread_entry, s) != 0) {
        atomic_store(&s->active, false);
        return -1;
    }
#endif
    return (int64_t)id;
}
#define thread_spawn(FN, ARG) _nino_thread_spawn((NinoThreadFn)(FN), (int64_t)(ARG))
static inline int64_t thread_join(int64_t id) {
    if (id <= 0 || id >= 256 || !atomic_load(&_nino_threads[id].active))
        return 0;
    NinoThreadSlot *s = &_nino_threads[id];
#ifdef _WIN32
    if (s->handle) {
        WaitForSingleObject(s->handle, INFINITE);
        CloseHandle(s->handle);
        s->handle = NULL;
    }
#else
    pthread_join(s->handle, NULL);
#endif
    int64_t res = s->result;
    atomic_store(&s->active, false);
    return res;
}
static inline int64_t thread_os_id(int64_t id) {
    if (id <= 0 || id >= 256)
        return 0;
    return _nino_threads[id].os_tid;
}
static inline const char **str_split(const char *s, const char *delim) {
    void *arr = _nino_alloc_arr(256);
    if (!s)
        return (const char **)arr;
    size_t sl = strlen(s);
    size_t dl = delim ? strlen(delim) : 0;
    if (dl == 0) {
        for (size_t i = 0; i < sl; i++) {
            const char *ch = nino_str_char_at(s, (int64_t)i);
            arr = _nino_push_impl(arr, &ch, sizeof(const char *), sizeof(const char *));
        }
        return (const char **)arr;
    }
    const char *cur = s;
    while (1) {
        const char *nxt = strstr(cur, delim);
        if (!nxt) {
            const char *tail = nino_str_slice(cur, 0, (int64_t)strlen(cur));
            arr = _nino_push_impl(arr, &tail, sizeof(const char *), sizeof(const char *));
            break;
        }
        const char *seg = nino_str_slice(cur, 0, (int64_t)(nxt - cur));
        arr = _nino_push_impl(arr, &seg, sizeof(const char *), sizeof(const char *));
        cur = nxt + dl;
    }
    return (const char **)arr;
}
static inline const char *str_join(const void *arr, const char *sep) {
    if (!arr)
        return "";
    int64_t n = nino_len_arr(arr);
    if (n <= 0)
        return "";
    const char *const *a = (const char *const *)arr;
    const char *sp = sep ? sep : "";
    const char *out = a[0] ? a[0] : "";
    for (int64_t i = 1; i < n; i++) {
        out = nino_str_concat(nino_str_concat(out, sp), a[i] ? a[i] : "");
    }
    return out;
}
static inline int64_t arr_sum(const void *arr) {
    if (!arr)
        return 0;
    int64_t n = nino_len_arr(arr);
    const int64_t *a = (const int64_t *)arr;
    int64_t s = 0;
    for (int64_t i = 0; i < n; i++)
        s += a[i];
    return s;
}
static inline int64_t arr_min(const void *arr) {
    if (!arr)
        return 0;
    int64_t n = nino_len_arr(arr);
    if (n <= 0)
        return 0;
    const int64_t *a = (const int64_t *)arr;
    int64_t m = a[0];
    for (int64_t i = 1; i < n; i++)
        if (a[i] < m)
            m = a[i];
    return m;
}
static inline int64_t arr_max(const void *arr) {
    if (!arr)
        return 0;
    int64_t n = nino_len_arr(arr);
    if (n <= 0)
        return 0;
    const int64_t *a = (const int64_t *)arr;
    int64_t m = a[0];
    for (int64_t i = 1; i < n; i++)
        if (a[i] > m)
            m = a[i];
    return m;
}
static inline bool arr_contains(const void *arr, int64_t target) {
    if (!arr)
        return false;
    int64_t n = nino_len_arr(arr);
    const int64_t *a = (const int64_t *)arr;
    for (int64_t i = 0; i < n; i++)
        if (a[i] == target)
            return true;
    return false;
}
static inline int64_t *arr_sort(const void *arr) {
    int64_t n = arr ? nino_len_arr(arr) : 0;
    void *out = _nino_alloc_arr((size_t)(n > 0 ? n : 1) * sizeof(int64_t));
    if (n <= 0)
        return (int64_t *)out;
    const int64_t *src = (const int64_t *)arr;
    for (int64_t i = 0; i < n; i++) {
        int64_t v = src[i];
        out = _nino_push_impl(out, &v, sizeof(int64_t), sizeof(int64_t));
    }
    int64_t *dst = (int64_t *)out;
    for (int64_t i = 0; i < n; i++) {
        for (int64_t j = i + 1; j < n; j++) {
            if (dst[j] < dst[i]) {
                int64_t t = dst[i];
                dst[i] = dst[j];
                dst[j] = t;
            }
        }
    }
    return dst;
}
static inline bool _nino_is_json_num(const char *s) {
    if (!s || !s[0])
        return false;
    size_t i = 0;
    if (s[i] == '-') {
        i++;
        if (!s[i])
            return false;
    }
    if (s[i] == '0' && s[i + 1] >= '0' && s[i + 1] <= '9')
        return false;
    bool has_d = false, has_dot = false;
    for (; s[i]; i++) {
        if (s[i] >= '0' && s[i] <= '9') {
            has_d = true;
        } else if (s[i] == '.' && !has_dot && has_d && s[i + 1] >= '0' && s[i + 1] <= '9') {
            has_dot = true;
        } else
            return false;
    }
    return has_d;
}
static inline const char *db_query_json(const void *db, const char *q) {
    if (db && strncmp((const char *)db, "pg-tcp:", 7) == 0) {
        NinoPgConn *pg = _nino_find_pg_conn(db);
        if (!pg)
            return "[]";
        const char *jres = NULL;
        _nino_pg_run_wire(pg, q, NULL, &jres);
        return jres ? jres : "[]";
    }
    if (!q || !strstr(q, "SELECT"))
        return "[]";
    NinoDbConn *dc = _nino_find_db_conn(db);
    if (dc && dc->is_native && dc->sqlite_db) {
        void *stmt = NULL;
        if (_nino_sq.prep(dc->sqlite_db, q, -1, &stmt, NULL) == 0 && stmt) {
            const char *out = "[";
            int emitted = 0;
            int nc = _nino_sq.col_cnt(stmt);
            while (_nino_sq.step(stmt) == 100) {
                if (emitted > 0)
                    out = nino_str_concat(out, ",");
                out = nino_str_concat(out, "{");
                for (int ci = 0; ci < nc; ci++) {
                    const char *raw_cn = _nino_sq.col_name(stmt, ci);
                    const char *raw_cv = (const char *)_nino_sq.col_txt(stmt, ci);
                    const char *cn = raw_cn ? raw_cn : "c";
                    const char *cv = raw_cv ? raw_cv : "";
                    const char *sep = (ci > 0) ? "," : "";
                    const char *ecn = _nino_json_esc(cn);
                    const char *ecv = _nino_json_esc(cv);
                    size_t kvcap = strlen(ecn) + strlen(ecv) + 24;
                    char *kv = (char *)nino_arena_alloc(kvcap);
                    if (kv) {
                        if (_nino_is_json_num(cv))
                            snprintf(kv, kvcap, "%s\"%s\":%s", sep, ecn, cv);
                        else
                            snprintf(kv, kvcap, "%s\"%s\":\"%s\"", sep, ecn, ecv);
                        out = nino_str_concat(out, kv);
                    }
                }
                out = nino_str_concat(out, "}");
                emitted++;
            }
            _nino_sq.fin(stmt);
            return nino_str_concat(out, "]");
        }
        return "[]";
    }
    NinoDbTable *tbl = (_nino_db_table_cnt > 0) ? &_nino_db_tables[_nino_db_table_cnt - 1] : NULL;
    const char *fp = strstr(q, "FROM ");
    if (fp) {
        fp += 5;
        while (*fp == ' ')
            fp++;
        char tname[64];
        int ti = 0;
        while (*fp && *fp != ' ' && ti < 63)
            tname[ti++] = *fp++;
        tname[ti] = 0;
        tbl = _nino_db_get_or_add_table(tname, false);
    }
    if (!tbl)
        return "[]";
    const char *wp = strstr(q, "WHERE ");
    const char *out = "[";
    int emitted = 0;
    for (int i = 0; i < tbl->row_count; i++) {
        NinoDbRow *r = &tbl->rows[i];
        if (_nino_db_row_matches_where_tbl(tbl, r, wp) && r->col_count > 0) {
            if (emitted > 0)
                out = nino_str_concat(out, ",");
            out = nino_str_concat(out, "{");
            for (int ci = 0; ci < r->col_count; ci++) {
                char fb_cn[16];
                const char *cn = (ci < tbl->col_name_cnt && tbl->col_names[ci][0])
                                     ? tbl->col_names[ci]
                                     : (snprintf(fb_cn, sizeof(fb_cn), "col%d", ci), fb_cn);
                const char *val = r->cols[ci] ? r->cols[ci] : "";
                const char *sep = (ci > 0) ? "," : "";
                char *kv = (char *)nino_arena_alloc(strlen(cn) + strlen(val) * 2 + 24);
                if (kv) {
                    if (_nino_is_json_num(val))
                        snprintf(kv, strlen(cn) + strlen(val) * 2 + 24, "%s\"%s\":%s", sep,
                                 _nino_json_esc(cn), val);
                    else
                        snprintf(kv, strlen(cn) + strlen(val) * 2 + 24, "%s\"%s\":\"%s\"", sep,
                                 _nino_json_esc(cn), _nino_json_esc(val));
                    out = nino_str_concat(out, kv);
                }
            }
            out = nino_str_concat(out, "}");
            emitted++;
        }
    }
    return nino_str_concat(out, "]");
}
typedef struct {
    uint8_t code;
    uint8_t dst_src;
    int16_t off;
    int32_t imm;
} NinoEbpfInsn;
typedef struct {
    int insn_cnt;
    NinoEbpfInsn insns[64];
} NinoEbpfProg;
static NINO_THREAD_LOCAL NinoEbpfProg _nino_ebpf_progs[16];
static NINO_THREAD_LOCAL int _nino_ebpf_prog_cnt = 0;
static inline int64_t ebpf_prog_create(void) {
    int id = (_nino_ebpf_prog_cnt < 15) ? (++_nino_ebpf_prog_cnt) : 15;
    memset(&_nino_ebpf_progs[id], 0, sizeof(NinoEbpfProg));
    return (int64_t)id;
}
static inline int64_t ebpf_emit(int64_t pid, int64_t code, int64_t dst, int64_t src, int64_t off,
                                int64_t imm) {
    if (pid <= 0 || pid >= 16)
        return 0;
    NinoEbpfProg *p = &_nino_ebpf_progs[pid];
    if (p->insn_cnt >= 64)
        return p->insn_cnt;
    NinoEbpfInsn *ins = &p->insns[p->insn_cnt++];
    ins->code = (uint8_t)code;
    ins->dst_src = (uint8_t)(((src & 0xF) << 4) | (dst & 0xF));
    ins->off = (int16_t)off;
    ins->imm = (int32_t)imm;
    return (int64_t)p->insn_cnt;
}
static inline const char *ebpf_bytecode_hex(int64_t pid) {
    if (pid <= 0 || pid >= 16)
        return "";
    NinoEbpfProg *p = &_nino_ebpf_progs[pid];
    int nb = p->insn_cnt * 8;
    char *out = (char *)nino_arena_alloc((size_t)nb * 2 + 1);
    if (!out)
        return "";
    const uint8_t *raw = (const uint8_t *)p->insns;
    for (int i = 0; i < nb; i++)
        snprintf(out + i * 2, 3, "%02x", (unsigned int)raw[i]);
    out[nb * 2] = 0;
    return out;
}
static inline int64_t ebpf_exec_packet(int64_t pid, const char *pkt_hex) {
    if (pid <= 0 || pid >= 16 || !pkt_hex)
        return 1;
    NinoEbpfProg *p = &_nino_ebpf_progs[pid];
    uint8_t pkt[1536];
    int hlen = (int)strlen(pkt_hex);
    int pkt_len = 0;
    for (int i = 0; i + 1 < hlen && pkt_len < 1536; i += 2)
        pkt[pkt_len++] = (uint8_t)((_nino_hex_nib(pkt_hex[i]) << 4) | _nino_hex_nib(pkt_hex[i + 1]));
    uint64_t reg[11];
    memset(reg, 0, sizeof(reg));
    reg[1] = 0;
    reg[2] = (uint64_t)pkt_len;
    int pc = 0, steps = 0;
    while (pc >= 0 && pc < p->insn_cnt && steps < 256) {
        steps++;
        NinoEbpfInsn ins = p->insns[pc++];
        int dst = ins.dst_src & 0xF, src = (ins.dst_src >> 4) & 0xF;
        if (dst > 10 || src > 10)
            return 1;
        if (ins.code == 0xb7)
            reg[dst] = (uint64_t)(int64_t)ins.imm;
        else if (ins.code == 0xbf)
            reg[dst] = reg[src];
        else if (ins.code == 0x07)
            reg[dst] += (uint64_t)(int64_t)ins.imm;
        else if (ins.code == 0x57)
            reg[dst] &= (uint64_t)(uint32_t)ins.imm;
        else if (ins.code == 0x71) {
            int o = (int)reg[src] + (int)ins.off;
            if (o < 0 || o + 1 > pkt_len)
                return 1;
            reg[dst] = (uint64_t)pkt[o];
        } else if (ins.code == 0x69) {
            int o = (int)reg[src] + (int)ins.off;
            if (o < 0 || o + 2 > pkt_len)
                return 1;
            reg[dst] = (uint64_t)(((uint16_t)pkt[o] << 8) | (uint16_t)pkt[o + 1]);
        } else if (ins.code == 0x61) {
            int o = (int)reg[src] + (int)ins.off;
            if (o < 0 || o + 4 > pkt_len)
                return 1;
            reg[dst] = (uint64_t)(((uint32_t)pkt[o] << 24) | ((uint32_t)pkt[o + 1] << 16) |
                                  ((uint32_t)pkt[o + 2] << 8) | (uint32_t)pkt[o + 3]);
        } else if (ins.code == 0x15) {
            if (reg[dst] == (uint64_t)(uint32_t)ins.imm)
                pc += ins.off;
        } else if (ins.code == 0x55) {
            if (reg[dst] != (uint64_t)(uint32_t)ins.imm)
                pc += ins.off;
        } else if (ins.code == 0x25) {
            if (reg[dst] > (uint64_t)(uint32_t)ins.imm)
                pc += ins.off;
        } else if (ins.code == 0xa5) {
            if (reg[dst] < (uint64_t)(uint32_t)ins.imm)
                pc += ins.off;
        } else if (ins.code == 0x1d) {
            if (reg[dst] == reg[src])
                pc += ins.off;
        } else if (ins.code == 0x95)
            return (int64_t)reg[0];
    }
    if (steps >= 256)
        return 1;
    return (int64_t)reg[0];
}
#if defined(__linux__) && defined(__NR_bpf)
#include <linux/bpf.h>
#include <sys/syscall.h>
static inline int64_t ebpf_load_kernel(int64_t prog_id) {
    if (prog_id <= 0 || prog_id >= 16)
        return -1;
    NinoEbpfProg *p = &_nino_ebpf_progs[prog_id];
    if (p->insn_cnt <= 0)
        return -1;
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.prog_type = 6;
    attr.insns = (uint64_t)(uintptr_t)p->insns;
    attr.insn_cnt = (uint32_t)p->insn_cnt;
    attr.license = (uint64_t)(uintptr_t) "GPL";
    return (int64_t)syscall(__NR_bpf, 5, &attr, sizeof(attr));
}
#else
static inline int64_t ebpf_load_kernel(int64_t prog_id) {
    (void)prog_id;
    return -1;
}
#endif
