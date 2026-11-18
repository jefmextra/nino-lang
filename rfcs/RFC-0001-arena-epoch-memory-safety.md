# RFC-0001: Scoped Arena Epoch Model & Static Region Escape Analysis (`E0515`)

- **Status:** Accepted / Implemented
- **Reference Implementation:** `compiler/ninoc.nino`, `runtime/nino_runtime.h`
- **Formal Proof Suite:** `formal/arena_soundness.smt2` (Theorems 1-4)

## 1. Motivation

Deterministic bare-metal and server runtimes require bulk memory reclamation without garbage collection pauses while preventing Use-After-Free (`CWE-416`) and out-of-bounds memory corruption (`CWE-125`/`CWE-787`) statically at compile time and deterministically at runtime.

## 2. Design Specification

### 2.1 Chained Slab Region & Epoch Counters

Each thread maintains a `NINO_THREAD_LOCAL NinoArena` containing:
- Chained 4 MiB `NinoArenaSlab` segments (`data`, `cap`, `used`, `base_offset`, `prev`).
- A 64-entry mark stack (`marks[64]`) and monotonic epoch identifier stack (`mark_ids[65]`, `next_mark_id`).
- A per-reset generation counter (`reset_gen`).

### 2.2 Object Header Invariants (`NinoArrHdr`)

Every arena-allocated dynamic array embeds a 48-byte `NinoArrHdr` recording `{ magic, origin, cap, len, reset_gen, mark_id }`. `origin == -1` indicates heap-promoted arrays (`region_pin` or cross-mark escape promotion).

### 2.3 Static Taint Soundness (`E0515`)

During frontend checking (`SemCtx`), region-allocated bindings carry `taint_depth`. Invoking `arena_rollback()` taints every unpinned binding allocated at depth `>= rb_depth`. Subsequent reads without `region_pin()` trigger static error `E0515`.

## 3. Formal Soundness

Theorems 1-4 in `formal/arena_soundness.smt2` verify via Microsoft Z3 (`UNSAT`) that epoch identifiers are strictly monotonic, popped epochs never reactivate across identical byte offsets (ABA immunity), and rolled-back handles deterministically fail `_nino_arr_is_alive`.
