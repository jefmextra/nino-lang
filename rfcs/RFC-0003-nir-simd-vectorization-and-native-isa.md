# RFC-0003: NIR Loop Auto-Vectorization & Direct Multi-ISA Native Code Generation

- **Status:** Accepted / Implemented
- **Reference Implementation:** `compiler/ninoc.nino` (`nir_vec_analyze_for`, `lower_try_emit_vec_for`, `nat_compile_ast`, `nat_build_pe32p`, `nat_build_elf64`)
- **Formal Proof Suite:** `formal/arena_soundness.smt2` (Theorem 5)

## 1. Motivation

Independent compiler sovereignty and numeric performance require both safe auto-vectorizable loop lowering without relaxing bounds checks and direct standalone executable emission free of external C compilers or linkers.

## 2. Design Specification

### 2.1 NIR Loop Vectorization (`NF_VEC_SAFE`)
- Identifies `0..N` loops with unit step and zero loop-carried dependencies across affine element-wise array maps (`VEC_MAP`, `dst[i] = ...`) and exact modular integer reductions (`VEC_REDUCE`, `acc = acc + rhs`).
- Hoists bounds and epoch validation to a single pre-loop guard (`if (n > 0)` verify `0` and `n - 1`), preserves transaction semantics (`_nino_tx.depth == 0`), verifies non-aliasing at runtime (`(const void*)dst != (const void*)src`), and emits ISO C11 `restrict`-qualified 4-lane loops plus LLVM `!llvm.loop` vectorize metadata.

### 2.2 Direct Native Machine-Code Emission (`--backend=native*`, `ninoc asm`)
- Encodes raw `x86_64` and `AArch64` instructions from `AstPool` into byte vectors and writes standalone Windows `PE32+` (`kernel32.dll` IAT), Linux `x86_64` `ELF64`, and Linux `AArch64` `ELF64` (`e_machine = 183`) binaries without invoking host `gcc`, `clang`, or `ld`.
- Rejects constructs outside the standalone runtime subset fail-closed with zero silent C fallback.
