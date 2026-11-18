# RFC-0002: SMT-LIB v2.6 BitVector / IEEE-754 Verification & Asymmetric Ed25519 PCC ABI

- **Status:** Accepted / Implemented
- **Reference Implementation:** `compiler/ninoc.nino` (`synthesize_formal_smt_ex`, `build_pcc_c_header`, `nino_init_args`), `runtime/nino_runtime.h`
- **Standards:** SMT-LIB v2.6, IEEE 754-2019, NIST FIPS 180-4, IETF RFC 2104, IETF RFC 8032

## 1. Motivation

Hardware arithmetic wraparound, IEEE 754 floating-point hazards (`NaN`, `Inf`, absorption), and symmetric-key-only Proof-Carrying Code (PCC) verification previously limited formal guarantees and third-party offline trust.

## 2. Design Specification

### 2.1 SMT Synthesis Modes
- **BitVector Default (`QF_BV`)**: All integer operations emit 64-bit bitvectors (`(_ BitVec 64)`) with 128-bit sign-extended overflow guards, `INT64_MIN / -1` division checks, division-by-zero checks, and shift-range assertions `[0, 63]`.
- **IEEE 754 `Float64` (`QF_BVFP` / `QF_FP`)**: `float`/`f64`/`f32` bindings and predicates (`is_nan`, `is_inf`, `is_finite`, `fp_abs`, `fp_sqrt`, `to_float`) lower to exact `(_ FloatingPoint 11 53)` with `RNE` rounding, float division-by-zero checks, and absorption detection.
- **Unbounded Integer Opt-In (`--int-logic`)**: Maps integers to mathematical `Int`.

### 2.2 Asymmetric Ed25519 + HMAC-SHA256 Binary Seal
- `ninoc build --proof` computes `NINO_PCC_V2:<src_sha>:<smt_sha>:<theorems>:<checks>:<logic>:<verdict>`.
- Signs the payload using pure ISO C11 SHA-512 + 16-limb `GF(2^255-19)` Ed25519 (`NINO_PCC_ED25519_SEED` from `ninoc keygen` or ephemeral keypair), embedding `_NINO_PCC_ED25519_PUB` and `_NINO_PCC_ED25519_SIG` alongside HMAC-SHA256.
- Verifiers run `<binary> --verify-proof --pubkey <64-hex> [--reverify-z3]` to authenticate binaries offline without sharing signing secrets.
