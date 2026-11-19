# NinoLang Adversarial Challenge: Break the Prover & Sandbox (v1.2.2)

**Target Release:** `v1.2.2` ([`compiler/`](compiler/ninoc.nino), [`runtime/nino_runtime.h`](runtime/nino_runtime.h), [`formal/arena_soundness.smt2`](formal/arena_soundness.smt2))  
**Track:** Programming Languages, Compilers, Formal Verification & AppSec

Nino (`ninoc`) is a self-hosted systems language prototype that pairs a modular AST-to-C11/LLVM/native compiler with a built-in Z3 SMT contract prover, Proof-Carrying Code (PCC) certificates, Bounds-Check Elision (BCE), and epoch-stamped arena memory safety. Following adversarial audits of earlier prototypes (`v1.0.0` / `v1.1.0` / `v1.2.0` / `v1.2.1`), `v1.2.2` hardens SMT array reassignment (`pop`/`push`), `for-in` loop havoc/gating, array-aliasing fail-closed proof checks, `ninoc equiv` lexical block scoping, direct LLVM SSA `for..continue` and signed division guards, transitive `E0384` parameter immutability, WASM LEB128 bounds, import diagnostic snippets, and `exit()` semantic registration.

We invite systems programmers, PL researchers, and AppSec auditors to **break our soundness guarantees**.

---

## In-Scope Targets

A valid finding demonstrates a reproducible violation in any of the four assurance guarantees below using safe Nino code (without `extern fn` C ABI abuse):

1. **SMT Contract Prover Unsoundness (`ninoc prove` / `ninoc build --proof`)**
   - A program containing a false `ensure(...)` postcondition, broken `invariant(...)`, or out-of-bounds index that incorrectly passes Z3 verification as `UNSAT Verified`, yet fails or traps when executed at runtime.
   - Relevant source: [`compiler/smt_prover.nino`](compiler/smt_prover.nino) (AST walker, SSA variable versioning, `if`/`else` Phi-join, loop invariant check, `QF_BV` / `QF_BVFP` / `--int-logic`).
2. **Proof-Carrying Code Forgery or Bypass (`--proof`, `--verify-proof`)**
   - Modifying executable proof behavior or bypassing Ed25519 / HMAC-SHA256 / Z3 offline verification (`--verify-proof --pubkey <hex> --reverify-z3`) without detection.
   - Relevant source: [`compiler/smt_prover.nino`](compiler/smt_prover.nino), [`compiler/c_codegen.nino`](compiler/c_codegen.nino), [`runtime/nino_runtime.h`](runtime/nino_runtime.h).
3. **BCE & Scoped Arena Memory Safety (`BCE=1`, `E0515`, `transact`, `let[]`)**
   - Reading or writing out-of-bounds via array aliases when BCE elides checks, escaping rollback-local allocations past `arena_rollback(...)` without `E0515` or runtime trap, or mutating an immutable `let` binding/element without `E0384`.
   - Relevant source: [`compiler/nir.nino`](compiler/nir.nino), [`compiler/sem_check.nino`](compiler/sem_check.nino), [`runtime/nino_runtime.h`](runtime/nino_runtime.h).
4. **Sealed Taint Leakage (`E0042`) & Fail-Closed Lowering (`ninoc llvm`, `--backend=native*`)**
   - Leaking a `sealed let` binding (scalar or string) via aliases, struct copies, or function returns without `E0042`, OR causing `ninoc llvm` / `ninoc build --backend=native` to emit silently corrupted IR/machine code instead of rejecting unsupported constructs fail-closed.
   - Relevant source: [`compiler/sem_check.nino`](compiler/sem_check.nino), [`compiler/llvm_ir.nino`](compiler/llvm_ir.nino), [`compiler/native_backend.nino`](compiler/native_backend.nino).

---

## Explicit Non-Goals (Out of Scope)

- **Experimental Cryptography Modules:** `std/quantum.nino`, `std/zkp.nino`, and `std/mpc.nino` are explicitly documented research prototypes under review and are out of scope for cryptographic security claims.
- **Intentional Runtime Traps:** Correct fail-closed rejections (exit code non-zero from `require`, `ensure`, division-by-zero, bounds trap, `E0515`/`E0042`/`E0384`, or `Nino LLVM Subset Error`).
- **Unsafe Host FFI:** Memory corruption triggered from raw C pointers obtained via `extern fn`, `dylib_*`, or `inline_asm`.

---

## Baseline Verification Commands

Before filing a counterexample, verify your reproduction against a clean build:

```sh
ninoc version
z3 -T:15 -t:5000 -smt2 formal/arena_soundness.smt2
ninoc prove your_poc.nino
ninoc build your_poc.nino --proof --strict-c11 -o poc_bin
./poc_bin
```

---

## How to Submit a Counterexample

Open an issue titled `[Break the Prover] <Component>: <Short Summary>` with:

1. Minimal single-file `.nino` reproducer (ideally under 40 lines).
2. Exact CLI command(s) and `ninoc version` output.
3. Expected invariant (e.g., `SAT` counterexample / compile error `E0042` / fail-closed rejection) vs. observed output and runtime behavior.

Confirmed soundness issues are credited in release changelogs and added permanently as adversarial regression fixtures under `tests/e2e/tier2/` or `tests/e2e/tier3/` and `tests/e2e/manifests/`.
