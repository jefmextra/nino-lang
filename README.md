<p align="center">
  <a href="https://ninosec.me">
    <img src="assets/nino_icon.png" width="130" height="130" alt="The Nino Programming Language Logo">
  </a>
</p>

<h1 align="center">The Nino Programming Language</h1>

<p align="center">
  <strong>A self-hosted systems programming language integrating SMT formal verification, deterministic arena memory safety, NIR auto-vectorization, and direct native code generation.</strong>
</p>

<p align="center">
  <a href="https://ninosec.me"><img src="https://img.shields.io/badge/Website-ninosec.me-f59e0b?style=flat-square" alt="Website"></a>
  <a href="https://github.com/jefmextra/nino-lang/releases/tag/v1.2.2"><img src="https://img.shields.io/badge/Release-v1.2.2-38bdf8?style=flat-square" alt="Release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-10b981?style=flat-square" alt="License"></a>
</p>

---

## Overview

Nino is a statically typed systems programming language designed as a transparent engineering platform combining compile-time theorem proving, region-based deterministic memory management, and reproducible self-hosting compilation.

Detailed syntax rules, compiler flags, certificate schemas, and standard library references live in [SPECIFICATION.md](SPECIFICATION.md), the [Online Documentation](docs/docs.html), and [rfcs/README.md](rfcs/README.md).

## Current Scope & Limitations

Nino is an evolving engineering prototype. While core compiler passes, static checks, formal arena proofs, and E2E suites are continuously tested across Windows and Linux CI, exploratory standard library modules remain under active review and should undergo independent evaluation before safety-critical use. Bug reports, RFC feedback, and reproducible test cases are warmly welcomed.

---

## Core Architecture

1. **Modular Self-Hosted Pratt AST & Semantic Analyzer**: 12 modular compiler units under [compiler/](compiler/ninoc.nino) implementing a DFA lexical scanner with standard `//` and `/* ... */` comment support, Pratt precedence parser over a contiguous AST pool, lexical symbol scoping, static mutability and arity enforcement, transitive sealed-data taint tracking, and static Use-After-Rollback escape detection.
2. **Formal SMT Verification & Proof-Carrying Code**: Pre/postcondition and three-phase Floyd-Hoare loop invariant synthesis via AST traversal + SSA Phi-join (`Microsoft Z3`) supporting 64-bit BitVectors with overflow checks, exact IEEE 754 floating-point arithmetic, array bounds theory, unbounded integer logic, fail-closed compilation gating, RFC 2104 HMAC-SHA256 tags, and asymmetric RFC 8032 Ed25519 digital signatures with offline public-key verification.
3. **Hierarchical Arena Epochs & Transactional Memory**: Chained thread-local linear arena slabs, epoch-stamped array headers with deterministic Use-After-Rollback runtime traps, cross-mark heap promotion, nested atomic state rollback transactions, and OS guard-paged sealed entropy buffers with volatile zeroization.
4. **NIR SSA Optimizer & Auto-Vectorization**: Single-pass expression lowering, constant folding, algebraic identity simplification, dead code elimination, proven bounds-check elision, affine loop dependency and non-aliasing analysis, ISO C11 `restrict` four-lane SIMD vector lowering, and LLVM vector loop metadata emission.
5. **Multi-Backend Native & Self-Hosting Pipeline**: Strict ISO C11 code generation with C11 atomics, LLVM Clang backend (`--backend=llvm`) and fail-closed direct opaque-pointer SSA IR emission (`ninoc llvm`), Self-Hosted Direct Machine-Code Backend generating standalone Windows PE32+, Linux x86_64 ELF64, and Linux AArch64 ELF64 executables with zero host C compiler invocation, and deterministic Stage-3 fixed-point bootstrap convergence.
6. **Formal Metatheory Proofs & Open RFC Standards**: Machine-verified Z3 inductive memory-model and vectorization soundness proofs in [formal/arena_soundness.smt2](formal/arena_soundness.smt2), open architecture RFC proposals in [rfcs/README.md](rfcs/README.md), and automated Clause-to-Test traceability across the 153-test E2E suite.
7. **Systems Toolchain & Ecosystem**: Monomorphized generic structures, native Language Server Protocol 3.17 engine with real-time Z3 IDE diagnostics, theorem-driven counterexample witness synthesis, differential equivalence prover, MISRA/JPL architectural linter, DWARF source line mapping, SHA-256 flight recorder, C-header bindgen, Android NDK JNI and Apple Swift/ModuleMap mobile targets, CycloneDX v1.5 SBOM generation, and SHA-256 locked decentralized package management.
8. **Standard Library & Subsystems**: 31 built-in modules covering native OS threading, dynamic FFI linking, TCP sockets, hybrid PostgreSQL v3 / SQLite / Redis database drivers, HTTP/1.1, JSON, CSV, JWT HS256, regex, SHA-256 / SHA-512 / Ed25519, RFC 9669 eBPF bytecode execution, WebAssembly stack VM, Feldman M61 MPC, and exploratory lattice KEM / Sigma ZK modules.

---

## Primary Toolchain Entrypoints

Full CLI options, proof flags, and usage examples are documented in [docs/docs.html](docs/docs.html) and [SPECIFICATION.md](SPECIFICATION.md).

- `ninoc build` / `ninoc run`: Compile or execute units across C11, LLVM, or Direct Native PE/ELF/ARM64 targets
- `ninoc asm`: Emit direct x86_64 or AArch64 native machine-code instruction listings
- `ninoc prove` / `ninoc witness` / `ninoc equiv`: SMT invariant proving, counterexample test synthesis, and equivalence proofs
- `ninoc keygen`: Generate RFC 8032 Ed25519 keypairs for asymmetric PCC verification
- `ninoc check` / `ninoc lint` / `ninoc ast` / `ninoc ir` / `ninoc llvm`: Static analysis, AST inspection, NIR SSA, and fail-closed direct LLVM SSA IR emission
- `ninoc test` / `ninoc pkg` / `ninoc mobile` / `ninoc lsp` / `ninoc trace` / `ninoc fmt` / `ninoc bindgen` / `ninoc sbom` / `ninoc bench`: Testing, package locks, mobile bridges, LSP, tracing, formatting, FFI generation, SBOMs, and profiling

---

## Quick Start & Bootstrap

Pre-built release bundles for Linux and Windows (`v1.2.2`) are published via [GitHub Releases](https://github.com/jefmextra/nino-lang/releases), or the toolchain can be built directly from the C11 seed:

```cmd
bootstrap\install.bat
```

```bash
./bootstrap/install.sh
```

---

## Documentation, Governance & Standards

- **[SPECIFICATION.md](SPECIFICATION.md)**: Formal Language Specification v1.2 and Normative Conformance Traceability Matrix
- **[CHALLENGE.md](CHALLENGE.md)**: Public "Break the Prover & Sandbox" Adversarial Challenge (v1.2.2)
- **[rfcs/README.md](rfcs/README.md)**: Accepted Architectural RFCs and Review Lifecycle
- **[formal/arena_soundness.smt2](formal/arena_soundness.smt2)**: Machine-Checked Z3 Formal Proofs for Arena Epochs and Vectorization Soundness
- **[GOVERNANCE.md](GOVERNANCE.md)**: Nino Open Foundation Charter and Working Groups
- **[ROADMAP.md](ROADMAP.md)**: Strategic Engineering Milestones
- **[CONTRIBUTING.md](CONTRIBUTING.md)**: Build, Bootstrap Verification, and Automated E2E Test Suites

---

## Author & License

Designed and developed by **vvictor** at [ninosec.me](https://ninosec.me) under the [MIT License](LICENSE).
