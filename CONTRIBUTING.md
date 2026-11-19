# Contributing to The Nino Programming Language

Thank you for your interest in contributing to Nino! Whether you are reporting bugs, improving documentation, designing standard library modules, or hacking on the compiler, your contributions help shape the future of sovereign systems programming.

---

## 1. Getting Started

### Prerequisites
- A standard C compiler (GCC or Clang with MinGW-w64 on Windows, or native on Linux/macOS).
- Git (for repository synchronization and version control).
- Microsoft Z3 theorem prover (bundled in `tools/z3.exe` for contract verification).
- LLVM Clang 17+ (optional, for LLVM SSA backend testing).

### Cloning the Repository
```bash
git clone https://github.com/jefmextra/nino-lang.git
cd nino-lang
```

---

## 2. Development & Build Workflow

The Nino compiler is 100% self-hosted across 12 modular units under `compiler/` (with `compiler/ninoc.nino` as the entrypoint).

### Building the Compiler
To compile the current compiler source using the existing `ninoc` binary:
```bash
ninoc build compiler/ninoc.nino -o ninoc_dev.exe
```

### Running the Test Suite
Before submitting any pull request, ensure all 29 native test suites pass with zero warnings (`ninoc test`) alongside the 160-test cross-platform Tier 1-4 E2E suite (`tests/e2e/`) and `tools/compliance_check.nino`:
```bash
ninoc test
```

### Verifying Deterministic 3-Stage Bootstrap Convergence
All core compiler changes must maintain mathematical bootstrap convergence:
```bash
# Stage 1: Build from seed
ninoc build compiler/ninoc.nino -o stage1.exe

# Stage 2: Stage 1 builds Stage 2
./stage1.exe build compiler/ninoc.nino -o stage2.exe

# Stage 3: Stage 2 builds Stage 3
./stage2.exe build compiler/ninoc.nino -o stage3.exe

# Verification: Hashes must match bit-for-bit
sha256sum stage2.exe stage3.exe
```

---

## 3. Contribution Guidelines

1. **Code Hygiene & Comment Syntax**: Standard `//` line comments, `/* ... */` block comments, and `///` docstrings are fully supported across `.nino` files. Unclosed `/*`, non-`#no_std` `#` lines, and typographic em/en dashes remain disallowed (`ninoc run tools/compliance_check.nino`).
2. **Deterministic Code Generation**: Emitted C11 code must be clean, conform to MISRA/CERT best practices, and compile with zero warnings under `-Wall -Wextra`.
3. **Formal Verification First**: When adding critical algorithms, accompany them with formal contract specifications (`require` and `ensure`) verifiable by `ninoc prove`.
4. **Adversarial & Bug Reporting**: Search existing GitHub issues before opening a new one. Security or prover counterexamples targeting SMT/PCC/BCE/sealed isolation follow [CHALLENGE.md](CHALLENGE.md); syntax/architectural changes follow [GOVERNANCE.md](GOVERNANCE.md).

---

## 4. Community & Code of Conduct

We are committed to providing a welcoming, productive, and meritocratic environment. Respectful collaboration, rigorous technical discourse, and constructive feedback are core tenets of the Nino community.
