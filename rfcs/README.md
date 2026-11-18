# NinoLang Request for Comments (RFC) Process

This directory contains formal engineering proposals and architectural standards for the **Nino Programming Language (`ninoc`)**.

## Editorial Process & Lifecycle

1. **Draft**: Technical design document submitted alongside a prototype, formal invariants, or test cases.
2. **Public Review**: Open discussion and security/soundness review per [GOVERNANCE.md](../GOVERNANCE.md).
3. **Accepted / Normative**: Ratified into [SPECIFICATION.md](../SPECIFICATION.md) and covered by deterministic automated checks in `tests/e2e/` and `formal/`.

## Index of Published RFCs

| RFC ID | Title | Status |
|---|---|---|
| [RFC-0001](RFC-0001-arena-epoch-memory-safety.md) | Scoped Arena Epoch Model & Static Region Escape Analysis (`E0515`) | Accepted / Implemented |
| [RFC-0002](RFC-0002-pcc-smt-ed25519-abi.md) | SMT-LIB v2.6 BitVector/IEEE-754 Verification & Asymmetric Ed25519 PCC ABI | Accepted / Implemented |
| [RFC-0003](RFC-0003-nir-simd-vectorization-and-native-isa.md) | NIR Loop Auto-Vectorization & Direct Multi-ISA Native Code Generation | Accepted / Implemented |
