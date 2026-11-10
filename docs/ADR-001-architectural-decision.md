# ADR-001: Autonomous Architecture Review Board (ARB) Co-Worker: CAF & WAF Conformance Gate

## Status
Accepted

## Service Owner & Sign-Off Authority
Enterprise Architecture Board Chair & Cloud Practice Lead

## Dominant Artefact
32-Test CAF/WAF Architecture Conformance Matrix

## Decision & Refusal Boundary
All production state mutations must pass deterministic pre-flight policy evaluation in `src/Test-ArbBicepConformance.ps1` and satisfy the 16-test Pester verification contract in `tests/Boundary-Verification.Tests.ps1` before execution.
