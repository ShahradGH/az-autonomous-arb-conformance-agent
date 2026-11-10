# Autonomous Architecture Review Board (ARB) Co-Worker: CAF & WAF Conformance Gate

[![Pester Verification](https://img.shields.io/badge/pester-16%2F16%20passing-brightgreen)](tests/ArbConformance.Tests.ps1)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Architecture Deep-Dive](https://img.shields.io/badge/blog-alerasoul.net-0a1128)](https://alerasoul.net/autonomous-arb-conformance-coworker/)

> **Primary Governance Artefact:** 32-Test CAF/WAF Architecture Conformance Matrix  
> **Accountable Service Owner:** Enterprise Architecture Board Chair & Cloud Practice Lead  
> **Full Architectural Deep-Dive:** [https://alerasoul.net/autonomous-arb-conformance-coworker/](https://alerasoul.net/autonomous-arb-conformance-coworker/)

---

## Repository Layout (11 Files)

```text
├── .github/workflows/arb-pr-check.yml
├── .gitignore
├── LICENSE
├── README.md
├── docs/ARB-EXEMPTION-PROCESS.md
├── fixtures/non-compliant-plan.json
├── infra/arb-webhook-runner.bicep
├── queries/Deployment-Conformance.kql
├── rules/waf-security-baseline.json
├── src/Test-ArbBicepConformance.ps1
└── tests/ArbConformance.Tests.ps1
```

## Quickstart & Offline Verification

```powershell
# 1. Execute the primary PowerShell 7 evaluator
pwsh -NoProfile -File ./src/Test-ArbBicepConformance.ps1

# 2. Run the 16-test Pester verification contract
Invoke-Pester -Path ./tests/ArbConformance.Tests.ps1 -Output Detailed
```

## License

Released under the [MIT License](LICENSE). Authored by **Shahrad Alerasoul** ([alerasoul.net](https://alerasoul.net)).
