# Architecture Review Board (ARB) Cryptographic Exemption & Conformance Process

## 1. Purpose and Epistemic Boundary

The Foundry Architecture Review Co-Worker automates Well-Architected Framework (WAF) design reviews on every Pull Request, scoring manifests against `ai/waf-pillar-rubric.json` and verifying live subscription posture via `src/Invoke-PolicyPreflightCheck.ps1` (`Invoke-AzRestMethod`).

However, enterprise delivery occasionally requires time-bound architectural exemptions—for example, during a controlled migration from public endpoints to Private Link. Exemptions are **never** granted by an AI model. Instead, they follow a cryptographically bound, human-approved Microsoft Teams workflow via Microsoft Graph v2.x.

## 2. Exemption Workflow Steps

1. **Automated Critique (`ai/Invoke-ArbDesignCritique.ps1`)**:
   - Evaluates the PR manifest against all five WAF pillars (Security, Reliability, Operational Excellence, Cost Optimization, Performance Efficiency).
   - If any `CRITICAL` control fails (such as `WAF-SEC-01` Public Network Exposure or `WAF-SEC-03` Static Credentials) or `WafScore < 80`, the gate emits `BLOCK_PR_MERGE_ARB_VIOLATION` along with exact `RemediationDiffs`.
   - If the manifest is incomplete (`Confidence < 0.75`), the gate emits `ABSTAIN_INCOMPLETE_MANIFEST` and refuses to guess.

2. **Cryptographic Digest & Teams Adaptive Card (`graph/Send-ArbExemptionApproval.ps1`)**:
   - The engineering lead triggers `Send-ArbExemptionApproval.ps1`, which computes a **SHA-256 digest** of the exact `CritiqueResult` payload and stamps an expiry timestamp (`ExemptionTtlDays`, default 30 days, maximum 90 days).
   - A Microsoft Teams Adaptive Card is posted to the ARB channel via `POST /v1.0/teams/{teamId}/channels/{channelId}/messages`.
   - Any subsequent edit to the PR manifest invalidates the SHA-256 digest, forcing re-evaluation.

3. **Live Policy Pre-Flight (`src/Invoke-PolicyPreflightCheck.ps1`)**:
   - Before merge, Azure Resource Graph (`Microsoft.ResourceGraph/resources`) and Azure Policy Insights (`policyStates/latest/queryResults`) confirm zero unapproved public endpoints or `NonCompliant` policy states in the target resource group.

4. **Audit Retention (`queries/Deployment-Conformance.kql`)**:
   - All ARB decisions, SHA-256 exemption digests, and expiry dates are logged to Azure Monitor Log Analytics for 365-day auditability.
