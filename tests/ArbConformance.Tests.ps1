BeforeAll {
    $script:RepoRoot = Split-Path -Parent $PSScriptRoot
    $script:CritiquePath = Join-Path $script:RepoRoot 'ai/Invoke-ArbDesignCritique.ps1'
    $script:PreflightPath = Join-Path $script:RepoRoot 'src/Invoke-PolicyPreflightCheck.ps1'
    $script:GraphExemptionPath = Join-Path $script:RepoRoot 'graph/Send-ArbExemptionApproval.ps1'
    $script:FixturesPath = Join-Path $script:RepoRoot 'fixtures/non-compliant-plan.json'
    $script:KqlPath = Join-Path $script:RepoRoot 'queries/Deployment-Conformance.kql'
    $script:Plans = Get-Content -Path $script:FixturesPath -Raw | ConvertFrom-Json
}

Describe 'Autonomous ARB Co-Worker - WAF Critique, Preflight & Graph Exemption Matrix' {
    Context 'AI WAF Design Critique (ai/Invoke-ArbDesignCritique.ps1)' {
        It 'Blocks non-compliant Tier-1 manifest (PR #412) and generates remediation diffs' {
            $res = & $script:CritiquePath -ArchitectureManifest $script:Plans[0]
            $res.GateDecision | Should -Be 'BLOCK_PR_MERGE_ARB_VIOLATION'
            $res.Passed | Should -BeFalse
            $res.WafScore | Should -BeLessThan 80
            $res.Findings.ControlId | Should -Contain 'WAF-SEC-01'
            $res.Findings.ControlId | Should -Contain 'WAF-SEC-02'
            $res.Findings.ControlId | Should -Contain 'WAF-SEC-03'
            $res.RemediationDiffs.Count | Should -BeGreaterThan 0
        }

        It 'Approves compliant Tier-1 manifest (PR #413) with score 100' {
            $res = & $script:CritiquePath -ArchitectureManifest $script:Plans[1]
            $res.GateDecision | Should -Be 'APPROVE_ARB_CONFORMANCE'
            $res.Passed | Should -BeTrue
            $res.WafScore | Should -Be 100
            $res.FindingCount | Should -Be 0
        }

        It 'Abstains on incomplete manifest (PR #414) below confidence threshold' {
            $res = & $script:CritiquePath -ArchitectureManifest $script:Plans[2]
            $res.GateDecision | Should -Be 'ABSTAIN_INCOMPLETE_MANIFEST'
            $res.Passed | Should -BeFalse
            $res.Confidence | Should -BeLessThan 0.75
        }

        It 'Integrates mocked Azure AI Foundry executive summary without overriding deterministic veto' {
            $mockFoundry = {
                param($ep, $dep, $body)
                return [PSCustomObject]@{
                    executiveSummary     = 'Critical public network exposure and static credentials detected.'
                    residualRisk         = 'HIGH'
                    confidenceAdjustment = 0.03
                }
            }
            $res = & $script:CritiquePath -ArchitectureManifest $script:Plans[0] -FoundryEndpoint 'https://foundry.contoso.invalid' -FoundryInvoker $mockFoundry
            $res.FoundryCritique.residualRisk | Should -Be 'HIGH'
            $res.GateDecision | Should -Be 'BLOCK_PR_MERGE_ARB_VIOLATION'
        }
    }

    Context 'Azure Control-Plane Preflight & Graph v2.x Teams Exemption' {
        It 'Detects publicly exposed resources and non-compliant policy states via Invoke-AzRestMethod' {
            $mockAz = {
                param($method, $path, $payload)
                if ($path -match 'ResourceGraph') {
                    return [PSCustomObject]@{ data = @([PSCustomObject]@{ name = 'stcontosopayroll01'; type = 'Microsoft.Storage/storageAccounts' }) }
                }
                return [PSCustomObject]@{ value = @([PSCustomObject]@{ policyDefinitionName = 'deny-public-blob' }) }
            }
            $res = & $script:PreflightPath -SubscriptionId '00000000-0000-0000-0000-000000000001' -ResourceGroupName 'rg-contoso-payroll' -AzRestInvoker $mockAz
            $res.PreflightPassed | Should -BeFalse
            $res.PubliclyExposedCount | Should -Be 1
            $res.NonCompliantPolicyCount | Should -Be 1
        }

        It 'Passes preflight when Resource Graph and Policy Insights return zero violations' {
            $mockAzClean = {
                param($method, $path, $payload)
                if ($path -match 'ResourceGraph') { return [PSCustomObject]@{ data = @() } }
                return [PSCustomObject]@{ value = @() }
            }
            $res = & $script:PreflightPath -SubscriptionId '00000000-0000-0000-0000-000000000001' -ResourceGroupName 'rg-contoso-ledger' -AzRestInvoker $mockAzClean
            $res.PreflightPassed | Should -BeTrue
        }

        It 'Dispatches SHA-256 bound Teams Adaptive Card exemption via Graph v1.0' {
            $failed = & $script:CritiquePath -ArchitectureManifest $script:Plans[0]
            $captured = [System.Collections.Generic.List[PSCustomObject]]::new()
            $mockGraph = {
                param($method, $uri, $body)
                $captured.Add([PSCustomObject]@{ Method = $method; Uri = $uri; Body = $body })
                return [PSCustomObject]@{ id = 'msg-arb-9901' }
            }
            $res = & $script:GraphExemptionPath `
                -TeamId 'team-111' `
                -ChannelId '19:arb@thread.tacv2' `
                -CritiqueResult $failed `
                -RequestorUpn 'alex.morgan@contoso.com' `
                -GraphInvoker $mockGraph

            $captured.Count | Should -Be 1
            $captured[0].Uri | Should -Be 'https://graph.microsoft.com/v1.0/teams/team-111/channels/19:arb@thread.tacv2/messages'
            $res.ManifestSha256.Length | Should -Be 64
            $res.MessageId | Should -Be 'msg-arb-9901'
        }
    }

    Context 'Repository Hygiene & Zero-Leak Boundaries' {
        It 'Contains zero declarative IaC (.bicep or .tf) files' {
            $iac = Get-ChildItem -Path $script:RepoRoot -Recurse -Include '*.bicep', '*.tf' -File
            $iac.Count | Should -Be 0
        }

        It 'KQL conformance query exists and uses projection/aggregation' {
            Test-Path $script:KqlPath | Should -BeTrue
            (Get-Content $script:KqlPath -Raw) | Should -Match 'where|summarize|project'
        }

        It 'README and docs contain zero internal sequence numbers or private orchestrator domains' {
            foreach ($f in @((Join-Path $script:RepoRoot 'README.md'), (Join-Path $script:RepoRoot 'docs/ARB-EXEMPTION-PROCESS.md'))) {
                $raw = Get-Content $f -Raw
                $raw | Should -Not -Match 'mvpfoundry\.alerasoul\.net|192\.142\.41\.43|Decision Pack 0|idea-011'
            }
        }
    }

    Context 'Identity & Microsoft Graph v2.x ARB Governance Module' {
        BeforeAll {
            Import-Module (Join-Path $script:RepoRoot 'identity/ArbIdentityGovernance.psd1') -Force
        }

        It 'Authorises an active non-guest member of the ARB Entra ID group' {
            $mockGraph = {
                param($method, $uri, $body)
                if ($uri -match '/users/') {
                    return [PSCustomObject]@{
                        id                = 'usr-001'
                        userPrincipalName = 'alex.morgan@contoso.com'
                        displayName       = 'Alex Morgan'
                        accountEnabled    = $true
                        userType          = 'Member'
                    }
                }
                return [PSCustomObject]@{
                    value = @([PSCustomObject]@{ id = 'usr-001'; userPrincipalName = 'alex.morgan@contoso.com' })
                }
            }

            $res = Get-ArbApproverDirectoryState -ApproverUpn 'alex.morgan@contoso.com' -ArbGroupId 'grp-arb-01' -GraphInvoker $mockGraph
            $res.IsAuthorised | Should -BeTrue
            $res.InArbGroup | Should -BeTrue
        }

        It 'Rejects guest or disabled accounts from approving ARB exemptions' {
            $mockGraph = {
                param($method, $uri, $body)
                if ($uri -match '/users/') {
                    return [PSCustomObject]@{
                        id                = 'usr-002'
                        userPrincipalName = 'guest.ext@contoso.com'
                        displayName       = 'External Guest'
                        accountEnabled    = $true
                        userType          = 'Guest'
                    }
                }
                return [PSCustomObject]@{
                    value = @([PSCustomObject]@{ id = 'usr-002'; userPrincipalName = 'guest.ext@contoso.com' })
                }
            }

            $res = Get-ArbApproverDirectoryState -ApproverUpn 'guest.ext@contoso.com' -ArbGroupId 'grp-arb-01' -GraphInvoker $mockGraph
            $res.IsAuthorised | Should -BeFalse
        }

        It 'Flags forbidden high-privilege Graph app role assignments on workload identities' {
            $mockGraph = {
                param($method, $uri, $body)
                return [PSCustomObject]@{
                    value = @(
                        [PSCustomObject]@{ appRoleId = '19dbc75e-c2e2-444c-a770-ec69d8559fc7' }
                    )
                }
            }

            $res = Test-ArbManagedIdentityLeastPrivilege -ServicePrincipalId 'sp-001' -GraphInvoker $mockGraph
            $res.LeastPrivilegePass | Should -BeFalse
            $res.ViolationCount | Should -Be 1
        }

        It 'Dispatches SHA-256 exemption audit record to Teams channel' {
            $mockGraph = {
                param($method, $uri, $body)
                return [PSCustomObject]@{ id = 'msg-audit-01' }
            }

            $res = New-ArbExemptionAuditRecord -TeamId 't-1' -ChannelId 'c-1' -PrNumber 'PR-402' -ManifestSha256 ('a' * 64) -ApproverUpn 'alex.morgan@contoso.com' -GraphInvoker $mockGraph
            $res.Dispatched | Should -BeTrue
            $res.MessageId | Should -Be 'msg-audit-01'
        }
    }
}
