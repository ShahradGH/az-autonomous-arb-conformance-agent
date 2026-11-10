# Test-ArbBicepConformance.ps1
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [PSCustomObject]$CompiledArmTemplate,
    [Parameter()] [string]$Environment = 'prod'
)

$ErrorActionPreference = 'Stop'
$violations = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($res in @($CompiledArmTemplate.resources)) {
    $props = $res.properties
    if (-not $props) { continue }

    # 1. Veto Public Network Access on Stateful PaaS Resources
    if ($props.PSObject.Properties['publicNetworkAccess'] -and $props.publicNetworkAccess -ne 'Disabled') {
        $violations.Add([PSCustomObject]@{
            ResourceName = $res.name
            ResourceType = $res.type
            RuleId       = 'CAF-NET-001'
            Severity     = 'HIGH'
            Message      = "Resource '$($res.name)' sets publicNetworkAccess='$($props.publicNetworkAccess)'. Must be 'Disabled' with Private Endpoint."
        })
    }

    # 2. Veto TLS < 1.2 on Storage, SQL, KeyVault, and Web Apps
    if ($props.PSObject.Properties['minimumTlsVersion'] -and $props.minimumTlsVersion -notin @('TLS1_2', '1.2', '1.3')) {
        $violations.Add([PSCustomObject]@{
            ResourceName = $res.name
            ResourceType = $res.type
            RuleId       = 'WAF-SEC-004'
            Severity     = 'CRITICAL'
            Message      = "Resource '$($res.name)' permits legacy TLS ('$($props.minimumTlsVersion)'). Minimum required: TLS 1.2."
        })
    }

    # 3. Veto Missing Mandatory FinOps & Governance Tags
    $tags = $res.tags
    if (-not $tags -or -not $tags.PSObject.Properties['CostCentre'] -or -not $tags.PSObject.Properties['DataClassification']) {
        $violations.Add([PSCustomObject]@{
            ResourceName = $res.name
            ResourceType = $res.type
            RuleId       = 'CAF-GOV-009'
            Severity     = 'MEDIUM'
            Message      = "Resource '$($res.name)' is missing mandatory 'CostCentre' or 'DataClassification' tags."
        })
    }
}

return [PSCustomObject]@{
    Environment    = $Environment
    Passed         = ($violations.Count -eq 0)
    GateDecision   = if ($violations.Count -eq 0) { 'APPROVE_PR_MERGE' } else { 'VETO_NON_COMPLIANT_BICEP' }
    ViolationCount = $violations.Count
    Violations     = @($violations)
}