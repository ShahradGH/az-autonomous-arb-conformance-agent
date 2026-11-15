<#
.SYNOPSIS
    Executes Azure Resource Graph and Azure Policy Insights pre-flight checks via Invoke-AzRestMethod.
.DESCRIPTION
    Queries live subscription posture before PR merge using Invoke-AzRestMethod against
    Microsoft.ResourceGraph/resources and Microsoft.PolicyInsights/policyStates/latest/queryResults.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$SubscriptionId,

    [Parameter(Mandatory)]
    [string]$ResourceGroupName,

    [Parameter()]
    [scriptblock]$AzRestInvoker
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-AzControlPlane {
    param([string]$Method, [string]$Path, [object]$Payload)
    if ($null -ne $AzRestInvoker) {
        return & $AzRestInvoker $Method $Path $Payload
    }
    $params = @{
        Method = $Method
        Path   = $Path
    }
    if ($null -ne $Payload) {
        $params['Payload'] = ($Payload | ConvertTo-Json -Depth 8)
    }
    $raw = Invoke-AzRestMethod @params
    if ($raw.StatusCode -ge 400) {
        throw "Azure REST call to '$Path' failed with HTTP $($raw.StatusCode): $($raw.Content)"
    }
    return ($raw.Content | ConvertFrom-Json)
}

$argPayload = @{
    subscriptions = @($SubscriptionId)
    query         = "Resources | where resourceGroup =~ '$ResourceGroupName' | where properties.publicNetworkAccess == 'Enabled' | project id, name, type"
}

$argPath = '/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01'
$argResult = Invoke-AzControlPlane -Method 'POST' -Path $argPath -Payload $argPayload

$policyPath = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.PolicyInsights/policyStates/latest/queryResults?api-version=2019-10-01&`$filter=ComplianceState eq 'NonCompliant'"
$policyResult = Invoke-AzControlPlane -Method 'POST' -Path $policyPath -Payload $null

$exposedResources = @($argResult.data)
$nonCompliantStates = @($policyResult.value)
$preflightPassed = ($exposedResources.Count -eq 0 -and $nonCompliantStates.Count -eq 0)

return [PSCustomObject]@{
    SubscriptionId          = $SubscriptionId
    ResourceGroupName       = $ResourceGroupName
    PreflightPassed         = $preflightPassed
    PubliclyExposedCount    = $exposedResources.Count
    NonCompliantPolicyCount = $nonCompliantStates.Count
    ExposedResources        = $exposedResources
    CheckedAtUtc            = (Get-Date).ToUniversalTime().ToString('o')
}
