<#
.SYNOPSIS
    Microsoft Graph v2.x identity and least-privilege governance module for ARB Conformance.
.DESCRIPTION
    Provides deterministic Entra ID approver verification, least-privilege workload identity
    auditing, and cryptographic exemption audit-record dispatch via Microsoft Graph v1.0.
    Uses British English conventions and supports offline testing via -GraphInvoker.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-ArbGraphRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('GET', 'POST', 'PATCH', 'DELETE')]
        [string]$Method,

        [Parameter(Mandatory)]
        [string]$Uri,

        [Parameter()]
        [object]$Body,

        [Parameter()]
        [scriptblock]$GraphInvoker
    )

    if ($null -ne $GraphInvoker) {
        return & $GraphInvoker $Method $Uri $Body
    }

    $params = @{
        Method = $Method
        Uri    = $Uri
    }
    if ($null -ne $Body) {
        $params['Body'] = ($Body | ConvertTo-Json -Depth 10)
        $params['ContentType'] = 'application/json'
    }

    return Invoke-MgGraphRequest @params
}

function Get-ArbApproverDirectoryState {
    <#
    .SYNOPSIS
        Verifies that an ARB exemption approver is an active, non-guest member of the authorised Entra ID group.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ApproverUpn,

        [Parameter(Mandatory)]
        [string]$ArbGroupId,

        [Parameter()]
        [scriptblock]$GraphInvoker
    )

    $encodedUpn = [System.Uri]::EscapeDataString($ApproverUpn)
    $userUri = "https://graph.microsoft.com/v1.0/users/$encodedUpn`?`$select=id,userPrincipalName,displayName,accountEnabled,userType"
    $user = Invoke-ArbGraphRequest -Method 'GET' -Uri $userUri -GraphInvoker $GraphInvoker

    $groupUri = "https://graph.microsoft.com/v1.0/groups/$ArbGroupId/members?`$select=id,userPrincipalName"
    $membersResp = Invoke-ArbGraphRequest -Method 'GET' -Uri $groupUri -GraphInvoker $GraphInvoker
    $members = @($membersResp.value)

    $isMember = @($members | Where-Object {
        $_.id -eq $user.id -or $_.userPrincipalName -eq $user.userPrincipalName
    }).Count -gt 0

    $isAuthorised = ($user.accountEnabled -eq $true) -and ($user.userType -ne 'Guest') -and $isMember

    return [PSCustomObject]@{
        ApproverUpn    = $user.userPrincipalName
        DisplayName    = $user.displayName
        AccountEnabled = [bool]$user.accountEnabled
        UserType       = $user.userType
        InArbGroup     = $isMember
        IsAuthorised   = $isAuthorised
        CheckedAtUtc   = (Get-Date).ToUniversalTime().ToString('o')
    }
}

function Test-ArbManagedIdentityLeastPrivilege {
    <#
    .SYNOPSIS
        Audits a workload service principal against high-privilege Microsoft Graph app role assignments.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ServicePrincipalId,

        [Parameter()]
        [string[]]$ForbiddenAppRoleIds = @(
            '19dbc75e-c2e2-444c-a770-ec69d8559fc7', # Directory.ReadWrite.All
            '9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8'  # RoleManagement.ReadWrite.Directory
        ),

        [Parameter()]
        [scriptblock]$GraphInvoker
    )

    $uri = "https://graph.microsoft.com/v1.0/servicePrincipals/$ServicePrincipalId/appRoleAssignments"
    $resp = Invoke-ArbGraphRequest -Method 'GET' -Uri $uri -GraphInvoker $GraphInvoker
    $assignments = @($resp.value)

    $violations = @($assignments | Where-Object { $ForbiddenAppRoleIds -contains $_.appRoleId })

    return [PSCustomObject]@{
        ServicePrincipalId = $ServicePrincipalId
        TotalAssignments   = $assignments.Count
        ViolationCount     = $violations.Count
        ViolatingRoleIds   = @($violations | ForEach-Object { $_.appRoleId })
        LeastPrivilegePass = ($violations.Count -eq 0)
        AuditedAtUtc       = (Get-Date).ToUniversalTime().ToString('o')
    }
}

function New-ArbExemptionAuditRecord {
    <#
    .SYNOPSIS
        Dispatches a SHA-256-bound ARB exemption audit record to a Teams governance channel via Microsoft Graph.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$TeamId,

        [Parameter(Mandatory)]
        [string]$ChannelId,

        [Parameter(Mandatory)]
        [string]$PrNumber,

        [Parameter(Mandatory)]
        [string]$ManifestSha256,

        [Parameter(Mandatory)]
        [string]$ApproverUpn,

        [Parameter()]
        [int]$TtlDays = 30,

        [Parameter()]
        [scriptblock]$GraphInvoker
    )

    $expiresUtc = (Get-Date).ToUniversalTime().AddDays($TtlDays).ToString('o')
    $uri = "https://graph.microsoft.com/v1.0/teams/$TeamId/channels/$ChannelId/messages"
    $payload = @{
        body = @{
            contentType = 'html'
            content     = "<b>ARB Exemption Audit</b> | PR: $PrNumber | Approver: $ApproverUpn | SHA-256: <code>$ManifestSha256</code> | Expires: $expiresUtc"
        }
    }

    if (-not $PSCmdlet.ShouldProcess("$TeamId/$ChannelId", "Record ARB exemption audit for PR $PrNumber")) {
        return [PSCustomObject]@{
            PrNumber       = $PrNumber
            ManifestSha256 = $ManifestSha256
            ExpiresUtc     = $expiresUtc
            Dispatched     = $false
            MessageId      = 'WHATIF-DRYRUN'
        }
    }

    $resp = Invoke-ArbGraphRequest -Method 'POST' -Uri $uri -Body $payload -GraphInvoker $GraphInvoker
    return [PSCustomObject]@{
        PrNumber       = $PrNumber
        ManifestSha256 = $ManifestSha256
        ExpiresUtc     = $expiresUtc
        Dispatched     = $true
        MessageId      = $resp.id
    }
}

Export-ModuleMember -Function @(
    'Get-ArbApproverDirectoryState',
    'Test-ArbManagedIdentityLeastPrivilege',
    'New-ArbExemptionAuditRecord'
)
