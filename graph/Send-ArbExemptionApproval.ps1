<#
.SYNOPSIS
    Dispatches a cryptographic Architecture Review Board (ARB) exemption Adaptive Card to Microsoft Teams via Graph v2.x.
.DESCRIPTION
    Computes a SHA-256 manifest digest of the non-compliant architecture plan and posts a time-bound exemption
    approval Adaptive Card to the ARB Teams channel via Microsoft Graph v1.0 /teams/{teamId}/channels/{channelId}/messages.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [string]$TeamId,

    [Parameter(Mandatory)]
    [string]$ChannelId,

    [Parameter(Mandatory)]
    [PSCustomObject]$CritiqueResult,

    [Parameter(Mandatory)]
    [string]$RequestorUpn,

    [Parameter()]
    [int]$ExemptionTtlDays = 30,

    [Parameter()]
    [scriptblock]$GraphInvoker
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$canonicalJson = $CritiqueResult | ConvertTo-Json -Depth 8 -Compress
$bytes = [System.Text.Encoding]::UTF8.GetBytes($canonicalJson)
$sha256 = [System.Security.Cryptography.SHA256]::Create()
$digestHex = ([BitConverter]::ToString($sha256.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
$expiresUtc = (Get-Date).ToUniversalTime().AddDays($ExemptionTtlDays).ToString('yyyy-MM-ddTHH:mm:ssZ')

$cardPayload = @{
    '$schema' = 'http://adaptivecards.io/schemas/adaptive-card.json'
    type      = 'AdaptiveCard'
    version   = '1.5'
    body      = @(
        @{
            type   = 'TextBlock'
            text   = "ARB Time-Bound Exemption Request: PR #$($CritiqueResult.PrNumber)"
            weight = 'Bolder'
            size   = 'Medium'
        },
        @{
            type  = 'FactSet'
            facts = @(
                @{ title = 'Requestor'; value = $RequestorUpn },
                @{ title = 'Service Tier'; value = $CritiqueResult.ServiceTier },
                @{ title = 'WAF Score'; value = "$($CritiqueResult.WafScore)/100" },
                @{ title = 'Findings'; value = "$($CritiqueResult.FindingCount)" },
                @{ title = 'SHA-256 Digest'; value = $digestHex.Substring(0, 16) + '...' },
                @{ title = 'Expires (UTC)'; value = $expiresUtc }
            )
        }
    )
}

$messageBody = @{
    body        = @{
        contentType = 'html'
        content     = "<attachment id=`"arbExemptionCard`"></attachment>"
    }
    attachments = @(
        @{
            id          = 'arbExemptionCard'
            contentType = 'application/vnd.microsoft.card.adaptive'
            content     = ($cardPayload | ConvertTo-Json -Depth 10 -Compress)
        }
    )
}

$uri = "https://graph.microsoft.com/v1.0/teams/$TeamId/channels/$ChannelId/messages"
$resp = $null

if ($PSCmdlet.ShouldProcess("Teams Channel $ChannelId", "Post ARB Exemption Card for PR #$($CritiqueResult.PrNumber)")) {
    if ($null -ne $GraphInvoker) {
        $resp = & $GraphInvoker 'POST' $uri $messageBody
    }
    else {
        $resp = Invoke-MgGraphRequest -Method Post -Uri $uri -Body ($messageBody | ConvertTo-Json -Depth 12) -ContentType 'application/json'
    }
}

return [PSCustomObject]@{
    PrNumber       = $CritiqueResult.PrNumber
    ChannelUri     = $uri
    MessageId      = if ($null -ne $resp -and $resp.id) { $resp.id } else { 'whatif-message' }
    ManifestSha256 = $digestHex
    ExpiresAtUtc   = $expiresUtc
    DispatchedAt   = (Get-Date).ToUniversalTime().ToString('o')
}
