@{
    RootModule        = 'ArbIdentityGovernance.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = '11111111-2222-3333-4444-555555550001'
    Author            = 'ShahradGH'
    CompanyName       = 'Independent Architecture'
    Copyright         = '(c) ShahradGH. MIT License.'
    Description       = 'Microsoft Graph v2.x Entra ID approver verification, least-privilege auditing, and cryptographic ARB exemption audit logging.'
    PowerShellVersion = '7.4'
    FunctionsToExport = @(
        'Get-ArbApproverDirectoryState',
        'Test-ArbManagedIdentityLeastPrivilege',
        'New-ArbExemptionAuditRecord'
    )
}
