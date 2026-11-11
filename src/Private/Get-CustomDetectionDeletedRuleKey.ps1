function Get-CustomDetectionDeletedRuleKey {
    <#
    .SYNOPSIS
        Builds the key that records a deleted rule.

    .DESCRIPTION
        The client id rule-<guid> is the same in every tenant a file deploys to,
        so the key pairs the id with the tenant of the current Graph connection.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$Id
    )

    return "$((Get-MgContext).TenantId)/$Id"
}
