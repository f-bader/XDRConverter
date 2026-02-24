function Assert-MgGraphConnection {
    <#
    .SYNOPSIS
        Validates Microsoft Graph connectivity prerequisites.

    .DESCRIPTION
        Ensures the Microsoft.Graph.Authentication module is installed, loaded,
        and that an active Graph API session exists. Throws if any check fails.
    #>
    [CmdletBinding()]
    param ()

    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
        throw 'Microsoft.Graph.Authentication module is not installed. Install it with: Install-Module Microsoft.Graph.Authentication'
    }

    if (-not (Get-Module -Name Microsoft.Graph.Authentication)) {
        Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    }

    $context = Get-MgContext
    if (-not $context) {
        throw 'Not connected to Microsoft Graph. Please run Connect-MgGraph first.'
    }
}
