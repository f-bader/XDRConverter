function Compare-CustomDetection {
    <#
    .SYNOPSIS
        Compares two detection rule objects for meaningful differences.

    .DESCRIPTION
        Compares the key properties of a local detection rule against the remote
        version and returns $true when they differ.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Local,

        [Parameter(Mandatory)]
        [PSObject]$Remote
    )

    # Properties to compare – order matches the JSON schema structure
    $propertiesToCompare = @(
        @{ Local = 'displayName'; Remote = 'displayName' }
        @{ Local = 'isEnabled'; Remote = 'isEnabled' }
        @{ Local = 'queryText'; Remote = 'queryCondition.queryText' }
        @{ Local = 'period'; Remote = 'schedule.period' }
        @{ Local = 'title'; Remote = 'detectionAction.alertTemplate.title' }
        @{ Local = 'description'; Remote = 'detectionAction.alertTemplate.description' }
        @{ Local = 'severity'; Remote = 'detectionAction.alertTemplate.severity' }
        @{ Local = 'category'; Remote = 'detectionAction.alertTemplate.category' }
    )

    # Helper to resolve dot-separated property paths on the remote object
    function Get-NestedValue {
        param([PSObject]$Object, [string]$Path)
        $current = $Object
        foreach ($segment in $Path.Split('.')) {
            if ($null -eq $current) { return $null }
            $current = $current.$segment
        }
        return $current
    }

    foreach ($prop in $propertiesToCompare) {
        $localVal = $Local[$prop.Local]
        $remoteVal = Get-NestedValue -Object $Remote -Path $prop.Remote

        # Normalise nulls / empty strings for fair comparison
        if ([string]::IsNullOrEmpty($localVal)) { $localVal = '' }
        if ([string]::IsNullOrEmpty($remoteVal)) { $remoteVal = '' }

        if ([string]$localVal -ne [string]$remoteVal) {
            Write-Verbose "Difference found on '$($prop.Local)': local='$localVal' remote='$remoteVal'"
            return $true
        }
    }

    return $false
}
