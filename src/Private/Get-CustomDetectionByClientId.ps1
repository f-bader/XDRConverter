function Get-CustomDetectionByClientId {
    <#
    .SYNOPSIS
        Fetches a rule by the client id built from its guid.

    .DESCRIPTION
        The rule list can omit a rule for a long time after its id was deleted
        and created again, while a request for the id answers at once. Returns
        the rule, or null when the API answers NotFound. Any other failure is
        raised.
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory)]
        [string]$Guid
    )

    try {
        $rule = Get-CustomDetection -DetectionId "rule-$Guid" -ErrorAction SilentlyContinue
        if ($rule -and $rule.id) { return $rule }
        return $null
    } catch {
        if (-not (Test-CustomDetectionNotFound -ErrorRecord $_)) { throw }
        return $null
    }
}
