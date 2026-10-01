function Get-CustomDetectionIdByDetectorId {
    <#
    .SYNOPSIS
        Gets the detection rule ID by the guid from the source file.

    .DESCRIPTION
        Looks up a detection rule whose rule ID equals the given guid, with or
        without the rule prefix, then a rule whose detector ID the API assigned
        equals it, then a rule whose description tag carries it, which is how
        rules created before the rule ID carried the guid are found.

    .PARAMETER DetectorId
        The guid to look up. Matched against the rule ID in its plain and
        rule-prefixed forms, then against the detector ID the API assigned,
        then against the description tag.

    .EXAMPLE
        Get-CustomDetectionIdByDetectorId -DetectorId "81fb771a-c57e-41b8-9905-63dbf267c13f"

        Returns the detection rule ID of the rule the guid names.

    .NOTES
        Requires the Microsoft.Graph.Authentication module and an active Graph API session.
        Use Connect-MgGraph before calling this function.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [string]$DetectorId
    )

    begin {
        Assert-MgGraphConnection
    }

    process {
        try {
            # Leverage the cached detection IDs list
            $detectionIds = Get-CustomDetectionIds

            # Match the rule id in its plain and rule-prefixed forms, then the detector id the API assigned
            $detectionRule = $detectionIds | Where-Object { $_.Id -eq $DetectorId -or $_.Id -eq "rule-$DetectorId" -or $_.DetectorId -eq $DetectorId } | Select-Object -First 1
            if ($detectionRule) {
                return $detectionRule.Id
            }

            # Then the description tag, which is how rules created before the rule id carried the guid are found
            $taggedId = Get-CustomDetectionTaggedId -Rule @($detectionIds) -DescriptionTag $DetectorId
            if ($taggedId) {
                return $taggedId
            }

            Write-Verbose "No detection rule found with detectorId: $DetectorId"
            return $null
        } catch {
            Write-Error "Error querying Microsoft Graph API: $($_.Exception.Message)"
            throw
        }
    }
}

