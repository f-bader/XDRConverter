function Get-CustomDetectionIdByDetectorId {
    <#
    .SYNOPSIS
        Gets the detection rule ID by its detector ID.

    .DESCRIPTION
        Queries Microsoft Graph API to retrieve the detection rule ID for a given detector ID.
        This function wraps Invoke-MgGraphRequest to query the Defender XDR detection rules endpoint.

    .PARAMETER DetectorId
        The detector ID (GUID) to look up.

    .EXAMPLE
        Get-CustomDetectionIdByDetectorId -DetectorId "81fb771a-c57e-41b8-9905-63dbf267c13f"

        Returns the detection rule ID for the specified detector ID.

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

            # Find the detection rule with the matching detectorId
            $detectionRule = $detectionIds | Where-Object { $_.DetectorId -eq $DetectorId }

            if ($detectionRule) {
                return $detectionRule.Id
            } else {
                Write-Warning "No detection rule found with detectorId: $DetectorId"
                return $null
            }
        } catch {
            Write-Error "Error querying Microsoft Graph API: $($_.Exception.Message)"
            throw
        }
    }
}

