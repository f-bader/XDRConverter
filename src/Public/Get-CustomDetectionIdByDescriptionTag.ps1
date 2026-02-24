function Get-CustomDetectionIdByDescriptionTag {
    <#
    .SYNOPSIS
        Gets the detection rule ID by its description tag UUID.

    .DESCRIPTION
        Looks up the detection rule ID for a given UUID that was embedded
        in the alert description as a tag (e.g. "[UUID]" or "[PREFIX:UUID]").
        This function leverages the cached output of Get-CustomDetectionIds.

    .PARAMETER DescriptionTag
        The UUID to search for in description tags.

    .EXAMPLE
        Get-CustomDetectionIdByDescriptionTag -DescriptionTag "81fb771a-c57e-41b8-9905-63dbf267c13f"

        Returns the detection rule ID for the rule whose description contains the specified UUID tag.

    .NOTES
        Requires the Microsoft.Graph.Authentication module and an active Graph API session.
        Use Connect-MgGraph before calling this function.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [string]$DescriptionTag
    )

    begin {
        Assert-MgGraphConnection
    }

    process {
        try {
            # Leverage the cached detection IDs list
            $detectionIds = Get-CustomDetectionIds

            # Find the detection rule with the matching description tag
            $detectionRule = $detectionIds | Where-Object { $_.DescriptionTag -eq $DescriptionTag }

            if ($detectionRule) {
                return $detectionRule.Id
            } else {
                Write-Warning "No detection rule found with description tag: $DescriptionTag"
                return $null
            }
        } catch {
            Write-Error "Error querying Microsoft Graph API: $($_.Exception.Message)"
            throw
        }
    }
}
