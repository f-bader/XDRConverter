function Get-CustomDetection {
    <#
    .SYNOPSIS
        Gets custom detection rules from Microsoft Defender XDR.

    .DESCRIPTION
        Queries Microsoft Graph API to retrieve one detection rule by ID or all detection rules.
        Returns PowerShell objects representing the detection rules.

    .PARAMETER DetectionId
        Optional. The detection rule ID (GUID). If omitted, all detection rules are returned.

    .EXAMPLE
        Get-CustomDetection

        Returns all detection rules.

    .EXAMPLE
        Get-CustomDetection -DetectionId "81fb771a-c57e-41b8-9905-63dbf267c13f"

        Returns the detection rule with the specified ID.

    .NOTES
        Requires the Microsoft.Graph.Authentication module and an active Graph API session.
        Use Connect-MgGraph before calling this function.
    #>
    [CmdletBinding()]
    [OutputType([PSObject])]
    param (
        [Parameter(ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [string]$DetectionId
    )

    begin {
        Assert-MgGraphConnection
    }

    process {
        try {
            if ($PSBoundParameters.ContainsKey('DetectionId')) {
                $uri = "https://graph.microsoft.com/beta/security/rules/detectionRules/$DetectionId"
                return Invoke-MgGraphRequestWithRetry -Method GET -Uri $uri
            }

            $uri = "https://graph.microsoft.com/beta/security/rules/detectionRules"
            $allDetections = [System.Collections.Generic.List[object]]::new()

            do {
                $response = Invoke-MgGraphRequestWithRetry -Method GET -Uri $uri
                if ($response.value) {
                    $allDetections.AddRange([object[]]$response.value)
                }
                $uri = $response.'@odata.nextLink'
            } while ($uri)

            return $allDetections
        } catch {
            Write-Error "Error querying Microsoft Graph API: $($_.Exception.Message)"
            throw
        }
    }
}
