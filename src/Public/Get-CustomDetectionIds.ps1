function Get-CustomDetectionIds {
    <#
    .SYNOPSIS
        Lists detection rule IDs with their detector IDs and description tags.

    .DESCRIPTION
        Queries Microsoft Graph API to retrieve all detection rules and returns
        their detection rule ID, detector ID, and the UUID from the description
        tag (if present). Results are cached for the duration specified by
        CacheTtlMinutes (default: 60 minutes).

    .PARAMETER CacheTtlMinutes
        How long (in minutes) to keep the cached result before re-querying the API.
        Defaults to 60 minutes.

    .PARAMETER Force
        Bypass the cache and force a fresh API call.

    .EXAMPLE
        Get-CustomDetectionIds

        Returns a list of detection rule IDs and detector IDs (cached for 60 min).

    .EXAMPLE
        Get-CustomDetectionIds -Force

        Forces a fresh API call, ignoring any cached data.

    .EXAMPLE
        Get-CustomDetectionIds -CacheTtlMinutes 10

        Returns the list, caching results for 10 minutes.

    .NOTES
        Requires the Microsoft.Graph.Authentication module and an active Graph API session.
        Use Connect-MgGraph before calling this function.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter()]
        [ValidateRange(0, [int]::MaxValue)]
        [int]$CacheTtlMinutes = 60,

        [Parameter()]
        [switch]$Force
    )

    begin {
        Assert-MgGraphConnection
    }

    process {
        # Return cached data if still valid
        $cacheValid = (-not $Force) -and
        ($null -ne $script:DetectionIdsCache.Data) -and
        ([datetime]::UtcNow -lt $script:DetectionIdsCache.ExpiresAt)

        if ($cacheValid) {
            Write-Verbose 'Returning cached detection IDs (use -Force to refresh).'
            return $script:DetectionIdsCache.Data
        }

        try {
            # Query the Microsoft Graph API with pagination support
            $uri = "https://graph.microsoft.com/beta/security/rules/detectionRules?`$select=id,detectorId,detectionAction"
            $allValues = [System.Collections.Generic.List[object]]::new()

            do {
                $response = Invoke-MgGraphRequestWithRetry -Method GET -Uri $uri
                if ($response.value) {
                    $allValues.AddRange([object[]]$response.value)
                }
                $uri = $response.'@odata.nextLink'
            } while ($uri)

            if ($allValues.Count -eq 0) {
                $result = @()
            } else {
                $uuidPattern = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
                $tagPattern = "\[(?:[^:\]]*:)?($uuidPattern)\]"

                $result = $allValues | ForEach-Object {
                    $descriptionTag = $null
                    $desc = $_.detectionAction.alertTemplate.description
                    if ($desc -and $desc -match $tagPattern) {
                        $descriptionTag = $Matches[1]
                    }

                    [PSCustomObject]@{
                        Id             = $_.id
                        DetectorId     = $_.detectorId
                        DescriptionTag = $descriptionTag
                    }
                }
            }

            # Update the cache
            $script:DetectionIdsCache.Data = $result
            $script:DetectionIdsCache.ExpiresAt = [datetime]::UtcNow.AddMinutes($CacheTtlMinutes)

            return $result
        } catch {
            Write-Error "Error querying Microsoft Graph API: $($_.Exception.Message)"
            throw
        }
    }
}

