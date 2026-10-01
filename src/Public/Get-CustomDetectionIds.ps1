function Get-CustomDetectionIds {
    <#
    .SYNOPSIS
        Lists detection rule IDs with their description tags.

    .DESCRIPTION
        Queries Microsoft Graph API to retrieve all detection rules and returns
        their detection rule ID, the detector ID the API assigned, the display
        name, the UUID from the description tag (if present), and the tag prefix
        (if present). Results are cached for the duration specified by
        CacheTtlMinutes (default: 60 minutes).

    .PARAMETER CacheTtlMinutes
        How long (in minutes) to keep the cached result before re-querying the API.
        Defaults to 60 minutes.

    .PARAMETER Force
        Bypass the cache and force a fresh API call.

    .EXAMPLE
        Get-CustomDetectionIds

        Returns a list of detection rule IDs, display names and description tags (cached for 60 min).

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

        # After a timeout and a failed retry the list is not asked again for five minutes, so a run does not pay the timeout once per rule
        $failedAt = $script:DetectionIdsCache.FailedAt
        if (-not $Force -and $failedAt -and ([datetime]::UtcNow - $failedAt) -lt [timespan]::FromMinutes(5)) {
            throw "The rule list is unavailable since $($failedAt.ToString('HH:mm:ss')) UTC and is asked again five minutes later."
        }

        try {
            # Query the Microsoft Graph API with pagination support. The projection names the properties the lookups read
            $listUri = 'https://graph.microsoft.com/beta/security/rules/detectionRules?$select=id,detectorId,displayName,detectionAction'
            $retried = $false

            while ($true) {
                try {
                    $allValues = [System.Collections.Generic.List[object]]::new()
                    $uri = $listUri
                    do {
                        $response = Invoke-MgGraphRequestWithRetry -Method GET -Uri $uri
                        if ($response.value) {
                            $allValues.AddRange([object[]]$response.value)
                        }
                        $uri = $response.'@odata.nextLink'
                    } while ($uri)
                    break
                } catch {
                    if (-not (Test-CustomDetectionListFailure -ErrorRecord $_)) { throw }
                    if ($retried) {
                        $script:DetectionIdsCache.FailedAt = [datetime]::UtcNow
                        throw
                    }
                    $retried = $true
                    Write-Warning 'The rule list timed out. It is asked once more.'
                }
            }

            $result = @($allValues | ForEach-Object { ConvertTo-CustomDetectionIdEntry -Rule $_ })

            # Update the cache
            $script:DetectionIdsCache.Data = $result
            $script:DetectionIdsCache.ExpiresAt = [datetime]::UtcNow.AddMinutes($CacheTtlMinutes)
            $script:DetectionIdsCache.FailedAt = $null

            return $result
        } catch {
            Write-Error "Error querying Microsoft Graph API: $($_.Exception.Message)"
            throw
        }
    }
}

