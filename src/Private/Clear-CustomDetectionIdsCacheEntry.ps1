function Clear-CustomDetectionIdsCacheEntry {
    <#
    .SYNOPSIS
        Removes a rule from the cached id list.

    .DESCRIPTION
        Called after a delete, so a later lookup does not find a rule that is
        gone. An empty cache is left alone.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Id
    )

    if ($null -eq $script:DetectionIdsCache.Data) { return }
    $script:DetectionIdsCache.Data = @($script:DetectionIdsCache.Data | Where-Object { $_.Id -ne $Id })
}
