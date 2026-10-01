function Add-CustomDetectionIdsCacheEntry {
    <#
    .SYNOPSIS
        Adds a rule to the cached id list.

    .DESCRIPTION
        Called after a create, so the next lookup finds the new rule without
        asking the list again. An entry with the same id is replaced. An empty
        cache is left alone, the next lookup fills it.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSObject]$Entry
    )

    if ($null -eq $script:DetectionIdsCache.Data) { return }
    $kept = @($script:DetectionIdsCache.Data | Where-Object { $_.Id -ne $Entry.Id })
    $script:DetectionIdsCache.Data = @($kept + $Entry)
}
