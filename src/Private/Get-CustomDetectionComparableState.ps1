function Get-CustomDetectionComparableState {
    <#
    .SYNOPSIS
        Projects a detection rule into a canonical shape for change detection.

    .DESCRIPTION
        Works for the local request body and for rules returned by the Graph
        API, whether they carry the legacy properties, the current properties
        or both. Legacy values are translated so both sides compare on the
        same fields. Collections are sorted so ordering never counts as a change.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)]
        [PSObject]$Rule
    )

    function ConvertTo-SortedObject {
        param([object]$Value)
        if ($null -eq $Value) { return $null }
        $map = ConvertTo-CustomDetectionHashtable -InputObject $Value
        if ($null -ne $map) {
            $sorted = [ordered]@{}
            foreach ($key in ($map.Keys | Sort-Object)) {
                $sorted[$key] = ConvertTo-SortedObject -Value $map[$key]
            }
            return $sorted
        }
        if ($Value -isnot [string] -and $Value -is [System.Collections.IEnumerable]) {
            $items = @($Value | ForEach-Object { ConvertTo-SortedObject -Value $_ })
            # Ordinal, so items that differ only by case never tie. The casts select the non-generic overload, the one that reorders the items
            $keys = [string[]]@($items | ForEach-Object { ConvertTo-Json -InputObject $_ -Compress -Depth 10 })
            [Array]::Sort([Array]$keys, [Array]$items, [System.Collections.IComparer][System.StringComparer]::Ordinal)
            return , $items
        }
        return $Value
    }

    function ConvertTo-SortedJson {
        param([object]$Value)
        if ($null -eq $Value) { return '' }
        $sorted = ConvertTo-SortedObject -Value $Value
        if ($null -eq $sorted) { return '' }
        return ($sorted | ConvertTo-Json -Compress -Depth 10)
    }

    $status = Get-CustomDetectionValue -Object $Rule -Path 'status'
    if ([string]::IsNullOrWhiteSpace("$status")) {
        $status = ConvertTo-CustomDetectionStatus -IsEnabled (Get-CustomDetectionValue -Object $Rule -Path 'isEnabled')
    }

    $frequencySource = Get-CustomDetectionValue -Object $Rule -Path 'schedule.frequency'
    if ([string]::IsNullOrWhiteSpace("$frequencySource")) {
        $frequencySource = Get-CustomDetectionValue -Object $Rule -Path 'schedule.period'
    }
    $frequency = ''
    if (-not [string]::IsNullOrWhiteSpace("$frequencySource")) {
        try {
            $frequency = ConvertTo-CustomDetectionFrequency -Value $frequencySource
        } catch {
            # An unrecognised remote value still has to compare, so keep it verbatim
            $frequency = "$frequencySource".Trim().ToUpperInvariant()
        }
    }

    $tacticsSource = Get-CustomDetectionValue -Object $Rule -Path 'detectionAction.alertTemplate.tactics'
    $tactics = $null
    if ($null -ne $tacticsSource -and @($tacticsSource).Count -gt 0) {
        $tactics = @(ConvertTo-CustomDetectionTactics -Tactics $tacticsSource)
    } else {
        $category = Get-CustomDetectionValue -Object $Rule -Path 'detectionAction.alertTemplate.category'
        $techniques = Get-CustomDetectionValue -Object $Rule -Path 'detectionAction.alertTemplate.mitreTechniques'
        if (-not [string]::IsNullOrWhiteSpace("$category")) {
            $tactics = @(ConvertTo-CustomDetectionTactics -Category "$category" -Techniques @($techniques))
        }
    }

    $entityMappingsSource = Get-CustomDetectionValue -Object $Rule -Path 'detectionAction.alertTemplate.entityMappings'
    $entityMappings = $null
    if (Test-CustomDetectionCollection -Value $entityMappingsSource) {
        $entityMappings = ConvertFrom-CustomDetectionEntityMappings -EntityMappings $entityMappingsSource
    } else {
        $impactedAssets = Get-CustomDetectionValue -Object $Rule -Path 'detectionAction.alertTemplate.impactedAssets'
        if ($null -ne $impactedAssets -and @($impactedAssets).Count -gt 0) {
            $entityMappings = ConvertFrom-CustomDetectionEntityMappings -ImpactedAssets @($impactedAssets)
        }
    }

    $automatedActionsSource = Get-CustomDetectionValue -Object $Rule -Path 'detectionAction.automatedActions'
    $actions = @()
    if (Test-CustomDetectionCollection -Value $automatedActionsSource) {
        $actions = @(ConvertFrom-CustomDetectionAutomatedActions -AutomatedActions $automatedActionsSource -WarningAction SilentlyContinue)
    } else {
        $responseActions = Get-CustomDetectionValue -Object $Rule -Path 'detectionAction.responseActions'
        if ($null -ne $responseActions -and @($responseActions).Count -gt 0) {
            $translated = ConvertTo-CustomDetectionAutomatedActions -ResponseActions @($responseActions)
            $actions = @(ConvertFrom-CustomDetectionAutomatedActions -AutomatedActions $translated -WarningAction SilentlyContinue)
        }
    }

    $scopeSource = Get-CustomDetectionValue -Object $Rule -Path 'detectionAction.organizationalScope'
    $deviceGroups = @()
    if ($null -ne $scopeSource) {
        $scopeMap = ConvertTo-CustomDetectionHashtable -InputObject $scopeSource
        if ($null -ne $scopeMap) {
            if ($scopeMap.Contains('deviceGroups') -and $null -ne $scopeMap['deviceGroups']) {
                $deviceGroups = @($scopeMap['deviceGroups'])
            } elseif ($scopeMap.Contains('scopeNames') -and $null -ne $scopeMap['scopeNames']) {
                $deviceGroups = @($scopeMap['scopeNames'])
            }
        } else {
            $deviceGroups = @($scopeSource)
        }
    }

    $customDetails = [ordered]@{}
    $customDetailsSource = ConvertTo-CustomDetectionHashtable -InputObject (Get-CustomDetectionValue -Object $Rule -Path 'detectionAction.alertTemplate.customDetails')
    if ($null -ne $customDetailsSource) {
        foreach ($key in ($customDetailsSource.Keys | Sort-Object)) {
            $value = $customDetailsSource[$key]
            if ($null -ne $value -and "$value" -ne '') {
                $customDetails[$key] = "$value"
            }
        }
    }

    return [ordered]@{
        displayName        = "$(Get-CustomDetectionValue -Object $Rule -Path 'displayName')"
        status             = "$status"
        description        = "$(Get-CustomDetectionValue -Object $Rule -Path 'description')"
        frequency          = $frequency
        queryText          = "$(Get-CustomDetectionValue -Object $Rule -Path 'queryCondition.queryText')"
        title              = "$(Get-CustomDetectionValue -Object $Rule -Path 'detectionAction.alertTemplate.title')"
        alertDescription   = "$(Get-CustomDetectionValue -Object $Rule -Path 'detectionAction.alertTemplate.description')"
        severity           = ("$(Get-CustomDetectionValue -Object $Rule -Path 'detectionAction.alertTemplate.severity')").ToLowerInvariant()
        recommendedActions = "$(Get-CustomDetectionValue -Object $Rule -Path 'detectionAction.alertTemplate.recommendedActions')"
        tactics            = ConvertTo-SortedJson -Value $tactics
        entityMappings     = ConvertTo-SortedJson -Value $entityMappings
        customDetails      = ConvertTo-SortedJson -Value $customDetails
        automatedActions   = ConvertTo-SortedJson -Value $actions
        deviceGroups       = ConvertTo-SortedJson -Value @($deviceGroups | ForEach-Object { "$_" } | Sort-Object)
    }
}
