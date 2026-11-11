function ConvertFrom-CustomDetectionYamlToJson {
    <#
    .SYNOPSIS
        Converts a YAML detection rule into the Graph API request body.

    .DESCRIPTION
        Accepts both the legacy YAML keys (isEnabled, alertCategory,
        mitreTechniques, impactedEntities, period-style frequency) and the
        current keys (status, tactics, entityMappings, customDetails,
        description, ISO 8601 frequency). Legacy values are translated to the
        current Graph properties. When both forms are present the current key wins.
        lookback, eventGroupingKind and isExcludedFromIncidentCorrelation reach
        the body only when the file sets them, since a request that omits them
        keeps the values the rule holds.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSObject]$YamlObject,

        [Parameter()]
        [bool]$SetEnabled,

        [Parameter()]
        [ValidateSet('Informational', 'Low', 'Medium', 'High')]
        [string]$SetSeverity,

        [Parameter()]
        [switch]$SkipIdentifierValidation
    )

    $knownKeys = @(
        'guid', 'id', 'detectorId', 'ruleName', 'description', 'isEnabled', 'status', 'frequency', 'lookback', 'alertTitle',
        'alertSeverity', 'alertDescription', 'alertRecommendedAction', 'eventGroupingKind', 'alertCategory', 'mitreTechniques',
        'tactics', 'impactedEntities', 'entityMappings', 'customDetails', 'organizationalScope', 'isExcludedFromIncidentCorrelation',
        'actions', 'queryText'
    )

    $yaml = ConvertTo-CustomDetectionHashtable -InputObject $YamlObject
    if ($null -eq $yaml) {
        throw 'The YAML input is not a detection rule object.'
    }

    foreach ($key in $yaml.Keys) {
        if ($key -notin $knownKeys) {
            Write-Warning "Unknown key '$key' is ignored."
        }
    }

    # The guid and the id alias name the same rule, with or without the rule prefix the request carries
    $guid = Get-CustomDetectionValue -Object $yaml -Path 'guid'
    $idAlias = Get-CustomDetectionValue -Object $yaml -Path 'id'
    $bareGuid = if (Test-CustomDetectionValue $guid) { "$guid".Trim() -replace '^rule-', '' } else { $null }
    $bareAlias = if (Test-CustomDetectionValue $idAlias) { "$idAlias".Trim() -replace '^rule-', '' } else { $null }
    if ($bareGuid -and $bareAlias -and ($bareGuid -ne $bareAlias)) {
        throw "The guid '$guid' and id '$idAlias' differ. Use one of them."
    }
    $ruleGuid = if ($bareGuid) { $bareGuid } elseif ($bareAlias) { $bareAlias } else { $null }

    $status = if ($PSBoundParameters.ContainsKey('SetEnabled')) {
        ConvertTo-CustomDetectionStatus -IsEnabled $SetEnabled
    } else {
        ConvertTo-CustomDetectionStatus -IsEnabled (Get-CustomDetectionValue -Object $yaml -Path 'isEnabled') -Status (Get-CustomDetectionValue -Object $yaml -Path 'status')
    }

    $severity = if ($SetSeverity) {
        $SetSeverity
    } else {
        Get-CustomDetectionValue -Object $yaml -Path 'alertSeverity'
    }
    if (-not (Test-CustomDetectionValue $severity)) {
        throw 'The alertSeverity value is required. Use Informational, Low, Medium or High.'
    }

    $alertTemplate = [ordered]@{
        title       = Get-CustomDetectionValue -Object $yaml -Path 'alertTitle'
        description = Get-CustomDetectionValue -Object $yaml -Path 'alertDescription'
        severity    = "$severity".ToLowerInvariant()
    }

    $recommendedActions = Get-CustomDetectionValue -Object $yaml -Path 'alertRecommendedAction'
    if (Test-CustomDetectionValue $recommendedActions) {
        $alertTemplate.recommendedActions = $recommendedActions
    }

    $groupingKind = Get-CustomDetectionValue -Object $yaml -Path 'eventGroupingKind'
    if (Test-CustomDetectionValue $groupingKind) {
        $resolvedKind = [string](@('alertPerEvent', 'singleAlert') | Where-Object { $_ -eq "$groupingKind".Trim() } | Select-Object -First 1)
        if (-not $resolvedKind) {
            throw "Unsupported eventGroupingKind '$groupingKind'. Use alertPerEvent or singleAlert."
        }
        $alertTemplate.eventGroupingKind = $resolvedKind
    }

    $tacticsInput = Get-CustomDetectionValue -Object $yaml -Path 'tactics'
    $category = Get-CustomDetectionValue -Object $yaml -Path 'alertCategory'
    $techniques = Get-CustomDetectionValue -Object $yaml -Path 'mitreTechniques'
    if ((Test-CustomDetectionValue $tacticsInput) -and ((Test-CustomDetectionValue $category) -or (Test-CustomDetectionValue $techniques))) {
        Write-Warning 'Both tactics and alertCategory/mitreTechniques are present. Using tactics.'
    }
    $tactics = @()
    if (Test-CustomDetectionValue $tacticsInput) {
        $tactics = @(ConvertTo-CustomDetectionTactics -Tactics $tacticsInput)
    } elseif (Test-CustomDetectionValue $category) {
        $tactics = @(ConvertTo-CustomDetectionTactics -Category "$category" -Techniques @($techniques))
    }
    if ($tactics.Count -eq 0) {
        throw 'The rule needs an alertCategory or a tactics list.'
    }
    $alertTemplate['tactics'] = [object[]]$tactics

    $entityMappingsInput = Get-CustomDetectionValue -Object $yaml -Path 'entityMappings'
    $impactedEntities = Get-CustomDetectionValue -Object $yaml -Path 'impactedEntities'
    $entityMappings = $null
    # A key that carries a value wins even when that value is empty, since an empty mapping is a statement that the rule maps no entity
    if ($yaml.Contains('entityMappings') -and $null -ne $entityMappingsInput) {
        if (Test-CustomDetectionValue $impactedEntities) {
            Write-Warning 'Both entityMappings and impactedEntities are present. Using entityMappings.'
        }
        $entityMappings = ConvertTo-CustomDetectionEntityMappings -EntityMappings $entityMappingsInput -SkipIdentifierValidation:$SkipIdentifierValidation
    } elseif (Test-CustomDetectionValue $impactedEntities) {
        $entityMappings = ConvertTo-CustomDetectionEntityMappings -ImpactedEntities @($impactedEntities) -SkipIdentifierValidation:$SkipIdentifierValidation
    }
    if ($entityMappings) {
        $alertTemplate.entityMappings = $entityMappings
    }

    $customDetailsInput = ConvertTo-CustomDetectionHashtable -InputObject (Get-CustomDetectionValue -Object $yaml -Path 'customDetails')
    if ($customDetailsInput -and $customDetailsInput.Count -gt 0) {
        if ($customDetailsInput.Count -gt 20) {
            throw "customDetails holds $($customDetailsInput.Count) entries. The limit is 20."
        }
        $customDetails = [ordered]@{}
        foreach ($key in $customDetailsInput.Keys) {
            $value = $customDetailsInput[$key]
            if ($value -isnot [string]) {
                throw "customDetails entry '$key' must be a single string value."
            }
            $customDetails[[string]$key] = "$value"
        }
        $alertTemplate.customDetails = $customDetails
    }

    $detectionAction = [ordered]@{
        alertTemplate = $alertTemplate
    }

    # The key is read in place. A one-item list unrolls on its way back from a helper, and an empty name would vanish with it
    if ($yaml.Contains('organizationalScope') -and $null -ne $yaml['organizationalScope']) {
        $entries = @($yaml['organizationalScope'])
        foreach ($entry in $entries) {
            if ($null -eq $entry -or [string]::IsNullOrWhiteSpace("$entry")) {
                throw 'organizationalScope contains an empty device group name.'
            }
            if ($entry -isnot [string]) {
                throw "organizationalScope entry '$entry' must be a single device group name."
            }
        }
        if ($entries.Count -gt 0) {
            $detectionAction['organizationalScope'] = [ordered]@{
                deviceGroups = [object[]]@($entries | ForEach-Object { "$_" })
            }
        }
    }

    $actions = Get-CustomDetectionValue -Object $yaml -Path 'actions'
    if (Test-CustomDetectionValue $actions) {
        $automatedActions = ConvertTo-CustomDetectionAutomatedActions -Actions @($actions)
        if ($automatedActions) {
            $detectionAction.automatedActions = $automatedActions
        }
    }

    $excluded = Get-CustomDetectionValue -Object $yaml -Path 'isExcludedFromIncidentCorrelation'
    if ($null -ne $excluded -and "$excluded" -ne '') {
        if ($excluded -isnot [bool] -and "$excluded" -notin @('true', 'false')) {
            throw "isExcludedFromIncidentCorrelation '$excluded' is not a boolean. Use true or false."
        }
        $detectionAction['incidentConfiguration'] = [ordered]@{
            isExcludedFromIncidentCorrelation = ("$excluded" -eq 'true')
        }
    }

    $jsonObj = [ordered]@{}
    if ($ruleGuid) {
        $jsonObj.id = "rule-$ruleGuid"
    }
    $detectorId = Get-CustomDetectionValue -Object $yaml -Path 'detectorId'
    if (Test-CustomDetectionValue $detectorId) {
        $jsonObj.detectorId = "$detectorId".Trim()
    }
    $jsonObj.displayName = Get-CustomDetectionValue -Object $yaml -Path 'ruleName'
    $jsonObj.status = $status

    $description = Get-CustomDetectionValue -Object $yaml -Path 'description'
    if (Test-CustomDetectionValue $description) {
        $jsonObj.description = $description
    }

    $jsonObj.queryCondition = [ordered]@{
        queryText = Get-CustomDetectionValue -Object $yaml -Path 'queryText'
    }
    $jsonObj.schedule = [ordered]@{
        frequency = ConvertTo-CustomDetectionFrequency -Value (Get-CustomDetectionValue -Object $yaml -Path 'frequency')
    }
    $lookback = Get-CustomDetectionValue -Object $yaml -Path 'lookback'
    if (Test-CustomDetectionValue $lookback) {
        $jsonObj.schedule.lookback = ConvertTo-CustomDetectionLookback -Value $lookback
    }
    $jsonObj.detectionAction = $detectionAction

    return $jsonObj
}
