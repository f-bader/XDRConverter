function ConvertFrom-CustomDetectionJsonToYaml {
    <#
    .SYNOPSIS
        Converts a Graph API detection rule into the YAML rule shape.

    .DESCRIPTION
        Emits the current YAML keys (tactics, entityMappings, customDetails,
        ISO 8601 frequency, description). Rules that still carry the legacy
        properties (category, mitreTechniques, impactedAssets, responseActions,
        period, isEnabled) are translated so the output uses the current keys.
        isEnabled is always emitted and status only for autoDisabled. Read-only
        and runtime properties are dropped.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSObject]$JsonObject,

        [Parameter()]
        [bool]$SetEnabled,

        [Parameter()]
        [ValidateSet('Informational', 'Low', 'Medium', 'High')]
        [string]$SetSeverity,

        [Parameter()]
        [switch]$ValidateIdentifiers
    )

    $DefaultSortOrderInYAML = @(
        'guid'
        'detectorId'
        'ruleName'
        'description'
        'isEnabled'
        'status'
        'alertTitle'
        'frequency'
        'alertSeverity'
        'alertDescription'
        'alertRecommendedAction'
        'tactics'
        'entityMappings'
        'customDetails'
        'organizationalScope'
        'actions'
        'queryText'
    )

    # Strip the description tag from the alert description
    $uuidPattern = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
    $alertDescription = Get-CustomDetectionValue -Object $JsonObject -Path 'detectionAction.alertTemplate.description'
    if ($alertDescription) {
        $alertDescription = ($alertDescription -replace "\s*\[(?:[^:\]]*:)?$uuidPattern\]", '').Trim()
    }

    # Keep the raw status here so an autoDisabled rule exports as such; the forward path maps it on deploy
    $rawStatus = "$(Get-CustomDetectionValue -Object $JsonObject -Path 'status')".Trim()
    $status = if ($PSBoundParameters.ContainsKey('SetEnabled')) {
        ConvertTo-CustomDetectionStatus -IsEnabled $SetEnabled
    } elseif ($rawStatus -eq 'autoDisabled') {
        'autoDisabled'
    } else {
        ConvertTo-CustomDetectionStatus -IsEnabled (Get-CustomDetectionValue -Object $JsonObject -Path 'isEnabled') -Status $rawStatus
    }

    $severity = if ($PSBoundParameters.ContainsKey('SetSeverity')) {
        $SetSeverity
    } else {
        $rawSeverity = Get-CustomDetectionValue -Object $JsonObject -Path 'detectionAction.alertTemplate.severity'
        if ($rawSeverity) { (Get-Culture).TextInfo.ToTitleCase("$rawSeverity".ToLowerInvariant()) } else { $null }
    }

    $yamlObj = [ordered]@{
        guid             = Get-CustomDetectionIdentity -Rule $JsonObject
        ruleName         = Get-CustomDetectionValue -Object $JsonObject -Path 'displayName'
        isEnabled        = ($status -eq 'enabled')
        alertTitle       = Get-CustomDetectionValue -Object $JsonObject -Path 'detectionAction.alertTemplate.title'
        alertSeverity    = $severity
        alertDescription = $alertDescription
        queryText        = Get-CustomDetectionValue -Object $JsonObject -Path 'queryCondition.queryText'
    }

    if ($status -notin @('enabled', 'disabled')) {
        $yamlObj['status'] = $status
    }

    $description = Get-CustomDetectionValue -Object $JsonObject -Path 'description'
    if (Test-CustomDetectionValue $description) {
        $yamlObj['description'] = $description
    }

    $frequencySource = Get-CustomDetectionValue -Object $JsonObject -Path 'schedule.frequency'
    if (-not (Test-CustomDetectionValue $frequencySource)) {
        $frequencySource = Get-CustomDetectionValue -Object $JsonObject -Path 'schedule.period'
    }
    if (Test-CustomDetectionValue $frequencySource) {
        $yamlObj['frequency'] = ConvertTo-CustomDetectionFrequency -Value $frequencySource
    }

    $recommendedActions = Get-CustomDetectionValue -Object $JsonObject -Path 'detectionAction.alertTemplate.recommendedActions'
    if (Test-CustomDetectionValue $recommendedActions) {
        $yamlObj['alertRecommendedAction'] = $recommendedActions
    }

    $tacticsSource = Get-CustomDetectionValue -Object $JsonObject -Path 'detectionAction.alertTemplate.tactics'
    $tactics = @()
    if (Test-CustomDetectionValue $tacticsSource) {
        $tactics = @(ConvertTo-CustomDetectionTactics -Tactics $tacticsSource)
    } else {
        $category = Get-CustomDetectionValue -Object $JsonObject -Path 'detectionAction.alertTemplate.category'
        if (Test-CustomDetectionValue $category) {
            $techniques = @(Get-CustomDetectionValue -Object $JsonObject -Path 'detectionAction.alertTemplate.mitreTechniques' | Where-Object { $_ })
            $tactics = @(ConvertTo-CustomDetectionTactics -Category "$category" -Techniques $techniques)
        }
    }
    if ($tactics.Count -gt 0) {
        $yamlObj['tactics'] = [object[]]$tactics
    }

    $entityMappingsSource = Get-CustomDetectionValue -Object $JsonObject -Path 'detectionAction.alertTemplate.entityMappings'
    $entityMappings = $null
    if (Test-CustomDetectionCollection -Value $entityMappingsSource) {
        $entityMappings = ConvertFrom-CustomDetectionEntityMappings -EntityMappings $entityMappingsSource -ValidateIdentifiers:$ValidateIdentifiers
    } else {
        $impactedAssets = Get-CustomDetectionValue -Object $JsonObject -Path 'detectionAction.alertTemplate.impactedAssets'
        if (Test-CustomDetectionValue $impactedAssets) {
            $entityMappings = ConvertFrom-CustomDetectionEntityMappings -ImpactedAssets @($impactedAssets) -ValidateIdentifiers:$ValidateIdentifiers
        }
    }
    if ($entityMappings) {
        $yamlObj['entityMappings'] = $entityMappings
    }

    $customDetailsSource = ConvertTo-CustomDetectionHashtable -InputObject (Get-CustomDetectionValue -Object $JsonObject -Path 'detectionAction.alertTemplate.customDetails')
    if ($customDetailsSource -and $customDetailsSource.Count -gt 0) {
        $customDetails = [ordered]@{}
        foreach ($key in $customDetailsSource.Keys) {
            if (Test-CustomDetectionValue $customDetailsSource[$key]) {
                # The value keeps its type so the deploy-side validation can reject one that is not a string
                $customDetails[[string]$key] = $customDetailsSource[$key]
            }
        }
        if ($customDetails.Count -gt 0) {
            $yamlObj['customDetails'] = $customDetails
        }
    }

    $scopeSource = Get-CustomDetectionValue -Object $JsonObject -Path 'detectionAction.organizationalScope'
    $deviceGroups = @()
    if ($null -ne $scopeSource) {
        $scopeMap = ConvertTo-CustomDetectionHashtable -InputObject $scopeSource
        if ($null -ne $scopeMap) {
            if (Test-CustomDetectionValue $scopeMap['deviceGroups']) {
                $deviceGroups = @($scopeMap['deviceGroups'])
            } elseif (Test-CustomDetectionValue $scopeMap['scopeNames']) {
                $deviceGroups = @($scopeMap['scopeNames'])
            }
        } else {
            $deviceGroups = @($scopeSource | Where-Object { $_ })
        }
    }
    if ($deviceGroups.Count -gt 0) {
        # Entries keep their type so the deploy-side validation can reject a name that is not a string
        $yamlObj['organizationalScope'] = [object[]]$deviceGroups
    }

    $automatedActionsSource = Get-CustomDetectionValue -Object $JsonObject -Path 'detectionAction.automatedActions'
    $actions = @()
    if (Test-CustomDetectionCollection -Value $automatedActionsSource) {
        $actions = @(ConvertFrom-CustomDetectionAutomatedActions -AutomatedActions $automatedActionsSource)
    } else {
        $responseActions = Get-CustomDetectionValue -Object $JsonObject -Path 'detectionAction.responseActions'
        if (Test-CustomDetectionValue $responseActions) {
            $translated = ConvertTo-CustomDetectionAutomatedActions -ResponseActions @($responseActions)
            $actions = @(ConvertFrom-CustomDetectionAutomatedActions -AutomatedActions $translated)
        }
    }
    if ($actions.Count -gt 0) {
        $yamlObj['actions'] = [object[]]$actions
    }

    # The detector id is assigned by the API and travels with the file for reference
    $detectorId = Get-CustomDetectionValue -Object $JsonObject -Path 'detectorId'
    if (Test-CustomDetectionValue $detectorId) {
        $yamlObj['detectorId'] = "$detectorId"
    }

    $orderedYamlObj = ConvertTo-CustomDetectionOrderedMap -Map $yamlObj -Order $DefaultSortOrderInYAML

    return $orderedYamlObj
}
