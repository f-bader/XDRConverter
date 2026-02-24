function ConvertFrom-CustomDetectionJsonToYaml {
    <#
    .SYNOPSIS
        Converts JSON content to YAML following the schema.

    .DESCRIPTION
        Performs the mapping from JSON properties back to YAML properties,
        omitting any properties not in the YAML schema.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSObject]$JsonObject,

        [Parameter()]
        [bool]$SetEnabled,

        [Parameter()]
        [ValidateSet('Informational', 'Low', 'Medium', 'High')]
        [string]$SetSeverity
    )

    $DefaultSortOrderInYAML = @(
        'guid'
        'isEnabled'
        'ruleName'
        'alertTitle'
        'alertCategory'
        'alertDescription'
        'frequency'
        'alertSeverity'
        'alertRecommendedAction'
        'mitreTechniques'
        'impactedEntities'
        'queryText'
    )

    # Extract DescriptionTag UUID from the description if present, preferring it over detectorId
    $descriptionTagGuid = $null
    $desc = $JsonObject.detectionAction.alertTemplate.description
    if ($desc) {
        $uuidPattern = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
        $tagPattern = "\[(?:[^:\]]*:)?($uuidPattern)\]"
        if ($desc -match $tagPattern) {
            $descriptionTagGuid = $Matches[1]
        }
    }

    # Clean the description tag from the description text
    $cleanDescription = $desc
    if ($descriptionTagGuid) {
        $cleanDescription = ($desc -replace '\s*\[(?:[^:\]]*:)?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\]', '').Trim()
    }

    # Create YAML object with only schema-defined properties
    $yamlObj = @{
        guid             = if ($descriptionTagGuid) { $descriptionTagGuid } else { $JsonObject.detectorId }
        ruleName         = $JsonObject.displayName
        isEnabled        = if ($PSBoundParameters.ContainsKey('SetEnabled')) { $SetEnabled } else { $JsonObject.isEnabled }
        alertTitle       = $JsonObject.detectionAction.alertTemplate.title
        frequency        = [string]$JsonObject.schedule.period
        alertSeverity    = if ($PSBoundParameters.ContainsKey('SetSeverity')) { $SetSeverity } else { (Get-Culture).TextInfo.ToTitleCase($JsonObject.detectionAction.alertTemplate.severity) }
        alertDescription = $cleanDescription
        alertCategory    = $JsonObject.detectionAction.alertTemplate.category
        queryText        = $JsonObject.queryCondition.queryText
    }

    # Add optional properties if they exist
    if ($JsonObject.detectionAction.alertTemplate.recommendedActions) {
        $yamlObj.alertRecommendedAction = $JsonObject.detectionAction.alertTemplate.recommendedActions
    }

    if ($JsonObject.detectionAction.alertTemplate.mitreTechniques) {
        $yamlObj.mitreTechniques = $JsonObject.detectionAction.alertTemplate.mitreTechniques
    }

    # Map impactedAssets back to impactedEntities
    if ($JsonObject.detectionAction.alertTemplate.impactedAssets) {
        $impactedEntities = [System.Collections.Generic.List[hashtable]]::new()
        foreach ($asset in $JsonObject.detectionAction.alertTemplate.impactedAssets) {
            # Extract entity type from @odata.type (e.g., "#microsoft.graph.security.impactedDeviceAsset" -> "Device")
            $odataType = $asset."@odata.type"
            if ($odataType -match 'impacted(\w+)Asset') {
                $entityType = $matches[1]
            }

            # Map Device back to Machine for YAML schema compliance
            $yamlEntityType = if ($entityType -eq 'Device') { 'Machine' } else { $entityType }

            $impactedEntities.Add(@{
                    entityType       = $yamlEntityType
                    entityIdentifier = $asset.identifier
                })
        }
        $yamlObj.impactedEntities = $impactedEntities
    }

    if ($JsonObject.detectionAction.organizationalScope) {
        $yamlObj.organizationalScope = $JsonObject.detectionAction.organizationalScope
    }

    if ($JsonObject.detectionAction.responseActions) {
        $yamlObj.actions = $JsonObject.detectionAction.responseActions
    }

    $orderedYamlObj = [ordered]@{}
    foreach ($key in $DefaultSortOrderInYAML) {
        if ($yamlObj.ContainsKey($key)) {
            $orderedYamlObj[$key] = $yamlObj[$key]
        }
    }

    foreach ($key in $yamlObj.Keys) {
        if (-not $orderedYamlObj.Contains($key)) {
            $orderedYamlObj[$key] = $yamlObj[$key]
        }
    }

    return $orderedYamlObj
}

