function ConvertTo-CustomDetectionLegacyYaml {
    <#
    .SYNOPSIS
        Rewrites a current-shape YAML object into the legacy YAML keys.

    .DESCRIPTION
        Produces alertCategory, mitreTechniques, impactedEntities, a legacy
        frequency token and actions without column mappings. Values the legacy
        keys cannot express are kept in their current form or dropped, each
        with a warning.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)]
        [PSObject]$YamlObject
    )

    $yaml = ConvertTo-CustomDetectionHashtable -InputObject $YamlObject

    $sortOrder = @(
        'guid', 'isEnabled', 'ruleName', 'alertTitle', 'alertCategory', 'alertDescription', 'frequency',
        'alertSeverity', 'alertRecommendedAction', 'mitreTechniques', 'impactedEntities', 'organizationalScope', 'actions', 'queryText'
    )

    $legacy = [ordered]@{}
    foreach ($key in @('guid', 'ruleName', 'isEnabled', 'alertTitle', 'alertSeverity', 'alertDescription', 'alertRecommendedAction', 'organizationalScope', 'queryText')) {
        if ($yaml.Contains($key)) { $legacy[$key] = $yaml[$key] }
    }

    if ($yaml.Contains('status')) {
        Write-Warning "Status '$($yaml['status'])' has no legacy key. Only isEnabled is emitted."
    }
    if ($yaml.Contains('detectorId')) {
        Write-Warning 'The detector id has no legacy key and is dropped. The guid identifies the rule.'
    }
    if ($yaml.Contains('description')) {
        Write-Warning 'The rule description has no legacy key and is dropped.'
    }
    if ($yaml.Contains('customDetails')) {
        Write-Warning 'customDetails has no legacy key and is dropped.'
    }

    $periodMap = @{ 'PT0S' = '0'; 'PT1H' = '1H'; 'PT3H' = '3H'; 'PT12H' = '12H'; 'P1D' = '24H'; 'PT24H' = '24H' }
    if ($yaml.Contains('frequency')) {
        $frequency = "$($yaml['frequency'])"
        $token = $periodMap[$frequency.ToUpperInvariant()]
        if ($token) {
            $legacy['frequency'] = $token
        } else {
            Write-Warning "Frequency '$frequency' has no legacy token and is kept as is."
            $legacy['frequency'] = $frequency
        }
    }

    $tactics = @($yaml['tactics'])
    if ($tactics.Count -gt 1) {
        Write-Warning "The rule lists $($tactics.Count) tactics. The legacy alertCategory keeps only the first."
    }
    if ($tactics.Count -gt 0) {
        $first = ConvertTo-CustomDetectionHashtable -InputObject $tactics[0]
        $legacy['alertCategory'] = "$($first['tactic'])"
        $techniques = [System.Collections.Generic.List[string]]::new()
        foreach ($technique in @($first['techniques'])) {
            if ($technique -is [string]) {
                if (-not $techniques.Contains($technique)) { $techniques.Add($technique) }
                continue
            }
            $map = ConvertTo-CustomDetectionHashtable -InputObject $technique
            if (-not $map) { continue }
            if ($map['technique'] -and -not $techniques.Contains("$($map['technique'])")) { $techniques.Add("$($map['technique'])") }
            foreach ($sub in @($map['subTechniques'])) {
                if ($sub -and -not $techniques.Contains("$sub")) { $techniques.Add("$sub") }
            }
        }
        if ($techniques.Count -gt 0) {
            $legacy['mitreTechniques'] = [object[]]@($techniques | Sort-Object)
        }
    }

    $entityTypes = @{ hosts = 'Machine'; accounts = 'User'; mailboxes = 'Mailbox' }
    $columnTypes = @{
        ips            = @{ addressColumn = 'IP' }
        urls           = @{ addressColumn = 'URL' }
        files          = @{ sha1Column = 'FileHash'; sha256Column = 'FileHash' }
        processes      = @{ sha1Column = 'Process'; sha256Column = 'Process' }
        registryValues = @{ keyColumn = 'RegistryKey'; valueNameColumn = 'RegistryValue' }
    }
    $legacyIdentifiers = Get-CustomDetectionLegacyIdentifierMap
    $impactedEntities = [System.Collections.Generic.List[object]]::new()
    $entityMappings = ConvertTo-CustomDetectionHashtable -InputObject $yaml['entityMappings']
    if ($entityMappings) {
        foreach ($collection in $entityMappings.Keys) {
            if ($columnTypes.ContainsKey($collection)) {
                foreach ($item in @($entityMappings[$collection])) {
                    $columns = ConvertTo-CustomDetectionHashtable -InputObject $item
                    if (-not $columns) { continue }
                    foreach ($column in $columns.Keys) {
                        $value = "$($columns[$column])"
                        if (-not $value) { continue }
                        $legacyType = $columnTypes[$collection][$column]
                        if (-not $legacyType) {
                            Write-Warning "Entity mapping $collection.$column = '$value' has no legacy entity type and is dropped."
                            continue
                        }
                        $impactedEntities.Add([ordered]@{
                                entityType       = $legacyType
                                entityIdentifier = $value.Substring(0, 1).ToLowerInvariant() + $value.Substring(1)
                            })
                    }
                }
                continue
            }
            if (-not $entityTypes.ContainsKey($collection)) {
                Write-Warning "Entity mapping '$collection' has no legacy entity type and is dropped."
                continue
            }
            foreach ($item in @($entityMappings[$collection])) {
                $columns = ConvertTo-CustomDetectionHashtable -InputObject $item
                if (-not $columns) { continue }
                foreach ($column in $columns.Keys) {
                    $value = "$($columns[$column])"
                    if (-not $value) { continue }
                    $identifier = $value.Substring(0, 1).ToLowerInvariant() + $value.Substring(1)
                    $known = @($legacyIdentifiers[$collection][$column]) | Where-Object { $_ -eq $identifier } | Select-Object -First 1
                    if (-not $known) {
                        Write-Warning "Entity mapping $collection.$column = '$value' has no legacy identifier and is dropped."
                        continue
                    }
                    $impactedEntities.Add([ordered]@{
                            entityType       = $entityTypes[$collection]
                            entityIdentifier = $known
                        })
                }
            }
        }
    }
    if ($impactedEntities.Count -gt 0) {
        $legacy['impactedEntities'] = [object[]]$impactedEntities.ToArray()
    }

    $legacyActionTypes = @('IsolateMachine', 'CollectInvestigationPackage', 'RunAntivirusScan', 'InitiateInvestigation', 'RestrictAppExecution')
    $actionMap = Get-CustomDetectionActionMap
    $actions = [System.Collections.Generic.List[object]]::new()
    foreach ($item in @($yaml['actions'])) {
        $map = ConvertTo-CustomDetectionHashtable -InputObject $item
        if (-not $map) { continue }
        $actionType = "$($map['actionType'])"
        $known = $legacyActionTypes | Where-Object { $_ -eq $actionType } | Select-Object -First 1
        if (-not $known) {
            Write-Warning "Action '$actionType' has no legacy action type and is dropped."
            continue
        }
        $action = [ordered]@{ actionType = $known }
        $fields = ConvertTo-CustomDetectionHashtable -InputObject $map['additionalFields']
        if ($known -eq 'IsolateMachine' -and $fields -and $fields['isolationType']) {
            $action['additionalFields'] = [ordered]@{ isolationType = (Get-Culture).TextInfo.ToTitleCase("$($fields['isolationType'])".ToLowerInvariant()) }
        }
        # The legacy keys carry no column mappings, so anything beyond the defaults is lost
        if ($fields) {
            $defaults = ($actionMap | Where-Object { $_.ActionType -eq $known } | Select-Object -First 1).Defaults
            foreach ($field in @($fields.Keys)) {
                if ($field -eq 'isolationType') { continue }
                if ($defaults.Contains($field) -and "$($defaults[$field])" -eq "$($fields[$field])") { continue }
                Write-Warning "Action '$known' column mapping $field = '$($fields[$field])' has no legacy form and is dropped. The rule redeploys with the default."
            }
        }
        $actions.Add($action)
    }
    if ($actions.Count -gt 0) {
        $legacy['actions'] = [object[]]$actions.ToArray()
    }

    return ConvertTo-CustomDetectionOrderedMap -Map $legacy -Order $sortOrder
}
