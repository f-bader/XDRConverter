function ConvertTo-CustomDetectionEntityMappings {
    <#
    .SYNOPSIS
        Builds the alertTemplate.entityMappings object.

    .DESCRIPTION
        Accepts either the legacy impactedEntities list (entityType plus
        entityIdentifier) or an entityMappings object keyed by entity
        collection. Both return the Graph shape: a dictionary of collections,
        each holding a list of column mapping items.
    #>
    [CmdletBinding(DefaultParameterSetName = 'EntityMappings')]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(ParameterSetName = 'ImpactedEntities')]
        [AllowNull()]
        [object[]]$ImpactedEntities,

        [Parameter(ParameterSetName = 'EntityMappings')]
        [AllowNull()]
        [object]$EntityMappings,

        [Parameter()]
        [switch]$SkipIdentifierValidation
    )

    $collectionColumns = Get-CustomDetectionEntityMappingColumns

    $legacyTypes = @{
        machine = @{ Collection = 'hosts'; DefaultColumn = 'nameColumn' }
        device  = @{ Collection = 'hosts'; DefaultColumn = 'nameColumn' }
        user    = @{ Collection = 'accounts'; DefaultColumn = 'nameColumn' }
        account = @{ Collection = 'accounts'; DefaultColumn = 'nameColumn' }
        mailbox = @{ Collection = 'mailboxes'; DefaultColumn = 'primaryAddressColumn' }
    }

    # Legacy types with one fixed column. The identifier is the query column name
    $columnTypes = @{
        ip            = @{ Collection = 'ips'; Column = 'addressColumn' }
        url           = @{ Collection = 'urls'; Column = 'addressColumn' }
        filehash      = @{ Collection = 'files'; Column = 'hash' }
        process       = @{ Collection = 'processes'; Column = 'hash' }
        registrykey   = @{ Collection = 'registryValues'; Column = 'keyColumn' }
        registryvalue = @{ Collection = 'registryValues'; Column = 'valueNameColumn' }
    }

    $legacyIdentifiers = Get-CustomDetectionLegacyIdentifierMap

    # Identifiers that share a prefix describe one entity, so accountSid and accountDomain
    # land in one item while initiatingAccountName starts another
    function Get-IdentifierPrefix {
        param([string]$Identifier)

        foreach ($suffix in @('ObjectId', 'Sid', 'Upn', 'Name', 'Domain', 'Id')) {
            if ($Identifier.Length -gt $suffix.Length -and $Identifier.EndsWith($suffix, [System.StringComparison]::OrdinalIgnoreCase)) {
                return $Identifier.Substring(0, $Identifier.Length - $suffix.Length).ToLowerInvariant()
            }
        }
        return $Identifier.ToLowerInvariant()
    }

    $groupItems = @{}

    function Add-MappingColumn {
        param([System.Collections.Specialized.OrderedDictionary]$Result, [string]$Collection, [string]$Column, [string]$Value, [string]$Group, [switch]$Pair)

        if (-not $Result.Contains($Collection)) {
            $Result[$Collection] = [System.Collections.Generic.List[object]]::new()
        }
        $groupKey = "$Collection|$Group"
        $target = $null
        if ($Pair) {
            # The column joins the first item that does not carry it yet, so the same entries pair the same way whatever their order
            foreach ($item in $Result[$Collection]) {
                if (-not $item.Contains($Column)) {
                    $target = $item
                    break
                }
            }
        } elseif ($groupItems.ContainsKey($groupKey) -and -not $groupItems[$groupKey].Contains($Column)) {
            $target = $groupItems[$groupKey]
        }
        if (-not $target) {
            $target = [ordered]@{}
            $Result[$Collection].Add($target)
            $groupItems[$groupKey] = $target
        }
        $target[$Column] = $Value
    }

    $result = [ordered]@{}

    if ($PSCmdlet.ParameterSetName -eq 'ImpactedEntities') {
        foreach ($entity in @($ImpactedEntities)) {
            $map = ConvertTo-CustomDetectionHashtable -InputObject $entity
            if (-not $map) {
                throw "Each item in impactedEntities must be a mapping with entityType and entityIdentifier. Got '$entity'."
            }
            $entityType = "$($map['entityType'])".Trim()
            $identifier = "$($map['entityIdentifier'])".Trim()
            if (-not $entityType -or -not $identifier) {
                throw 'Each impactedEntities entry needs entityType and entityIdentifier.'
            }

            $columnType = $columnTypes[$entityType.ToLowerInvariant()]
            if ($columnType) {
                $column = $columnType.Column
                if ($column -eq 'hash') {
                    if ($identifier -match 'sha256') {
                        $column = 'sha256Column'
                    } elseif ($identifier -match 'sha1') {
                        $column = 'sha1Column'
                    } else {
                        throw "Identifier '$identifier' for entity type '$entityType' must name a SHA1 or SHA256 column."
                    }
                }
                $columnValue = $identifier.Substring(0, 1).ToUpperInvariant() + $identifier.Substring(1)
                # A registry key and a value name describe one registry value, so they pair into one item. Every other column type is one entity per identifier
                $pair = $columnType.Collection -eq 'registryValues'
                Add-MappingColumn -Result $result -Collection $columnType.Collection -Column $column -Value $columnValue -Group $identifier -Pair:$pair
                continue
            }

            $typeInfo = $legacyTypes[$entityType.ToLowerInvariant()]
            if (-not $typeInfo) {
                throw "Entity type '$entityType' is not supported in impactedEntities. Use entityMappings for this entity."
            }

            $collection = $typeInfo.Collection
            $column = $null
            $canonical = $null
            foreach ($candidateColumn in $legacyIdentifiers[$collection].Keys) {
                $match = $legacyIdentifiers[$collection][$candidateColumn] | Where-Object { $_ -eq $identifier } | Select-Object -First 1
                if ($match) {
                    $column = $candidateColumn
                    $canonical = $match
                    break
                }
            }

            if (-not $column) {
                $validList = ($legacyIdentifiers[$collection].Values | ForEach-Object { $_ }) -join ', '
                if ($SkipIdentifierValidation) {
                    Write-Warning "Identifier '$identifier' for entity type '$entityType' is not in the official documentation. Valid identifiers are: $validList"
                    $column = $typeInfo.DefaultColumn
                    $canonical = $identifier
                } else {
                    throw "Invalid identifier '$identifier' for entity type '$entityType'. Valid identifiers are: $validList"
                }
            } elseif ($canonical -eq 'accountId') {
                Write-Warning "Identifier 'accountId' has no dedicated entity mapping column. Mapped to accounts.nameColumn."
            }

            $columnValue = $canonical.Substring(0, 1).ToUpperInvariant() + $canonical.Substring(1)
            Add-MappingColumn -Result $result -Collection $collection -Column $column -Value $columnValue -Group (Get-IdentifierPrefix -Identifier $canonical)
        }
    } else {
        $mappings = ConvertTo-CustomDetectionHashtable -InputObject $EntityMappings
        foreach ($key in @($mappings.Keys)) {
            $collection = $collectionColumns.Keys | Where-Object { $_ -eq $key } | Select-Object -First 1
            if (-not $collection) {
                $known = $collectionColumns.Keys -join ', '
                if ($SkipIdentifierValidation) {
                    Write-Warning "Unknown entity mapping '$key'. Known mappings are: $known"
                    $collection = $key
                } else {
                    throw "Unknown entity mapping '$key'. Known mappings are: $known"
                }
            }

            $rawItems = ConvertTo-CustomDetectionList -Value $mappings[$key]

            foreach ($rawItem in $rawItems) {
                $item = ConvertTo-CustomDetectionHashtable -InputObject $rawItem
                if (-not $item) {
                    throw "Each item in entity mapping '$collection' must be a mapping of column name to value. Got '$rawItem'."
                }
                $cleanItem = [ordered]@{}
                $columns = Get-CustomDetectionPopulatedEntry -Map $item
                foreach ($columnKey in @($columns.Keys)) {
                    $value = $columns[$columnKey]
                    if ($value -isnot [string]) {
                        throw "Column '$columnKey' of entity mapping '$collection' must be a single column name."
                    }
                    if ($collectionColumns.Contains($collection) -and $columnKey -notin $collectionColumns[$collection]) {
                        $validColumns = $collectionColumns[$collection] -join ', '
                        if ($SkipIdentifierValidation) {
                            Write-Warning "Column '$columnKey' is not documented for '$collection'. Documented columns are: $validColumns"
                        } else {
                            throw "Invalid column '$columnKey' for entity mapping '$collection'. Documented columns are: $validColumns"
                        }
                    }
                    $cleanItem[$columnKey] = $value
                }
                if ($cleanItem.Count -eq 0) { continue }
                if (-not $result.Contains($collection)) {
                    $result[$collection] = [System.Collections.Generic.List[object]]::new()
                }
                $result[$collection].Add($cleanItem)
            }
        }
    }

    # The API rejects an account mapping that has no key column and no name plus domain pair.
    # Legacy input is dropped with a warning, which is what the API did with impactedAssets.
    # Explicit input is an error unless validation is skipped.
    if ($result.Contains('accounts')) {
        $dropIncomplete = ($PSCmdlet.ParameterSetName -eq 'ImpactedEntities') -or $SkipIdentifierValidation
        $complete = [System.Collections.Generic.List[object]]::new()
        foreach ($item in $result['accounts']) {
            $hasKeyColumn = $item.Contains('aadUserIdColumn') -or $item.Contains('sidColumn') -or $item.Contains('upnColumn')
            $hasNameAndDomain = $item.Contains('nameColumn') -and ($item.Contains('ntDomainColumn') -or $item.Contains('dnsDomainColumn') -or $item.Contains('upnSuffixColumn'))
            if ($hasKeyColumn -or $hasNameAndDomain) {
                $complete.Add($item)
                continue
            }
            $columns = ($item.Keys | ForEach-Object { "$_ = $($item[$_])" }) -join ', '
            $message = "Account mapping ($columns) needs aadUserIdColumn, sidColumn, upnColumn, or nameColumn together with a domain column."
            if (-not $dropIncomplete) {
                throw $message
            }
            Write-Warning "$message It is dropped."
        }
        if ($complete.Count -eq 0) {
            $result.Remove('accounts')
        } else {
            $result['accounts'] = $complete
        }
    }

    if ($result.Count -eq 0) {
        return $null
    }

    # Columns follow the documented order, so the same entries give the same body whatever their order in the file
    foreach ($collection in @($result.Keys)) {
        $items = [System.Collections.Generic.List[object]]::new()
        $knownColumns = if ($collectionColumns.Contains($collection)) { $collectionColumns[$collection] } else { @() }
        foreach ($item in $result[$collection]) {
            $items.Add((ConvertTo-CustomDetectionOrderedMap -Map $item -Order $knownColumns))
        }
        $result[$collection] = [object[]]$items.ToArray()
    }

    return $result
}
