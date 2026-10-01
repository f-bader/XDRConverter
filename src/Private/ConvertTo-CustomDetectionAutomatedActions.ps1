function ConvertTo-CustomDetectionAutomatedActions {
    <#
    .SYNOPSIS
        Builds the detectionAction.automatedActions object.

    .DESCRIPTION
        Accepts the YAML actions list (actionType plus optional additionalFields)
        or the legacy Graph responseActions collection and returns a dictionary
        keyed by automatedActions collection, each holding a list of action items.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Actions')]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(ParameterSetName = 'Actions')]
        [AllowNull()]
        [object[]]$Actions,

        [Parameter(ParameterSetName = 'ResponseActions')]
        [AllowNull()]
        [object[]]$ResponseActions
    )

    $actionMap = Get-CustomDetectionActionMap

    if ($PSCmdlet.ParameterSetName -eq 'ResponseActions') {
        $translated = [System.Collections.Generic.List[object]]::new()
        foreach ($responseAction in @($ResponseActions)) {
            $map = ConvertTo-CustomDetectionHashtable -InputObject $responseAction
            if (-not $map) { continue }
            $legacy = Get-CustomDetectionLegacyAction -ResponseAction $map -ActionMap $actionMap
            if (-not $legacy.Entry) {
                throw "Unsupported response action type '$($legacy.OdataType)'."
            }
            $action = [ordered]@{ actionType = $legacy.Entry.ActionType }
            if ($map['isolationType']) {
                $action.additionalFields = @{ isolationType = "$($map['isolationType'])" }
            }
            $translated.Add($action)
        }
        $Actions = $translated.ToArray()
    }

    $result = [ordered]@{}

    foreach ($action in @($Actions)) {
        $map = ConvertTo-CustomDetectionHashtable -InputObject $action
        if (-not $map) {
            throw "Each item in actions must be a mapping with an actionType. Got '$action'."
        }
        $actionType = "$($map['actionType'])".Trim()
        $entry = $actionMap | Where-Object { $_.ActionType -eq $actionType } | Select-Object -First 1
        if (-not $entry) {
            $supported = ($actionMap | ForEach-Object { $_.ActionType }) -join ', '
            throw "Unsupported response action type '$actionType'. Supported types are: $supported"
        }

        $item = [ordered]@{}
        foreach ($key in $entry.Defaults.Keys) {
            $item[$key] = $entry.Defaults[$key]
        }

        $additional = ConvertTo-CustomDetectionHashtable -InputObject $map['additionalFields']
        if ($null -ne $map['additionalFields'] -and $null -eq $additional) {
            throw "The additionalFields value of action '$actionType' must be a mapping of field name to column name."
        }
        if ($additional) {
            # Fields are matched without case and written under their documented name
            $fields = [ordered]@{}
            foreach ($key in @($additional.Keys)) {
                if ("$key".StartsWith('@')) { continue }
                $field = @($entry.Fields | Where-Object { $_ -eq $key })
                if ($field.Count -eq 0) {
                    throw "Field '$key' is not documented for action '$actionType'. Documented fields are: $($entry.Fields -join ', ')"
                }
                $fields[$field[0]] = $additional[$key]
            }
            $hasSha1 = $fields.Contains('sha1Column') -and "$($fields['sha1Column'])" -ne ''
            $hasSha256 = $fields.Contains('sha256Column') -and "$($fields['sha256Column'])" -ne ''
            if ($hasSha1 -and $hasSha256) {
                throw "Action '$actionType' names sha1Column and sha256Column. A file action carries one hash column."
            }
            # A file action carries one hash column, so an explicit sha256Column replaces the sha1Column default
            if ($hasSha256 -and -not $hasSha1 -and $item.Contains('sha1Column')) {
                $item.Remove('sha1Column')
            }
            $populated = Get-CustomDetectionPopulatedEntry -Map $fields
            foreach ($key in @($populated.Keys)) {
                $value = $populated[$key]
                if ($key -eq 'isolationType') {
                    $isolationType = "$value".ToLowerInvariant()
                    if ($isolationType -notin @('full', 'selective')) {
                        throw "Isolation type '$value' is not supported. Use 'Full' or 'Selective'."
                    }
                    $item[$key] = $isolationType
                } elseif ($key -eq 'deviceGroupNames') {
                    $groups = @($value)
                    foreach ($group in $groups) {
                        if ($group -isnot [string] -or [string]::IsNullOrWhiteSpace($group)) {
                            throw "Action '$actionType' names a device group that is not a single name."
                        }
                    }
                    $item[$key] = [object[]]@($groups | ForEach-Object { "$_" })
                } else {
                    if ($value -isnot [string]) {
                        throw "Field '$key' of action '$actionType' must be a single column name."
                    }
                    $item[$key] = $value
                }
            }
        }

        # Fields follow the documented order, so the same entries give the same item whatever their order in the file
        $item = ConvertTo-CustomDetectionOrderedMap -Map $item -Order $entry.Fields

        # File input only. The API keeps every item it is sent, so an exact repeat is a mistake and a repeat with other fields gets a warning
        if ($PSCmdlet.ParameterSetName -eq 'Actions' -and $result.Contains($entry.Collection)) {
            $itemJson = $item | ConvertTo-Json -Compress -Depth 5
            foreach ($existing in $result[$entry.Collection]) {
                if (($existing | ConvertTo-Json -Compress -Depth 5) -ceq $itemJson) {
                    throw "Action '$actionType' is listed twice with the same fields. List each action once."
                }
            }
            Write-Warning "Action '$actionType' is listed more than once. The rule keeps every item, so check that both are intended."
        }

        if (-not $result.Contains($entry.Collection)) {
            $result[$entry.Collection] = [System.Collections.Generic.List[object]]::new()
        }
        $result[$entry.Collection].Add($item)
    }

    if ($result.Count -eq 0) {
        return $null
    }

    foreach ($collection in @($result.Keys)) {
        $result[$collection] = [object[]]$result[$collection].ToArray()
    }

    return $result
}
