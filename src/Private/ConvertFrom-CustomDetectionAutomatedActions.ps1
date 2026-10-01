function ConvertFrom-CustomDetectionAutomatedActions {
    <#
    .SYNOPSIS
        Converts Graph automated actions into the YAML actions list.

    .DESCRIPTION
        Each populated automatedActions collection becomes one or more YAML
        actions carrying the column mapping in additionalFields. Unknown
        collections are kept under their collection name with a warning.
        The legacy responseActions collection is translated as well.
    #>
    [CmdletBinding(DefaultParameterSetName = 'AutomatedActions')]
    [OutputType([object[]])]
    param(
        [Parameter(ParameterSetName = 'AutomatedActions')]
        [AllowNull()]
        [object]$AutomatedActions,

        [Parameter(ParameterSetName = 'ResponseActions')]
        [AllowNull()]
        [object[]]$ResponseActions
    )

    $actionMap = Get-CustomDetectionActionMap
    $textInfo = (Get-Culture).TextInfo
    $result = [System.Collections.Generic.List[object]]::new()

    if ($PSCmdlet.ParameterSetName -eq 'ResponseActions') {
        foreach ($responseAction in @($ResponseActions)) {
            $map = ConvertTo-CustomDetectionHashtable -InputObject $responseAction
            if (-not $map) { continue }
            $legacy = Get-CustomDetectionLegacyAction -ResponseAction $map -ActionMap $actionMap
            if (-not $legacy.Entry) {
                Write-Warning "Unknown response action type '$($legacy.OdataType)'. Skipping."
                continue
            }
            $action = [ordered]@{ actionType = $legacy.Entry.ActionType }
            if ($map['isolationType']) {
                $action.additionalFields = [ordered]@{ isolationType = $textInfo.ToTitleCase("$($map['isolationType'])") }
            }
            $result.Add($action)
        }
        return $result.ToArray()
    }

    $collections = ConvertTo-CustomDetectionHashtable -InputObject $AutomatedActions
    if (-not $collections) {
        return $result.ToArray()
    }

    foreach ($key in @($collections.Keys)) {
        if ("$key".StartsWith('@')) { continue }
        $rawItems = ConvertTo-CustomDetectionList -Value $collections[$key]
        if ($rawItems.Count -eq 0) { continue }

        $entry = $actionMap | Where-Object { $_.Collection -eq $key } | Select-Object -First 1
        $actionType = if ($entry) { $entry.ActionType } else {
            Write-Warning "Unknown automated action collection '$key'. Keeping it under its collection name."
            $key
        }

        foreach ($rawItem in $rawItems) {
            $item = ConvertTo-CustomDetectionHashtable -InputObject $rawItem
            $action = [ordered]@{ actionType = $actionType }
            $fields = [ordered]@{}
            if ($item) {
                $columns = Get-CustomDetectionPopulatedEntry -Map $item
                foreach ($columnKey in @($columns.Keys)) {
                    $value = $columns[$columnKey]
                    if ($columnKey -eq 'isolationType') {
                        $fields[$columnKey] = $textInfo.ToTitleCase("$value")
                    } else {
                        $fields[$columnKey] = $value
                    }
                }
            }
            if ($fields.Count -gt 0) {
                $action.additionalFields = $fields
            }
            $result.Add($action)
        }
    }

    return $result.ToArray()
}
