function ConvertTo-CustomDetectionTactics {
    <#
    .SYNOPSIS
        Builds the alertTemplate.tactics collection.

    .DESCRIPTION
        An explicit tactics list wins. Otherwise the alert category becomes the
        single tactic and the flat technique list is grouped so that
        sub-techniques sit under their parent technique.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Category,

        [Parameter()]
        [AllowNull()]
        [object[]]$Techniques,

        [Parameter()]
        [AllowNull()]
        [object]$Tactics
    )

    function Group-Technique {
        param([object[]]$Items)

        $parents = [ordered]@{}
        foreach ($item in $Items) {
            if ($null -eq $item) { continue }

            $techniqueId = $null
            $subTechniqueIds = @()

            if ($item -is [string]) {
                $techniqueId = $item.Trim()
            } else {
                $map = ConvertTo-CustomDetectionHashtable -InputObject $item
                if (-not $map) { continue }
                $techniqueId = "$($map['technique'])".Trim()
                if ($map['subTechniques']) {
                    $subTechniqueIds = @($map['subTechniques'] | ForEach-Object { "$_".Trim() })
                }
            }

            if ([string]::IsNullOrEmpty($techniqueId)) { continue }

            $parentId = $techniqueId.Split('.')[0]
            if (-not $parents.Contains($parentId)) {
                $parents[$parentId] = [System.Collections.Generic.List[string]]::new()
            }
            if ($techniqueId -ne $parentId) {
                $subTechniqueIds += $techniqueId
            }
            foreach ($sub in $subTechniqueIds) {
                if ($sub -and -not $parents[$parentId].Contains($sub)) {
                    $parents[$parentId].Add($sub)
                }
            }
        }

        $grouped = [System.Collections.Generic.List[object]]::new()
        foreach ($parentId in ($parents.Keys | Sort-Object)) {
            $entry = [ordered]@{ technique = $parentId }
            if ($parents[$parentId].Count -gt 0) {
                $entry['subTechniques'] = [object[]]@($parents[$parentId] | Sort-Object)
            }
            $grouped.Add($entry)
        }
        return $grouped.ToArray()
    }

    if ($Tactics) {
        $result = [System.Collections.Generic.List[object]]::new()
        foreach ($tacticItem in @($Tactics)) {
            $map = ConvertTo-CustomDetectionHashtable -InputObject $tacticItem
            if (-not $map -or [string]::IsNullOrWhiteSpace("$($map['tactic'])")) {
                throw "Each tactics entry needs a non-empty 'tactic' value."
            }
            $entry = [ordered]@{ tactic = "$($map['tactic'])".Trim() }
            $grouped = @()
            if ($map['techniques']) {
                $grouped = @(Group-Technique -Items @($map['techniques']))
            }
            if ($grouped.Count -gt 0) {
                $entry['techniques'] = [object[]]$grouped
            }
            $result.Add($entry)
        }
        return $result.ToArray()
    }

    if ([string]::IsNullOrWhiteSpace($Category)) {
        if ($Techniques -and @($Techniques).Count -gt 0) {
            throw 'MITRE techniques need an alert category or an explicit tactics list.'
        }
        return $null
    }

    $entry = [ordered]@{ tactic = $Category.Trim() }
    $grouped = @()
    if ($Techniques) {
        $grouped = @(Group-Technique -Items $Techniques)
    }
    if ($grouped.Count -gt 0) {
        $entry['techniques'] = [object[]]$grouped
    }

    return $entry
}
