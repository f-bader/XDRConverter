function Complete-CustomDetectionPatchBody {
    <#
    .SYNOPSIS
        Builds the PATCH body from a full rule body.

    .DESCRIPTION
        The API keeps any collection that a PATCH omits, so an action, entity
        mapping or device group removed from the file would stay live. The
        PATCH body therefore sends an empty list for every collection the
        remote rule carries and the file does not, including collections this
        module does not know. Each cleared collection is named in a warning.
        Collections neither side carries are left out. Custom details are
        left out when unset because the API offers no way to clear them.
        The rule id is left out because it cannot change. Without a remote
        rule every known collection is named, which is the shape that
        predates the remote-driven one.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Body,

        [Parameter()]
        [AllowNull()]
        [PSObject]$Remote
    )

    # Collections the remote rule carries with at least one item, annotations excluded
    function Get-RemoteCollectionList {
        param([object]$Source)
        $names = [System.Collections.Generic.List[string]]::new()
        $map = ConvertTo-CustomDetectionHashtable -InputObject $Source
        if ($null -eq $map) { return $names }
        foreach ($key in $map.Keys) {
            if ("$key".StartsWith('@')) { continue }
            if ($null -ne $map[$key] -and @($map[$key]).Count -gt 0) { $names.Add([string]$key) }
        }
        return $names
    }

    function Merge-CollectionSet {
        param([System.Collections.IDictionary]$Local, [string[]]$Known, [object]$RemoteSource)

        $merged = [ordered]@{}
        $names = [System.Collections.Generic.List[string]]::new()
        if ($null -ne $Remote) {
            foreach ($name in (Get-RemoteCollectionList -Source $RemoteSource)) { $names.Add($name) }
        } else {
            foreach ($name in $Known) { $names.Add($name) }
        }
        if ($Local) {
            foreach ($name in $Local.Keys) { if (-not $names.Contains([string]$name)) { $names.Add([string]$name) } }
        }
        foreach ($name in $names) {
            if ($Local -and $Local.Contains($name) -and $null -ne $Local[$name]) {
                $merged[$name] = [object[]]@($Local[$name])
            } else {
                if ($null -ne $Remote) {
                    $unknownNote = if ($name -notin $Known) { " (not one of this module's known columns)" } else { '' }
                    Write-Warning "The rule carries '$name'$unknownNote that the file does not set. It is cleared."
                }
                $merged[$name] = [object[]]@()
            }
        }
        return $merged
    }

    $patch = [ordered]@{}
    foreach ($key in $Body.Keys) {
        if ($key -ne 'id') { $patch[$key] = $Body[$key] }
    }

    $detectionAction = [ordered]@{}
    foreach ($key in $Body['detectionAction'].Keys) {
        $detectionAction[$key] = $Body['detectionAction'][$key]
    }
    $patch['detectionAction'] = $detectionAction

    $alertTemplate = [ordered]@{}
    foreach ($key in $detectionAction['alertTemplate'].Keys) {
        $alertTemplate[$key] = $detectionAction['alertTemplate'][$key]
    }
    $detectionAction['alertTemplate'] = $alertTemplate

    $entityMappings = Merge-CollectionSet -Local $alertTemplate['entityMappings'] -Known @((Get-CustomDetectionEntityMappingColumns).Keys) -RemoteSource (Get-CustomDetectionValue -Object $Remote -Path 'detectionAction.alertTemplate.entityMappings')
    if ($entityMappings.Count -gt 0) {
        $alertTemplate['entityMappings'] = $entityMappings
    } else {
        $alertTemplate.Remove('entityMappings')
    }

    $automatedActions = Merge-CollectionSet -Local $detectionAction['automatedActions'] -Known @((Get-CustomDetectionActionMap).Collection) -RemoteSource (Get-CustomDetectionValue -Object $Remote -Path 'detectionAction.automatedActions')
    if ($automatedActions.Count -gt 0) {
        $detectionAction['automatedActions'] = $automatedActions
    } else {
        $detectionAction.Remove('automatedActions')
    }

    if (-not $detectionAction.Contains('organizationalScope') -or $null -eq $detectionAction['organizationalScope']) {
        $remoteScope = ConvertTo-CustomDetectionHashtable -InputObject (Get-CustomDetectionValue -Object $Remote -Path 'detectionAction.organizationalScope')
        $remoteHasGroups = $false
        if ($null -ne $remoteScope) {
            foreach ($key in @('deviceGroups', 'scopeNames')) {
                if ($remoteScope.Contains($key) -and $null -ne $remoteScope[$key] -and @($remoteScope[$key]).Count -gt 0) { $remoteHasGroups = $true }
            }
        }
        if ($null -eq $Remote -or $remoteHasGroups) {
            $detectionAction['organizationalScope'] = [ordered]@{ deviceGroups = [object[]]@() }
        } else {
            $detectionAction.Remove('organizationalScope')
        }
    }

    return $patch
}
