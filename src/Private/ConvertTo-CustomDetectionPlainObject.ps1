function ConvertTo-CustomDetectionPlainObject {
    <#
    .SYNOPSIS
        Strips PSObject wrappers from a request body.

    .DESCRIPTION
        Values that passed through Sort-Object, Select-Object or Where-Object
        arrive wrapped in a PSObject. The Graph client serialises those wrappers
        as objects, which fails with a self-referencing loop on string members.
        This returns the same tree built from plain dictionaries, arrays and
        base values. Children are written straight into their parent container,
        so nothing is re-wrapped by the pipeline on the way back.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        [object]$InputObject
    )

    function Test-IsList {
        param([object]$Value)
        return ($null -ne $Value -and $Value -isnot [string] -and $Value -isnot [System.Collections.IDictionary] -and $Value -is [System.Collections.IEnumerable])
    }

    function Copy-PlainValue {
        param([object]$Container, [object]$Key, [object]$Value)

        # Assigning an if-expression would unroll a one-element array, so branch explicitly
        $base = $Value
        if ($null -ne $Value -and $Value -is [psobject]) {
            $base = $Value.PSObject.BaseObject
        }
        $plain = $null

        if ($null -eq $base) {
            $plain = $null
        } elseif ($base -is [string]) {
            $plain = [string]$base
        } elseif ($base -is [ValueType]) {
            $plain = $base
        } elseif ($base -is [System.Collections.IDictionary]) {
            $plain = [ordered]@{}
            foreach ($childKey in $base.Keys) {
                Copy-PlainValue -Container $plain -Key ([string]$childKey) -Value $base[$childKey]
            }
        } elseif (Test-IsList -Value $base) {
            $list = [System.Collections.Generic.List[object]]::new()
            foreach ($item in $base) {
                Copy-PlainValue -Container $list -Key $null -Value $item
            }
            $plain = [object[]]$list.ToArray()
        } elseif ($base -is [System.Management.Automation.PSCustomObject]) {
            $plain = [ordered]@{}
            foreach ($property in $Value.PSObject.Properties) {
                Copy-PlainValue -Container $plain -Key $property.Name -Value $property.Value
            }
        } else {
            $plain = $base
        }

        if ($Container -is [System.Collections.IDictionary]) {
            $Container[$Key] = $plain
        } else {
            $Container.Add($plain)
        }
    }

    $root = [System.Collections.Generic.List[object]]::new()
    Copy-PlainValue -Container $root -Key $null -Value $InputObject
    $result = $root[0]

    if (Test-IsList -Value $InputObject) {
        return , ([object[]]$result)
    }
    return $result
}
