function Resolve-QueryVariables {
    <#
    .SYNOPSIS
        Applies parameter file transformations (prepend, append, variable replacement) to a query string.

    .DESCRIPTION
        Reads a YAML parameter file that may contain:
          - PrependQuery:  text prepended to the query
          - AppendQuery:   text appended to the query
          - ReplaceQueryVariables:  hashtable of variable names and values

        Variables in the query use the syntax %%VARIABLENAME%% or %%VARIABLENAME:DEFAULT%%.

        Replacement rules:
          %%VAR%%        with VAR = "value"  -> "value"
          %%VAR%%        with VAR not set    -> "" (empty string) + warning
          %%VAR:default%%  with VAR = "value"  -> "value"
          %%VAR:default%%  with VAR not set    -> "default"

        Array values are joined with a comma (e.g. "403","404" becomes "403","404").

    .PARAMETER QueryText
        The KQL query string containing %%VARIABLE%% placeholders.

    .PARAMETER ParameterFilePath
        Path to the YAML parameter file.

    .OUTPUTS
        [string] The transformed query text.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$QueryText,

        [Parameter(Mandatory)]
        [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
        [string]$ParameterFilePath
    )

    # Parse the parameter file
    $paramContent = Get-Content -Path $ParameterFilePath -Raw
    $paramObj = $paramContent | ConvertFrom-Yaml

    if (-not $paramObj -or $paramObj -isnot [System.Collections.IDictionary]) {
        Write-Warning "Parameter file '$ParameterFilePath' is empty or invalid. Returning query unchanged."
        return $QueryText
    }

    $result = $QueryText

    # ── 1. Replace variables ────────────────────────────────────────────
    $variables = $null
    if ($paramObj.ContainsKey('ReplaceQueryVariables') -and $paramObj['ReplaceQueryVariables']) {
        $variables = $paramObj['ReplaceQueryVariables']
    }

    # Find all %%VARNAME%% and %%VARNAME:DEFAULT%% placeholders
    $pattern = '%%([^%:]+?)(?::([^%]*?))?%%'
    $result = [regex]::Replace($result, $pattern, {
            param($match)
            $varName = $match.Groups[1].Value
            $hasDefault = $match.Groups[2].Success
            $defaultValue = if ($hasDefault) { $match.Groups[2].Value } else { $null }

            # Look up the variable
            $found = $false
            $value = $null
            if ($variables -and $variables.ContainsKey($varName)) {
                $found = $true
                $value = $variables[$varName]
            }

            if ($found) {
                # Format array values as comma-separated quoted strings
                if ($value -is [System.Collections.IList]) {
                    return ($value | ForEach-Object { "`"$_`"" }) -join ','
                }
                return [string]$value
            }

            if ($hasDefault) {
                # Use default value — no warning
                return $defaultValue
            }

            # No value and no default — warn and replace with empty string
            Write-Warning "Query variable '%%${varName}%%' is not defined in the parameter file and has no default value."
            return ''
        })

    # ── 2. Prepend query ────────────────────────────────────────────────
    if ($paramObj.ContainsKey('PrependQuery') -and $paramObj['PrependQuery']) {
        $prepend = $paramObj['PrependQuery'].TrimEnd("`r", "`n")
        $result = $prepend + "`n" + $result
    }

    # ── 3. Append query ─────────────────────────────────────────────────
    if ($paramObj.ContainsKey('AppendQuery') -and $paramObj['AppendQuery']) {
        $append = $paramObj['AppendQuery'].TrimEnd("`r", "`n")
        $result = $result.TrimEnd("`r", "`n") + "`n" + $append
    }

    return $result
}
