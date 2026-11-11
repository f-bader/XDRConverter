function Test-CustomDetectionMitreTechnique {
    <#
    .SYNOPSIS
        Validates that MITRE ATT&CK techniques in a detection rule are supported by XDR for the selected category.

    .DESCRIPTION
        Reads the tactics list, or the legacy alertCategory and mitreTechniques, from a detection
        YAML file or object and checks each technique against the set of techniques that Microsoft
        XDR supports for that category. Techniques not supported by XDR for the given category are
        reported as invalid. With a tactics list every tactic is validated and the results are combined.

        The technique mapping is derived from the XDR portal's front-end data and reflects the
        actual techniques available in each alert category dropdown.

        Categories not present in the XDR mapping (e.g. SuspiciousActivity) cannot be validated;
        in that case the function emits a warning and returns IsValid = $true with no invalid techniques.

    .PARAMETER InputFile
        Path to a detection YAML (.yaml/.yml) file.

    .PARAMETER InputObject
        A parsed YAML/detection PSObject. Accepts pipeline input.

    .OUTPUTS
        PSCustomObject with:
          IsValid          - $true if all listed techniques are supported for their category
          Category         - the tactic name(s), comma separated when several tactics are listed
          ValidTechniques  - techniques that are supported for the category
          InvalidTechniques- techniques that are NOT supported for the category

    .EXAMPLE
        Test-CustomDetectionMitreTechnique -InputFile '.\detection.yaml'

        Validates all MITRE techniques in the YAML file against the XDR category mapping.

    .EXAMPLE
        Get-ChildItem '.\detections\*.yaml' | ForEach-Object { Test-CustomDetectionMitreTechnique -InputFile $_.FullName }

        Validates all YAML files in a directory.

    .EXAMPLE
        ConvertFrom-Yaml (Get-Content '.\detection.yaml' -Raw) | Test-CustomDetectionMitreTechnique

        Pipeline input from a parsed YAML object.

    .EXAMPLE
        $result = Test-CustomDetectionMitreTechnique -InputFile '.\detection.yaml'
        if (-not $result.IsValid) {
            Write-Warning "Unsupported techniques: $($result.InvalidTechniques -join ', ')"
        }
    #>
    [CmdletBinding(DefaultParameterSetName = 'File')]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory, ParameterSetName = 'File', HelpMessage = 'Path to a detection YAML file')]
        [ValidateScript({ Test-Path $_ -PathType Leaf })]
        [string]$InputFile,

        [Parameter(Mandatory, ParameterSetName = 'Object', ValueFromPipeline, HelpMessage = 'Parsed detection object')]
        [ValidateNotNull()]
        [PSObject]$InputObject
    )

    begin {
        $xdrTechniqueMap = Get-CustomDetectionMitreTechniqueMap
    }

    process {
        try {
            $yamlObj = if ($PSCmdlet.ParameterSetName -eq 'File') {
                Import-CustomDetectionYamlFile -FilePath $InputFile
            } else {
                $InputObject
            }

            # Build one (category, techniques) pair per tactic. A tactics list wins over the legacy keys.
            $sets = [System.Collections.Generic.List[object]]::new()
            if ($yamlObj.tactics) {
                # Entries are validated as written. A listed parent counts alongside its sub-techniques, a derived one does not
                foreach ($tacticItem in @($yamlObj.tactics)) {
                    $tactic = ConvertTo-CustomDetectionHashtable -InputObject $tacticItem
                    if (-not $tactic) { continue }
                    $flattened = [System.Collections.Generic.List[string]]::new()
                    foreach ($technique in @($tactic['techniques'])) {
                        if ($null -eq $technique) { continue }
                        if ($technique -is [string]) {
                            if ($technique.Trim()) { $flattened.Add($technique.Trim()) }
                            continue
                        }
                        $entry = ConvertTo-CustomDetectionHashtable -InputObject $technique
                        if (-not $entry) { continue }
                        if ("$($entry['technique'])".Trim()) { $flattened.Add("$($entry['technique'])".Trim()) }
                        foreach ($sub in @($entry['subTechniques'])) {
                            if ("$sub".Trim()) { $flattened.Add("$sub".Trim()) }
                        }
                    }
                    $sets.Add(@{ Category = "$($tactic['tactic'])"; Techniques = $flattened.ToArray() })
                }
            } else {
                $category = $yamlObj.alertCategory
                if (-not $category) {
                    throw "The detection object does not contain an 'alertCategory' or 'tactics' property."
                }
                $sets.Add(@{ Category = $category; Techniques = @($yamlObj.mitreTechniques | Where-Object { $_ }) })
            }

            $validTechniques = [System.Collections.Generic.List[string]]::new()
            $invalidTechniques = [System.Collections.Generic.List[string]]::new()

            foreach ($set in $sets) {
                $category = $set.Category
                $techniques = @($set.Techniques)

                # No techniques defined — nothing to validate
                if ($techniques.Count -eq 0) {
                    Write-Verbose "No techniques defined for category '$category'. Nothing to validate."
                    continue
                }

                # Category not present in XDR mapping — cannot validate
                if (-not $xdrTechniqueMap.ContainsKey($category)) {
                    Write-Warning "Category '$category' is not present in the XDR technique mapping. Validation skipped."
                    foreach ($technique in $techniques) { $validTechniques.Add($technique) }
                    continue
                }

                $supported = $xdrTechniqueMap[$category]
                $invalidForCategory = [System.Collections.Generic.List[string]]::new()
                foreach ($technique in $techniques) {
                    if ($technique -in $supported) {
                        $validTechniques.Add($technique)
                    } else {
                        $invalidTechniques.Add($technique)
                        $invalidForCategory.Add($technique)
                    }
                }

                if ($invalidForCategory.Count -gt 0) {
                    $invalidList = $invalidForCategory -join ', '
                    Write-Warning "The following MITRE technique(s) are not supported by XDR for category '$category': $invalidList"
                }
            }

            [PSCustomObject]@{
                IsValid           = ($invalidTechniques.Count -eq 0)
                Category          = (($sets | ForEach-Object { $_.Category }) -join ', ')
                ValidTechniques   = $validTechniques.ToArray()
                InvalidTechniques = $invalidTechniques.ToArray()
            }
        } catch {
            Write-Error "Error validating MITRE techniques: $_"
            throw
        }
    }
}
