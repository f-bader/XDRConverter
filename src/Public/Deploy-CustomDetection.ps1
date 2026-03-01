function Deploy-CustomDetection {
    <#
    .SYNOPSIS
        Creates or updates a Defender XDR custom detection rule from a YAML or JSON file.

    .DESCRIPTION
        Reads a detection rule from a YAML or JSON file, optionally overrides severity,
        title prefix, and enabled state, then deploys it to Microsoft Defender XDR via
        the Microsoft Graph API.

        By default the YAML/JSON guid (detectorId) is appended to the description as
        "[<UUID>]". Use -DescriptionTagPrefix to add a prefix (e.g. "[PREFIX:<UUID>]")
        or -NoDescriptionTag to suppress the tag entirely.

        The function automatically detects whether the rule already exists (by detectorId
        or by scanning descriptions for the UUID tag) and issues a PATCH (update) instead
        of a POST (create). Before updating it compares the local rule against the remote
        version and skips the call when nothing changed.

    .PARAMETER InputFile
        Path to the input YAML (.yaml/.yml) or JSON (.json) file.

    .PARAMETER Severity
        Override the alert severity. Valid values: Informational, Low, Medium, High.

    .PARAMETER TitlePrefix
        Optional string prepended to the displayName / alertTitle.
        Example: -TitlePrefix '[PREFIX] ' produces "[PREFIX] My Rule".

    .PARAMETER Disabled
        Deploy the rule with isEnabled = $false regardless of the file value.

    .PARAMETER NoDescriptionTag
        When set, the "[<UUID>]" tag is NOT appended to the description.

    .PARAMETER DescriptionTagPrefix
        Prefix placed before the UUID inside the tag, e.g. 'PREFIX' produces "[PREFIX:<UUID>]".
        Ignored when -NoDescriptionTag is set.

    .PARAMETER ParameterFile
        Path to a YAML parameter file that can prepend/append text to the query
        and replace %%VARIABLE%% or %%VARIABLE:DEFAULT%% placeholders.

        The file may contain:
          PrependQuery: text added to the beginning of the query
          AppendQuery:  text added to the end of the query
          ReplaceQueryVariables: key-value pairs for placeholder substitution

    .PARAMETER Force
        Skip the change-detection check and always push the rule to the API.

    .PARAMETER WhatIf
        Shows what changes would be made without actually applying them.

    .PARAMETER Confirm
        Prompts for confirmation before creating or updating each rule.

    .EXAMPLE
        Deploy-CustomDetection -InputFile '.\input.yaml'

        Deploys the rule; appends "[<guid>]" to the description.

    .EXAMPLE
        Deploy-CustomDetection -InputFile '.\input.yaml' -DescriptionTagPrefix 'PREFIX'

        Deploys the rule; appends "[PREFIX:<guid>]" to the description.

    .EXAMPLE
        Deploy-CustomDetection -InputFile '.\input.yaml' -NoDescriptionTag -Disabled

        Deploys the rule in disabled mode without a description tag.

    .EXAMPLE
        Deploy-CustomDetection -InputFile '.\input.yaml' -Severity High -TitlePrefix '[PREFIX] '

        Deploys with severity override and a title prefix.

    .EXAMPLE
        Deploy-CustomDetection -InputFile '.\input.yaml' -ParameterFile '.\params.yaml'

        Deploys the rule and applies query transformations from the parameter file.

    .NOTES
        Requires the Microsoft.Graph.Authentication module and an active Graph API session.
        Use Connect-MgGraph before calling this function.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory, ValueFromPipeline, HelpMessage = 'Path to the input YAML or JSON file')]
        [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
        [string]$InputFile,

        [Parameter(HelpMessage = 'Override alert severity')]
        [ValidateSet('Informational', 'Low', 'Medium', 'High')]
        [string]$Severity,

        [Parameter(HelpMessage = 'String prepended to the rule display name')]
        [string]$TitlePrefix,

        [Parameter(HelpMessage = 'Deploy the rule in disabled mode')]
        [switch]$Disabled,

        [Parameter(HelpMessage = 'Do not append a UUID tag to the description')]
        [switch]$NoDescriptionTag,

        [Parameter(HelpMessage = 'Prefix inside the description tag, e.g. PREFIX produces [PREFIX:<UUID>]')]
        [string]$DescriptionTagPrefix,

        [Parameter(HelpMessage = 'Path to a YAML parameter file for query variable replacement')]
        [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
        [string]$ParameterFile,

        [Parameter(HelpMessage = 'Skip change-detection and always push')]
        [switch]$Force
    )

    begin {
        Assert-MgGraphConnection
        $baseUri = 'https://graph.microsoft.com/beta/security/rules/detectionRules'
    }

    process {
        try {
            # ── 1. Load the file ────────────────────────────────────────────
            $extension = [System.IO.Path]::GetExtension($InputFile).ToLowerInvariant()
            switch ($extension) {
                { $_ -in '.yaml', '.yml' } {
                    $yamlObj = Import-CustomDetectionYamlFile -FilePath $InputFile
                    $convertParams = @{ YamlObject = $yamlObj }
                    $jsonObj = ConvertFrom-CustomDetectionYamlToJson @convertParams
                }
                '.json' {
                    $jsonObj = Import-CustomDetectionJsonFile -FilePath $InputFile
                    # Ensure it's a mutable hashtable
                    if ($jsonObj -isnot [hashtable]) {
                        $jsonObj = $jsonObj | ConvertTo-Json -Depth 10 | ConvertFrom-Json -AsHashtable
                    }
                }
                default {
                    throw "Unsupported file extension '$extension'. Use .yaml, .yml, or .json."
                }
            }

            $detectorId = $jsonObj.detectorId
            if (-not $detectorId) {
                throw "The input file does not contain a detectorId (guid). Cannot deploy."
            }

            # ── 1b. Apply parameter file (prepend/append/replace variables) ──
            if ($PSBoundParameters.ContainsKey('ParameterFile')) {
                $originalQuery = $jsonObj.queryCondition.queryText
                $resolvedQuery = Resolve-QueryVariables -QueryText $originalQuery -ParameterFilePath $ParameterFile
                $jsonObj.queryCondition.queryText = $resolvedQuery
                Write-Verbose "Applied parameter file '$ParameterFile' to query."
            } else {
                # Check if the query contains %%VARIABLE%% placeholders without a parameter file
                $queryText = $jsonObj.queryCondition.queryText
                $placeholders = [regex]::Matches($queryText, '%%([^%:]+?)(?::([^%]*?))?%%')
                if ($placeholders.Count -gt 0) {
                    $withDefault = @()
                    $withoutDefault = @()
                    foreach ($ph in $placeholders) {
                        $varName = $ph.Groups[1].Value
                        if ($ph.Groups[2].Success) {
                            $withDefault += $varName
                        } else {
                            $withoutDefault += $varName
                        }
                    }
                    $withDefault = $withDefault | Select-Object -Unique
                    $withoutDefault = $withoutDefault | Select-Object -Unique

                    # Resolve defaults inline
                    if ($withDefault.Count -gt 0) {
                        $jsonObj.queryCondition.queryText = [regex]::Replace($queryText, '%%([^%:]+?):([^%]*?)%%', '$2')
                        $defaultNames = $withDefault -join ', '
                        Write-Information "Query placeholder(s) ($defaultNames) resolved to their default values because no -ParameterFile was specified."
                    }

                    # Warn for placeholders without defaults
                    if ($withoutDefault.Count -gt 0) {
                        $warnNames = $withoutDefault -join ', '
                        Write-Warning "Query contains variable placeholder(s) ($warnNames) without default values and no -ParameterFile was specified. These placeholders will not be replaced."
                    }
                }
            }

            # ── 2. Apply overrides ──────────────────────────────────────────
            if ($Disabled) {
                $jsonObj.isEnabled = $false
            }

            if ($PSBoundParameters.ContainsKey('Severity')) {
                $jsonObj.detectionAction.alertTemplate.severity = $Severity.ToLowerInvariant()
            }

            if ($PSBoundParameters.ContainsKey('TitlePrefix')) {
                $currentName = $jsonObj.displayName
                if (-not $currentName.StartsWith($TitlePrefix)) {
                    $jsonObj.displayName = "$TitlePrefix$currentName"
                }
                $currentTitle = $jsonObj.detectionAction.alertTemplate.title
                if ($currentTitle -and -not $currentTitle.StartsWith($TitlePrefix)) {
                    $jsonObj.detectionAction.alertTemplate.title = "$TitlePrefix$currentTitle"
                }
            }

            # ── 3. Build and apply description tag ──────────────────────────
            if (-not $NoDescriptionTag) {
                $tag = if ($PSBoundParameters.ContainsKey('DescriptionTagPrefix') -and $DescriptionTagPrefix) {
                    "[$DescriptionTagPrefix`:$detectorId]"
                } else {
                    "[$detectorId]"
                }

                $desc = $jsonObj.detectionAction.alertTemplate.description
                # Remove any existing tag pattern before appending
                $tagPattern = '\s*\[[^\]]*' + [regex]::Escape($detectorId) + '\]'
                if ($desc) {
                    $desc = [regex]::Replace($desc, $tagPattern, '').TrimEnd()
                    $jsonObj.detectionAction.alertTemplate.description = "$desc $tag"
                } else {
                    $jsonObj.detectionAction.alertTemplate.description = $tag
                }
            }

            # ── 4. Discover if rule already exists ──────────────────────────
            $existingRuleId = $null
            $existingRule = $null

            # Try by detectorId first (cached)
            $existingRuleId = Get-CustomDetectionIdByDetectorId -DetectorId $detectorId -ErrorAction SilentlyContinue

            # Fallback: scan all rules for UUID tag in description
            if (-not $existingRuleId) {
                Write-Verbose "DetectorId '$detectorId' not found by ID lookup. Scanning descriptions for UUID tag..."
                $existingRuleId = Get-CustomDetectionIdByDescriptionTag -DescriptionTag $detectorId
                if ($existingRuleId) {
                    Write-Verbose "Found matching detection by description tag: Rule Id '$existingRuleId'."
                }
            }

            # Fetch the full existing rule if we found one
            if ($existingRuleId) {
                $existingRule = Get-CustomDetection -DetectionId $existingRuleId
            }

            # ── 5. Flatten local rule for comparison ────────────────────────
            $localFlat = @{
                displayName = $jsonObj.displayName
                isEnabled   = $jsonObj.isEnabled
                queryText   = $jsonObj.queryCondition.queryText
                period      = [string]$jsonObj.schedule.period
                title       = $jsonObj.detectionAction.alertTemplate.title
                description = $jsonObj.detectionAction.alertTemplate.description
                severity    = $jsonObj.detectionAction.alertTemplate.severity
                category    = $jsonObj.detectionAction.alertTemplate.category
            }

            # ── 6. Create or update ────────────────────────────────────────
            $ruleName = $jsonObj.displayName

            if ($existingRule) {
                # Check for actual changes
                $hasChanges = Compare-CustomDetection -Local $localFlat -Remote $existingRule

                if (-not $hasChanges -and -not $Force) {
                    Write-Verbose "Rule '$ruleName' (Id: $existingRuleId) is up-to-date. Skipping update."
                    return [PSCustomObject]@{
                        Action     = 'Skipped'
                        RuleName   = $ruleName
                        RuleId     = $existingRuleId
                        DetectorId = $detectorId
                        Reason     = 'No changes detected'
                    }
                }

                # Update existing rule via PATCH
                if ($PSCmdlet.ShouldProcess("Rule '$ruleName' (Id: $existingRuleId)", 'Update detection rule')) {
                    $uri = "$baseUri/$existingRuleId"
                    Invoke-MgGraphRequestWithRetry -Method PATCH -Uri $uri -Body $jsonObj | Out-Null
                    Write-Verbose "Updated rule '$ruleName' (Id: $existingRuleId)."

                    [PSCustomObject]@{
                        Action     = 'Updated'
                        RuleName   = $ruleName
                        RuleId     = $existingRuleId
                        DetectorId = $detectorId
                    }
                }
            } else {
                # Create new rule via POST
                if ($PSCmdlet.ShouldProcess("Rule '$ruleName'", 'Create detection rule')) {
                    $response = Invoke-MgGraphRequestWithRetry -Method POST -Uri $baseUri -Body $jsonObj
                    $newId = $response.id
                    Write-Verbose "Created rule '$ruleName' (Id: $newId, DetectorId: $detectorId)."

                    [PSCustomObject]@{
                        Action     = 'Created'
                        RuleName   = $ruleName
                        RuleId     = $newId
                        DetectorId = $detectorId
                    }
                }
            }
        } catch {
            Write-Error "Error deploying detection rule from '$InputFile': $($_.Exception.Message)"
            throw
        }
    }
}
