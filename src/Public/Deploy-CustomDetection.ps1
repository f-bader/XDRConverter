function Deploy-CustomDetection {
    <#
    .SYNOPSIS
        Creates or updates a Defender XDR custom detection rule from a YAML or JSON file.

    .DESCRIPTION
        Reads a detection rule from a YAML or JSON file, optionally overrides severity,
        title prefix, and enabled state, then deploys it to Microsoft Defender XDR via
        the Microsoft Graph API.

        By default the YAML/JSON guid is appended to the description as "[<UUID>]".
        Use -DescriptionTagPrefix to add a prefix (e.g. "[PREFIX:<UUID>]") or
        -NoDescriptionTag to suppress the tag entirely.

        New rules are sent with the id "rule-<guid>", and the guid also travels
        in the description tag. The API assigns an id when none is sent, whatever
        the reference says, and rejects one that starts with a digit. The function finds an existing rule through that id, through the
        tag, or, with -NoDescriptionTag, through the display name. When the rule
        list carries none of them it asks for "rule-<guid>" directly, since the
        list can lag behind a create or a delete. A found rule gets a
        PATCH (update) instead of a POST (create). Before
        updating it compares the local rule against the remote version and skips the
        call when nothing changed.

    .PARAMETER InputFile
        Path to the input YAML (.yaml/.yml) or JSON (.json) file.

    .PARAMETER Severity
        Override the alert severity. Valid values: Informational, Low, Medium, High.

    .PARAMETER TitlePrefix
        Optional string prepended to the displayName / alertTitle.
        Example: -TitlePrefix '[PREFIX] ' produces "[PREFIX] My Rule".

    .PARAMETER Disabled
        Deploy the rule with status = disabled regardless of the file value.

    .PARAMETER NoDescriptionTag
        When set, the "[<UUID>]" tag is NOT appended to the description. A rule
        that does not carry the rule-<guid> id is then matched by its display name alone.

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

    .PARAMETER SkipMitreTechniqueValidation
        Skip the pre-deployment check that verifies all listed MITRE ATT&CK techniques are supported
        by XDR for each tactic. Use this to deploy rules that include techniques not
        yet reflected in the local XDR technique mapping.

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

    .EXAMPLE
        Deploy-CustomDetection -InputFile '.\input.yaml' -SkipMitreTechniqueValidation

        Deploys the rule without validating the MITRE techniques against the XDR category mapping.

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
        [switch]$Force,

        [Parameter(HelpMessage = 'Allow identifiers not listed in the official documentation (emits a warning instead of throwing)')]
        [switch]$SkipIdentifierValidation,

        [Parameter(HelpMessage = 'Skip the MITRE ATT&CK technique validation against the XDR category mapping')]
        [switch]$SkipMitreTechniqueValidation
    )

    begin {
        Assert-MgGraphConnection
        $baseUri = 'https://graph.microsoft.com/beta/security/rules/detectionRules'
    }

    process {
        try {
            #region Load the file
            $extension = [System.IO.Path]::GetExtension($InputFile).ToLowerInvariant()
            $yamlObj = switch ($extension) {
                { $_ -in '.yaml', '.yml' } {
                    Import-CustomDetectionYamlFile -FilePath $InputFile
                }
                '.json' {
                    # Normalise JSON input through the YAML shape so legacy files deploy with the current body
                    $rawJson = Import-CustomDetectionJsonFile -FilePath $InputFile
                    ConvertFrom-CustomDetectionJsonToYaml -JsonObject $rawJson -ValidateIdentifiers:(-not $SkipIdentifierValidation)
                }
                default {
                    throw "Unsupported file extension '$extension'. Use .yaml, .yml, or .json."
                }
            }

            $convertParams = @{ YamlObject = $yamlObj }
            if ($SkipIdentifierValidation) {
                $convertParams['SkipIdentifierValidation'] = $true
            }
            $jsonObj = ConvertFrom-CustomDetectionYamlToJson @convertParams

            # The body carries the client id rule-<guid>. The bare guid is the tag and the lookup key
            $detectorId = "$($jsonObj.id)" -replace '^rule-', ''
            if (-not $detectorId) {
                throw "The input file does not contain a guid. Cannot deploy."
            }
            #endregion

            #region Apply parameter file
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
            #endregion

            #region Validate MITRE technique coverage
            if (-not $SkipMitreTechniqueValidation) {
                # YAML input is validated as written, so a listed parent counts and a derived one does not. JSON input is normalised first, so its derived parents are validated too
                $mitreResult = Test-CustomDetectionMitreTechnique -InputObject $yamlObj
                if (-not $mitreResult.IsValid) {
                    $invalidList = $mitreResult.InvalidTechniques -join ', '
                    throw "MITRE technique(s) not supported by XDR for category '$($mitreResult.Category)': $invalidList. Use -SkipMitreTechniqueValidation to bypass this check."
                }
            }
            #endregion

            #region Apply overrides
            if ($Disabled) {
                $jsonObj.status = 'disabled'
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
            #endregion

            #region Build and apply description tag
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
            #endregion

            #region Discover existing rule
            $existingRule = $null
            $existingRuleId = $null
            $listUnavailable = $false

            # The three lookups read the rule list. When it does not answer, the client id is the only lookup left
            try {
                # Try by rule id first (cached)
                $existingRuleId = Get-CustomDetectionIdByDetectorId -DetectorId $detectorId -ErrorAction SilentlyContinue

                # Fallback: scan all rules for UUID tag in description
                if (-not $existingRuleId) {
                    Write-Verbose "Guid '$detectorId' not found by ID lookup. Scanning descriptions for UUID tag..."
                    $existingRuleId = Get-CustomDetectionIdByDescriptionTag -DescriptionTag $detectorId -WarningAction SilentlyContinue
                    if ($existingRuleId) {
                        Write-Verbose "Found matching detection by description tag: Rule Id '$existingRuleId'."
                    } else {
                        Write-Verbose "No existing rule carries the tag '$detectorId'."
                    }
                }

                # A rule without the client id and without a tag can only be matched by name. The API keeps names unique
                if (-not $existingRuleId -and $NoDescriptionTag) {
                    $byName = Get-CustomDetectionIds | Where-Object { $_.DisplayName -eq $jsonObj.displayName } | Select-Object -First 1
                    if ($byName) {
                        $existingRuleId = $byName.Id
                        Write-Warning "Rule '$($jsonObj.displayName)' was matched by its display name alone. Without the tag a renamed file creates a new rule and leaves this one behind."
                    }
                }
            } catch {
                if (-not (Test-CustomDetectionListFailure -ErrorRecord $_)) { throw }
                $listUnavailable = $true
                Write-Warning "The rule list did not answer. Rule '$($jsonObj.displayName)' is looked up by its client id only."
            }
            # The list can lag behind a create or a delete, so the client id is asked for directly before a create
            if (-not $existingRuleId) {
                $byId = Get-CustomDetectionByClientId -Guid $detectorId
                if ($byId) {
                    $existingRuleId = $byId.id
                    $existingRule = $byId
                    Write-Verbose "Found the rule through its client id '$existingRuleId', which the list did not carry."
                }
            }

            if (-not $existingRuleId -and $listUnavailable) {
                throw "The rule list is unavailable and rule '$($jsonObj.displayName)' was not found by its client id. Nothing was created."
            }
            if (-not $existingRuleId) {
                Write-Verbose "The rule will be created."
            }

            # Fetch the full existing rule if we found one
            if ($existingRuleId -and -not $existingRule) {
                $existingRule = Get-CustomDetection -DetectionId $existingRuleId
            }
            #endregion

            #region Create or update
            $ruleName = $jsonObj.displayName

            if ($existingRule) {
                # Check for actual changes
                $hasChanges = Compare-CustomDetection -Local $jsonObj -Remote $existingRule

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
                    $patchBody = Complete-CustomDetectionPatchBody -Body $jsonObj -Remote $existingRule
                    Invoke-MgGraphRequestWithRetry -Method PATCH -Uri $uri -Body $patchBody | Out-Null
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
                    # The API assigns an id when none is sent and rejects one that starts with a digit, hence the prefixed client id in the body
                    $response = Invoke-MgGraphRequestWithRetry -Method POST -Uri $baseUri -Body $jsonObj
                    $newId = $response.id
                    # The created rule joins the cached list, so the next rule does not ask the list again
                    $created = [ordered]@{ id = $newId; detectorId = $response.detectorId; displayName = $jsonObj.displayName; detectionAction = $jsonObj.detectionAction }
                    Add-CustomDetectionIdsCacheEntry -Entry (ConvertTo-CustomDetectionIdEntry -Rule $created)
                    Write-Verbose "Created rule '$ruleName' (Id: $newId, Guid: $detectorId)."

                    [PSCustomObject]@{
                        Action     = 'Created'
                        RuleName   = $ruleName
                        RuleId     = $newId
                        DetectorId = $detectorId
                    }
                }
            }
            #endregion
        }
        catch [Microsoft.Graph.PowerShell.Authentication.Helpers.HttpResponseException] {
            $exMsg = $_.Exception.Message

            if ($_.ErrorDetails.Message -and $_.ErrorDetails.Message -match '(\{.+\})\s*$') {
                try {
                    $errorBody = $Matches[1] | ConvertFrom-Json
                    if ($errorBody.error.message) {
                        $exMsg = $exMsg -replace '\(([^)]+)\)\.?\s*$', "($($errorBody.error.message))"
                    }
                }
                catch {
                    # JSON parsing failed; keep original message
                }
            }

            Write-Error "Error deploying detection rule from '$InputFile': $exMsg"
            Write-Debug "$(($jsonObj | ConvertTo-Json -Depth 10))"
            throw
        }
        catch {
            Write-Error "Unexpected error deploying detection rule from '$InputFile': $_"
            Write-Debug "$(($jsonObj | ConvertTo-Json -Depth 10))"
            throw
        }
    }
}