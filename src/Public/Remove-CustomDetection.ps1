function Remove-CustomDetection {
    <#
    .SYNOPSIS
        Deletes a custom detection rule from Microsoft Defender XDR.

    .DESCRIPTION
        Removes a detection rule via the Microsoft Graph API. The rule can be
        identified by its detection rule Id, by the guid from the source file
        (matched against the rule Id and then the description tag), or by the
        DescriptionTag UUID that was appended to the alert description during
        deployment.

        Only one identification method may be used per call (parameter sets).

    .PARAMETER Id
        The detection rule ID as returned by the Graph API.

    .PARAMETER DetectorId
        The guid from the source file. Resolved to the rule ID via
        Get-CustomDetectionIdByDetectorId, which matches the rule ID with or
        without the rule prefix, the detector ID the API assigned and then the
        description tag. When the list does not carry the rule or does not
        answer, the client id rule-<guid> is asked for directly.

    .PARAMETER DescriptionTag
        The UUID tag embedded in the alert description. Resolved to the rule ID
        via Get-CustomDetectionIdByDescriptionTag.

    .EXAMPLE
        Remove-CustomDetection -Id "12345"

        Deletes the detection rule with the specified ID.

    .EXAMPLE
        Remove-CustomDetection -DetectorId "81fb771a-c57e-41b8-9905-63dbf267c13f"

        Looks up and deletes the detection rule the guid names.

    .EXAMPLE
        Remove-CustomDetection -DescriptionTag "81fb771a-c57e-41b8-9905-63dbf267c13f"

        Looks up and deletes the detection rule whose description contains the specified UUID tag.

    .NOTES
        Requires the Microsoft.Graph.Authentication module and an active Graph API session.
        Use Connect-MgGraph before calling this function.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = 'ById')]
        [ValidateNotNullOrEmpty()]
        [string]$Id,

        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = 'ByDetectorId')]
        [ValidateNotNullOrEmpty()]
        [string]$DetectorId,

        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = 'ByDescriptionTag')]
        [ValidateNotNullOrEmpty()]
        [string]$DescriptionTag
    )

    begin {
        Assert-MgGraphConnection
        $baseUri = 'https://graph.microsoft.com/beta/security/rules/detectionRules'
    }

    process {
        try {
            #region Resolve the detection rule ID
            $ruleId = $null

            switch ($PSCmdlet.ParameterSetName) {
                'ById' {
                    $ruleId = $Id
                }
                'ByDetectorId' {
                    # The list can omit a rule for a long time after a delete and recreate, and it holds off after a timeout. The client id answers in both cases
                    try {
                        $ruleId = Get-CustomDetectionIdByDetectorId -DetectorId $DetectorId -ErrorAction SilentlyContinue
                    } catch {
                        if (-not (Test-CustomDetectionListFailure -ErrorRecord $_)) { throw }
                        Write-Warning "The rule list did not answer. The rule is looked up by its client id only."
                    }
                    if (-not $ruleId) {
                        $ruleId = (Get-CustomDetectionByClientId -Guid $DetectorId).id
                    }
                    if (-not $ruleId) {
                        Write-Error "No detection rule found with DetectorId: $DetectorId"
                        return
                    }
                }
                'ByDescriptionTag' {
                    try {
                        $ruleId = Get-CustomDetectionIdByDescriptionTag -DescriptionTag $DescriptionTag -ErrorAction SilentlyContinue
                    } catch {
                        if (-not (Test-CustomDetectionListFailure -ErrorRecord $_)) { throw }
                        Write-Warning "The rule list did not answer. The rule is looked up by its client id only."
                    }
                    if (-not $ruleId) {
                        $ruleId = (Get-CustomDetectionByClientId -Guid $DescriptionTag).id
                    }
                    if (-not $ruleId) {
                        Write-Error "No detection rule found with DescriptionTag: $DescriptionTag"
                        return
                    }
                }
            }
            #endregion

            #region Fetch the rule to get its display name for confirmation
            $rule = Get-CustomDetection -DetectionId $ruleId
            if (-not $rule) {
                Write-Error "Detection rule with Id '$ruleId' not found."
                return
            }

            $ruleName = $rule.displayName
            #endregion

            #region Delete the rule
            if ($PSCmdlet.ShouldProcess("Rule '$ruleName' (Id: $ruleId)", 'Delete detection rule')) {
                $uri = "$baseUri/$ruleId"
                Invoke-MgGraphRequestWithRetry -Method DELETE -Uri $uri | Out-Null
                Clear-CustomDetectionIdsCacheEntry -Id $ruleId
                Write-Verbose "Deleted rule '$ruleName' (Id: $ruleId)."

                [PSCustomObject]@{
                    Action   = 'Deleted'
                    RuleName = $ruleName
                    RuleId   = $ruleId
                }
            }
            #endregion
        } catch {
            Write-Error "Error deleting detection rule: $($_.Exception.Message)"
            throw
        }
    }
}
