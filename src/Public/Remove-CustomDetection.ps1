function Remove-CustomDetection {
    <#
    .SYNOPSIS
        Deletes a custom detection rule from Microsoft Defender XDR.

    .DESCRIPTION
        Removes a detection rule via the Microsoft Graph API. The rule can be
        identified by its detection rule Id, its DetectorId (the GUID embedded
        in the YAML/JSON source), or by the DescriptionTag UUID that was
        appended to the alert description during deployment.

        Only one identification method may be used per call (parameter sets).

    .PARAMETER Id
        The detection rule ID as returned by the Graph API.

    .PARAMETER DetectorId
        The detector ID (GUID from the source file). Resolved to the rule ID
        via Get-CustomDetectionIdByDetectorId.

    .PARAMETER DescriptionTag
        The UUID tag embedded in the alert description. Resolved to the rule ID
        via Get-CustomDetectionIdByDescriptionTag.

    .EXAMPLE
        Remove-CustomDetection -Id "12345"

        Deletes the detection rule with the specified ID.

    .EXAMPLE
        Remove-CustomDetection -DetectorId "81fb771a-c57e-41b8-9905-63dbf267c13f"

        Looks up and deletes the detection rule that matches the given detector ID.

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
                    $ruleId = Get-CustomDetectionIdByDetectorId -DetectorId $DetectorId
                    if (-not $ruleId) {
                        Write-Error "No detection rule found with DetectorId: $DetectorId"
                        return
                    }
                }
                'ByDescriptionTag' {
                    $ruleId = Get-CustomDetectionIdByDescriptionTag -DescriptionTag $DescriptionTag
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
