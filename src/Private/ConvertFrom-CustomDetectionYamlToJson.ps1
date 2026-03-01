function ConvertFrom-CustomDetectionYamlToJson {
    <#
    .SYNOPSIS
        Converts YAML content to JSON following the Defender XDR schema.

    .DESCRIPTION
        Performs the mapping from YAML properties to JSON properties according to
        the Microsoft Defender XDR custom detection JSON schema.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSObject]$YamlObject,

        [Parameter()]
        [bool]$SetEnabled,

        [Parameter()]
        [ValidateSet('Informational', 'Low', 'Medium', 'High')]
        [string]$SetSeverity
    )

    # Start building the JSON object
    $jsonObj = @{
        detectionAction = @{
            alertTemplate       = @{}
            organizationalScope = $null
            responseActions     = @()
        }
        detectorId      = $YamlObject.guid
        displayName     = $YamlObject.ruleName
        isEnabled       = if ($PSBoundParameters.ContainsKey('SetEnabled')) { $SetEnabled } else { $YamlObject.isEnabled }
        queryCondition  = @{
            queryText = $YamlObject.queryText
        }
        schedule        = @{
            period = [string]$YamlObject.frequency
        }
    }

    # Map alertTemplate properties
    $jsonObj.detectionAction.alertTemplate.title = $YamlObject.alertTitle
    $jsonObj.detectionAction.alertTemplate.description = $YamlObject.alertDescription
    $jsonObj.detectionAction.alertTemplate.category = $YamlObject.alertCategory
    $jsonObj.detectionAction.alertTemplate.severity = if ($SetSeverity) { $SetSeverity.ToLower() } else { $YamlObject.alertSeverity.ToLower() }
    $jsonObj.detectionAction.alertTemplate.recommendedActions = $YamlObject.alertRecommendedAction

    # Map MITRE techniques
    if ($YamlObject.mitreTechniques) {
        $jsonObj.detectionAction.alertTemplate.mitreTechniques = $YamlObject.mitreTechniques
    }

    # Map impacted entities to impactedAssets
    if ($YamlObject.impactedEntities) {
        # Define valid identifiers for each asset type
        # https://learn.microsoft.com/en-us/graph/api/resources/security-impactedasset?view=graph-rest-beta
        $validIdentifiers = @{
            'Device'  = @(
                'deviceId', 'deviceName', 'remoteDeviceName', 'targetDeviceName', 'destinationDeviceName'
            )
            'User'    = @(
                'accountObjectId', 'accountSid', 'accountUpn', 'accountName', 'accountDomain',
                'accountId', 'requestAccountSid', 'requestAccountName', 'requestAccountDomain',
                'recipientObjectId', 'processAccountObjectId', 'initiatingAccountSid',
                'initiatingProcessAccountUpn', 'initiatingAccountName', 'initiatingAccountDomain',
                'servicePrincipalId', 'servicePrincipalName', 'targetAccountUpn',
                'initiatingProcessAccountObjectId', 'initiatingProcessAccountSid'
            )
            'Mailbox' = @(
                'accountUpn', 'fileOwnerUpn', 'initiatingProcessAccountUpn', 'lastModifyingAccountUpn',
                'targetAccountUpn', 'senderFromAddress', 'senderDisplayName', 'recipientEmailAddress',
                'senderMailFromAddress'
            )
        }

        $impactedAssets = [System.Collections.Generic.List[hashtable]]::new()
        foreach ($entity in $YamlObject.impactedEntities) {
            # Map Machine to Device for Microsoft Graph API compliance
            $odataEntityType = if ($entity.entityType -eq 'Machine') { 'Device' } else { $entity.entityType }

            # Convert first letter to lowercase for Graph API compliance
            $identifier = if ($entity.entityIdentifier.Length -gt 0) {
                $entity.entityIdentifier.Substring(0, 1).ToLower() + $entity.entityIdentifier.Substring(1)
            } else {
                $entity.entityIdentifier
            }

            # Validate identifier for the entity type
            if ($validIdentifiers.ContainsKey($odataEntityType)) {
                if ($identifier -notin $validIdentifiers[$odataEntityType]) {
                    $validList = $validIdentifiers[$odataEntityType] -join ', '
                    throw "Invalid identifier '$identifier' for entity type '$odataEntityType'. Valid identifiers are: $validList"
                }
            }

            $impactedAssets.Add(@{
                    '@odata.type' = "#microsoft.graph.security.impacted$($odataEntityType)Asset"
                    identifier    = $identifier
                })
        }
        $jsonObj.detectionAction.alertTemplate.impactedAssets = $impactedAssets
    }

    # Map organizational scope
    if ($YamlObject.organizationalScope) {
        $jsonObj.detectionAction.organizationalScope = $YamlObject.organizationalScope
    }

    # Map response actions
    if ($YamlObject.actions) {
        $jsonObj.detectionAction.responseActions = $YamlObject.actions
    }

    return $jsonObj
}

