function Get-CustomDetectionLegacyIdentifierMap {
    <#
    .SYNOPSIS
        Returns the legacy impactedEntities identifiers per entity mapping column.

    .DESCRIPTION
        Keyed by entity mapping collection, then by column. Each value lists the
        legacy entityIdentifier names that map to that column.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    return @{
        hosts     = @{
            deviceIdColumn = @('deviceId')
            nameColumn     = @('deviceName', 'remoteDeviceName', 'targetDeviceName', 'destinationDeviceName')
        }
        accounts  = @{
            aadUserIdColumn = @('accountObjectId', 'recipientObjectId', 'processAccountObjectId', 'initiatingProcessAccountObjectId', 'servicePrincipalId')
            sidColumn       = @('accountSid', 'requestAccountSid', 'initiatingAccountSid', 'initiatingProcessAccountSid')
            upnColumn       = @('accountUpn', 'initiatingProcessAccountUpn', 'targetAccountUpn')
            nameColumn      = @('accountName', 'requestAccountName', 'initiatingAccountName', 'servicePrincipalName', 'accountId')
            ntDomainColumn  = @('accountDomain', 'requestAccountDomain', 'initiatingAccountDomain')
        }
        mailboxes = @{
            primaryAddressColumn = @('accountUpn', 'fileOwnerUpn', 'initiatingProcessAccountUpn', 'lastModifyingAccountUpn', 'targetAccountUpn', 'senderFromAddress', 'senderDisplayName', 'recipientEmailAddress', 'senderMailFromAddress')
        }
    }
}
