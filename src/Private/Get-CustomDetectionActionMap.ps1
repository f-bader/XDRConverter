function Get-CustomDetectionActionMap {
    <#
    .SYNOPSIS
        Returns the table of supported automated actions.

    .DESCRIPTION
        Each entry links the YAML actionType to its automatedActions collection,
        the legacy responseAction type name and the default column mapping.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param()

    $deviceDefaults = [ordered]@{ deviceIdColumn = 'DeviceId' }
    # The API stores one hash column per file action, so only sha1Column is defaulted
    $fileDefaults = [ordered]@{ sha1Column = 'SHA1' }
    $sidDefaults = [ordered]@{ accountSidColumn = 'AccountSid' }
    $emailDefaults = [ordered]@{ networkMessageIdColumn = 'NetworkMessageId'; recipientColumn = 'RecipientEmailAddress' }

    # Fields lists the properties the Graph action type documents
    $deviceFields = @('deviceIdColumn')
    $fileFields = @('sha1Column', 'sha256Column', 'deviceGroupNames')
    $sidFields = @('accountSidColumn')
    $emailFields = @('networkMessageIdColumn', 'recipientColumn')

    return @(
        [PSCustomObject]@{ ActionType = 'IsolateMachine'; Collection = 'isolateDevices'; LegacyType = 'isolateDeviceResponseAction'; Defaults = [ordered]@{ deviceIdColumn = 'DeviceId'; isolationType = 'full' }; Fields = @('deviceIdColumn', 'isolationType') }
        [PSCustomObject]@{ ActionType = 'CollectInvestigationPackage'; Collection = 'collectInvestigationPackages'; LegacyType = 'collectInvestigationPackageResponseAction'; Defaults = $deviceDefaults; Fields = $deviceFields }
        [PSCustomObject]@{ ActionType = 'RunAntivirusScan'; Collection = 'runAntivirusScans'; LegacyType = 'runAntivirusScanResponseAction'; Defaults = $deviceDefaults; Fields = $deviceFields }
        [PSCustomObject]@{ ActionType = 'InitiateInvestigation'; Collection = 'initiateInvestigations'; LegacyType = 'initiateInvestigationResponseAction'; Defaults = $deviceDefaults; Fields = $deviceFields }
        [PSCustomObject]@{ ActionType = 'RestrictAppExecution'; Collection = 'restrictAppExecutions'; LegacyType = 'restrictAppExecutionResponseAction'; Defaults = $deviceDefaults; Fields = $deviceFields }
        [PSCustomObject]@{ ActionType = 'StopAndQuarantineFile'; Collection = 'stopAndQuarantineFiles'; LegacyType = 'stopAndQuarantineFileResponseAction'; Defaults = [ordered]@{ deviceIdColumn = 'DeviceId'; sha1Column = 'SHA1' }; Fields = @('deviceIdColumn', 'sha1Column') }
        [PSCustomObject]@{ ActionType = 'AllowFile'; Collection = 'allowFiles'; LegacyType = 'allowFileResponseAction'; Defaults = $fileDefaults; Fields = $fileFields }
        [PSCustomObject]@{ ActionType = 'BlockFile'; Collection = 'blockFiles'; LegacyType = 'blockFileResponseAction'; Defaults = $fileDefaults; Fields = $fileFields }
        [PSCustomObject]@{ ActionType = 'DisableUser'; Collection = 'disableUsers'; LegacyType = 'disableUserResponseAction'; Defaults = $sidDefaults; Fields = $sidFields }
        [PSCustomObject]@{ ActionType = 'ForceUserPasswordReset'; Collection = 'forceUserPasswordResets'; LegacyType = 'forceUserPasswordResetResponseAction'; Defaults = $sidDefaults; Fields = $sidFields }
        [PSCustomObject]@{ ActionType = 'MarkUserAsCompromised'; Collection = 'markUsersAsCompromised'; LegacyType = 'markUserAsCompromisedResponseAction'; Defaults = [ordered]@{ accountObjectIdColumn = 'AccountObjectId' }; Fields = @('accountObjectIdColumn') }
        [PSCustomObject]@{ ActionType = 'HardDeleteEmail'; Collection = 'hardDeleteEmails'; LegacyType = 'hardDeleteResponseAction'; Defaults = $emailDefaults; Fields = $emailFields }
        [PSCustomObject]@{ ActionType = 'SoftDeleteEmail'; Collection = 'softDeleteEmails'; LegacyType = 'softDeleteResponseAction'; Defaults = $emailDefaults; Fields = $emailFields }
        [PSCustomObject]@{ ActionType = 'MoveEmailToInbox'; Collection = 'moveEmailsToInbox'; LegacyType = 'moveToInboxResponseAction'; Defaults = $emailDefaults; Fields = $emailFields }
        [PSCustomObject]@{ ActionType = 'MoveEmailToJunk'; Collection = 'moveEmailsToJunk'; LegacyType = 'moveToJunkResponseAction'; Defaults = $emailDefaults; Fields = $emailFields }
        [PSCustomObject]@{ ActionType = 'MoveEmailToDeletedItems'; Collection = 'moveEmailsToDeletedItems'; LegacyType = 'moveToDeletedItemsResponseAction'; Defaults = $emailDefaults; Fields = $emailFields }
    )
}
