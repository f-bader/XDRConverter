function Get-CustomDetectionIdentity {
    <#
    .SYNOPSIS
        Returns the stable identifier of a detection rule object.

    .DESCRIPTION
        Prefers the UUID from the description tag, then a UUID-shaped id, then
        whatever follows the rule prefix of the id, then the detector ID the API assigned.
        Returns $null when none is present.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [PSObject]$Rule
    )

    $uuidPattern = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'

    $description = $Rule.detectionAction.alertTemplate.description
    if ($description -and $description -match "\[(?:[^:\]]*:)?($uuidPattern)\]") {
        return $Matches[1]
    }

    $id = "$($Rule.id)"
    if ($id -match "^$uuidPattern$") {
        return $id
    }
    if ($id -match '^rule-(.+)$') {
        return $Matches[1]
    }

    $detectorId = "$($Rule.detectorId)"
    if ($detectorId) {
        return $detectorId
    }

    return $null
}
