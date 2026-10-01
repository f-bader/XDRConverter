function ConvertTo-CustomDetectionIdEntry {
    <#
    .SYNOPSIS
        Builds the id list entry of a rule.

    .DESCRIPTION
        Reads the rule id, the detector id the API assigned, the display name
        and the description tag with its prefix. The id list and its cache
        carry entries in this shape.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [object]$Rule
    )

    $uuidPattern = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
    $tagPattern = "\[(?:([^:\]]+):)?($uuidPattern)\]"
    $descriptionTag = $null
    $tagPrefix = $null
    $description = Get-CustomDetectionValue -Object $Rule -Path 'detectionAction.alertTemplate.description'
    if ($description -and "$description" -match $tagPattern) {
        $tagPrefix = $Matches[1]
        $descriptionTag = $Matches[2]
    }

    [PSCustomObject]@{
        Id             = Get-CustomDetectionValue -Object $Rule -Path 'id'
        DetectorId     = Get-CustomDetectionValue -Object $Rule -Path 'detectorId'
        DisplayName    = Get-CustomDetectionValue -Object $Rule -Path 'displayName'
        DescriptionTag = $descriptionTag
        TagPrefix      = $tagPrefix
    }
}
