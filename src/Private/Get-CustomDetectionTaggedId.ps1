function Get-CustomDetectionTaggedId {
    <#
    .SYNOPSIS
        Returns the id of the rule whose description tag carries the guid.

    .DESCRIPTION
        One tag on two rules is a tenant defect, so the first rule wins and
        every match is named in a warning. Returns null when no rule carries
        the tag, which is the normal case for a rule that does not exist yet.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Rule,

        [Parameter(Mandatory)]
        [string]$DescriptionTag
    )

    $tagged = @($Rule | Where-Object { $_.DescriptionTag -eq $DescriptionTag })
    if ($tagged.Count -eq 0) {
        return $null
    }
    if ($tagged.Count -gt 1) {
        Write-Warning "Description tag '$DescriptionTag' is carried by $($tagged.Count) rules ($(($tagged | ForEach-Object { $_.Id }) -join ', ')). The first one is used."
    }
    return [string]$tagged[0].Id
}
