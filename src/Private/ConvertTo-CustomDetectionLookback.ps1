function ConvertTo-CustomDetectionLookback {
    <#
    .SYNOPSIS
        Normalises a rule lookback to the ISO 8601 form the API stores.

    .DESCRIPTION
        Accepts the ISO 8601 durations the frequency accepts and renders them
        the same way, so PT240M becomes PT4H. The legacy frequency tokens have
        no lookback meaning and are rejected.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [AllowNull()]
        [object]$Value
    )

    $text = "$Value".Trim()
    $message = "Unsupported lookback '$text'. Use an ISO 8601 duration of days, hours, minutes and seconds such as PT4H or P2D."
    if ($text -notmatch '^[Pp]') {
        throw $message
    }
    try {
        return ConvertTo-CustomDetectionFrequency -Value $text
    } catch {
        throw $message
    }
}
