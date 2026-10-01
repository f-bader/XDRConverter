function ConvertTo-CustomDetectionFrequency {
    <#
    .SYNOPSIS
        Normalises a rule frequency to the ISO 8601 form the API stores.

    .DESCRIPTION
        Accepts the legacy period tokens (0, 1H, 3H, 12H, 24H) and ISO 8601
        durations made of days, hours, minutes and seconds. The result is the
        canonical rendering the API returns, so PT1440M becomes P1D and PT90M
        becomes PT1H30M. Weeks, months and years are rejected, as the API does.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [AllowNull()]
        [object]$Value
    )

    $text = "$Value".Trim()
    if ([string]::IsNullOrEmpty($text)) {
        throw 'The rule frequency is required.'
    }

    $legacyMap = @{
        '0'   = 'PT0S'
        '1H'  = 'PT1H'
        '3H'  = 'PT3H'
        '12H' = 'PT12H'
        '24H' = 'P1D'
    }

    $key = $text.ToUpperInvariant()
    if ($legacyMap.ContainsKey($key)) {
        return $legacyMap[$key]
    }

    # Edm.Duration allows days and a time part only. XmlConvert renders the canonical form the API stores
    if ($key -match '^P(?=\d|T\d)(?:\d+D)?(?:T(?=\d)(?:\d+H)?(?:\d+M)?(?:\d+(?:\.\d+)?S)?)?$') {
        return [System.Xml.XmlConvert]::ToString([System.Xml.XmlConvert]::ToTimeSpan($key))
    }

    throw "Unsupported frequency '$text'. Use 0, 1H, 3H, 12H, 24H or an ISO 8601 duration of days, hours, minutes and seconds such as PT1H."
}
