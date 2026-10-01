function ConvertTo-CustomDetectionStatus {
    <#
    .SYNOPSIS
        Resolves the rule status from the status and isEnabled inputs.

    .DESCRIPTION
        The status value wins when both are supplied. A contradicting
        isEnabled value produces a warning. When neither is supplied the
        rule is enabled. The API rejects autoDisabled on write, so that
        value is sent as disabled with a warning.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [AllowNull()]
        [object]$IsEnabled,

        [Parameter()]
        [AllowNull()]
        [string]$Status
    )

    $validStatuses = @('enabled', 'disabled', 'autoDisabled')

    $enabledFromFlag = $null
    if ($null -ne $IsEnabled -and "$IsEnabled" -ne '') {
        if ($IsEnabled -is [bool]) {
            $enabledFromFlag = $IsEnabled
        } elseif ("$IsEnabled" -in @('true', 'false')) {
            $enabledFromFlag = ("$IsEnabled" -eq 'true')
        } else {
            throw "isEnabled '$IsEnabled' is not a boolean. Use true or false."
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($Status)) {
        $resolved = [string]($validStatuses | Where-Object { $_ -eq $Status.Trim() } | Select-Object -First 1)
        if (-not $resolved) {
            throw "Unsupported status '$Status'. Use enabled, disabled or autoDisabled."
        }

        if ($resolved -eq 'autoDisabled') {
            Write-Warning "Status 'autoDisabled' is read-only in the API. Sending 'disabled'."
            $resolved = 'disabled'
        }

        if ($null -ne $enabledFromFlag) {
            $flagStatus = if ($enabledFromFlag) { 'enabled' } else { 'disabled' }
            if ($flagStatus -ne $resolved) {
                Write-Warning "isEnabled '$IsEnabled' contradicts status '$resolved'. Using status."
            }
        }

        return $resolved
    }

    if ($null -eq $enabledFromFlag -or $enabledFromFlag) {
        return 'enabled'
    }

    return 'disabled'
}
