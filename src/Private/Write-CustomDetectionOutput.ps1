function Write-CustomDetectionOutput {
    <#
    .SYNOPSIS
        Writes content to a file or stdout.

    .DESCRIPTION
        Writes content to the specified file or outputs to stdout if no file is specified.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$Content,

        [Parameter()]
        [string]$OutputFile
    )

    if ($OutputFile) {
        if ($PSCmdlet.ShouldProcess($OutputFile, 'Write detection rule output')) {
            Set-Content -Path $OutputFile -Value $Content -Encoding utf8NoBOM -NoNewline
            Write-Verbose "Output written to: $OutputFile"
        }
    } else {
        Write-Output $Content
    }
}

