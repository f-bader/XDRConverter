function Test-CustomDetectionListFailure {
    <#
    .SYNOPSIS
        Tells whether an error means the rule list did not answer.

    .DESCRIPTION
        True for the Graph client's request timeout, which arrives as a
        cancelled task or as a message naming the HttpClient timeout, and for
        the error the id list raises while it holds off after a timeout.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    $exception = $ErrorRecord.Exception
    while ($exception) {
        if ($exception -is [System.OperationCanceledException]) { return $true }
        if ($exception.Message -match 'HttpClient\.Timeout|rule list is unavailable') { return $true }
        $exception = $exception.InnerException
    }
    return $false
}
