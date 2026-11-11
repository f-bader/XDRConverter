function Test-CustomDetectionNotFound {
    <#
    .SYNOPSIS
        Tells whether an error means the API answered NotFound.

    .DESCRIPTION
        True when the response carries status 404, or when the message names
        NotFound or 404, which is how the Graph client reports it.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    $statusCode = if ($ErrorRecord.Exception.Response) { [int]$ErrorRecord.Exception.Response.StatusCode } else { 0 }
    return ($statusCode -eq 404 -or $ErrorRecord.Exception.Message -match 'NotFound|\b404\b')
}
