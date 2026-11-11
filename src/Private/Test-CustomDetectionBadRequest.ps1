function Test-CustomDetectionBadRequest {
    <#
    .SYNOPSIS
        Tells whether an error means the API answered BadRequest.

    .DESCRIPTION
        True when the response carries status 400, or when the message names
        BadRequest, which is how the Graph client reports it.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    $statusCode = if ($ErrorRecord.Exception.Response) { [int]$ErrorRecord.Exception.Response.StatusCode } else { 0 }
    return ($statusCode -eq 400 -or $ErrorRecord.Exception.Message -match 'BadRequest|Bad Request')
}
