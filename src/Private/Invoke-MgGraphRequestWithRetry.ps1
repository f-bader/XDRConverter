function Invoke-MgGraphRequestWithRetry {
    <#
    .SYNOPSIS
        Wraps Invoke-MgGraphRequest with automatic retry on HTTP 429 (Too Many Requests).

    .DESCRIPTION
        Calls Invoke-MgGraphRequest and retries up to MaxRetries times when a 429
        throttling response is received. Uses the Retry-After header value when
        available, falling back to exponential back-off (2^attempt seconds).

    .PARAMETER Method
        The HTTP method (GET, POST, PATCH, DELETE, etc.).

    .PARAMETER Uri
        The Graph API URI to call.

    .PARAMETER Body
        Optional request body (for POST/PATCH).

    .PARAMETER MaxRetries
        Maximum number of retry attempts on 429 responses. Defaults to 3.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('GET', 'POST', 'PUT', 'PATCH', 'DELETE')]
        [string]$Method,

        [Parameter(Mandatory)]
        [string]$Uri,

        [Parameter()]
        [object]$Body,

        [Parameter()]
        [ValidateRange(0, 10)]
        [int]$MaxRetries = 3
    )

    $attempt = 0
    while ($true) {
        try {
            $params = @{
                Method = $Method
                Uri    = $Uri
            }
            if ($PSBoundParameters.ContainsKey('Body')) {
                $params['Body'] = $Body
            }
            return Invoke-MgGraphRequest @params
        } catch {
            $statusCode = $null

            # Extract HTTP status code from the exception
            if ($_.Exception.Response) {
                $statusCode = [int]$_.Exception.Response.StatusCode
            } elseif ($_.Exception.Message -match '\b429\b') {
                $statusCode = 429
            }

            if ($statusCode -eq 429 -and $attempt -lt $MaxRetries) {
                $attempt++

                # Use Retry-After header if available, otherwise exponential back-off
                $retryAfterSeconds = [math]::Pow(2, $attempt)
                if ($_.Exception.Response.Headers) {
                    try {
                        $retryHeader = $_.Exception.Response.Headers |
                            Where-Object { $_.Key -eq 'Retry-After' } |
                            Select-Object -ExpandProperty Value -First 1
                        if ($retryHeader) {
                            $retryAfterSeconds = [int]$retryHeader
                        }
                    } catch {
                        # Ignore header parsing errors; use default back-off
                    }
                }

                Write-Warning "Request throttled (HTTP 429). Retrying in $retryAfterSeconds seconds (attempt $attempt of $MaxRetries)..."
                Start-Sleep -Seconds $retryAfterSeconds
            } else {
                # Not a 429 or retries exhausted — re-throw
                throw
            }
        }
    }
}
