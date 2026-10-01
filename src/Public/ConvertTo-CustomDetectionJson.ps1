function ConvertTo-CustomDetectionJson {
    <#
    .SYNOPSIS
        Converts a YAML Defender XDR detection file to JSON format.

    .DESCRIPTION
        Reads a YAML file containing a Defender XDR custom detection rule
        and converts it to JSON format following the Microsoft Defender XDR schema.
        Optionally modifies the enabled status and severity properties.

    .PARAMETER InputFile
        The path to the input YAML file.

    .PARAMETER InputObject
        A detection rule object to serialize, as returned by Get-CustomDetection.
        Accepts pipeline input. The rule is written as the API returned it, so an
        export keeps every property the API sends. The request body shape is
        produced by the file input path.

    .PARAMETER OutputFile
        Optional. The path to the output JSON file. If not specified, output is written to stdout.
        Cannot be combined with -UseDisplayNameAsFilename or -UseIdAsFilename.

    .PARAMETER UseDisplayNameAsFilename
        Use the rule's display name as the output filename (with .json extension).
        The file is written to -OutputFolder (or the user's temp directory if not specified).
        Cannot be combined with -OutputFile or -UseIdAsFilename.

    .PARAMETER UseIdAsFilename
        Use the rule's guid as the output filename (with .json extension). The guid is
        taken from the description tag, then from a UUID-shaped rule id, then from the
        detector ID the API assigned.
        The file is written to -OutputFolder (or the user's temp directory if not specified).
        Cannot be combined with -OutputFile or -UseDisplayNameAsFilename.

    .PARAMETER OutputFolder
        The folder to write the output file to when using -UseDisplayNameAsFilename or -UseIdAsFilename.
        Defaults to the user's temp directory ([System.IO.Path]::GetTempPath()).

    .PARAMETER Enabled
        Optional. Set the rule status to enabled (true) or disabled (false).

    .PARAMETER Severity
        Optional. Override the alert severity. Valid values: Informational, Low, Medium, High.

    .EXAMPLE
        ConvertTo-CustomDetectionJson -InputFile '.\input.yaml' -OutputFile '.\output.json'

    .EXAMPLE
        Get-CustomDetection | ConvertTo-CustomDetectionJson

    .EXAMPLE
        ConvertTo-CustomDetectionJson -InputFile '.\input.yaml' -Severity High

    .EXAMPLE
        ConvertTo-CustomDetectionJson -InputFile '.\input.yaml' -Enabled $false | ConvertFrom-Json

    .EXAMPLE
        Get-CustomDetection | ConvertTo-CustomDetectionJson -UseDisplayNameAsFilename -OutputFolder 'C:\Detections'

        Writes each rule to a JSON file named after its display name in C:\Detections.

    .EXAMPLE
        Get-CustomDetection | ConvertTo-CustomDetectionJson -UseIdAsFilename

        Writes each rule to a JSON file named after its guid in the user's temp directory.
    #>
    [CmdletBinding(DefaultParameterSetName = 'File')]
    [OutputType([string])]
    param(
        [Parameter(Mandatory, ParameterSetName = 'File', HelpMessage = 'Path to the input YAML file')]
        [ValidateScript({ Test-Path $_ })]
        [string]$InputFile,

        [Parameter(Mandatory, ParameterSetName = 'Object', ValueFromPipeline, HelpMessage = 'JSON detection rule object')]
        [Parameter(Mandatory, ParameterSetName = 'ObjectByDisplayName', ValueFromPipeline, HelpMessage = 'JSON detection rule object')]
        [Parameter(Mandatory, ParameterSetName = 'ObjectById', ValueFromPipeline, HelpMessage = 'JSON detection rule object')]
        [ValidateNotNull()]
        [PSObject]$InputObject,

        [Parameter(HelpMessage = 'Path to the output JSON file (optional, outputs to stdout if not specified)', ParameterSetName = 'File')]
        [Parameter(HelpMessage = 'Path to the output JSON file (optional, outputs to stdout if not specified)', ParameterSetName = 'Object')]
        [string]$OutputFile,

        [Parameter(Mandatory, ParameterSetName = 'ObjectByDisplayName', HelpMessage = 'Use the display name as the output filename')]
        [switch]$UseDisplayNameAsFilename,

        [Parameter(Mandatory, ParameterSetName = 'ObjectById', HelpMessage = 'Use the guid as the output filename')]
        [switch]$UseIdAsFilename,

        [Parameter(ParameterSetName = 'ObjectByDisplayName', HelpMessage = 'Folder to write the output file to')]
        [Parameter(ParameterSetName = 'ObjectById', HelpMessage = 'Folder to write the output file to')]
        [string]$OutputFolder,

        [Parameter(HelpMessage = 'Set the enabled status of the rule')]
        [bool]$Enabled,

        [Parameter(HelpMessage = 'Set the severity level (Informational, Low, Medium, High)')]
        [ValidateSet('Informational', 'Low', 'Medium', 'High')]
        [string]$Severity,

        [Parameter(HelpMessage = 'Allow identifiers not listed in the official documentation (emits a warning instead of throwing)')]
        [switch]$SkipIdentifierValidation
    )

    process {
        try {
            $jsonObj = $null
            if ($PSCmdlet.ParameterSetName -eq 'File') {
                # Read YAML file
                $yamlObj = Import-CustomDetectionYamlFile -FilePath $InputFile

                # Prepare parameters for conversion
                $convertParams = @{
                    YamlObject = $yamlObj
                }

                if ($PSBoundParameters.ContainsKey('Enabled')) {
                    $convertParams['SetEnabled'] = $Enabled
                }

                if ($PSBoundParameters.ContainsKey('Severity')) {
                    $convertParams['SetSeverity'] = $Severity
                }

                if ($SkipIdentifierValidation) {
                    $convertParams['SkipIdentifierValidation'] = $true
                }

                # Convert to JSON object
                $jsonObj = ConvertFrom-CustomDetectionYamlToJson @convertParams
            } else {
                $jsonObj = $InputObject

                if ($PSBoundParameters.ContainsKey('Enabled')) {
                    $newStatus = ConvertTo-CustomDetectionStatus -IsEnabled $Enabled
                    if ($jsonObj -is [System.Collections.IDictionary]) {
                        $jsonObj['status'] = $newStatus
                        if ($jsonObj.Contains('isEnabled')) { $jsonObj['isEnabled'] = $Enabled }
                    } else {
                        $jsonObj | Add-Member -NotePropertyName 'status' -NotePropertyValue $newStatus -Force
                        if ($jsonObj.PSObject.Properties['isEnabled']) { $jsonObj.isEnabled = $Enabled }
                    }
                }

                if ($PSBoundParameters.ContainsKey('Severity')) {
                    if (-not $jsonObj.detectionAction) {
                        $jsonObj.detectionAction = @{}
                    }

                    if (-not $jsonObj.detectionAction.alertTemplate) {
                        $jsonObj.detectionAction.alertTemplate = @{}
                    }

                    $jsonObj.detectionAction.alertTemplate.severity = $Severity.ToLowerInvariant()
                }
            }

            # Determine output file path when using naming switches
            if ($UseDisplayNameAsFilename -or $UseIdAsFilename) {
                $OutputFile = Resolve-CustomDetectionOutputFile -Rule $jsonObj -Extension '.json' -OutputFolder $OutputFolder -UseDisplayName:$UseDisplayNameAsFilename
            }

            # Convert to JSON string with proper formatting
            $jsonString = $jsonObj | ConvertTo-Json -Depth 10

            # Output to file or stdout
            Write-CustomDetectionOutput -Content $jsonString -OutputFile $OutputFile
        } catch {
            Write-Error "Error converting YAML to JSON: $_"
            throw
        }
    }
}

