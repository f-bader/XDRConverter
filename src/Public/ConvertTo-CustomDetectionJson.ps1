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
        The JSON detection rule object to serialize. Accepts pipeline input.

    .PARAMETER OutputFile
        Optional. The path to the output JSON file. If not specified, output is written to stdout.
        Cannot be combined with -UseDisplayNameAsFilename or -UseIdAsFilename.

    .PARAMETER UseDisplayNameAsFilename
        Use the rule's display name as the output filename (with .json extension).
        The file is written to -OutputFolder (or the user's temp directory if not specified).
        Cannot be combined with -OutputFile or -UseIdAsFilename.

    .PARAMETER UseIdAsFilename
        Use the rule's detectorId (GUID) as the output filename (with .json extension).
        The file is written to -OutputFolder (or the user's temp directory if not specified).
        Cannot be combined with -OutputFile or -UseDisplayNameAsFilename.

    .PARAMETER OutputFolder
        The folder to write the output file to when using -UseDisplayNameAsFilename or -UseIdAsFilename.
        Defaults to the user's temp directory ([System.IO.Path]::GetTempPath()).

    .PARAMETER Enabled
        Optional. Set the isEnabled property to this value (true or false).

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

        Writes each rule to a JSON file named after its detectorId in the user's temp directory.
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

        [Parameter(Mandatory, ParameterSetName = 'ObjectById', HelpMessage = 'Use the detectorId as the output filename')]
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
                    $jsonObj.isEnabled = $Enabled
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
                $folder = if ($OutputFolder) { $OutputFolder } else { [System.IO.Path]::GetTempPath() }
                if (-not (Test-Path $folder)) {
                    New-Item -ItemType Directory -Path $folder -Force | Out-Null
                }
                if ($UseDisplayNameAsFilename) {
                    # sanitize  display name for use as a filename
                    $safeName = $jsonObj.displayName -replace '[\\/:*?"<>|]', '_'
                    # Convert whitespace-separated words to CamelCase
                    $safeName = ($safeName -split '\s+' | ForEach-Object { $_.Substring(0, 1).ToUpper() + $_.Substring(1) }) -join ''
                    $OutputFile = Join-Path $folder "$safeName.json"
                } else {
                    $OutputFile = Join-Path $folder "$($jsonObj.detectorId).json"
                }
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

