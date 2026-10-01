function ConvertTo-CustomDetectionYaml {
    <#
    .SYNOPSIS
        Converts a JSON Defender XDR detection file to YAML format.

    .DESCRIPTION
        Reads a JSON file containing a Defender XDR custom detection rule
        and converts it to YAML format, omitting properties not referenced in the YAML schema.
        Optionally modifies the enabled status and severity properties.

    .PARAMETER InputFile
        The path to the input JSON file.

    .PARAMETER InputObject
        The JSON detection rule object to convert. Accepts pipeline input.

    .PARAMETER OutputFile
        Optional. The path to the output YAML file. If not specified, output is written to stdout.
        Cannot be combined with -UseDisplayNameAsFilename or -UseIdAsFilename.

    .PARAMETER UseDisplayNameAsFilename
        Use the rule's display name as the output filename (with .yaml extension).
        The file is written to -OutputFolder (or the user's temp directory if not specified).
        Cannot be combined with -OutputFile or -UseIdAsFilename.

    .PARAMETER UseIdAsFilename
        Use the rule's guid as the output filename (with .yaml extension). Taken from the
        description tag, then a UUID rule id, then the guid after the rule- prefix, then
        the detector ID the API assigned.
        The file is written to -OutputFolder (or the user's temp directory if not specified).
        Cannot be combined with -OutputFile or -UseDisplayNameAsFilename.

    .PARAMETER OutputFolder
        The folder to write the output file to when using -UseDisplayNameAsFilename or -UseIdAsFilename.
        Defaults to the user's temp directory ([System.IO.Path]::GetTempPath()).

    .PARAMETER Enabled
        Optional. Set the isEnabled property to this value (true or false).

    .PARAMETER LegacyKeys
        Emit the legacy YAML keys instead of the current ones. Values the legacy keys cannot
        express are kept in their current form or dropped, each with a warning.

    .PARAMETER Severity
        Optional. Override the alert severity. Valid values: Informational, Low, Medium, High.

    .EXAMPLE
        ConvertTo-CustomDetectionYaml -InputFile '.\output.json' -OutputFile '.\input.yaml'

    .EXAMPLE
        Get-CustomDetection | ConvertTo-CustomDetectionYaml

    .EXAMPLE
        ConvertTo-CustomDetectionYaml -InputFile '.\output.json' -Severity Low

    .EXAMPLE
        ConvertTo-CustomDetectionYaml -InputFile '.\output.json' -Enabled $true

    .EXAMPLE
        Get-CustomDetection | ConvertTo-CustomDetectionYaml -UseDisplayNameAsFilename -OutputFolder 'C:\Detections'

        Writes each rule to a YAML file named after its display name in C:\Detections.

    .EXAMPLE
        Get-CustomDetection | ConvertTo-CustomDetectionYaml -UseIdAsFilename

        Writes each rule to a YAML file named after its guid in the user's temp directory.
    #>
    [CmdletBinding(DefaultParameterSetName = 'File')]
    [OutputType([string])]
    param(
        [Parameter(Mandatory, ParameterSetName = 'File', HelpMessage = 'Path to the input JSON file')]
        [ValidateScript({ Test-Path $_ })]
        [string]$InputFile,

        [Parameter(Mandatory, ParameterSetName = 'Object', ValueFromPipeline, HelpMessage = 'JSON detection rule object')]
        [Parameter(Mandatory, ParameterSetName = 'ObjectByDisplayName', ValueFromPipeline, HelpMessage = 'JSON detection rule object')]
        [Parameter(Mandatory, ParameterSetName = 'ObjectById', ValueFromPipeline, HelpMessage = 'JSON detection rule object')]
        [ValidateNotNull()]
        [PSObject]$InputObject,

        [Parameter(HelpMessage = 'Path to the output YAML file (optional, outputs to stdout if not specified)', ParameterSetName = 'File')]
        [Parameter(HelpMessage = 'Path to the output YAML file (optional, outputs to stdout if not specified)', ParameterSetName = 'Object')]
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

        [Parameter(HelpMessage = 'Emit the legacy YAML keys (alertCategory, mitreTechniques, impactedEntities, period-style frequency)')]
        [switch]$LegacyKeys
    )

    process {
        try {
            # Read JSON from file or pipeline
            $jsonObj = if ($PSCmdlet.ParameterSetName -eq 'File') {
                Import-CustomDetectionJsonFile -FilePath $InputFile
            } else {
                $InputObject
            }

            # Determine output file path when using naming switches
            if ($UseDisplayNameAsFilename -or $UseIdAsFilename) {
                $OutputFile = Resolve-CustomDetectionOutputFile -Rule $jsonObj -Extension '.yaml' -OutputFolder $OutputFolder -UseDisplayName:$UseDisplayNameAsFilename
            }

            # Prepare parameters for conversion
            $convertParams = @{
                JsonObject = $jsonObj
            }

            if ($PSBoundParameters.ContainsKey('Enabled')) {
                $convertParams.SetEnabled = $Enabled
            }

            if ($PSBoundParameters.ContainsKey('Severity')) {
                $convertParams.SetSeverity = $Severity
            }

            # Convert to YAML object
            $yamlObj = ConvertFrom-CustomDetectionJsonToYaml @convertParams

            if ($LegacyKeys) {
                $yamlObj = ConvertTo-CustomDetectionLegacyYaml -YamlObject $yamlObj
            }

            # Convert to YAML string (inline: single line operation)
            $yamlString = $yamlObj | ConvertTo-Yaml -OutFile $null

            # Output to file or stdout
            Write-CustomDetectionOutput -Content $yamlString -OutputFile $OutputFile
        } catch {
            Write-Error "Error converting JSON to YAML: $_"
            throw
        }
    }
}

