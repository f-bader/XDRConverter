@{
    RootModule        = 'XDRConverter.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = '81fb771a-c57e-41b8-9905-63dbf267c13f'
    Author            = 'Fabian Bader'
    CompanyName       = ''
    RequiredModules   = @('powershell-yaml')
    Description       = 'PowerShell module for converting Defender XDR detection rules between YAML and JSON formats and deploying them in a GitHub CI/CD pipeline.'
    PowerShellVersion = '7.0'
    FunctionsToExport = @(
        'ConvertTo-CustomDetectionJson',
        'ConvertTo-CustomDetectionYaml',
        'Deploy-CustomDetection',
        'Get-CustomDetectionIdByDescriptionTag',
        'Get-CustomDetectionIdByDetectorId',
        'Get-CustomDetectionIds',
        'Get-CustomDetection',
        'Remove-CustomDetection'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData       = @{
        PSData = @{
            Tags         = @('XDR', 'Defender', 'Detection', 'YAML', 'JSON', 'Security', 'MITRE')
            LicenseUri   = ''
            ProjectUri   = 'https://github.com/f-bader/XDRConverter'
            ReleaseNotes = 'Version 1.0.0: Initial release'
        }
    }
}


