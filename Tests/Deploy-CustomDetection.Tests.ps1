Describe 'Deploy-CustomDetection' {

    BeforeAll {
        # Create a stub for Invoke-MgGraphRequest so Pester can mock it
        # even when Microsoft.Graph.Authentication is not installed.
        # The stub must declare the parameters used by Invoke-MgGraphRequestWithRetry
        # so that Pester's generated mock exposes them (e.g. $Body for assertions).
        if (-not (Get-Command -Name Invoke-MgGraphRequest -ErrorAction SilentlyContinue)) {
            function global:Invoke-MgGraphRequest {
                param($Method, $Uri, $Body, $Headers, $OutputType)
            }
        }

        $ModulePath = Split-Path -Path $PSScriptRoot -Parent
        $ModulePath = Join-Path -Path $ModulePath -ChildPath 'src' | Join-Path -ChildPath 'XDRConverter.psd1'
        Import-Module -Name $ModulePath -Force
    }

    AfterAll {
        Remove-Module -Name XDRConverter -Force -ErrorAction SilentlyContinue
    }

    BeforeEach {
        # Mock all Graph-dependent functions at the Describe level so every test
        # runs without real authentication. Individual contexts/tests can override
        # these mocks with more specific behaviour as needed.
        Mock Assert-MgGraphConnection {} -ModuleName XDRConverter
        Mock Invoke-MgGraphRequest {} -ModuleName XDRConverter
        Mock Get-CustomDetectionIdByDetectorId { return $null } -ModuleName XDRConverter
        Mock Get-CustomDetection { return @() } -ModuleName XDRConverter
    }

    Context 'Parameter Validation' {

        It 'Should throw when InputFile does not exist' {
            { Deploy-CustomDetection -InputFile 'C:\nonexistent\file.yaml' } | Should -Throw
        }

        It 'Should have Mandatory InputFile parameter' {
            $cmd = Get-Command -Name 'Deploy-CustomDetection'
            $param = $cmd.Parameters['InputFile']
            $mandatory = $param.Attributes | Where-Object { $_.TypeId.Name -eq 'ParameterAttribute' } |
            Select-Object -First 1
            $mandatory.Mandatory | Should -Be $true
        }

        It 'Should accept valid Severity values' {
            $cmd = Get-Command -Name 'Deploy-CustomDetection'
            $severityParam = $cmd.Parameters['Severity']
            $validateSet = $severityParam.Attributes | Where-Object { $_.TypeId.Name -eq 'ValidateSetAttribute' }
            $validateSet.ValidValues | Should -Contain 'Informational'
            $validateSet.ValidValues | Should -Contain 'Low'
            $validateSet.ValidValues | Should -Contain 'Medium'
            $validateSet.ValidValues | Should -Contain 'High'
        }

        It 'Should have SupportsShouldProcess' {
            $cmd = Get-Command -Name 'Deploy-CustomDetection'
            $cmdletBinding = $cmd.ScriptBlock.Attributes | Where-Object { $_.TypeId.Name -eq 'CmdletBindingAttribute' }
            $cmdletBinding.SupportsShouldProcess | Should -Be $true
        }

        It 'Should have TitlePrefix parameter' {
            $cmd = Get-Command -Name 'Deploy-CustomDetection'
            $cmd.Parameters.Keys | Should -Contain 'TitlePrefix'
        }

        It 'Should have Disabled switch parameter' {
            $cmd = Get-Command -Name 'Deploy-CustomDetection'
            $param = $cmd.Parameters['Disabled']
            $param.ParameterType.Name | Should -Be 'SwitchParameter'
        }

        It 'Should have NoDescriptionTag switch parameter' {
            $cmd = Get-Command -Name 'Deploy-CustomDetection'
            $param = $cmd.Parameters['NoDescriptionTag']
            $param.ParameterType.Name | Should -Be 'SwitchParameter'
        }

        It 'Should have DescriptionTagPrefix parameter' {
            $cmd = Get-Command -Name 'Deploy-CustomDetection'
            $cmd.Parameters.Keys | Should -Contain 'DescriptionTagPrefix'
        }

        It 'Should have Force switch parameter' {
            $cmd = Get-Command -Name 'Deploy-CustomDetection'
            $param = $cmd.Parameters['Force']
            $param.ParameterType.Name | Should -Be 'SwitchParameter'
        }
    }

    Context 'File Loading' {

        It 'Should reject unsupported file extensions' {
            $tempFile = Join-Path TestDrive: 'unsupported.txt'
            'test' | Out-File -FilePath $tempFile -Encoding UTF8

            { Deploy-CustomDetection -InputFile $tempFile } | Should -Throw '*Unsupported file extension*'
        }

        It 'Should load YAML files successfully' {
            $testYaml = @"
guid: 81fb771a-c57e-41b8-9905-63dbf267c13f
ruleName: TEST-Deploy
isEnabled: true
alertTitle: Test Alert
frequency: 0
alertSeverity: Medium
alertDescription: Test description
alertCategory: DefenseEvasion
queryText: DeviceEvents | where ActionType == "Test"
"@
            $tempFile = Join-Path TestDrive: 'load-yaml.yaml'
            $testYaml | Out-File -FilePath $tempFile -Encoding UTF8

            Mock Invoke-MgGraphRequest { return @{ id = 'new-rule-id' } } -ModuleName XDRConverter

            $result = Deploy-CustomDetection -InputFile $tempFile -Confirm:$false
            $result | Should -Not -BeNullOrEmpty
            $result.Action | Should -Be 'Created'
            $result.DetectorId | Should -Be '81fb771a-c57e-41b8-9905-63dbf267c13f'
        }

        It 'Should load JSON files successfully' {
            $testJson = @"
{
    "detectorId": "81fb771a-c57e-41b8-9905-63dbf267c13f",
    "displayName": "TEST-Deploy",
    "isEnabled": true,
    "detectionAction": {
        "alertTemplate": {
            "title": "Test Alert",
            "description": "Test description",
            "severity": "medium",
            "category": "DefenseEvasion"
        },
        "organizationalScope": null,
        "responseActions": []
    },
    "queryCondition": { "queryText": "DeviceEvents" },
    "schedule": { "period": "0" }
}
"@
            $tempFile = Join-Path TestDrive: 'load-json.json'
            $testJson | Out-File -FilePath $tempFile -Encoding UTF8

            Mock Invoke-MgGraphRequest { return @{ id = 'new-rule-id' } } -ModuleName XDRConverter

            $result = Deploy-CustomDetection -InputFile $tempFile -Confirm:$false
            $result | Should -Not -BeNullOrEmpty
            $result.Action | Should -Be 'Created'
        }
    }

    Context 'Description Tag' {

        BeforeEach {
            Mock Invoke-MgGraphRequest {
                # Capture the body for assertions
                $script:CapturedBody = $Body
                return @{ id = 'new-rule-id' }
            } -ModuleName XDRConverter
        }

        It 'Should append [<UUID>] tag to description by default' {
            $testYaml = @"
guid: 81fb771a-c57e-41b8-9905-63dbf267c13f
ruleName: PREFIX-TEST
isEnabled: true
alertTitle: Test
frequency: 0
alertSeverity: Medium
alertDescription: Original desc
alertCategory: DefenseEvasion
queryText: DeviceEvents
"@
            $tempFile = Join-Path TestDrive: 'tag-default.yaml'
            $testYaml | Out-File -FilePath $tempFile -Encoding UTF8

            Deploy-CustomDetection -InputFile $tempFile -Confirm:$false
            $script:CapturedBody.detectionAction.alertTemplate.description |
            Should -Match '\[81fb771a-c57e-41b8-9905-63dbf267c13f\]$'
        }

        It 'Should append [PREFIX:<UUID>] tag when DescriptionTagPrefix is given' {
            $testYaml = @"
guid: 81fb771a-c57e-41b8-9905-63dbf267c13f
ruleName: TEST
isEnabled: true
alertTitle: Test
frequency: 0
alertSeverity: Medium
alertDescription: Original desc
alertCategory: DefenseEvasion
queryText: DeviceEvents
"@
            $tempFile = Join-Path TestDrive: 'tag-prefix.yaml'
            $testYaml | Out-File -FilePath $tempFile -Encoding UTF8

            Deploy-CustomDetection -InputFile $tempFile -DescriptionTagPrefix 'PREFIX' -Confirm:$false
            $script:CapturedBody.detectionAction.alertTemplate.description |
            Should -Match '\[PREFIX:81fb771a-c57e-41b8-9905-63dbf267c13f\]$'
        }

        It 'Should NOT append tag when -NoDescriptionTag is set' {
            $testYaml = @"
guid: 81fb771a-c57e-41b8-9905-63dbf267c13f
ruleName: TEST
isEnabled: true
alertTitle: Test
frequency: 0
alertSeverity: Medium
alertDescription: Original desc
alertCategory: DefenseEvasion
queryText: DeviceEvents
"@
            $tempFile = Join-Path TestDrive: 'tag-none.yaml'
            $testYaml | Out-File -FilePath $tempFile -Encoding UTF8

            Deploy-CustomDetection -InputFile $tempFile -NoDescriptionTag -Confirm:$false
            $script:CapturedBody.detectionAction.alertTemplate.description |
            Should -Be 'Original desc'
        }

        It 'Should not duplicate the tag on repeated deploys' {
            $testYaml = @"
guid: 81fb771a-c57e-41b8-9905-63dbf267c13f
ruleName: TEST
isEnabled: true
alertTitle: Test
frequency: 0
alertSeverity: Medium
alertDescription: Original desc [81fb771a-c57e-41b8-9905-63dbf267c13f]
alertCategory: DefenseEvasion
queryText: DeviceEvents
"@
            $tempFile = Join-Path TestDrive: 'tag-nodupe.yaml'
            $testYaml | Out-File -FilePath $tempFile -Encoding UTF8

            Deploy-CustomDetection -InputFile $tempFile -Confirm:$false
            $desc = $script:CapturedBody.detectionAction.alertTemplate.description
            # Should contain the tag exactly once
            $UUIDmatches = [regex]::Matches($desc, [regex]::Escape('81fb771a-c57e-41b8-9905-63dbf267c13f'))
            $UUIDmatches.Count | Should -Be 1
        }
    }

    Context 'Overrides' {

        BeforeEach {
            Mock Invoke-MgGraphRequest {
                $script:CapturedBody = $Body
                return @{ id = 'new-rule-id' }
            } -ModuleName XDRConverter
        }

        It 'Should override severity when -Severity is specified' {
            $testYaml = @"
guid: 81fb771a-c57e-41b8-9905-63dbf267c13f
ruleName: PREFIX-TEST
isEnabled: true
alertTitle: Test
frequency: 0
alertSeverity: Low
alertDescription: Test
alertCategory: DefenseEvasion
queryText: DeviceEvents
"@
            $tempFile = Join-Path TestDrive: 'override-severity.yaml'
            $testYaml | Out-File -FilePath $tempFile -Encoding UTF8

            Deploy-CustomDetection -InputFile $tempFile -Severity High -Confirm:$false
            $script:CapturedBody.detectionAction.alertTemplate.severity | Should -Be 'high'
        }

        It 'Should prepend TitlePrefix to displayName and alertTitle' {
            $testYaml = @"
guid: 81fb771a-c57e-41b8-9905-63dbf267c13f
ruleName: MyRule
isEnabled: true
alertTitle: My Alert
frequency: 0
alertSeverity: Medium
alertDescription: Test
alertCategory: DefenseEvasion
queryText: DeviceEvents
"@
            $tempFile = Join-Path TestDrive: 'override-titleprefix.yaml'
            $testYaml | Out-File -FilePath $tempFile -Encoding UTF8

            Deploy-CustomDetection -InputFile $tempFile -TitlePrefix '[PREFIX] ' -Confirm:$false
            $script:CapturedBody.displayName | Should -Be '[PREFIX] MyRule'
            $script:CapturedBody.detectionAction.alertTemplate.title | Should -Be '[PREFIX] My Alert'
        }

        It 'Should not double-prefix if title already starts with prefix' {
            $testYaml = @"
guid: 81fb771a-c57e-41b8-9905-63dbf267c13f
ruleName: "[PREFIX] MyRule"
isEnabled: true
alertTitle: "[PREFIX] My Alert"
frequency: 0
alertSeverity: Medium
alertDescription: Test
alertCategory: DefenseEvasion
queryText: DeviceEvents
"@
            $tempFile = Join-Path TestDrive: 'override-nodoubleprefix.yaml'
            $testYaml | Out-File -FilePath $tempFile -Encoding UTF8

            Deploy-CustomDetection -InputFile $tempFile -TitlePrefix '[PREFIX] ' -Confirm:$false
            $script:CapturedBody.displayName | Should -Be '[PREFIX] MyRule'
        }

        It 'Should deploy in disabled mode with -Disabled switch' {
            $testYaml = @"
guid: 81fb771a-c57e-41b8-9905-63dbf267c13f
ruleName: PREFIX-TEST
isEnabled: true
alertTitle: Test
frequency: 0
alertSeverity: Medium
alertDescription: Test
alertCategory: DefenseEvasion
queryText: DeviceEvents
"@
            $tempFile = Join-Path TestDrive: 'override-disabled.yaml'
            $testYaml | Out-File -FilePath $tempFile -Encoding UTF8

            Deploy-CustomDetection -InputFile $tempFile -Disabled -Confirm:$false
            $script:CapturedBody.isEnabled | Should -Be $false
        }
    }

    Context 'Create vs Update Logic' {

        It 'Should create a rule when it does not exist' {
            Mock Invoke-MgGraphRequest {
                return @{ id = 'new-id' }
            } -ModuleName XDRConverter

            $testYaml = @"
guid: 81fb771a-c57e-41b8-9905-63dbf267c13f
ruleName: PREFIX-TEST-New
isEnabled: true
alertTitle: Test
frequency: 0
alertSeverity: Medium
alertDescription: Test
alertCategory: DefenseEvasion
queryText: DeviceEvents
"@
            $tempFile = Join-Path TestDrive: 'create-new.yaml'
            $testYaml | Out-File -FilePath $tempFile -Encoding UTF8

            $result = Deploy-CustomDetection -InputFile $tempFile -Confirm:$false
            $result.Action | Should -Be 'Created'
            Should -Invoke Invoke-MgGraphRequest -ModuleName XDRConverter -ParameterFilter { $Method -eq 'POST' }
        }

        It 'Should update an existing rule when detectorId matches' {
            Mock Get-CustomDetectionIdByDetectorId { return 'existing-id' } -ModuleName XDRConverter
            Mock Get-CustomDetection {
                return @{
                    id              = 'existing-id'
                    detectorId      = '81fb771a-c57e-41b8-9905-63dbf267c13f'
                    displayName     = 'OLD-NAME'
                    isEnabled       = $true
                    detectionAction = @{
                        alertTemplate = @{
                            title       = 'Old Title'
                            description = 'Old desc'
                            severity    = 'low'
                            category    = 'DefenseEvasion'
                        }
                    }
                    queryCondition  = @{ queryText = 'DeviceEvents | old' }
                    schedule        = @{ period = '0' }
                }
            } -ModuleName XDRConverter
            Mock Invoke-MgGraphRequest {} -ModuleName XDRConverter

            $testYaml = @"
guid: 81fb771a-c57e-41b8-9905-63dbf267c13f
ruleName: PREFIX-TEST-Updated
isEnabled: true
alertTitle: New Title
frequency: 0
alertSeverity: Medium
alertDescription: New desc
alertCategory: DefenseEvasion
queryText: DeviceEvents | new
"@
            $tempFile = Join-Path TestDrive: 'update-existing.yaml'
            $testYaml | Out-File -FilePath $tempFile -Encoding UTF8

            $result = Deploy-CustomDetection -InputFile $tempFile -Confirm:$false
            $result.Action | Should -Be 'Updated'
            Should -Invoke Invoke-MgGraphRequest -ModuleName XDRConverter -ParameterFilter { $Method -eq 'PATCH' }
        }

        It 'Should skip update when rule has not changed' {
            $guid = '81fb771a-c57e-41b8-9905-63dbf267c13f'
            Mock Get-CustomDetectionIdByDetectorId { return 'existing-id' } -ModuleName XDRConverter
            Mock Get-CustomDetection {
                return @{
                    id              = 'existing-id'
                    detectorId      = $guid
                    displayName     = 'PREFIX-TEST'
                    isEnabled       = $true
                    detectionAction = @{
                        alertTemplate = @{
                            title       = 'Test'
                            description = "My desc [$guid]"
                            severity    = 'medium'
                            category    = 'DefenseEvasion'
                        }
                    }
                    queryCondition  = @{ queryText = 'DeviceEvents' }
                    schedule        = @{ period = '0' }
                }
            } -ModuleName XDRConverter

            $testYaml = @"
guid: $guid
ruleName: PREFIX-TEST
isEnabled: true
alertTitle: Test
frequency: 0
alertSeverity: Medium
alertDescription: My desc
alertCategory: DefenseEvasion
queryText: DeviceEvents
"@
            $tempFile = Join-Path TestDrive: 'skip-nochange.yaml'
            $testYaml | Out-File -FilePath $tempFile -Encoding UTF8

            $result = Deploy-CustomDetection -InputFile $tempFile -Confirm:$false
            $result.Action | Should -Be 'Skipped'
            $result.Reason | Should -Be 'No changes detected'
            Should -Not -Invoke Invoke-MgGraphRequest -ModuleName XDRConverter
        }

        It 'Should find rule by description UUID tag when detectorId lookup fails' {
            $guid = '81fb771a-c57e-41b8-9905-63dbf267c13f'
            # Return all detections with a matching description
            Mock Get-CustomDetection {
                if ($DetectionId) {
                    return @{
                        id              = 'found-by-desc'
                        detectorId      = 'different-detector'
                        displayName     = 'OLD-NAME'
                        isEnabled       = $false
                        detectionAction = @{
                            alertTemplate = @{
                                title       = 'Old Title'
                                description = "Some desc [$guid]"
                                severity    = 'low'
                                category    = 'DefenseEvasion'
                            }
                        }
                        queryCondition  = @{ queryText = 'DeviceEvents | old' }
                        schedule        = @{ period = '0' }
                    }
                }
                return @(
                    @{
                        id              = 'found-by-desc'
                        detectorId      = 'different-detector'
                        displayName     = 'OLD-NAME'
                        isEnabled       = $false
                        detectionAction = @{
                            alertTemplate = @{
                                title       = 'Old Title'
                                description = "Some desc [$guid]"
                                severity    = 'low'
                                category    = 'DefenseEvasion'
                            }
                        }
                        queryCondition  = @{ queryText = 'DeviceEvents | old' }
                        schedule        = @{ period = '0' }
                    }
                )
            } -ModuleName XDRConverter
            Mock Invoke-MgGraphRequest {} -ModuleName XDRConverter

            $testYaml = @"
guid: $guid
ruleName: PREFIX-TEST-Remapped
isEnabled: true
alertTitle: New Title
frequency: 0
alertSeverity: Medium
alertDescription: New desc
alertCategory: DefenseEvasion
queryText: DeviceEvents | new
"@
            $tempFile = Join-Path TestDrive: 'find-by-desc.yaml'
            $testYaml | Out-File -FilePath $tempFile -Encoding UTF8

            $result = Deploy-CustomDetection -InputFile $tempFile -Confirm:$false
            $result.Action | Should -Be 'Updated'
            $result.RuleId | Should -Be 'found-by-desc'
        }
    }

    Context 'Help Documentation' {

        It 'Should have help documentation' {
            $help = Get-Help -Name 'Deploy-CustomDetection' -ErrorAction SilentlyContinue
            $help | Should -Not -BeNullOrEmpty
            $help.Synopsis | Should -Not -BeNullOrEmpty
        }

        It 'Should have examples' {
            $help = Get-Help -Name 'Deploy-CustomDetection' -ErrorAction SilentlyContinue
            $help.Examples | Should -Not -BeNullOrEmpty
        }
    }
}
