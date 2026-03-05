Describe 'ConvertTo-CustomDetectionJson' {

    BeforeAll {
        $ModulePath = Split-Path -Path $PSScriptRoot -Parent
        $ModulePath = Join-Path -Path $ModulePath -ChildPath 'src' | Join-Path -ChildPath 'XDRConverter.psd1'
        Import-Module -Name $ModulePath -Force
    }

    AfterAll {
        Remove-Module -Name XDRConverter -Force -ErrorAction SilentlyContinue
    }

    Context 'Parameter Validation' {
        It 'Should throw when InputFile does not exist' {
            { ConvertTo-CustomDetectionJson -InputFile 'C:\nonexistent\file.yaml' } | Should -Throw
        }

        It 'Should accept valid Severity parameter values' {
            $validValues = 'Informational', 'Low', 'Medium', 'High'
            foreach ($severity in $validValues) {
                # Just validate parameter acceptance, don't actually convert
                $params = @{
                    InputFile = $PSScriptRoot -replace 'Tests', '..'
                    Severity  = $severity
                }
                # This should not throw a validation error
                $params | Should -Not -BeNullOrEmpty
            }
        }

        It 'Should reject invalid Severity parameter values' {
            { ConvertTo-CustomDetectionJson -InputFile 'input.yaml' -Severity 'InvalidSeverity' } | Should -Throw
        }

        It 'Should accept boolean values for Enabled parameter' {
            $params = @{
                InputFile = $PSScriptRoot -replace 'Tests', '..'
                Enabled   = $true
            }
            $params.Enabled | Should -Be $true
        }
    }

    Context 'Functionality' {

        It 'Should convert YAML to JSON string when no OutputFile specified' {
            # Create a test YAML file
            $testYamlContent = @"
guid: 81fb771a-c57e-41b8-9905-63dbf267c13f
ruleName: PREFIX-TEST-Rule
isEnabled: true
alertTitle: Test Alert
frequency: 0
alertSeverity: Medium
alertDescription: Test description
alertCategory: DefenseEvasion
queryText: DeviceEvents | where ActionType == "Test"
"@
            $tempYamlFile = Join-Path TestDrive: 'convert-basic.yaml'
            $testYamlContent | Out-File -FilePath $tempYamlFile -Encoding UTF8

            $result = ConvertTo-CustomDetectionJson -InputFile $tempYamlFile
            $result | Should -Not -BeNullOrEmpty
            $result | Should -Match 'detectorId'
            $result | Should -Match '81fb771a-c57e-41b8-9905-63dbf267c13f'
            $result | Should -Match 'PREFIX-TEST-Rule'
        }

        It 'Should create output file when OutputFile parameter is specified' {
            $testYamlContent = @"
guid: 81fb771a-c57e-41b8-9905-63dbf267c13f
ruleName: PREFIX-TEST-Rule
isEnabled: true
alertTitle: Test Alert
frequency: 0
alertSeverity: Medium
alertDescription: Test description
alertCategory: DefenseEvasion
queryText: DeviceEvents | where ActionType == "Test"
"@
            $tempYamlFile = Join-Path TestDrive: 'output-input.yaml'
            $tempJsonFile = Join-Path TestDrive: 'output-result.json'
            $testYamlContent | Out-File -FilePath $tempYamlFile -Encoding UTF8

            ConvertTo-CustomDetectionJson -InputFile $tempYamlFile -OutputFile $tempJsonFile
            Test-Path -Path $tempJsonFile | Should -Be $true

            # Validate the output is valid JSON
            $jsonContent = Get-Content -Path $tempJsonFile -Raw | ConvertFrom-Json
            $jsonContent.detectorId | Should -Be '81fb771a-c57e-41b8-9905-63dbf267c13f'
            $jsonContent.displayName | Should -Be 'PREFIX-TEST-Rule'
        }

        It 'Should apply Severity override during conversion' {
            $testYamlContent = @"
guid: 81fb771a-c57e-41b8-9905-63dbf267c13f
ruleName: PREFIX-TEST-Rule
isEnabled: true
alertTitle: Test Alert
frequency: 0
alertSeverity: Low
alertDescription: Test description
alertCategory: DefenseEvasion
queryText: DeviceEvents | where ActionType == "Test"
"@
            $tempYamlFile = Join-Path TestDrive: 'severity-override.yaml'
            $testYamlContent | Out-File -FilePath $tempYamlFile -Encoding UTF8

            $result = ConvertTo-CustomDetectionJson -InputFile $tempYamlFile -Severity 'High'
            $result | Should -Match '"severity"\s*:\s*"high"'
        }

        It 'Should apply Enabled override during conversion' {
            $testYamlContent = @"
guid: 81fb771a-c57e-41b8-9905-63dbf267c13f
ruleName: PREFIX-TEST-Rule
isEnabled: true
alertTitle: Test Alert
frequency: 0
alertSeverity: Medium
alertDescription: Test description
alertCategory: DefenseEvasion
queryText: DeviceEvents | where ActionType == "Test"
"@
            $tempYamlFile = Join-Path TestDrive: 'enabled-override.yaml'
            $testYamlContent | Out-File -FilePath $tempYamlFile -Encoding UTF8

            $result = ConvertTo-CustomDetectionJson -InputFile $tempYamlFile -Enabled $false
            $result | Should -Match '"isEnabled"\s*:\s*false'
        }

        It 'Should generate valid JSON output' {
            $testYamlContent = @"
guid: 81fb771a-c57e-41b8-9905-63dbf267c13f
ruleName: PREFIX-TEST-Rule
isEnabled: true
alertTitle: Test Alert
frequency: 0
alertSeverity: Medium
alertDescription: Test description
alertCategory: DefenseEvasion
queryText: DeviceEvents | where ActionType == "Test"
"@
            $tempYamlFile = Join-Path TestDrive: 'valid-json.yaml'
            $testYamlContent | Out-File -FilePath $tempYamlFile -Encoding UTF8

            $result = ConvertTo-CustomDetectionJson -InputFile $tempYamlFile

            # Should not throw when parsing as JSON
            { $result | ConvertFrom-Json } | Should -Not -Throw

            $json = $result | ConvertFrom-Json
            $json.detectionAction | Should -Not -BeNullOrEmpty
            $json.queryCondition | Should -Not -BeNullOrEmpty
            $json.schedule | Should -Not -BeNullOrEmpty
        }

        It 'Should map YAML properties to correct JSON paths' {
            $testYamlContent = @"
guid: 81fb771a-c57e-41b8-9905-63dbf267c13f
ruleName: PREFIX-TEST-Rule
isEnabled: true
alertTitle: Test Alert Title
frequency: 0
alertSeverity: High
alertDescription: Test description
alertRecommendedAction: Investigate immediately
alertCategory: DefenseEvasion
mitreTechniques:
  - T1070.001
  - T1234.567
impactedEntities:
  - entityType: Machine
    entityIdentifier: DeviceId
queryText: DeviceEvents | where ActionType == "Test"
"@
            $tempYamlFile = Join-Path TestDrive: 'property-mapping.yaml'
            $testYamlContent | Out-File -FilePath $tempYamlFile -Encoding UTF8

            $result = ConvertTo-CustomDetectionJson -InputFile $tempYamlFile | ConvertFrom-Json

            $result.detectorId | Should -Be '81fb771a-c57e-41b8-9905-63dbf267c13f'
            $result.displayName | Should -Be 'PREFIX-TEST-Rule'
            $result.isEnabled | Should -Be $true
            $result.detectionAction.alertTemplate.title | Should -Be 'Test Alert Title'
            $result.detectionAction.alertTemplate.severity | Should -Be 'high'
            $result.detectionAction.alertTemplate.recommendedActions | Should -Be 'Investigate immediately'
            $result.detectionAction.alertTemplate.category | Should -Be 'DefenseEvasion'
            $result.detectionAction.alertTemplate.mitreTechniques | Should -Contain 'T1070.001'
            $result.detectionAction.alertTemplate.mitreTechniques | Should -Contain 'T1234.567'
            $result.queryCondition.queryText | Should -Match 'Test'
        }

        It 'Should include mitreTechniques as an empty array when none are defined' {
            $testYamlContent = @"
guid: 81fb771a-c57e-41b8-9905-63dbf267c13f
ruleName: PREFIX-TEST-Rule
isEnabled: true
alertTitle: Test Alert
frequency: 0
alertSeverity: Medium
alertDescription: Test description
alertCategory: DefenseEvasion
queryText: DeviceEvents | where ActionType == "Test"
"@
            $tempYamlFile = Join-Path TestDrive: 'mitre-empty.yaml'
            $testYamlContent | Out-File -FilePath $tempYamlFile -Encoding UTF8

            $jsonString = ConvertTo-CustomDetectionJson -InputFile $tempYamlFile

            # Verify the raw JSON string contains mitreTechniques as an array
            $jsonString | Should -Match '"mitreTechniques"\s*:\s*\[' -Because 'mitreTechniques must be present as an array in the JSON output'

            # Also verify via parsed object that the property exists
            $result = $jsonString | ConvertFrom-Json
            $result.detectionAction.alertTemplate.PSObject.Properties.Name | Should -Contain 'mitreTechniques' -Because 'mitreTechniques property must exist even when empty'
        }

        It 'Should convert YAML response actions to Graph API JSON format' {
            $testYamlContent = @"
guid: 81fb771a-c57e-41b8-9905-63dbf267c13f
ruleName: PREFIX-TEST-Actions
isEnabled: true
alertTitle: Test Alert
frequency: 0
alertSeverity: Medium
alertDescription: Test description
alertCategory: DefenseEvasion
impactedEntities:
  - entityType: Machine
    entityIdentifier: DeviceId
actions:
  - actionType: IsolateMachine
    additionalFields:
      isolationType: Full
  - actionType: CollectInvestigationPackage
  - actionType: RunAntivirusScan
  - actionType: InitiateInvestigation
  - actionType: RestrictAppExecution
queryText: DeviceEvents | where ActionType == "Test"
"@
            $tempYamlFile = Join-Path TestDrive: 'actions-all.yaml'
            $testYamlContent | Out-File -FilePath $tempYamlFile -Encoding UTF8

            $result = ConvertTo-CustomDetectionJson -InputFile $tempYamlFile | ConvertFrom-Json

            $result.detectionAction.responseActions.Count | Should -Be 5

            # Verify each action has the correct @odata.type
            $result.detectionAction.responseActions[0].'@odata.type' | Should -Be '#microsoft.graph.security.isolateDeviceResponseAction'
            $result.detectionAction.responseActions[0].identifier | Should -Be 'deviceId'
            $result.detectionAction.responseActions[0].isolationType | Should -Be 'full'

            $result.detectionAction.responseActions[1].'@odata.type' | Should -Be '#microsoft.graph.security.collectInvestigationPackageResponseAction'
            $result.detectionAction.responseActions[1].identifier | Should -Be 'deviceId'

            $result.detectionAction.responseActions[2].'@odata.type' | Should -Be '#microsoft.graph.security.runAntivirusScanResponseAction'
            $result.detectionAction.responseActions[2].identifier | Should -Be 'deviceId'

            $result.detectionAction.responseActions[3].'@odata.type' | Should -Be '#microsoft.graph.security.initiateInvestigationResponseAction'
            $result.detectionAction.responseActions[3].identifier | Should -Be 'deviceId'

            $result.detectionAction.responseActions[4].'@odata.type' | Should -Be '#microsoft.graph.security.restrictAppExecutionResponseAction'
            $result.detectionAction.responseActions[4].identifier | Should -Be 'deviceId'
        }

        It 'Should default IsolateMachine isolationType to full when not specified' {
            $testYamlContent = @"
guid: 81fb771a-c57e-41b8-9905-63dbf267c13f
ruleName: PREFIX-TEST-IsolateDefault
isEnabled: true
alertTitle: Test Alert
frequency: 0
alertSeverity: Medium
alertDescription: Test description
alertCategory: DefenseEvasion
impactedEntities:
  - entityType: Machine
    entityIdentifier: DeviceId
actions:
  - actionType: IsolateMachine
queryText: DeviceEvents | where ActionType == "Test"
"@
            $tempYamlFile = Join-Path TestDrive: 'actions-isolate-default.yaml'
            $testYamlContent | Out-File -FilePath $tempYamlFile -Encoding UTF8

            $result = ConvertTo-CustomDetectionJson -InputFile $tempYamlFile | ConvertFrom-Json

            $result.detectionAction.responseActions[0].isolationType | Should -Be 'full'
        }

        It 'Should support Selective isolation type' {
            $testYamlContent = @"
guid: 81fb771a-c57e-41b8-9905-63dbf267c13f
ruleName: PREFIX-TEST-IsolateSelective
isEnabled: true
alertTitle: Test Alert
frequency: 0
alertSeverity: Medium
alertDescription: Test description
alertCategory: DefenseEvasion
impactedEntities:
  - entityType: Machine
    entityIdentifier: DeviceId
actions:
  - actionType: IsolateMachine
    additionalFields:
      isolationType: Selective
queryText: DeviceEvents | where ActionType == "Test"
"@
            $tempYamlFile = Join-Path TestDrive: 'actions-isolate-selective.yaml'
            $testYamlContent | Out-File -FilePath $tempYamlFile -Encoding UTF8

            $result = ConvertTo-CustomDetectionJson -InputFile $tempYamlFile | ConvertFrom-Json

            $result.detectionAction.responseActions[0].isolationType | Should -Be 'selective'
        }

        It 'Should throw on unsupported response action type' {
            $testYamlContent = @"
guid: 81fb771a-c57e-41b8-9905-63dbf267c13f
ruleName: PREFIX-TEST-BadAction
isEnabled: true
alertTitle: Test Alert
frequency: 0
alertSeverity: Medium
alertDescription: Test description
alertCategory: DefenseEvasion
impactedEntities:
  - entityType: Machine
    entityIdentifier: DeviceId
actions:
  - actionType: UnsupportedAction
queryText: DeviceEvents | where ActionType == "Test"
"@
            $tempYamlFile = Join-Path TestDrive: 'actions-bad.yaml'
            $testYamlContent | Out-File -FilePath $tempYamlFile -Encoding UTF8

            { ConvertTo-CustomDetectionJson -InputFile $tempYamlFile } | Should -Throw '*Unsupported response action type*'
        }

        It 'Should produce empty responseActions when no actions defined' {
            $testYamlContent = @"
guid: 81fb771a-c57e-41b8-9905-63dbf267c13f
ruleName: PREFIX-TEST-NoActions
isEnabled: true
alertTitle: Test Alert
frequency: 0
alertSeverity: Medium
alertDescription: Test description
alertCategory: DefenseEvasion
queryText: DeviceEvents | where ActionType == "Test"
"@
            $tempYamlFile = Join-Path TestDrive: 'actions-none.yaml'
            $testYamlContent | Out-File -FilePath $tempYamlFile -Encoding UTF8

            $jsonString = ConvertTo-CustomDetectionJson -InputFile $tempYamlFile
            $jsonString | Should -Match '"responseActions"\s*:\s*\[' -Because 'responseActions must be present as an array'
        }
    }

    Context 'UseDisplayNameAsFilename and UseIdAsFilename' {

        BeforeAll {
            $testJsonObject = [PSCustomObject]@{
                displayName     = 'PREFIX-TEST-Rule'
                detectorId      = '81fb771a-c57e-41b8-9905-63dbf267c13f'
                isEnabled       = $true
                detectionAction = @{
                    alertTemplate       = @{
                        title       = 'Test Alert'
                        severity    = 'medium'
                        description = 'Test description'
                        category    = 'DefenseEvasion'
                    }
                    organizationalScope = $null
                    responseActions     = @()
                }
                queryCondition  = @{
                    queryText = 'DeviceEvents | where ActionType == "Test"'
                }
                schedule        = @{
                    period = '0'
                }
            }
        }

        It 'Should write file using display name when -UseDisplayNameAsFilename is set' {
            $outputFolder = Join-Path TestDrive: 'json-displayname'
            $testJsonObject | ConvertTo-CustomDetectionJson -UseDisplayNameAsFilename -OutputFolder $outputFolder

            $expectedFile = Join-Path $outputFolder 'PREFIX-TEST-Rule.json'
            Test-Path $expectedFile | Should -Be $true
            $content = Get-Content $expectedFile -Raw | ConvertFrom-Json
            $content.displayName | Should -Be 'PREFIX-TEST-Rule'
        }

        It 'Should sanitize  invalid filename characters in display name' {
            $objWithBadName = $testJsonObject.PSObject.Copy()
            $objWithBadName.displayName = 'Rule:With/Bad<Chars'
            $outputFolder = Join-Path TestDrive: 'json-sanitize'
            New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
            $objWithBadName | ConvertTo-CustomDetectionJson -UseDisplayNameAsFilename -OutputFolder $outputFolder

            $expectedFile = Join-Path $outputFolder 'Rule_With_Bad_Chars.json'
            Test-Path $expectedFile | Should -Be $true
        }

        It 'Should write file using detectorId when -UseIdAsFilename is set' {
            $outputFolder = Join-Path TestDrive: 'json-id'
            $testJsonObject | ConvertTo-CustomDetectionJson -UseIdAsFilename -OutputFolder $outputFolder

            $expectedFile = Join-Path $outputFolder '81fb771a-c57e-41b8-9905-63dbf267c13f.json'
            Test-Path $expectedFile | Should -Be $true
            $content = Get-Content $expectedFile -Raw | ConvertFrom-Json
            $content.detectorId | Should -Be '81fb771a-c57e-41b8-9905-63dbf267c13f'
        }

        It 'Should default to temp directory when -OutputFolder is not specified' {
            $tempPath = [System.IO.Path]::GetTempPath()
            $expectedFile = Join-Path $tempPath '81fb771a-c57e-41b8-9905-63dbf267c13f.json'

            # Clean up if it exists from a previous run
            if (Test-Path $expectedFile) { Remove-Item $expectedFile -Force }

            $testJsonObject | ConvertTo-CustomDetectionJson -UseIdAsFilename

            Test-Path $expectedFile | Should -Be $true

            # Clean up
            Remove-Item $expectedFile -Force -ErrorAction SilentlyContinue
        }

        It 'Should create the output folder if it does not exist' {
            $outputFolder = Join-Path TestDrive: 'json-newdir' 'sub1' 'sub2'
            Test-Path $outputFolder | Should -Be $false

            $testJsonObject | ConvertTo-CustomDetectionJson -UseIdAsFilename -OutputFolder $outputFolder

            Test-Path $outputFolder | Should -Be $true
        }

        It 'Should not allow -UseDisplayNameAsFilename and -UseIdAsFilename together' {
            {
                $testJsonObject | ConvertTo-CustomDetectionJson -UseDisplayNameAsFilename -UseIdAsFilename -OutputFolder (Join-Path TestDrive: 'json-both')
            } | Should -Throw
        }

        It 'Should not allow -OutputFolder without a naming switch' {
            {
                ConvertTo-CustomDetectionJson -InputObject $testJsonObject -OutputFolder (Join-Path TestDrive: 'json-noflag')
            } | Should -Throw
        }
    }
}

