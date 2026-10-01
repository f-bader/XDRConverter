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
            $result | Should -Match '"id"'
            $result | Should -Not -Match 'detectorId'
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
            $jsonContent.id | Should -Be 'rule-81fb771a-c57e-41b8-9905-63dbf267c13f'
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
            $result | Should -Match '"status"\s*:\s*"disabled"'
            $result | Should -Not -Match 'isEnabled'
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

            $result.id | Should -Be 'rule-81fb771a-c57e-41b8-9905-63dbf267c13f'
            $result.displayName | Should -Be 'PREFIX-TEST-Rule'
            $result.status | Should -Be 'enabled'
            $result.schedule.frequency | Should -Be 'PT0S'
            $result.detectionAction.alertTemplate.title | Should -Be 'Test Alert Title'
            $result.detectionAction.alertTemplate.severity | Should -Be 'high'
            $result.detectionAction.alertTemplate.recommendedActions | Should -Be 'Investigate immediately'
            @($result.detectionAction.alertTemplate.tactics).Count | Should -Be 1
            $result.detectionAction.alertTemplate.tactics[0].tactic | Should -Be 'DefenseEvasion'
            $techniques = @($result.detectionAction.alertTemplate.tactics[0].techniques)
            ($techniques | Where-Object { $_.technique -eq 'T1070' }).subTechniques | Should -Be @('T1070.001')
            ($techniques | Where-Object { $_.technique -eq 'T1234' }).subTechniques | Should -Be @('T1234.567')
            $result.detectionAction.alertTemplate.entityMappings.hosts[0].deviceIdColumn | Should -Be 'DeviceId'
            $result.queryCondition.queryText | Should -Match 'Test'
            $result.PSObject.Properties.Name | Should -Not -Contain 'detectorId'
            $result.PSObject.Properties.Name | Should -Not -Contain 'isEnabled'
            $result.schedule.PSObject.Properties.Name | Should -Not -Contain 'period'
            $result.detectionAction.alertTemplate.PSObject.Properties.Name | Should -Not -Contain 'category'
            $result.detectionAction.alertTemplate.PSObject.Properties.Name | Should -Not -Contain 'mitreTechniques'
            $result.detectionAction.alertTemplate.PSObject.Properties.Name | Should -Not -Contain 'impactedAssets'
        }

        It 'Should emit the category as a tactic without techniques when none are defined' {
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

            $result = ConvertTo-CustomDetectionJson -InputFile $tempYamlFile | ConvertFrom-Json

            $result.detectionAction.alertTemplate.tactics[0].tactic | Should -Be 'DefenseEvasion'
            $result.detectionAction.alertTemplate.tactics[0].PSObject.Properties.Name | Should -Not -Contain 'techniques'
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

            $actions = $result.detectionAction.automatedActions
            $result.detectionAction.PSObject.Properties.Name | Should -Not -Contain 'responseActions'
            @($actions.PSObject.Properties.Name | Sort-Object) | Should -Be @('collectInvestigationPackages', 'initiateInvestigations', 'isolateDevices', 'restrictAppExecutions', 'runAntivirusScans')

            $actions.isolateDevices[0].deviceIdColumn | Should -Be 'DeviceId'
            $actions.isolateDevices[0].isolationType | Should -Be 'full'
            $actions.collectInvestigationPackages[0].deviceIdColumn | Should -Be 'DeviceId'
            $actions.runAntivirusScans[0].deviceIdColumn | Should -Be 'DeviceId'
            $actions.initiateInvestigations[0].deviceIdColumn | Should -Be 'DeviceId'
            $actions.restrictAppExecutions[0].deviceIdColumn | Should -Be 'DeviceId'
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

            $result.detectionAction.automatedActions.isolateDevices[0].isolationType | Should -Be 'full'
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

            $result.detectionAction.automatedActions.isolateDevices[0].isolationType | Should -Be 'selective'
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

        It 'Should omit automatedActions when no actions are defined' {
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

            $result = ConvertTo-CustomDetectionJson -InputFile $tempYamlFile | ConvertFrom-Json
            $result.detectionAction.PSObject.Properties.Name | Should -Not -Contain 'automatedActions'
            $result.detectionAction.PSObject.Properties.Name | Should -Not -Contain 'responseActions'
        }
    }

    Context 'Schema bridging' {

        BeforeAll {
            function New-YamlFile {
                param([string]$Name, [string]$Content)
                $path = Join-Path TestDrive: $Name
                $Content | Out-File -FilePath $path -Encoding UTF8
                return $path
            }
            $baseYaml = @"
guid: 81fb771a-c57e-41b8-9905-63dbf267c13f
ruleName: BRIDGE-Rule
alertTitle: Bridge
alertSeverity: Medium
alertDescription: Bridge description
alertCategory: Execution
queryText: DeviceEvents | take 1
"@
        }

        It 'Maps legacy frequency <Value> to <Expected>' -ForEach @(
            @{ Value = '1H'; Expected = 'PT1H' }
            @{ Value = '"0"'; Expected = 'PT0S' }
            @{ Value = '24H'; Expected = 'P1D' }
            @{ Value = 'PT3H'; Expected = 'PT3H' }
        ) {
            $file = New-YamlFile -Name "freq-$($Expected).yaml" -Content ($baseYaml + "`nfrequency: $Value")
            $result = ConvertTo-CustomDetectionJson -InputFile $file | ConvertFrom-Json
            $result.schedule.frequency | Should -Be $Expected
        }

        It 'Defaults status to enabled when isEnabled is absent' {
            $file = New-YamlFile -Name 'status-default.yaml' -Content ($baseYaml + "`nfrequency: 1H")
            (ConvertTo-CustomDetectionJson -InputFile $file | ConvertFrom-Json).status | Should -Be 'enabled'
        }

        It 'Lets status win over isEnabled' {
            $file = New-YamlFile -Name 'status-wins.yaml' -Content ($baseYaml + "`nfrequency: 1H`nisEnabled: true`nstatus: disabled")
            (ConvertTo-CustomDetectionJson -InputFile $file -WarningAction SilentlyContinue | ConvertFrom-Json).status | Should -Be 'disabled'
        }

        It 'Lets an explicit tactics list win over alertCategory and mitreTechniques' {
            $yaml = $baseYaml + @"

frequency: 1H
mitreTechniques:
  - T1485
tactics:
  - tactic: Persistence
    techniques:
      - T1547.001
"@
            $file = New-YamlFile -Name 'tactics-win.yaml' -Content $yaml
                        $result = ConvertTo-CustomDetectionJson -InputFile $file -WarningVariable warning -WarningAction SilentlyContinue | ConvertFrom-Json
            @($result.detectionAction.alertTemplate.tactics).Count | Should -Be 1
            $result.detectionAction.alertTemplate.tactics[0].tactic | Should -Be 'Persistence'
            $result.detectionAction.alertTemplate.tactics[0].techniques[0].technique | Should -Be 'T1547'
                        "$warning" | Should -Match 'Both tactics and alertCategory/mitreTechniques'
        }

        It 'Carries a detectorId from the file into the body without a warning' {
            $yaml = @"
guid: 81fb771a-c57e-41b8-9905-63dbf267c13f
detectorId: 7cb0d5af-690e-4f63-b4b9-6b40728cac5f
ruleName: WithDetector
alertTitle: t
frequency: PT1H
alertSeverity: Low
alertDescription: d
alertCategory: Execution
queryText: DeviceEvents
"@
            $file = New-YamlFile -Name 'detector.yaml' -Content $yaml
            $result = ConvertTo-CustomDetectionJson -InputFile $file -WarningVariable warning -WarningAction SilentlyContinue | ConvertFrom-Json
            $result.detectorId | Should -Be '7cb0d5af-690e-4f63-b4b9-6b40728cac5f'
            $result.id | Should -Be 'rule-81fb771a-c57e-41b8-9905-63dbf267c13f'
            "$warning" | Should -Not -Match 'detectorId'
        }

        It 'Throws when more than one tactic is listed because the API accepts a single tactic' {
            $yaml = $baseYaml + @"

frequency: 1H
tactics:
  - tactic: Persistence
  - tactic: Execution
"@
            $file = New-YamlFile -Name 'tactics-multi.yaml' -Content $yaml
            { ConvertTo-CustomDetectionJson -InputFile $file } | Should -Throw '*single tactic*'
        }

        It 'Throws when neither alertCategory nor tactics is present' {
            $yaml = @"
guid: 81fb771a-c57e-41b8-9905-63dbf267c13f
ruleName: BRIDGE-Rule
alertTitle: Bridge
alertSeverity: Medium
alertDescription: Bridge description
frequency: 1H
queryText: DeviceEvents | take 1
"@
            $file = New-YamlFile -Name 'no-category.yaml' -Content $yaml
            { ConvertTo-CustomDetectionJson -InputFile $file } | Should -Throw '*alertCategory*'
        }

        It 'Lets entityMappings win over impactedEntities' {
            $yaml = $baseYaml + @"

frequency: 1H
impactedEntities:
  - entityType: Machine
    entityIdentifier: DeviceId
entityMappings:
  files:
    - sha256Column: SHA256
"@
            $file = New-YamlFile -Name 'entity-wins.yaml' -Content $yaml
                        $result = ConvertTo-CustomDetectionJson -InputFile $file -WarningVariable warning -WarningAction SilentlyContinue | ConvertFrom-Json
            $result.detectionAction.alertTemplate.entityMappings.PSObject.Properties.Name | Should -Be @('files')
            $result.detectionAction.alertTemplate.entityMappings.files[0].sha256Column | Should -Be 'SHA256'
                        "$warning" | Should -Match 'Both entityMappings and impactedEntities'
        }

        It 'Maps a corpus-style rule with mixed-case identifiers and an empty scope' {
            $yaml = $baseYaml + @"

frequency: 0
isEnabled: true
impactedEntities:
  - entityIdentifier: deviceId
    entityType: Machine
  - entityIdentifier: initiatingProcessAccountUpn
    entityType: User
organizationalScope: []
"@
            $file = New-YamlFile -Name 'corpus.yaml' -Content $yaml
            $result = ConvertTo-CustomDetectionJson -InputFile $file | ConvertFrom-Json
            $result.detectionAction.alertTemplate.entityMappings.hosts[0].deviceIdColumn | Should -Be 'DeviceId'
            $result.detectionAction.alertTemplate.entityMappings.accounts[0].upnColumn | Should -Be 'InitiatingProcessAccountUpn'
            $result.detectionAction.PSObject.Properties.Name | Should -Not -Contain 'organizationalScope'
        }

        It 'Wraps organizationalScope names in deviceGroups' {
            $file = New-YamlFile -Name 'scope.yaml' -Content ($baseYaml + "`nfrequency: 1H`norganizationalScope:`n  - Servers`n  - Workstations")
            $result = ConvertTo-CustomDetectionJson -InputFile $file | ConvertFrom-Json
            @($result.detectionAction.organizationalScope.deviceGroups) | Should -Be @('Servers', 'Workstations')
        }

        It 'Emits description and customDetails when given' {
            $file = New-YamlFile -Name 'details.yaml' -Content ($baseYaml + "`nfrequency: 1H`ndescription: Rule note`ncustomDetails:`n  CommandLine: ProcessCommandLine")
            $result = ConvertTo-CustomDetectionJson -InputFile $file | ConvertFrom-Json
            $result.description | Should -Be 'Rule note'
            $result.detectionAction.alertTemplate.customDetails.CommandLine | Should -Be 'ProcessCommandLine'
        }

        It 'Throws when customDetails has more than 20 entries' {
            $details = (1..21 | ForEach-Object { "  Detail$($_): Column$($_)" }) -join "`n"
            $file = New-YamlFile -Name 'details-21.yaml' -Content ($baseYaml + "`nfrequency: 1H`ncustomDetails:`n$details")
            { ConvertTo-CustomDetectionJson -InputFile $file } | Should -Throw '*customDetails*'
        }

        It 'Accepts id as an alias of guid and throws when both differ' {
            $aliasYaml = ($baseYaml -replace 'guid: .*', 'id: 81fb771a-c57e-41b8-9905-63dbf267c13f') + "`nfrequency: 1H"
            $aliasFile = New-YamlFile -Name 'id-alias.yaml' -Content $aliasYaml
            (ConvertTo-CustomDetectionJson -InputFile $aliasFile | ConvertFrom-Json).id | Should -Be 'rule-81fb771a-c57e-41b8-9905-63dbf267c13f'

            $bothFile = New-YamlFile -Name 'id-both.yaml' -Content ($baseYaml + "`nid: 00000000-0000-0000-0000-000000000000`nfrequency: 1H")
            { ConvertTo-CustomDetectionJson -InputFile $bothFile } | Should -Throw '*guid*'
        }

        It 'Accepts an id that already carries the rule prefix' {
            $prefixedYaml = ($baseYaml -replace 'guid: .*', 'id: rule-81fb771a-c57e-41b8-9905-63dbf267c13f') + "`nfrequency: 1H"
            $prefixedFile = New-YamlFile -Name 'id-prefixed.yaml' -Content $prefixedYaml
            (ConvertTo-CustomDetectionJson -InputFile $prefixedFile | ConvertFrom-Json).id | Should -Be 'rule-81fb771a-c57e-41b8-9905-63dbf267c13f'

            $sameFile = New-YamlFile -Name 'id-same.yaml' -Content ($baseYaml + "`nid: rule-81fb771a-c57e-41b8-9905-63dbf267c13f`nfrequency: 1H")
            (ConvertTo-CustomDetectionJson -InputFile $sameFile | ConvertFrom-Json).id | Should -Be 'rule-81fb771a-c57e-41b8-9905-63dbf267c13f'
        }

        It 'Throws a clear message when alertSeverity is missing' {
            $yaml = ($baseYaml -replace 'alertSeverity: Medium\r?\n', '') + "`nfrequency: 1H"
            $file = New-YamlFile -Name 'no-severity.yaml' -Content $yaml
            { ConvertTo-CustomDetectionJson -InputFile $file } | Should -Throw '*alertSeverity*'
        }

        It 'Maps every new action type' {
            $actions = @('StopAndQuarantineFile', 'AllowFile', 'BlockFile', 'DisableUser', 'ForceUserPasswordReset', 'MarkUserAsCompromised', 'HardDeleteEmail', 'SoftDeleteEmail', 'MoveEmailToInbox', 'MoveEmailToJunk', 'MoveEmailToDeletedItems')
            $yaml = $baseYaml + "`nfrequency: 1H`nactions:`n" + (($actions | ForEach-Object { "  - actionType: $_" }) -join "`n")
            $file = New-YamlFile -Name 'actions-new.yaml' -Content $yaml
            $result = ConvertTo-CustomDetectionJson -InputFile $file | ConvertFrom-Json
            @($result.detectionAction.automatedActions.PSObject.Properties.Name).Count | Should -Be 11
            $result.detectionAction.automatedActions.blockFiles[0].sha1Column | Should -Be 'SHA1'
            $result.detectionAction.automatedActions.moveEmailsToJunk[0].recipientColumn | Should -Be 'RecipientEmailAddress'
        }

        It 'Warns on unknown YAML keys' {
            $file = New-YamlFile -Name 'unknown-key.yaml' -Content ($baseYaml + "`nfrequency: 1H`nowner: someone")
            ConvertTo-CustomDetectionJson -InputFile $file -WarningVariable w -WarningAction SilentlyContinue | Out-Null
            $w | Should -Not -BeNullOrEmpty
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

        It 'Should prefer the description tag, then id, over detectorId for -UseIdAsFilename' {
            $outputFolder = Join-Path TestDrive: 'json-id-new'
            $newShape = [PSCustomObject]@{
                id              = '11111111-2222-3333-4444-555555555555'
                displayName     = 'NEW-Rule'
                status          = 'enabled'
                detectionAction = @{ alertTemplate = @{ title = 'T'; severity = 'low'; description = 'D' } }
                queryCondition  = @{ queryText = 'DeviceEvents' }
                schedule        = @{ frequency = 'PT1H' }
            }
            $newShape | ConvertTo-CustomDetectionJson -UseIdAsFilename -OutputFolder $outputFolder
            Test-Path (Join-Path $outputFolder '11111111-2222-3333-4444-555555555555.json') | Should -Be $true

            $tagged = $newShape.PSObject.Copy()
            $tagged.detectionAction = @{ alertTemplate = @{ title = 'T'; severity = 'low'; description = 'D [PREFIX:81fb771a-c57e-41b8-9905-63dbf267c13f]' } }
            $tagged | ConvertTo-CustomDetectionJson -UseIdAsFilename -OutputFolder $outputFolder
            Test-Path (Join-Path $outputFolder '81fb771a-c57e-41b8-9905-63dbf267c13f.json') | Should -Be $true
        }

        It 'Should set status when -Enabled is used on object input' {
            $obj = $testJsonObject.PSObject.Copy()
            $result = $obj | ConvertTo-CustomDetectionJson -Enabled $false | ConvertFrom-Json
            $result.status | Should -Be 'disabled'
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

