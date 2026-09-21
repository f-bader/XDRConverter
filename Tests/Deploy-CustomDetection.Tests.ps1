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
        # The module keeps the id cache between calls, so every test starts from an empty one
        InModuleScope XDRConverter { $script:DetectionIdsCache = @{ Data = $null; ExpiresAt = [datetime]::MinValue; FailedAt = $null } }
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

        It 'Should reject an incomplete account mapping from JSON input' {
            $testJson = @"
{
    "id": "rule-81fb771a-c57e-41b8-9905-63dbf267c13f",
    "displayName": "TEST-IncompleteAccount",
    "status": "disabled",
    "detectionAction": {
        "alertTemplate": {
            "title": "Test",
            "description": "Test",
            "severity": "informational",
            "tactics": [{ "tactic": "Execution" }],
            "entityMappings": {
                "accounts": [{ "nameColumn": "AccountName" }],
                "hosts": [{ "deviceIdColumn": "DeviceId" }]
            }
        }
    },
    "queryCondition": { "queryText": "DeviceEvents | take 0" },
    "schedule": { "frequency": "PT1H" }
}
"@
            $tempFile = Join-Path TestDrive: 'incomplete-account.json'
            $testJson | Out-File -FilePath $tempFile -Encoding UTF8

            { Deploy-CustomDetection -InputFile $tempFile -Confirm:$false } | Should -Throw '*aadUserIdColumn*'
        }

        It 'Should reject an array-valued custom detail from JSON input before any request' {
            $testJson = @"
{
    "id": "rule-81fb771a-c57e-41b8-9905-63dbf267c13f",
    "displayName": "TEST-ArrayCustomDetail",
    "status": "disabled",
    "detectionAction": {
        "alertTemplate": {
            "title": "Test",
            "description": "Test",
            "severity": "informational",
            "tactics": [{ "tactic": "Execution" }],
            "customDetails": { "Bad": ["First", "Second"] }
        }
    },
    "queryCondition": { "queryText": "DeviceEvents | take 0" },
    "schedule": { "frequency": "PT1H" }
}
"@
            $tempFile = Join-Path TestDrive: 'array-custom-detail.json'
            $testJson | Out-File -FilePath $tempFile -Encoding UTF8

            { Deploy-CustomDetection -InputFile $tempFile -Confirm:$false } | Should -Throw "*customDetails entry 'Bad'*"
            Should -Not -Invoke Invoke-MgGraphRequest -ModuleName XDRConverter
        }

        It 'Should reject a numeric device group from JSON input before any request' {
            $testJson = @"
{
    "id": "rule-81fb771a-c57e-41b8-9905-63dbf267c13f",
    "displayName": "TEST-NumericDeviceGroup",
    "status": "disabled",
    "detectionAction": {
        "alertTemplate": {
            "title": "Test",
            "description": "Test",
            "severity": "informational",
            "tactics": [{ "tactic": "Execution" }]
        },
        "organizationalScope": { "deviceGroups": [123] }
    },
    "queryCondition": { "queryText": "DeviceEvents | take 0" },
    "schedule": { "frequency": "PT1H" }
}
"@
            $tempFile = Join-Path TestDrive: 'numeric-device-group.json'
            $testJson | Out-File -FilePath $tempFile -Encoding UTF8

            { Deploy-CustomDetection -InputFile $tempFile -Confirm:$false } | Should -Throw "*organizationalScope entry '123'*"
            Should -Not -Invoke Invoke-MgGraphRequest -ModuleName XDRConverter
        }

        It 'Should drop an incomplete account mapping from JSON input when -SkipIdentifierValidation is set' {
            $testJson = @"
{
    "id": "rule-81fb771a-c57e-41b8-9905-63dbf267c13f",
    "displayName": "TEST-IncompleteAccountSkipped",
    "status": "disabled",
    "detectionAction": {
        "alertTemplate": {
            "title": "Test",
            "description": "Test",
            "severity": "informational",
            "tactics": [{ "tactic": "Execution" }],
            "entityMappings": {
                "accounts": [{ "nameColumn": "AccountName" }],
                "hosts": [{ "deviceIdColumn": "DeviceId" }]
            }
        }
    },
    "queryCondition": { "queryText": "DeviceEvents | take 0" },
    "schedule": { "frequency": "PT1H" }
}
"@
            $tempFile = Join-Path TestDrive: 'incomplete-account-skipped.json'
            $testJson | Out-File -FilePath $tempFile -Encoding UTF8
            Mock Invoke-MgGraphRequest { return @{ id = 'new-rule-id' } } -ModuleName XDRConverter

            $result = Deploy-CustomDetection -InputFile $tempFile -SkipIdentifierValidation -Confirm:$false -WarningVariable warning -WarningAction SilentlyContinue
            $result.Action | Should -Be 'Created'
            "$warning" | Should -Match 'aadUserIdColumn'
            Should -Invoke Invoke-MgGraphRequest -ModuleName XDRConverter -ParameterFilter {
                $Method -eq 'POST' -and $Body.detectionAction.alertTemplate.entityMappings.Keys -notcontains 'accounts'
            }
        }

        It 'Should warn when JSON status contradicts isEnabled' {
            $testJson = @"
{
    "id": "rule-81fb771a-c57e-41b8-9905-63dbf267c13f",
    "displayName": "TEST-StatusContradiction",
    "isEnabled": false,
    "status": "enabled",
    "detectionAction": {
        "alertTemplate": {
            "title": "Test",
            "description": "Test",
            "severity": "informational",
            "tactics": [{ "tactic": "Execution" }]
        }
    },
    "queryCondition": { "queryText": "DeviceEvents | take 0" },
    "schedule": { "frequency": "PT1H" }
}
"@
            $tempFile = Join-Path TestDrive: 'status-contradiction.json'
            $testJson | Out-File -FilePath $tempFile -Encoding UTF8
            Mock Invoke-MgGraphRequest { return @{ id = 'new-rule-id' } } -ModuleName XDRConverter

            $result = Deploy-CustomDetection -InputFile $tempFile -Confirm:$false -WarningVariable warning -WarningAction SilentlyContinue
            $result.Action | Should -Be 'Created'
            "$warning" | Should -Match 'contradicts status'
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
            $script:CapturedBody.status | Should -Be 'disabled'
            $script:CapturedBody.Keys | Should -Not -Contain 'isEnabled'
        }
    }

    Context 'Request body shape' {

        BeforeEach {
            Mock Invoke-MgGraphRequest {
                $script:CapturedBody = $Body
                $script:CapturedMethod = $Method
                return @{ id = 'new-rule-id' }
            } -ModuleName XDRConverter
            InModuleScope XDRConverter {
                $script:DetectionIdsCache = @{ Data = @([PSCustomObject]@{ Id = 'stale' }); ExpiresAt = [datetime]::UtcNow.AddHours(1) }
            }
        }

        It 'Should POST a letter-prefixed id derived from the guid with the current property names' {
            $testYaml = @"
guid: 81fb771a-c57e-41b8-9905-63dbf267c13f
ruleName: BODY-Create
isEnabled: true
alertTitle: Test
frequency: 1H
alertSeverity: Medium
alertDescription: Test
alertCategory: DefenseEvasion
mitreTechniques:
  - T1562.001
impactedEntities:
  - entityType: Machine
    entityIdentifier: DeviceId
actions:
  - actionType: IsolateMachine
queryText: DeviceEvents
"@
            $tempFile = Join-Path TestDrive: 'body-create.yaml'
            $testYaml | Out-File -FilePath $tempFile -Encoding UTF8

            $result = Deploy-CustomDetection -InputFile $tempFile -Confirm:$false
            $result.Action | Should -Be 'Created'
            $result.DetectorId | Should -Be '81fb771a-c57e-41b8-9905-63dbf267c13f'
            $script:CapturedMethod | Should -Be 'POST'

            $body = $script:CapturedBody
            $body.id | Should -Be 'rule-81fb771a-c57e-41b8-9905-63dbf267c13f'
            $body.status | Should -Be 'enabled'
            $body.schedule.frequency | Should -Be 'PT1H'
            $body.detectionAction.alertTemplate.tactics[0].tactic | Should -Be 'DefenseEvasion'
            $body.detectionAction.alertTemplate.entityMappings.hosts[0].deviceIdColumn | Should -Be 'DeviceId'
            $body.detectionAction.automatedActions.isolateDevices[0].isolationType | Should -Be 'full'
            $body.Keys | Should -Not -Contain 'detectorId'
            $body.Keys | Should -Not -Contain 'isEnabled'
            $body.schedule.Keys | Should -Not -Contain 'period'
            $body.detectionAction.Keys | Should -Not -Contain 'responseActions'
        }

        It 'Should hand the Graph client a body without PSObject-wrapped values' {
            $testYaml = @"
guid: 81fb771a-c57e-41b8-9905-63dbf267c13f
ruleName: BODY-Plain
alertTitle: Test
frequency: 1H
alertSeverity: Medium
alertDescription: Test
alertCategory: DefenseEvasion
mitreTechniques:
  - T1562.001
impactedEntities:
  - entityType: Machine
    entityIdentifier: DeviceId
actions:
  - actionType: IsolateMachine
queryText: DeviceEvents
"@
            $tempFile = Join-Path TestDrive: 'body-plain.yaml'
            $testYaml | Out-File -FilePath $tempFile -Encoding UTF8

            Deploy-CustomDetection -InputFile $tempFile -Confirm:$false | Out-Null

            function Find-WrappedValue {
                param($Value, [string]$Path)
                if ($null -eq $Value) { return }
                if ($Value -is [string] -or $Value -is [ValueType]) {
                    if ($Value -is [psobject]) { return $Path }
                    return
                }
                if ($Value -is [System.Collections.IDictionary]) {
                    foreach ($k in $Value.Keys) { Find-WrappedValue -Value $Value[$k] -Path "$Path.$k" }
                    return
                }
                if ($Value -is [System.Collections.IEnumerable]) {
                    $i = 0
                    foreach ($item in $Value) { Find-WrappedValue -Value $item -Path "$Path[$i]"; $i++ }
                    return
                }
                foreach ($p in $Value.PSObject.Properties) { Find-WrappedValue -Value $p.Value -Path "$Path.$($p.Name)" }
            }
            $wrapped = @(Find-WrappedValue -Value $script:CapturedBody -Path 'body')
            $wrapped | Should -BeNullOrEmpty
        }

        It 'Should append the created rule to the id cache' {
            Mock Invoke-MgGraphRequest { return @{ id = 'new-id'; detectorId = 'assigned-1' } } -ModuleName XDRConverter
            InModuleScope XDRConverter {
                $script:DetectionIdsCache = @{
                    Data      = @([PSCustomObject]@{ Id = '77'; DetectorId = 'assigned-0'; DisplayName = 'Other'; DescriptionTag = $null; TagPrefix = $null })
                    ExpiresAt = [datetime]::UtcNow.AddHours(1)
                }
            }
            $testYaml = @"
guid: 81fb771a-c57e-41b8-9905-63dbf267c13f
ruleName: BODY-Cache
alertTitle: Test
frequency: 1H
alertSeverity: Medium
alertDescription: Test
alertCategory: DefenseEvasion
queryText: DeviceEvents
"@
            $tempFile = Join-Path TestDrive: 'body-cache.yaml'
            $testYaml | Out-File -FilePath $tempFile -Encoding UTF8

            Deploy-CustomDetection -InputFile $tempFile -DescriptionTagPrefix 'PREFIX' -Confirm:$false | Out-Null
            InModuleScope XDRConverter {
                @($script:DetectionIdsCache.Data).Count | Should -Be 2
                $entry = $script:DetectionIdsCache.Data | Where-Object Id -eq 'new-id'
                $entry.DetectorId | Should -Be 'assigned-1'
                $entry.DisplayName | Should -Be 'BODY-Cache'
                $entry.DescriptionTag | Should -Be '81fb771a-c57e-41b8-9905-63dbf267c13f'
                $entry.TagPrefix | Should -Be 'PREFIX'
            }
            InModuleScope XDRConverter { $script:DetectionIdsCache = @{ Data = $null; ExpiresAt = [datetime]::MinValue } }
        }

        It 'Should append the created rule to a cache that holds an empty list' {
            Mock Invoke-MgGraphRequest { return @{ id = 'new-id' } } -ModuleName XDRConverter
            InModuleScope XDRConverter {
                $script:DetectionIdsCache = @{ Data = @(); ExpiresAt = [datetime]::UtcNow.AddHours(1) }
            }
            $testYaml = @"
guid: 81fb771a-c57e-41b8-9905-63dbf267c13f
ruleName: BODY-Cache-Empty
alertTitle: Test
frequency: 1H
alertSeverity: Medium
alertDescription: Test
alertCategory: DefenseEvasion
queryText: DeviceEvents
"@
            $tempFile = Join-Path TestDrive: 'body-cache-empty.yaml'
            $testYaml | Out-File -FilePath $tempFile -Encoding UTF8

            Deploy-CustomDetection -InputFile $tempFile -Confirm:$false | Out-Null
            InModuleScope XDRConverter {
                @($script:DetectionIdsCache.Data).Id | Should -Be @('new-id')
            }
            InModuleScope XDRConverter { $script:DetectionIdsCache = @{ Data = $null; ExpiresAt = [datetime]::MinValue } }
        }

        It 'Should find an untagged rule by display name when -NoDescriptionTag is set' {
            InModuleScope XDRConverter {
                $script:DetectionIdsCache = @{
                    Data      = @([PSCustomObject]@{ Id = '77'; DetectorId = '77'; DisplayName = 'BODY-NoTag'; DescriptionTag = $null; TagPrefix = $null })
                    ExpiresAt = [datetime]::UtcNow.AddHours(1)
                }
            }
            Mock Get-CustomDetection {
                return @{
                    id              = '77'
                    displayName     = 'BODY-NoTag'
                    status          = 'enabled'
                    detectionAction = @{ alertTemplate = @{ title = 'Old'; description = 'Old'; severity = 'low'; tactics = @(@{ tactic = 'DefenseEvasion' }) } }
                    queryCondition  = @{ queryText = 'DeviceEvents' }
                    schedule        = @{ frequency = 'PT1H' }
                }
            } -ModuleName XDRConverter

            $testYaml = @"
guid: 4d3a1c81-d784-4ef2-9e17-18d2d8e455f6
ruleName: BODY-NoTag
alertTitle: Test
frequency: 1H
alertSeverity: Medium
alertDescription: Test
alertCategory: DefenseEvasion
queryText: DeviceEvents
"@
            $tempFile = Join-Path TestDrive: 'body-notag.yaml'
            $testYaml | Out-File -FilePath $tempFile -Encoding UTF8

            $result = Deploy-CustomDetection -InputFile $tempFile -NoDescriptionTag -Confirm:$false -WarningVariable w -WarningAction SilentlyContinue
            $result.Action | Should -Be 'Updated'
            $result.RuleId | Should -Be '77'
            $script:CapturedMethod | Should -Be 'PATCH'
            "$w" | Should -Match 'display name'
        }

        It 'Should PATCH without the id property' {
            $guid = '81fb771a-c57e-41b8-9905-63dbf267c13f'
            Mock Get-CustomDetectionIdByDetectorId { return '48' } -ModuleName XDRConverter
            Mock Get-CustomDetection {
                return @{
                    id              = '48'
                    displayName     = 'OLD'
                    status          = 'enabled'
                    detectionAction = @{
                        alertTemplate       = @{ title = 'Old'; description = "Old [$guid]"; severity = 'low'; tactics = @(@{ tactic = 'DefenseEvasion' }); entityMappings = @{ hosts = @(@{ deviceIdColumn = 'DeviceId' }); accounts = $null } }
                        automatedActions    = @{ isolateDevices = @(@{ deviceIdColumn = 'DeviceId'; isolationType = 'full' }); allowFiles = $null }
                        organizationalScope = @{ deviceGroups = @('Servers') }
                    }
                    queryCondition  = @{ queryText = 'DeviceEvents' }
                    schedule        = @{ frequency = 'PT1H' }
                }
            } -ModuleName XDRConverter

            $testYaml = @"
guid: $guid
ruleName: BODY-Patch
alertTitle: Test
frequency: 1H
alertSeverity: Medium
alertDescription: Test
alertCategory: DefenseEvasion
queryText: DeviceEvents
"@
            $tempFile = Join-Path TestDrive: 'body-patch.yaml'
            $testYaml | Out-File -FilePath $tempFile -Encoding UTF8

            $result = Deploy-CustomDetection -InputFile $tempFile -Confirm:$false
            $result.Action | Should -Be 'Updated'
            $result.RuleId | Should -Be '48'
            $script:CapturedMethod | Should -Be 'PATCH'
            $script:CapturedBody.Keys | Should -Not -Contain 'id'
            $script:CapturedBody.displayName | Should -Be 'BODY-Patch'

            # A collection the remote rule carries and the file does not is sent empty, so it is cleared server-side
            @($script:CapturedBody.detectionAction.automatedActions.Keys) | Should -Be @('isolateDevices')
            @($script:CapturedBody.detectionAction.automatedActions.isolateDevices).Count | Should -Be 0
            @($script:CapturedBody.detectionAction.alertTemplate.entityMappings.Keys) | Should -Be @('hosts')
            @($script:CapturedBody.detectionAction.alertTemplate.entityMappings.hosts).Count | Should -Be 0
            @($script:CapturedBody.detectionAction.organizationalScope.deviceGroups).Count | Should -Be 0
        }

        It 'Should POST only the populated collections' {
            $testYaml = @"
guid: 81fb771a-c57e-41b8-9905-63dbf267c13f
ruleName: BODY-Post-Sparse
alertTitle: Test
frequency: 1H
alertSeverity: Medium
alertDescription: Test
alertCategory: DefenseEvasion
queryText: DeviceEvents
"@
            $tempFile = Join-Path TestDrive: 'body-post-sparse.yaml'
            $testYaml | Out-File -FilePath $tempFile -Encoding UTF8

            Deploy-CustomDetection -InputFile $tempFile -Confirm:$false | Out-Null
            $script:CapturedMethod | Should -Be 'POST'
            $script:CapturedBody.detectionAction.Keys | Should -Not -Contain 'automatedActions'
            $script:CapturedBody.detectionAction.Keys | Should -Not -Contain 'organizationalScope'
            $script:CapturedBody.detectionAction.alertTemplate.Keys | Should -Not -Contain 'entityMappings'
        }

        It 'Should leave an autoDisabled rule alone and warn when the file is otherwise unchanged' {
            $guid = '81fb771a-c57e-41b8-9905-63dbf267c13f'
            Mock Get-CustomDetectionIdByDetectorId { return '48' } -ModuleName XDRConverter
            Mock Get-CustomDetection {
                return @{
                    id              = '48'
                    displayName     = 'AUTO'
                    isEnabled       = $false
                    status          = 'autoDisabled'
                    detectionAction = @{
                        alertTemplate = @{
                            title       = 'Test'
                            description = "Test [$guid]"
                            severity    = 'medium'
                            tactics     = @(@{ tactic = 'DefenseEvasion' })
                        }
                    }
                    queryCondition  = @{ queryText = 'DeviceEvents' }
                    schedule        = @{ frequency = 'PT1H' }
                }
            } -ModuleName XDRConverter
            Mock Invoke-MgGraphRequest { $script:ForceMethod = $Method; $script:ForceBody = $Body } -ModuleName XDRConverter

            $testYaml = @"
guid: $guid
ruleName: AUTO
isEnabled: true
alertTitle: Test
frequency: 1H
alertSeverity: Medium
alertDescription: Test
alertCategory: DefenseEvasion
queryText: DeviceEvents
"@
            $tempFile = Join-Path TestDrive: 'auto-disabled.yaml'
            $testYaml | Out-File -FilePath $tempFile -Encoding UTF8

            $result = Deploy-CustomDetection -InputFile $tempFile -Confirm:$false -WarningVariable warning -WarningAction SilentlyContinue
            $result.Action | Should -Be 'Skipped'
            "$warning" | Should -Match 'autoDisabled'
            Should -Invoke Invoke-MgGraphRequest -ModuleName XDRConverter -Times 0 -Exactly -ParameterFilter { $Method -eq 'PATCH' }
        }

        It 'Should enable an autoDisabled rule again with -Force' {
            $guid = '81fb771a-c57e-41b8-9905-63dbf267c13f'
            $script:ForceMethod = $null
            $script:ForceBody = $null
            Mock Get-CustomDetectionIdByDetectorId { return '48' } -ModuleName XDRConverter
            Mock Get-CustomDetection {
                return @{
                    id              = '48'
                    displayName     = 'AUTO'
                    isEnabled       = $false
                    status          = 'autoDisabled'
                    detectionAction = @{
                        alertTemplate = @{
                            title       = 'Test'
                            description = "Test [$guid]"
                            severity    = 'medium'
                            tactics     = @(@{ tactic = 'DefenseEvasion' })
                        }
                    }
                    queryCondition  = @{ queryText = 'DeviceEvents' }
                    schedule        = @{ frequency = 'PT1H' }
                }
            } -ModuleName XDRConverter
            Mock Invoke-MgGraphRequest { $script:ForceMethod = $Method; $script:ForceBody = $Body } -ModuleName XDRConverter

            $testYaml = @"
guid: $guid
ruleName: AUTO
isEnabled: true
alertTitle: Test
frequency: 1H
alertSeverity: Medium
alertDescription: Test
alertCategory: DefenseEvasion
queryText: DeviceEvents
"@
            $tempFile = Join-Path TestDrive: 'auto-disabled-force.yaml'
            $testYaml | Out-File -FilePath $tempFile -Encoding UTF8

            $result = Deploy-CustomDetection -InputFile $tempFile -Force -Confirm:$false -WarningAction SilentlyContinue
            $result.Action | Should -Be 'Updated'
            $script:ForceMethod | Should -Be 'PATCH'
            $script:ForceBody.status | Should -Be 'enabled'
        }

        It 'Should skip an unchanged rule returned in the dual old-plus-new shape' {
            $guid = '81fb771a-c57e-41b8-9905-63dbf267c13f'
            Mock Get-CustomDetectionIdByDetectorId { return '48' } -ModuleName XDRConverter
            Mock Get-CustomDetection {
                return @{
                    id              = '48'
                    detectorId      = 'f687512c-0654-4999-a0ac-d5906ffc3972'
                    displayName     = 'DUAL'
                    isEnabled       = $true
                    status          = 'enabled'
                    detectionAction = @{
                        alertTemplate    = @{
                            title           = 'Test'
                            description     = "Test [$guid]"
                            severity        = 'medium'
                            category        = 'DefenseEvasion'
                            mitreTechniques = @('T1562', 'T1562.001')
                            tactics         = @(@{ tactic = 'DefenseEvasion'; techniques = @(@{ technique = 'T1562'; subTechniques = @('T1562.001') }) })
                            impactedAssets  = @(@{ '@odata.type' = '#microsoft.graph.security.impactedDeviceAsset'; identifier = 'deviceId' })
                            entityMappings  = @{ hosts = @(@{ deviceIdColumn = 'DeviceId'; nameColumn = '' }); accounts = $null }
                        }
                        responseActions  = @(@{ '@odata.type' = '#microsoft.graph.security.isolateDeviceResponseAction'; identifier = 'deviceId'; isolationType = 'full' })
                        automatedActions = @{ isolateDevices = @(@{ deviceIdColumn = 'DeviceId'; isolationType = 'full' }); allowFiles = $null }
                    }
                    queryCondition  = @{ queryText = 'DeviceEvents' }
                    schedule        = @{ period = '1H'; frequency = 'PT1H' }
                }
            } -ModuleName XDRConverter

            $testYaml = @"
guid: $guid
ruleName: DUAL
isEnabled: true
alertTitle: Test
frequency: 1H
alertSeverity: Medium
alertDescription: Test
alertCategory: DefenseEvasion
mitreTechniques:
  - T1562.001
impactedEntities:
  - entityType: Machine
    entityIdentifier: DeviceId
actions:
  - actionType: IsolateMachine
queryText: DeviceEvents
"@
            $tempFile = Join-Path TestDrive: 'body-dual.yaml'
            $testYaml | Out-File -FilePath $tempFile -Encoding UTF8

            $result = Deploy-CustomDetection -InputFile $tempFile -Confirm:$false
            $result.Action | Should -Be 'Skipped'
            Should -Not -Invoke Invoke-MgGraphRequest -ModuleName XDRConverter
        }

        It 'Should deploy a corpus-style file through the consumer call shape' {
            $testYaml = @"
actions:
- actionType: IsolateMachine
  additionalFields:
    isolationType: Full
alertCategory: InitialAccess
alertDescription: Desc
alertRecommendedAction: |
  Do things.
alertSeverity: High
alertTitle: '[X] Title'
frequency: 0
guid: 9b5a2396-03e3-4bdb-8355-8e3fb3a3d22d
impactedEntities:
- entityIdentifier: DeviceId
  entityType: Machine
- entityIdentifier: InitiatingProcessAccountUpn
  entityType: User
isEnabled: true
organizationalScope: []
queryText: |
  DeviceFileEvents
  | take 1
ruleName: CORPUS-Rule
"@
            $tempFile = Join-Path TestDrive: 'corpus.yml'
            $testYaml | Out-File -FilePath $tempFile -Encoding UTF8

            $params = @{
                InputFile                    = $tempFile
                DescriptionTagPrefix         = 'PREFIX'
                SkipIdentifierValidation     = $true
                SkipMitreTechniqueValidation = $true
            }
            $result = Deploy-CustomDetection @params -Confirm:$false
            $result.Action | Should -Be 'Created'
            $script:CapturedBody.schedule.frequency | Should -Be 'PT0S'
            $script:CapturedBody.detectionAction.alertTemplate.description | Should -Match '\[PREFIX:9b5a2396-03e3-4bdb-8355-8e3fb3a3d22d\]$'
            $script:CapturedBody.detectionAction.alertTemplate.entityMappings.accounts[0].upnColumn | Should -Be 'InitiatingProcessAccountUpn'
            $script:CapturedBody.detectionAction.Keys | Should -Not -Contain 'organizationalScope'
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

        It 'Should update when only the response actions changed' {
            $guid = '81fb771a-c57e-41b8-9905-63dbf267c13f'
            Mock Get-CustomDetectionIdByDetectorId { return 'existing-id' } -ModuleName XDRConverter
            Mock Get-CustomDetection {
                return @{
                    id              = 'existing-id'
                    detectorId      = $guid
                    displayName     = 'PREFIX-TEST'
                    isEnabled       = $true
                    detectionAction = @{
                        alertTemplate   = @{
                            title       = 'Test'
                            description = "My desc [$guid]"
                            severity    = 'medium'
                            category    = 'DefenseEvasion'
                        }
                        responseActions = @(
                            @{ '@odata.type' = '#microsoft.graph.security.isolateDeviceResponseAction'; identifier = 'deviceId'; isolationType = 'full' }
                        )
                    }
                    queryCondition  = @{ queryText = 'DeviceEvents' }
                    schedule        = @{ period = '0' }
                }
            } -ModuleName XDRConverter
            Mock Invoke-MgGraphRequest {} -ModuleName XDRConverter

            $testYaml = @"
guid: $guid
ruleName: PREFIX-TEST
isEnabled: true
alertTitle: Test
frequency: 0
alertSeverity: Medium
alertDescription: My desc
alertCategory: DefenseEvasion
actions:
  - actionType: RestrictAppExecution
queryText: DeviceEvents
"@
            $tempFile = Join-Path TestDrive: 'update-actions-only.yaml'
            $testYaml | Out-File -FilePath $tempFile -Encoding UTF8

            $result = Deploy-CustomDetection -InputFile $tempFile -Confirm:$false
            $result.Action | Should -Be 'Updated'
            Should -Invoke Invoke-MgGraphRequest -ModuleName XDRConverter -ParameterFilter { $Method -eq 'PATCH' }
        }

        It 'Should update a rule that carries the guid only in its description tag' {
            $guid = '81fb771a-c57e-41b8-9905-63dbf267c13f'
            # Only the rule the tag names answers. Any other id falls through to the empty default mock
            Mock Get-CustomDetection {
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
            } -ModuleName XDRConverter -ParameterFilter { $DetectionId -eq 'found-by-desc' }
            Mock Invoke-MgGraphRequest {} -ModuleName XDRConverter
            Mock Get-CustomDetectionIds {
                return @(
                    @{
                        Id = 'found-by-desc'
                        DetectorId = 'different-detector'
                        DescriptionTag = $guid
                        TagPrefix = $null
                    }
                )
            } -ModuleName XDRConverter

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
            Should -Invoke Get-CustomDetection -ModuleName XDRConverter -Times 0 -Exactly -ParameterFilter { $DetectionId -eq "rule-$guid" }
            Should -Invoke Invoke-MgGraphRequest -ModuleName XDRConverter -Times 1 -Exactly -ParameterFilter { $Method -eq 'PATCH' -and $Uri -like '*/found-by-desc' }
        }
    }

    Context 'List unavailable' {
        BeforeEach {
            $script:guid = '81fb771a-c57e-41b8-9905-63dbf267c13f'
            Mock Get-CustomDetectionIdByDetectorId { throw 'The request was canceled due to the configured HttpClient.Timeout of 300 seconds elapsing.' } -ModuleName XDRConverter
            Mock Get-CustomDetectionIdByDescriptionTag { return $null } -ModuleName XDRConverter
            Mock Invoke-MgGraphRequest { return @{ id = 'new-id' } } -ModuleName XDRConverter
            $testYaml = @"
guid: $script:guid
ruleName: TEST-ListDown
isEnabled: true
alertTitle: Test
frequency: 0
alertSeverity: Medium
alertDescription: Test
alertCategory: DefenseEvasion
queryText: DeviceEvents | new
"@
            $script:listDownFile = Join-Path TestDrive: 'list-down.yaml'
            $testYaml | Out-File -FilePath $script:listDownFile -Encoding UTF8
        }

        It 'Updates a rule found by its client id while the list is unavailable' {
            Mock Get-CustomDetection {
                return @{
                    id              = "rule-$script:guid"
                    displayName     = 'TEST-ListDown'
                    status          = 'enabled'
                    detectionAction = @{ alertTemplate = @{ title = 'Old'; description = "Test [$script:guid]"; severity = 'medium'; tactics = @(@{ tactic = 'DefenseEvasion' }) } }
                    queryCondition  = @{ queryText = 'DeviceEvents | old' }
                    schedule        = @{ frequency = 'PT0S' }
                }
            } -ModuleName XDRConverter -ParameterFilter { $DetectionId -eq "rule-$script:guid" }

            $result = Deploy-CustomDetection -InputFile $script:listDownFile -Confirm:$false -WarningVariable warning -WarningAction SilentlyContinue
            $result.Action | Should -Be 'Updated'
            "$warning" | Should -Match 'rule list'
            Should -Invoke Get-CustomDetectionIdByDescriptionTag -ModuleName XDRConverter -Times 0 -Exactly
            Should -Invoke Invoke-MgGraphRequest -ModuleName XDRConverter -Times 1 -Exactly -ParameterFilter { $Method -eq 'PATCH' }
            Should -Invoke Invoke-MgGraphRequest -ModuleName XDRConverter -Times 0 -Exactly -ParameterFilter { $Method -eq 'POST' }
        }

        It 'Stops without creating when the list is unavailable and the client id is not found' {
            Mock Get-CustomDetection { throw 'Response status code does not indicate success: NotFound (Not Found).' } -ModuleName XDRConverter -ParameterFilter { $DetectionId -eq "rule-$script:guid" }

            { Deploy-CustomDetection -InputFile $script:listDownFile -Confirm:$false -WarningAction SilentlyContinue } | Should -Throw '*Nothing was created*'
            Should -Invoke Invoke-MgGraphRequest -ModuleName XDRConverter -Times 0 -Exactly -ParameterFilter { $Method -eq 'POST' }
        }
    }

    Context 'MITRE Technique Validation' {

        It 'Should have SkipMitreTechniqueValidation switch parameter' {
            $cmd = Get-Command -Name 'Deploy-CustomDetection'
            $param = $cmd.Parameters['SkipMitreTechniqueValidation']
            $param | Should -Not -BeNullOrEmpty
            $param.ParameterType.Name | Should -Be 'SwitchParameter'
        }

        It 'Should throw when a technique is not supported for the category' {
            $testYaml = @"
guid: 81fb771a-c57e-41b8-9905-63dbf267c13f
ruleName: TEST-MitreInvalid
isEnabled: true
alertTitle: Test
frequency: 1H
alertSeverity: Medium
alertDescription: Test
alertCategory: Exfiltration
mitreTechniques:
  - T1041
  - T1059.001
queryText: DeviceEvents | take 1
"@
            $tempFile = Join-Path TestDrive: 'mitre-invalid.yaml'
            $testYaml | Out-File -FilePath $tempFile -Encoding UTF8

            { Deploy-CustomDetection -InputFile $tempFile -Confirm:$false } |
                Should -Throw '*not supported by XDR*'
        }

        It 'Should deploy successfully when all techniques are valid for the category' {
            Mock Invoke-MgGraphRequest { return @{ id = 'new-rule-id' } } -ModuleName XDRConverter

            $testYaml = @"
guid: 81fb771a-c57e-41b8-9905-63dbf267c13f
ruleName: TEST-MitreValid
isEnabled: true
alertTitle: Test
frequency: 1H
alertSeverity: Medium
alertDescription: Test
alertCategory: Exfiltration
mitreTechniques:
  - T1041
  - T1048
queryText: DeviceEvents | take 1
"@
            $tempFile = Join-Path TestDrive: 'mitre-valid.yaml'
            $testYaml | Out-File -FilePath $tempFile -Encoding UTF8

            $result = Deploy-CustomDetection -InputFile $tempFile -Confirm:$false
            $result.Action | Should -Be 'Created'
        }

                It 'Should surface the warning when the category has no XDR mapping' {
                        Mock Invoke-MgGraphRequest { return @{ id = 'new-rule-id' } } -ModuleName XDRConverter

                    $testJson = @"
        {
            "id": "rule-81fb771a-c57e-41b8-9905-63dbf267c13f",
            "displayName": "TEST-MitreUnmapped",
            "status": "disabled",
            "detectionAction": {
                "alertTemplate": {
                    "title": "Test",
                    "description": "Test",
                    "severity": "informational",
                    "tactics": [{ "tactic": "SuspiciousActivity", "techniques": [{ "technique": "T9999" }] }]
                }
            },
            "queryCondition": { "queryText": "DeviceEvents | take 0" },
            "schedule": { "frequency": "PT1H" }
        }
"@
                    $tempFile = Join-Path TestDrive: 'mitre-unmapped.json'
                    $testJson | Out-File -FilePath $tempFile -Encoding UTF8

                    $result = Deploy-CustomDetection -InputFile $tempFile -Confirm:$false -WarningVariable warning -WarningAction SilentlyContinue
                    $result.Action | Should -Be 'Created'
                    "$warning" | Should -Match 'not present in the XDR technique mapping'
                }

        It 'Should bypass validation and deploy when -SkipMitreTechniqueValidation is set' {
            Mock Invoke-MgGraphRequest { return @{ id = 'new-rule-id' } } -ModuleName XDRConverter

            $testYaml = @"
guid: 81fb771a-c57e-41b8-9905-63dbf267c13f
ruleName: TEST-MitreSkip
isEnabled: true
alertTitle: Test
frequency: 1H
alertSeverity: Medium
alertDescription: Test
alertCategory: Exfiltration
mitreTechniques:
  - T1041
  - T1059.001
queryText: DeviceEvents | take 1
"@
            $tempFile = Join-Path TestDrive: 'mitre-skip.yaml'
            $testYaml | Out-File -FilePath $tempFile -Encoding UTF8

            $result = Deploy-CustomDetection -InputFile $tempFile -SkipMitreTechniqueValidation -Confirm:$false
            $result.Action | Should -Be 'Created'
        }

        It 'Should deploy successfully when no mitreTechniques are defined' {
            Mock Invoke-MgGraphRequest { return @{ id = 'new-rule-id' } } -ModuleName XDRConverter

            $testYaml = @"
guid: 81fb771a-c57e-41b8-9905-63dbf267c13f
ruleName: TEST-MitreNone
isEnabled: true
alertTitle: Test
frequency: 1H
alertSeverity: Medium
alertDescription: Test
alertCategory: DefenseEvasion
queryText: DeviceEvents | take 1
"@
            $tempFile = Join-Path TestDrive: 'mitre-none.yaml'
            $testYaml | Out-File -FilePath $tempFile -Encoding UTF8

            { Deploy-CustomDetection -InputFile $tempFile -Confirm:$false } | Should -Not -Throw
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

    Context 'Direct lookup by client id' {

        BeforeEach {
            $script:directYaml = @"
guid: 81fb771a-c57e-41b8-9905-63dbf267c13f
ruleName: TEST-Direct
isEnabled: true
alertTitle: Direct Alert
frequency: 1H
alertSeverity: Low
alertDescription: Direct description
alertCategory: Execution
queryText: DeviceEvents | take 1
"@
            $script:directFile = Join-Path TestDrive: 'direct.yaml'
            $script:directYaml | Out-File -FilePath $script:directFile -Encoding UTF8
            Mock Get-CustomDetectionIdByDescriptionTag { return $null } -ModuleName XDRConverter
            Mock Invoke-MgGraphRequest { return @{ id = 'rule-81fb771a-c57e-41b8-9905-63dbf267c13f' } } -ModuleName XDRConverter
        }

        It 'Finds a rule through its client id when the list does not carry it' {
            Mock Get-CustomDetection {
                return @{
                    id              = 'rule-81fb771a-c57e-41b8-9905-63dbf267c13f'
                    displayName     = 'TEST-Direct'
                    status          = 'enabled'
                    queryCondition  = @{ queryText = 'DeviceEvents | take 2' }
                    schedule        = @{ frequency = 'PT1H' }
                    detectionAction = @{ alertTemplate = @{ title = 'Direct Alert'; description = 'Direct description [81fb771a-c57e-41b8-9905-63dbf267c13f]'; severity = 'low'; tactics = @(@{ tactic = 'Execution' }) } }
                }
            } -ModuleName XDRConverter -ParameterFilter { $DetectionId -eq 'rule-81fb771a-c57e-41b8-9905-63dbf267c13f' }

            $result = Deploy-CustomDetection -InputFile $script:directFile -Confirm:$false
            $result.Action | Should -Be 'Updated'
            $result.RuleId | Should -Be 'rule-81fb771a-c57e-41b8-9905-63dbf267c13f'
            Should -Invoke Invoke-MgGraphRequest -ModuleName XDRConverter -ParameterFilter { $Method -eq 'PATCH' } -Times 1 -Exactly
            Should -Invoke Invoke-MgGraphRequest -ModuleName XDRConverter -ParameterFilter { $Method -eq 'POST' } -Times 0 -Exactly
        }

        It 'Creates the rule when the direct lookup answers not found' {
            Mock Get-CustomDetection { throw 'Response status code does not indicate success: NotFound (Not Found).' } -ModuleName XDRConverter -ParameterFilter { $DetectionId -eq 'rule-81fb771a-c57e-41b8-9905-63dbf267c13f' }

            $result = Deploy-CustomDetection -InputFile $script:directFile -Confirm:$false
            $result.Action | Should -Be 'Created'
            Should -Invoke Invoke-MgGraphRequest -ModuleName XDRConverter -ParameterFilter { $Method -eq 'POST' } -Times 1 -Exactly
        }

        It 'Fails when the direct lookup fails for another reason' {
            Mock Get-CustomDetection { throw 'Response status code does not indicate success: Forbidden (Forbidden).' } -ModuleName XDRConverter -ParameterFilter { $DetectionId -eq 'rule-81fb771a-c57e-41b8-9905-63dbf267c13f' }

            { Deploy-CustomDetection -InputFile $script:directFile -Confirm:$false -ErrorAction Stop } | Should -Throw '*Forbidden*'
            Should -Invoke Invoke-MgGraphRequest -ModuleName XDRConverter -ParameterFilter { $Method -eq 'POST' } -Times 0 -Exactly
        }
    }
}
