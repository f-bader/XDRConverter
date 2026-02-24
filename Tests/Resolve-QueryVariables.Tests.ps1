Describe 'Resolve-QueryVariables' {

    BeforeAll {
        $ModulePath = Split-Path -Path $PSScriptRoot -Parent
        $ModulePath = Join-Path -Path $ModulePath -ChildPath 'src' | Join-Path -ChildPath 'XDRConverter.psd1'
        Import-Module -Name $ModulePath -Force
    }

    AfterAll {
        Remove-Module -Name XDRConverter -Force -ErrorAction SilentlyContinue
    }

    Context 'Variable Replacement' {

        It 'Should replace a simple variable with its value' {
            $paramYaml = @"
ReplaceQueryVariables:
  ErrorThreshold: 200
"@
            $paramFile = Join-Path TestDrive: 'params-simple.yaml'
            $paramYaml | Out-File -FilePath $paramFile -Encoding UTF8

            $query = '| where ErrorCount > %%ErrorThreshold%%'
            $result = InModuleScope XDRConverter { Resolve-QueryVariables -QueryText $args[0] -ParameterFilePath $args[1] } -ArgumentList $query, $paramFile
            $result | Should -Be '| where ErrorCount > 200'
        }

        It 'Should replace a variable with a default when variable is set' {
            $paramYaml = @"
ReplaceQueryVariables:
  ErrorThreshold: 200
"@
            $paramFile = Join-Path TestDrive: 'params-override-default.yaml'
            $paramYaml | Out-File -FilePath $paramFile -Encoding UTF8

            $query = '| where ErrorCount > %%ErrorThreshold:100%%'
            $result = InModuleScope XDRConverter { Resolve-QueryVariables -QueryText $args[0] -ParameterFilePath $args[1] } -ArgumentList $query, $paramFile
            $result | Should -Be '| where ErrorCount > 200'
        }

        It 'Should use the default value when variable is NOT set' {
            $paramYaml = @"
ReplaceQueryVariables:
  SomeOtherVar: foo
"@
            $paramFile = Join-Path TestDrive: 'params-use-default.yaml'
            $paramYaml | Out-File -FilePath $paramFile -Encoding UTF8

            $query = '| where ErrorCount > %%ErrorThreshold:100%%'
            $result = InModuleScope XDRConverter { Resolve-QueryVariables -QueryText $args[0] -ParameterFilePath $args[1] } -ArgumentList $query, $paramFile
            $result | Should -Be '| where ErrorCount > 100'
        }

        It 'Should replace with empty string and warn when variable has no default and is not set' {
            $paramYaml = @"
ReplaceQueryVariables:
  SomeOtherVar: foo
"@
            $paramFile = Join-Path TestDrive: 'params-warn.yaml'
            $paramYaml | Out-File -FilePath $paramFile -Encoding UTF8

            $query = '| where Message contains "%%MessageFilter%%"'
            $result = InModuleScope XDRConverter {
                Resolve-QueryVariables -QueryText $args[0] -ParameterFilePath $args[1] -WarningVariable warnings 3>&1
            } -ArgumentList $query, $paramFile

            # The result string should have the variable replaced with empty
            # (warnings may be mixed in with output, extract the string)
            $outputString = $result | Where-Object { $_ -is [string] }
            $warningMessages = $result | Where-Object { $_ -is [System.Management.Automation.WarningRecord] }

            $outputString | Should -Be '| where Message contains ""'
            $warningMessages.Message | Should -BeLike "*MessageFilter*"
        }

        It 'Should join array values as comma-separated quoted strings' {
            $paramYaml = @"
ReplaceQueryVariables:
  ErrorCodes:
    - "403"
    - "404"
"@
            $paramFile = Join-Path TestDrive: 'params-array.yaml'
            $paramYaml | Out-File -FilePath $paramFile -Encoding UTF8

            $query = '| where ErrorCode in (%%ErrorCodes:500%%)'
            $result = InModuleScope XDRConverter { Resolve-QueryVariables -QueryText $args[0] -ParameterFilePath $args[1] } -ArgumentList $query, $paramFile
            $result | Should -Be '| where ErrorCode in ("403","404")'
        }

        It 'Should handle multiple variables in one query' {
            $paramYaml = @"
ReplaceQueryVariables:
  ErrorThreshold: 200
  Source: MySource
"@
            $paramFile = Join-Path TestDrive: 'params-multi.yaml'
            $paramYaml | Out-File -FilePath $paramFile -Encoding UTF8

            $query = @"
| where ErrorCount > %%ErrorThreshold:100%%
| where Source == "%%Source:DefaultSource%%"
"@
            $result = InModuleScope XDRConverter { Resolve-QueryVariables -QueryText $args[0] -ParameterFilePath $args[1] } -ArgumentList $query, $paramFile
            $result | Should -BeLike '*ErrorCount > 200*'
            $result | Should -BeLike '*Source == "MySource"*'
        }

        It 'Should return default when ReplaceQueryVariables section is missing' {
            $paramYaml = @"
PrependQuery: |
  // header
"@
            $paramFile = Join-Path TestDrive: 'params-no-vars.yaml'
            $paramYaml | Out-File -FilePath $paramFile -Encoding UTF8

            $query = '| where ErrorCount > %%ErrorThreshold:100%%'
            $result = InModuleScope XDRConverter { Resolve-QueryVariables -QueryText $args[0] -ParameterFilePath $args[1] } -ArgumentList $query, $paramFile
            $result | Should -BeLike '*ErrorCount > 100*'
        }
    }

    Context 'Prepend and Append' {

        It 'Should prepend text to the query' {
            $paramYaml = @"
PrependQuery: |
  // This is a header comment
"@
            $paramFile = Join-Path TestDrive: 'params-prepend.yaml'
            $paramYaml | Out-File -FilePath $paramFile -Encoding UTF8

            $query = 'DeviceEvents | where ActionType == "Test"'
            $result = InModuleScope XDRConverter { Resolve-QueryVariables -QueryText $args[0] -ParameterFilePath $args[1] } -ArgumentList $query, $paramFile
            $result | Should -BeLike '// This is a header comment*'
            $result | Should -BeLike '*DeviceEvents*'
        }

        It 'Should append text to the query' {
            $paramYaml = @"
AppendQuery: |
  // This is a footer comment
"@
            $paramFile = Join-Path TestDrive: 'params-append.yaml'
            $paramYaml | Out-File -FilePath $paramFile -Encoding UTF8

            $query = 'DeviceEvents | where ActionType == "Test"'
            $result = InModuleScope XDRConverter { Resolve-QueryVariables -QueryText $args[0] -ParameterFilePath $args[1] } -ArgumentList $query, $paramFile
            $result | Should -BeLike '*DeviceEvents*'
            $result | Should -BeLike '*// This is a footer comment*'
        }

        It 'Should prepend and append together' {
            $paramYaml = @"
PrependQuery: |
  // Header
AppendQuery: |
  // Footer
"@
            $paramFile = Join-Path TestDrive: 'params-both.yaml'
            $paramYaml | Out-File -FilePath $paramFile -Encoding UTF8

            $query = 'DeviceEvents'
            $result = InModuleScope XDRConverter { Resolve-QueryVariables -QueryText $args[0] -ParameterFilePath $args[1] } -ArgumentList $query, $paramFile
            $lines = $result -split "`n"
            $lines[0].Trim() | Should -Be '// Header'
            $lines[-1].Trim() | Should -Be '// Footer'
        }
    }

    Context 'Edge Cases' {

        It 'Should leave query unchanged when parameter file has no matching keys' {
            $paramYaml = @"
ReplaceQueryVariables:
  UnrelatedVar: 42
"@
            $paramFile = Join-Path TestDrive: 'params-no-match.yaml'
            $paramYaml | Out-File -FilePath $paramFile -Encoding UTF8

            $query = 'DeviceEvents | where ActionType == "SecurityLogCleared"'
            $result = InModuleScope XDRConverter { Resolve-QueryVariables -QueryText $args[0] -ParameterFilePath $args[1] } -ArgumentList $query, $paramFile
            $result | Should -Be 'DeviceEvents | where ActionType == "SecurityLogCleared"'
        }

        It 'Should leave query unchanged when parameter file has no sections' {
            # YAML with an empty mapping
            $paramYaml = "---`n"
            $paramFile = Join-Path TestDrive: 'params-empty-sections.yaml'
            $paramYaml | Out-File -FilePath $paramFile -Encoding UTF8

            $query = 'DeviceEvents'
            $result = InModuleScope XDRConverter { Resolve-QueryVariables -QueryText $args[0] -ParameterFilePath $args[1] } -ArgumentList $query, $paramFile
            $result | Should -BeLike '*DeviceEvents*'
        }

        It 'Should handle a variable with value zero' {
            $paramYaml = @"
ReplaceQueryVariables:
  Threshold: 0
"@
            $paramFile = Join-Path TestDrive: 'params-zero.yaml'
            $paramYaml | Out-File -FilePath $paramFile -Encoding UTF8

            $query = '| where Count > %%Threshold:10%%'
            $result = InModuleScope XDRConverter { Resolve-QueryVariables -QueryText $args[0] -ParameterFilePath $args[1] } -ArgumentList $query, $paramFile
            $result | Should -Be '| where Count > 0'
        }

        It 'Should handle adjacent variables' {
            $paramYaml = @"
ReplaceQueryVariables:
  Table: DeviceEvents
  Filter: ActionType
"@
            $paramFile = Join-Path TestDrive: 'params-adjacent.yaml'
            $paramYaml | Out-File -FilePath $paramFile -Encoding UTF8

            $query = '%%Table%% | where %%Filter%% == "Test"'
            $result = InModuleScope XDRConverter { Resolve-QueryVariables -QueryText $args[0] -ParameterFilePath $args[1] } -ArgumentList $query, $paramFile
            $result | Should -Be 'DeviceEvents | where ActionType == "Test"'
        }

        It 'Should handle a single-element array' {
            $paramYaml = @"
ReplaceQueryVariables:
  ErrorCodes:
    - "500"
"@
            $paramFile = Join-Path TestDrive: 'params-single-array.yaml'
            $paramYaml | Out-File -FilePath $paramFile -Encoding UTF8

            $query = '| where ErrorCode in (%%ErrorCodes%%)'
            $result = InModuleScope XDRConverter { Resolve-QueryVariables -QueryText $args[0] -ParameterFilePath $args[1] } -ArgumentList $query, $paramFile
            $result | Should -Be '| where ErrorCode in ("500")'
        }

        It 'Should handle a variable at the very start and end of the query' {
            $paramYaml = @"
ReplaceQueryVariables:
  Start: DeviceEvents
  End: "| take 10"
"@
            $paramFile = Join-Path TestDrive: 'params-startend.yaml'
            $paramYaml | Out-File -FilePath $paramFile -Encoding UTF8

            $query = '%%Start%% | where true %%End%%'
            $result = InModuleScope XDRConverter { Resolve-QueryVariables -QueryText $args[0] -ParameterFilePath $args[1] } -ArgumentList $query, $paramFile
            $result | Should -Be 'DeviceEvents | where true | take 10'
        }

        It 'Should warn for each undefined variable without a default' {
            $paramYaml = @"
ReplaceQueryVariables:
  OnlyOne: value
"@
            $paramFile = Join-Path TestDrive: 'params-multi-warn.yaml'
            $paramYaml | Out-File -FilePath $paramFile -Encoding UTF8

            $query = '%%MissingA%% and %%MissingB%%'
            $result = InModuleScope XDRConverter {
                Resolve-QueryVariables -QueryText $args[0] -ParameterFilePath $args[1] 3>&1
            } -ArgumentList $query, $paramFile

            $warnings = $result | Where-Object { $_ -is [System.Management.Automation.WarningRecord] }
            $warnings.Count | Should -Be 2
            ($warnings | Where-Object { $_.Message -like '*MissingA*' }) | Should -Not -BeNullOrEmpty
            ($warnings | Where-Object { $_.Message -like '*MissingB*' }) | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Full Integration' {

        It 'Should apply all transformations: prepend, replace, append' {
            $paramYaml = @"
PrependQuery: |
  // Auto-generated query
AppendQuery: |
  | project Timestamp, ErrorCount
ReplaceQueryVariables:
  ErrorThreshold: 200
  ErrorCodes:
    - "403"
    - "404"
"@
            $paramFile = Join-Path TestDrive: 'params-full.yaml'
            $paramYaml | Out-File -FilePath $paramFile -Encoding UTF8

            $query = @"
DeviceEvents
| where ErrorCount > %%ErrorThreshold:100%%
| where ErrorCode in (%%ErrorCodes:500%%)
"@
            $result = InModuleScope XDRConverter { Resolve-QueryVariables -QueryText $args[0] -ParameterFilePath $args[1] } -ArgumentList $query, $paramFile
            $result | Should -BeLike '// Auto-generated query*'
            $result | Should -BeLike '*ErrorCount > 200*'
            $result | Should -BeLike '*("403","404")*'
            $result | Should -BeLike '*| project Timestamp, ErrorCount*'
        }

        It 'Should work with a real-world SecurityEventsCleared query and prepend/append' {
            $paramYaml = @"
PrependQuery: |
  // TEST automated deployment
AppendQuery: |
  | where DeviceName !in ("ExcludedHost1", "ExcludedHost2")
ReplaceQueryVariables:
  ActionFilter: SecurityLogCleared
"@
            $paramFile = Join-Path TestDrive: 'params-realworld.yaml'
            $paramYaml | Out-File -FilePath $paramFile -Encoding UTF8

            $query = @"
DeviceEvents
| where ActionType == "%%ActionFilter%%"
| project Timestamp, DeviceId, DeviceName, ActionType, InitiatingProcessAccountName, InitiatingProcessAccountDomain, InitiatingProcessAccountSid, ReportId
"@
            $result = InModuleScope XDRConverter { Resolve-QueryVariables -QueryText $args[0] -ParameterFilePath $args[1] } -ArgumentList $query, $paramFile
            $result | Should -BeLike '// TEST automated deployment*'
            $result | Should -BeLike '*ActionType == "SecurityLogCleared"*'
            $result | Should -BeLike '*| project Timestamp, DeviceId*'
            $result | Should -BeLike '*ExcludedHost1*'
        }

        It 'Should leave a query without placeholders unchanged except for prepend/append' {
            $paramYaml = @"
PrependQuery: |
  // Header
ReplaceQueryVariables:
  Unused: 123
"@
            $paramFile = Join-Path TestDrive: 'params-no-placeholders.yaml'
            $paramYaml | Out-File -FilePath $paramFile -Encoding UTF8

            $query = @"
DeviceEvents
| where ActionType == "SecurityLogCleared"
| project Timestamp, DeviceId, DeviceName
"@
            $result = InModuleScope XDRConverter { Resolve-QueryVariables -QueryText $args[0] -ParameterFilePath $args[1] } -ArgumentList $query, $paramFile
            $result | Should -BeLike '// Header*'
            $result | Should -BeLike '*ActionType == "SecurityLogCleared"*'
            $result | Should -BeLike '*| project Timestamp, DeviceId, DeviceName*'
        }
    }
}

Describe 'Deploy-CustomDetection with ParameterFile' {

    BeforeAll {
        if (-not (Get-Command -Name Invoke-MgGraphRequest -ErrorAction SilentlyContinue)) {
            function global:Invoke-MgGraphRequest { }
        }

        $ModulePath = Split-Path -Path $PSScriptRoot -Parent
        $ModulePath = Join-Path -Path $ModulePath -ChildPath 'src' | Join-Path -ChildPath 'XDRConverter.psd1'
        Import-Module -Name $ModulePath -Force
    }

    AfterAll {
        Remove-Module -Name XDRConverter -Force -ErrorAction SilentlyContinue
    }

    BeforeEach {
        Mock Assert-MgGraphConnection {} -ModuleName XDRConverter
        Mock Invoke-MgGraphRequest {
            $script:CapturedBody = $Body
            return @{ id = 'new-rule-id' }
        } -ModuleName XDRConverter
        Mock Get-CustomDetectionIdByDetectorId { return $null } -ModuleName XDRConverter
        Mock Get-CustomDetection { return @() } -ModuleName XDRConverter
    }

    It 'Should have ParameterFile parameter' {
        $cmd = Get-Command -Name 'Deploy-CustomDetection'
        $cmd.Parameters.Keys | Should -Contain 'ParameterFile'
    }

    It 'Should apply variable replacement from parameter file to query' {
        $testYaml = @"
guid: 81fb771a-c57e-41b8-9905-63dbf267c13f
ruleName: TEST-Params
isEnabled: true
alertTitle: Test Alert
frequency: 0
alertSeverity: Medium
alertDescription: Test description
alertCategory: DefenseEvasion
queryText: "DeviceEvents | where ErrorCount > %%ErrorThreshold:100%%"
"@
        $tempFile = Join-Path TestDrive: 'deploy-param-test.yaml'
        $testYaml | Out-File -FilePath $tempFile -Encoding UTF8

        $paramYaml = @"
ReplaceQueryVariables:
  ErrorThreshold: 200
"@
        $paramFile = Join-Path TestDrive: 'deploy-params.yaml'
        $paramYaml | Out-File -FilePath $paramFile -Encoding UTF8

        $result = Deploy-CustomDetection -InputFile $tempFile -ParameterFile $paramFile -Confirm:$false
        $result | Should -Not -BeNullOrEmpty
        $result.Action | Should -Be 'Created'
        $script:CapturedBody.queryCondition.queryText | Should -BeLike '*ErrorCount > 200*'
    }

    It 'Should apply prepend and append from parameter file' {
        $testYaml = @"
guid: 81fb771a-c57e-41b8-9905-63dbf267c13f
ruleName: TEST-PrependAppend
isEnabled: true
alertTitle: Test Alert
frequency: 0
alertSeverity: Medium
alertDescription: Test description
alertCategory: DefenseEvasion
queryText: DeviceEvents | where ActionType == "Test"
"@
        $tempFile = Join-Path TestDrive: 'deploy-prepend-append.yaml'
        $testYaml | Out-File -FilePath $tempFile -Encoding UTF8

        $paramYaml = @"
PrependQuery: |
  // Header added by parameter file
AppendQuery: |
  | project Timestamp
"@
        $paramFile = Join-Path TestDrive: 'deploy-prepend-append-params.yaml'
        $paramYaml | Out-File -FilePath $paramFile -Encoding UTF8

        $result = Deploy-CustomDetection -InputFile $tempFile -ParameterFile $paramFile -Confirm:$false
        $result | Should -Not -BeNullOrEmpty
        $script:CapturedBody.queryCondition.queryText | Should -BeLike '*// Header added by parameter file*'
        $script:CapturedBody.queryCondition.queryText | Should -BeLike '*| project Timestamp*'
    }

    It 'Should resolve defaults and emit informational message when no ParameterFile is specified' {
        $testYaml = @"
guid: 81fb771a-c57e-41b8-9905-63dbf267c13f
ruleName: TEST-NoParams
isEnabled: true
alertTitle: Test Alert
frequency: 0
alertSeverity: Medium
alertDescription: Test description
alertCategory: DefenseEvasion
queryText: "DeviceEvents | where ErrorCount > %%ErrorThreshold:100%%"
"@
        $tempFile = Join-Path TestDrive: 'deploy-no-param.yaml'
        $testYaml | Out-File -FilePath $tempFile -Encoding UTF8

        $result = Deploy-CustomDetection -InputFile $tempFile -Confirm:$false -InformationVariable infoMessages
        $result | Should -Not -BeNullOrEmpty
        # Placeholders with defaults should be resolved to default values
        $script:CapturedBody.queryCondition.queryText | Should -BeLike '*ErrorCount > 100*'
        $script:CapturedBody.queryCondition.queryText | Should -Not -BeLike '*%%ErrorThreshold*'
        # Should have an informational message about defaults being used
        $infoMessages | Should -Not -BeNullOrEmpty
        ($infoMessages.MessageData -join ' ') | Should -BeLike '*ErrorThreshold*default*'
    }

    It 'Should warn only for placeholders without defaults when no ParameterFile is given' {
        $testYaml = @"
guid: 81fb771a-c57e-41b8-9905-63dbf267c13f
ruleName: TEST-WarnNoParamFile
isEnabled: true
alertTitle: Test Alert
frequency: 0
alertSeverity: Medium
alertDescription: Test description
alertCategory: DefenseEvasion
queryText: "DeviceEvents | where ErrorCount > %%ErrorThreshold:100%% | where Source == %%Source%%"
"@
        $tempFile = Join-Path TestDrive: 'deploy-warn-no-paramfile.yaml'
        $testYaml | Out-File -FilePath $tempFile -Encoding UTF8

        $result = Deploy-CustomDetection -InputFile $tempFile -Confirm:$false -WarningVariable warnings -InformationVariable infoMessages
        # ErrorThreshold has a default -> informational, not warning
        $warningMessages = $warnings | Where-Object { $_ -is [System.Management.Automation.WarningRecord] }
        $warningMessages | Should -Not -BeNullOrEmpty
        ($warningMessages.Message -join ' ') | Should -Not -BeLike '*ErrorThreshold*'
        ($warningMessages.Message -join ' ') | Should -BeLike '*Source*'
        ($warningMessages.Message -join ' ') | Should -BeLike '*ParameterFile*'
        # ErrorThreshold should be in the informational message
        $infoMessages | Should -Not -BeNullOrEmpty
        ($infoMessages.MessageData -join ' ') | Should -BeLike '*ErrorThreshold*default*'
        # The default should have been resolved in the query
        $script:CapturedBody.queryCondition.queryText | Should -BeLike '*ErrorCount > 100*'
    }

    It 'Should NOT warn when query has no placeholders and no ParameterFile is given' {
        $testYaml = @"
guid: 81fb771a-c57e-41b8-9905-63dbf267c13f
ruleName: TEST-NoWarn
isEnabled: true
alertTitle: Test Alert
frequency: 0
alertSeverity: Medium
alertDescription: Test description
alertCategory: DefenseEvasion
queryText: "DeviceEvents | where ActionType == \"SecurityLogCleared\""
"@
        $tempFile = Join-Path TestDrive: 'deploy-no-warn.yaml'
        $testYaml | Out-File -FilePath $tempFile -Encoding UTF8

        $result = Deploy-CustomDetection -InputFile $tempFile -Confirm:$false -WarningVariable warnings 3>&1
        $placeholderWarnings = $warnings | Where-Object { $_ -is [System.Management.Automation.WarningRecord] -and $_.Message -like '*placeholder*' }
        $placeholderWarnings | Should -BeNullOrEmpty
    }

    It 'Should apply parameter file to a real-world SecurityEventsCleared rule' {
        $testYaml = @"
guid: 81fb771a-c57e-41b8-9905-63dbf267c13f
ruleName: PREFIX-CUD-SecurityEventsCleared
isEnabled: true
alertTitle: "[PREFIX] Security Events Cleared"
alertCategory: DefenseEvasion
alertDescription: Security Events on a device were cleared
frequency: "0"
alertSeverity: Medium
queryText: |+
  DeviceEvents
  | where ActionType == "%%ActionFilter:SecurityLogCleared%%"
  | project Timestamp, DeviceId, DeviceName, ActionType, InitiatingProcessAccountName, InitiatingProcessAccountDomain, InitiatingProcessAccountSid, ReportId
"@
        $tempFile = Join-Path TestDrive: 'deploy-realworld.yaml'
        $testYaml | Out-File -FilePath $tempFile -Encoding UTF8

        $paramYaml = @"
PrependQuery: |
  // Deployed via automation
AppendQuery: |
  | where DeviceName !in ("ExcludedHost")
ReplaceQueryVariables:
  ActionFilter: SecurityLogCleared
"@
        $paramFile = Join-Path TestDrive: 'deploy-realworld-params.yaml'
        $paramYaml | Out-File -FilePath $paramFile -Encoding UTF8

        $result = Deploy-CustomDetection -InputFile $tempFile -ParameterFile $paramFile -Confirm:$false
        $result | Should -Not -BeNullOrEmpty
        $result.Action | Should -Be 'Created'
        $query = $script:CapturedBody.queryCondition.queryText
        $query | Should -BeLike '*// Deployed via automation*'
        $query | Should -BeLike '*ActionType == "SecurityLogCleared"*'
        $query | Should -BeLike '*ExcludedHost*'
        # Should NOT contain the placeholder anymore
        $query | Should -Not -BeLike '*%%ActionFilter*%%*'
    }

    It 'Should combine ParameterFile with other overrides like Severity and TitlePrefix' {
        $testYaml = @"
guid: 81fb771a-c57e-41b8-9905-63dbf267c13f
ruleName: PREFIX-CUD-SecurityEventsCleared
isEnabled: true
alertTitle: "[PREFIX] Security Events Cleared"
alertCategory: DefenseEvasion
alertDescription: Security Events on a device were cleared
frequency: "0"
alertSeverity: Medium
queryText: "DeviceEvents | where ActionType == \"%%ActionFilter:SecurityLogCleared%%\""
"@
        $tempFile = Join-Path TestDrive: 'deploy-combined.yaml'
        $testYaml | Out-File -FilePath $tempFile -Encoding UTF8

        $paramYaml = @"
ReplaceQueryVariables:
  ActionFilter: SecurityLogCleared
"@
        $paramFile = Join-Path TestDrive: 'deploy-combined-params.yaml'
        $paramYaml | Out-File -FilePath $paramFile -Encoding UTF8

        $result = Deploy-CustomDetection -InputFile $tempFile -ParameterFile $paramFile -Severity High -TitlePrefix '[PROD] ' -Confirm:$false
        $result | Should -Not -BeNullOrEmpty
        $script:CapturedBody.detectionAction.alertTemplate.severity | Should -Be 'high'
        $script:CapturedBody.displayName | Should -BeLike '*`[PROD`] *'
        $script:CapturedBody.queryCondition.queryText | Should -BeLike '*SecurityLogCleared*'
    }
}
