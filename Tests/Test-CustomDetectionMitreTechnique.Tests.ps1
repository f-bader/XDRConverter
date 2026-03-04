Describe 'Test-CustomDetectionMitreTechnique' {

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
            { Test-CustomDetectionMitreTechnique -InputFile 'C:\nonexistent\file.yaml' } | Should -Throw
        }

        It 'Should accept pipeline input from a PSObject' {
            $obj = [PSCustomObject]@{ alertCategory = 'DefenseEvasion'; mitreTechniques = @('T1070.001') }
            { $obj | Test-CustomDetectionMitreTechnique } | Should -Not -Throw
        }
    }

    Context 'Valid Techniques' {

        It 'Should return IsValid = true when all techniques are supported for the category' {
            $yamlContent = @"
guid: 11111111-1111-1111-1111-111111111111
ruleName: TestRule
isEnabled: true
alertTitle: Test
frequency: 1H
alertSeverity: Medium
alertDescription: Test
alertCategory: DefenseEvasion
mitreTechniques:
  - T1070.001
  - T1562.001
queryText: DeviceEvents | take 1
"@
            $tempFile = Join-Path TestDrive: 'valid.yaml'
            $yamlContent | Out-File -FilePath $tempFile -Encoding UTF8

            $result = Test-CustomDetectionMitreTechnique -InputFile $tempFile
            $result.IsValid | Should -Be $true
            $result.InvalidTechniques | Should -BeNullOrEmpty
        }

        It 'Should return ValidTechniques containing all listed techniques when all are valid' {
            $yamlContent = @"
guid: 22222222-2222-2222-2222-222222222222
ruleName: TestRule2
isEnabled: true
alertTitle: Test
frequency: 1H
alertSeverity: Low
alertDescription: Test
alertCategory: Execution
mitreTechniques:
  - T1059.001
  - T1059.003
  - T1047
queryText: DeviceEvents | take 1
"@
            $tempFile = Join-Path TestDrive: 'valid2.yaml'
            $yamlContent | Out-File -FilePath $tempFile -Encoding UTF8

            $result = Test-CustomDetectionMitreTechnique -InputFile $tempFile
            $result.IsValid | Should -Be $true
            $result.ValidTechniques | Should -Contain 'T1059.001'
            $result.ValidTechniques | Should -Contain 'T1059.003'
            $result.ValidTechniques | Should -Contain 'T1047'
        }

        It 'Should return IsValid = true and empty arrays when no techniques are defined' {
            $yamlContent = @"
guid: 33333333-3333-3333-3333-333333333333
ruleName: NoTechniques
isEnabled: true
alertTitle: Test
frequency: 1H
alertSeverity: Low
alertDescription: Test
alertCategory: Discovery
queryText: DeviceEvents | take 1
"@
            $tempFile = Join-Path TestDrive: 'no-techniques.yaml'
            $yamlContent | Out-File -FilePath $tempFile -Encoding UTF8

            $result = Test-CustomDetectionMitreTechnique -InputFile $tempFile
            $result.IsValid | Should -Be $true
            $result.ValidTechniques.Count | Should -Be 0
            $result.InvalidTechniques.Count | Should -Be 0
        }
    }

    Context 'Invalid Techniques' {

        It 'Should return IsValid = false when a technique is not supported for the category' {
            $yamlContent = @"
guid: 44444444-4444-4444-4444-444444444444
ruleName: InvalidTechnique
isEnabled: true
alertTitle: Test
frequency: 1H
alertSeverity: High
alertDescription: Test
alertCategory: Exfiltration
mitreTechniques:
  - T1041
  - T1059.001
queryText: DeviceEvents | take 1
"@
            $tempFile = Join-Path TestDrive: 'invalid.yaml'
            $yamlContent | Out-File -FilePath $tempFile -Encoding UTF8

            $result = Test-CustomDetectionMitreTechnique -InputFile $tempFile -WarningAction SilentlyContinue
            $result.IsValid | Should -Be $false
            $result.InvalidTechniques | Should -Contain 'T1059.001'
            $result.ValidTechniques | Should -Contain 'T1041'
        }

        It 'Should emit a warning for unsupported techniques' {
            $yamlContent = @"
guid: 55555555-5555-5555-5555-555555555555
ruleName: WarnTest
isEnabled: true
alertTitle: Test
frequency: 1H
alertSeverity: Medium
alertDescription: Test
alertCategory: InitialAccess
mitreTechniques:
  - T9999.999
queryText: DeviceEvents | take 1
"@
            $tempFile = Join-Path TestDrive: 'warn.yaml'
            $yamlContent | Out-File -FilePath $tempFile -Encoding UTF8

            { Test-CustomDetectionMitreTechnique -InputFile $tempFile -WarningAction Stop } | Should -Throw
        }
    }

    Context 'Category Not in XDR Mapping' {

        It 'Should return IsValid = true with a warning for SuspiciousActivity category' {
            $yamlContent = @"
guid: 66666666-6666-6666-6666-666666666666
ruleName: SuspiciousRule
isEnabled: true
alertTitle: Test
frequency: 1H
alertSeverity: Medium
alertDescription: Test
alertCategory: SuspiciousActivity
mitreTechniques:
  - T1059.001
queryText: DeviceEvents | take 1
"@
            $tempFile = Join-Path TestDrive: 'suspicious.yaml'
            $yamlContent | Out-File -FilePath $tempFile -Encoding UTF8

            $result = Test-CustomDetectionMitreTechnique -InputFile $tempFile -WarningAction SilentlyContinue
            $result.IsValid | Should -Be $true
            $result.InvalidTechniques | Should -BeNullOrEmpty
        }
    }

    Context 'Output Structure' {

        It 'Should return an object with IsValid, Category, ValidTechniques, InvalidTechniques properties' {
            $obj = [PSCustomObject]@{ alertCategory = 'Persistence'; mitreTechniques = @('T1547.001') }
            $result = $obj | Test-CustomDetectionMitreTechnique

            $result.PSObject.Properties.Name | Should -Contain 'IsValid'
            $result.PSObject.Properties.Name | Should -Contain 'Category'
            $result.PSObject.Properties.Name | Should -Contain 'ValidTechniques'
            $result.PSObject.Properties.Name | Should -Contain 'InvalidTechniques'
        }

        It 'Should return the correct Category value' {
            $obj = [PSCustomObject]@{ alertCategory = 'LateralMovement'; mitreTechniques = @('T1021.001') }
            $result = $obj | Test-CustomDetectionMitreTechnique

            $result.Category | Should -Be 'LateralMovement'
        }
    }

    Context 'Pipeline Input' {

        It 'Should accept multiple objects from the pipeline' {
            $objects = @(
                [PSCustomObject]@{ alertCategory = 'CredentialAccess'; mitreTechniques = @('T1003') },
                [PSCustomObject]@{ alertCategory = 'Discovery'; mitreTechniques = @('T1082') }
            )
            $results = $objects | Test-CustomDetectionMitreTechnique
            $results.Count | Should -Be 2
            $results[0].IsValid | Should -Be $true
            $results[1].IsValid | Should -Be $true
        }
    }
}
