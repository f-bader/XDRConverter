Describe 'XDRConverter Module' {

    BeforeAll {
        $ModulePath = Split-Path -Path $PSScriptRoot -Parent
        $ModulePath = Join-Path -Path $ModulePath -ChildPath 'src' | Join-Path -ChildPath 'XDRConverter.psd1'
        Import-Module -Name $ModulePath -Force
    }

    AfterAll {
        Remove-Module -Name XDRConverter -Force -ErrorAction SilentlyContinue
    }

    Context 'Module Loading' {

        It 'Should load the module successfully' {
            Get-Module -Name 'XDRConverter' | Should -Not -BeNullOrEmpty
        }

        It 'Should export only public cmdlets' {
            $module = Get-Module -Name 'XDRConverter'
            $exportedFunctions = $module.ExportedFunctions.Keys

            $exportedFunctions | Should -Contain 'ConvertTo-CustomDetectionJson'
            $exportedFunctions | Should -Contain 'ConvertTo-CustomDetectionYaml'
            $exportedFunctions | Should -Contain 'Deploy-CustomDetection'
            $exportedFunctions | Should -Contain 'Get-CustomDetection'
            $exportedFunctions | Should -Contain 'Get-CustomDetectionIdByDetectorId'
            $exportedFunctions | Should -Contain 'Get-CustomDetectionIdByDescriptionTag'
            $exportedFunctions | Should -Contain 'Get-CustomDetectionIds'

            # Should only have 7 exported functions
            $exportedFunctions.Count | Should -Be 7
        }

        It 'Should require powershell-yaml module' {
            # The module should have a requirement for powershell-yaml
            $moduleInfo = Get-Module -Name 'XDRConverter'
            $requiredModules = $moduleInfo.RequiredModules.Name

            $requiredModules | Should -Contain 'powershell-yaml'
        }

        It 'ConvertTo-CustomDetectionJson function should exist and be callable' {
            $cmd = Get-Command -Name 'ConvertTo-CustomDetectionJson' -ErrorAction SilentlyContinue
            $cmd | Should -Not -BeNullOrEmpty
            $cmd.CommandType | Should -Be 'Function'
        }

        It 'ConvertTo-CustomDetectionYaml function should exist and be callable' {
            $cmd = Get-Command -Name 'ConvertTo-CustomDetectionYaml' -ErrorAction SilentlyContinue
            $cmd | Should -Not -BeNullOrEmpty
            $cmd.CommandType | Should -Be 'Function'
        }

        It 'Get-CustomDetection function should exist and be callable' {
            $cmd = Get-Command -Name 'Get-CustomDetection' -ErrorAction SilentlyContinue
            $cmd | Should -Not -BeNullOrEmpty
            $cmd.CommandType | Should -Be 'Function'
        }

        It 'Get-CustomDetectionIdByDetectorId function should exist and be callable' {
            $cmd = Get-Command -Name 'Get-CustomDetectionIdByDetectorId' -ErrorAction SilentlyContinue
            $cmd | Should -Not -BeNullOrEmpty
            $cmd.CommandType | Should -Be 'Function'
        }

        It 'Get-CustomDetectionIds function should exist and be callable' {
            $cmd = Get-Command -Name 'Get-CustomDetectionIds' -ErrorAction SilentlyContinue
            $cmd | Should -Not -BeNullOrEmpty
            $cmd.CommandType | Should -Be 'Function'
        }

        It 'Deploy-CustomDetection function should exist and be callable' {
            $cmd = Get-Command -Name 'Deploy-CustomDetection' -ErrorAction SilentlyContinue
            $cmd | Should -Not -BeNullOrEmpty
            $cmd.CommandType | Should -Be 'Function'
        }
    }

    Context 'Function Signatures' {

        It 'ConvertTo-CustomDetectionJson should have required parameters' {
            $cmd = Get-Command -Name 'ConvertTo-CustomDetectionJson'

            $cmd.Parameters.Keys | Should -Contain 'InputFile'
            $cmd.Parameters.Keys | Should -Contain 'OutputFile'
            $cmd.Parameters.Keys | Should -Contain 'Enabled'
            $cmd.Parameters.Keys | Should -Contain 'Severity'
        }

        It 'ConvertTo-CustomDetectionYaml should have required parameters' {
            $cmd = Get-Command -Name 'ConvertTo-CustomDetectionYaml'

            $cmd.Parameters.Keys | Should -Contain 'InputFile'
            $cmd.Parameters.Keys | Should -Contain 'OutputFile'
            $cmd.Parameters.Keys | Should -Contain 'Enabled'
            $cmd.Parameters.Keys | Should -Contain 'Severity'
        }

        It 'InputFile parameter should be mandatory for ConvertTo-CustomDetectionJson' {
            $cmd = Get-Command -Name 'ConvertTo-CustomDetectionJson'
            $inputFileParam = $cmd.Parameters['InputFile']

            $inputFileParam.Attributes | Where-Object { $_.TypeId.Name -eq 'ParameterAttribute' } |
            Select-Object -First 1 |
            ForEach-Object { $_.Mandatory | Should -Be $true }
        }

        It 'InputFile parameter should be mandatory for ConvertTo-CustomDetectionYaml' {
            $cmd = Get-Command -Name 'ConvertTo-CustomDetectionYaml'
            $inputFileParam = $cmd.Parameters['InputFile']

            $inputFileParam.Attributes | Where-Object { $_.TypeId.Name -eq 'ParameterAttribute' } |
            Select-Object -First 1 |
            ForEach-Object { $_.Mandatory | Should -Be $true }
        }

        It 'OutputFile parameter should be optional for ConvertTo-CustomDetectionJson' {
            $cmd = Get-Command -Name 'ConvertTo-CustomDetectionJson'
            $outputFileParam = $cmd.Parameters['OutputFile']

            $outputFileParam.Attributes | Where-Object { $_.TypeId.Name -eq 'ParameterAttribute' } |
            Select-Object -First 1 |
            ForEach-Object { $_.Mandatory | Should -Be $false }
        }

        It 'Severity parameter should have ValidateSet attribute' {
            $cmd = Get-Command -Name 'ConvertTo-CustomDetectionJson'
            $severityParam = $cmd.Parameters['Severity']

            $severityParam.Attributes | Where-Object { $_.TypeId.Name -eq 'ValidateSetAttribute' } |
            ForEach-Object {
                $_.ValidValues | Should -Contain 'Informational'
                $_.ValidValues | Should -Contain 'Low'
                $_.ValidValues | Should -Contain 'Medium'
                $_.ValidValues | Should -Contain 'High'
            }
        }
    }

    Context 'Help Documentation' {

        It 'ConvertTo-CustomDetectionJson should have help documentation' {
            $help = Get-Help -Name 'ConvertTo-CustomDetectionJson' -ErrorAction SilentlyContinue
            $help | Should -Not -BeNullOrEmpty
            $help.Synopsis | Should -Not -BeNullOrEmpty
        }

        It 'ConvertTo-CustomDetectionYaml should have help documentation' {
            $help = Get-Help -Name 'ConvertTo-CustomDetectionYaml' -ErrorAction SilentlyContinue
            $help | Should -Not -BeNullOrEmpty
            $help.Synopsis | Should -Not -BeNullOrEmpty
        }

        It 'ConvertTo-CustomDetectionJson help should include examples' {
            $help = Get-Help -Name 'ConvertTo-CustomDetectionJson' -ErrorAction SilentlyContinue
            $help.Examples | Should -Not -BeNullOrEmpty
        }

        It 'ConvertTo-CustomDetectionYaml help should include examples' {
            $help = Get-Help -Name 'ConvertTo-CustomDetectionYaml' -ErrorAction SilentlyContinue
            $help.Examples | Should -Not -BeNullOrEmpty
        }

        It 'ConvertTo-CustomDetectionJson parameters should be documented' {
            $help = Get-Help -Name 'ConvertTo-CustomDetectionJson' -ErrorAction SilentlyContinue
            $help.Parameters.Parameter | Should -Not -BeNullOrEmpty

            # Check for key parameters
            $paramNames = $help.Parameters.Parameter.Name
            $paramNames | Should -Contain 'InputFile'
            $paramNames | Should -Contain 'OutputFile'
        }
    }

    Context 'Error Handling' {

        It 'Should throw error for non-existent input file' {
            { ConvertTo-CustomDetectionJson -InputFile 'C:\nonexistent\path\file.yaml' } | Should -Throw
        }

        It 'Should handle encoding correctly for UTF-8 files' {
            $testContent = "guid: test"
            $tempFile = Join-Path TestDrive: 'encoding-test.yaml'

            $testContent | Out-File -FilePath $tempFile -Encoding UTF8
            # Should not throw
            { Get-Content -Path $tempFile -Raw } | Should -Not -Throw
        }
    }

    Context 'Round-Trip Conversion' {

        It 'Should handle round-trip conversion (YAML -> JSON -> YAML)' {
            $testYamlContent = @"
guid: 81fb771a-c57e-41b8-9905-63dbf267c13f
ruleName: PREFIX-ROUND-TRIP-Test
isEnabled: true
alertTitle: Round Trip Test
frequency: 0
alertSeverity: Medium
alertDescription: Test for round trip conversion
alertCategory: DefenseEvasion
queryText: DeviceEvents | where ActionType == "Test"
"@
            $tempYamlFile = Join-Path TestDrive: 'roundtrip-input.yaml'
            $tempJsonFile = Join-Path TestDrive: 'roundtrip-mid.json'
            $tempYamlFile2 = Join-Path TestDrive: 'roundtrip-output.yaml'

            $testYamlContent | Out-File -FilePath $tempYamlFile -Encoding UTF8

            # YAML -> JSON
            ConvertTo-CustomDetectionJson -InputFile $tempYamlFile -OutputFile $tempJsonFile
            Test-Path -Path $tempJsonFile | Should -Be $true

            # JSON -> YAML
            ConvertTo-CustomDetectionYaml -InputFile $tempJsonFile -OutputFile $tempYamlFile2
            Test-Path -Path $tempYamlFile2 | Should -Be $true

            # Verify content
            $yamlContent = Get-Content -Path $tempYamlFile2 -Raw
            $yamlContent | Should -Match 'PREFIX-ROUND-TRIP-Test'
            $yamlContent | Should -Match '81fb771a-c57e-41b8-9905-63dbf267c13f'
        }
    }
}

