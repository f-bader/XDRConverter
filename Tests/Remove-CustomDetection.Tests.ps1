Describe 'Remove-CustomDetection' {

    BeforeAll {
        # Create a stub for Invoke-MgGraphRequest so Pester can mock it
        # even when Microsoft.Graph.Authentication is not installed.
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
        Mock Assert-MgGraphConnection {} -ModuleName XDRConverter
        Mock Invoke-MgGraphRequest {} -ModuleName XDRConverter
        Mock Get-CustomDetectionIdByDetectorId { return $null } -ModuleName XDRConverter
        Mock Get-CustomDetectionIdByDescriptionTag { return $null } -ModuleName XDRConverter
        Mock Get-CustomDetection { return $null } -ModuleName XDRConverter
    }

    Context 'Parameter Validation' {

        It 'Should have Mandatory Id parameter' {
            $cmd = Get-Command -Name 'Remove-CustomDetection'
            $param = $cmd.Parameters['Id']
            $mandatory = $param.Attributes | Where-Object { $_.TypeId.Name -eq 'ParameterAttribute' } |
                Select-Object -First 1
            $mandatory.Mandatory | Should -Be $true
        }

        It 'Should have Mandatory DetectorId parameter' {
            $cmd = Get-Command -Name 'Remove-CustomDetection'
            $param = $cmd.Parameters['DetectorId']
            $mandatory = $param.Attributes | Where-Object { $_.TypeId.Name -eq 'ParameterAttribute' } |
                Select-Object -First 1
            $mandatory.Mandatory | Should -Be $true
        }

        It 'Should have Mandatory DescriptionTag parameter' {
            $cmd = Get-Command -Name 'Remove-CustomDetection'
            $param = $cmd.Parameters['DescriptionTag']
            $mandatory = $param.Attributes | Where-Object { $_.TypeId.Name -eq 'ParameterAttribute' } |
                Select-Object -First 1
            $mandatory.Mandatory | Should -Be $true
        }

        It 'Should have three parameter sets: ById, ByDetectorId, ByDescriptionTag' {
            $cmd = Get-Command -Name 'Remove-CustomDetection'
            $cmd.ParameterSets.Name | Should -Contain 'ById'
            $cmd.ParameterSets.Name | Should -Contain 'ByDetectorId'
            $cmd.ParameterSets.Name | Should -Contain 'ByDescriptionTag'
        }

        It 'Should have SupportsShouldProcess' {
            $cmd = Get-Command -Name 'Remove-CustomDetection'
            $cmdletBinding = $cmd.ScriptBlock.Attributes | Where-Object { $_.TypeId.Name -eq 'CmdletBindingAttribute' }
            $cmdletBinding.SupportsShouldProcess | Should -Be $true
        }

        It 'Should have ConfirmImpact set to High' {
            $cmd = Get-Command -Name 'Remove-CustomDetection'
            $cmdletBinding = $cmd.ScriptBlock.Attributes | Where-Object { $_.TypeId.Name -eq 'CmdletBindingAttribute' }
            $cmdletBinding.ConfirmImpact | Should -Be 'High'
        }

        It 'Should have Id in the ById parameter set' {
            $cmd = Get-Command -Name 'Remove-CustomDetection'
            $param = $cmd.Parameters['Id']
            $paramAttr = $param.Attributes | Where-Object { $_.TypeId.Name -eq 'ParameterAttribute' }
            $paramAttr.ParameterSetName | Should -Be 'ById'
        }

        It 'Should have DetectorId in the ByDetectorId parameter set' {
            $cmd = Get-Command -Name 'Remove-CustomDetection'
            $param = $cmd.Parameters['DetectorId']
            $paramAttr = $param.Attributes | Where-Object { $_.TypeId.Name -eq 'ParameterAttribute' }
            $paramAttr.ParameterSetName | Should -Be 'ByDetectorId'
        }

        It 'Should have DescriptionTag in the ByDescriptionTag parameter set' {
            $cmd = Get-Command -Name 'Remove-CustomDetection'
            $param = $cmd.Parameters['DescriptionTag']
            $paramAttr = $param.Attributes | Where-Object { $_.TypeId.Name -eq 'ParameterAttribute' }
            $paramAttr.ParameterSetName | Should -Be 'ByDescriptionTag'
        }

        It 'Should accept pipeline input for Id' {
            $cmd = Get-Command -Name 'Remove-CustomDetection'
            $param = $cmd.Parameters['Id']
            $paramAttr = $param.Attributes | Where-Object { $_.TypeId.Name -eq 'ParameterAttribute' }
            $paramAttr.ValueFromPipeline | Should -Be $true
        }

        It 'Should accept pipeline input for DetectorId' {
            $cmd = Get-Command -Name 'Remove-CustomDetection'
            $param = $cmd.Parameters['DetectorId']
            $paramAttr = $param.Attributes | Where-Object { $_.TypeId.Name -eq 'ParameterAttribute' }
            $paramAttr.ValueFromPipeline | Should -Be $true
        }

        It 'Should accept pipeline input for DescriptionTag' {
            $cmd = Get-Command -Name 'Remove-CustomDetection'
            $param = $cmd.Parameters['DescriptionTag']
            $paramAttr = $param.Attributes | Where-Object { $_.TypeId.Name -eq 'ParameterAttribute' }
            $paramAttr.ValueFromPipeline | Should -Be $true
        }
    }

    Context 'Delete by Id' {

        It 'Should delete the rule and return a result object' {
            Mock Get-CustomDetection {
                return @{ id = 'rule-123'; displayName = 'Test Rule' }
            } -ModuleName XDRConverter
            Mock Invoke-MgGraphRequest {} -ModuleName XDRConverter

            $result = Remove-CustomDetection -Id 'rule-123' -Confirm:$false
            $result | Should -Not -BeNullOrEmpty
            $result.Action | Should -Be 'Deleted'
            $result.RuleName | Should -Be 'Test Rule'
            $result.RuleId | Should -Be 'rule-123'
        }

        It 'Should call DELETE on the correct URI' {
            Mock Get-CustomDetection {
                return @{ id = 'rule-456'; displayName = 'My Rule' }
            } -ModuleName XDRConverter
            Mock Invoke-MgGraphRequest {} -ModuleName XDRConverter

            Remove-CustomDetection -Id 'rule-456' -Confirm:$false

            Should -Invoke Invoke-MgGraphRequest -ModuleName XDRConverter -ParameterFilter {
                $Method -eq 'DELETE' -and
                $Uri -eq 'https://graph.microsoft.com/beta/security/rules/detectionRules/rule-456'
            }
        }

        It 'Should write an error when rule Id is not found' {
            Mock Get-CustomDetection { return $null } -ModuleName XDRConverter

            $result = Remove-CustomDetection -Id 'nonexistent' -Confirm:$false -ErrorAction SilentlyContinue
            $result | Should -BeNullOrEmpty

            Should -Not -Invoke Invoke-MgGraphRequest -ModuleName XDRConverter -ParameterFilter {
                $Method -eq 'DELETE'
            }
        }
    }

    Context 'Delete by DetectorId' {

        It 'Should resolve DetectorId and delete the rule' {
            Mock Get-CustomDetectionIdByDetectorId { return 'resolved-id-1' } -ModuleName XDRConverter
            Mock Get-CustomDetection {
                return @{ id = 'resolved-id-1'; displayName = 'Detector Rule' }
            } -ModuleName XDRConverter
            Mock Invoke-MgGraphRequest {} -ModuleName XDRConverter

            $result = Remove-CustomDetection -DetectorId '81fb771a-c57e-41b8-9905-63dbf267c13f' -Confirm:$false
            $result | Should -Not -BeNullOrEmpty
            $result.Action | Should -Be 'Deleted'
            $result.RuleId | Should -Be 'resolved-id-1'
        }

        It 'Should call Get-CustomDetectionIdByDetectorId to resolve the ID' {
            Mock Get-CustomDetectionIdByDetectorId { return 'resolved-id-2' } -ModuleName XDRConverter
            Mock Get-CustomDetection {
                return @{ id = 'resolved-id-2'; displayName = 'Detector Rule' }
            } -ModuleName XDRConverter
            Mock Invoke-MgGraphRequest {} -ModuleName XDRConverter

            Remove-CustomDetection -DetectorId 'some-detector-guid' -Confirm:$false

            Should -Invoke Get-CustomDetectionIdByDetectorId -ModuleName XDRConverter -ParameterFilter {
                $DetectorId -eq 'some-detector-guid'
            }
        }

        It 'Should write an error when DetectorId cannot be resolved' {
            Mock Get-CustomDetectionIdByDetectorId { return $null } -ModuleName XDRConverter

            $result = Remove-CustomDetection -DetectorId 'unknown-detector' -Confirm:$false -ErrorAction SilentlyContinue
            $result | Should -BeNullOrEmpty

            Should -Not -Invoke Invoke-MgGraphRequest -ModuleName XDRConverter -ParameterFilter {
                $Method -eq 'DELETE'
            }
        }
    }

    Context 'Delete by DescriptionTag' {

        It 'Should resolve DescriptionTag and delete the rule' {
            Mock Get-CustomDetectionIdByDescriptionTag { return 'tag-resolved-id' } -ModuleName XDRConverter
            Mock Get-CustomDetection {
                return @{ id = 'tag-resolved-id'; displayName = 'Tagged Rule' }
            } -ModuleName XDRConverter
            Mock Invoke-MgGraphRequest {} -ModuleName XDRConverter

            $result = Remove-CustomDetection -DescriptionTag '81fb771a-c57e-41b8-9905-63dbf267c13f' -Confirm:$false
            $result | Should -Not -BeNullOrEmpty
            $result.Action | Should -Be 'Deleted'
            $result.RuleId | Should -Be 'tag-resolved-id'
        }

        It 'Should call Get-CustomDetectionIdByDescriptionTag to resolve the ID' {
            Mock Get-CustomDetectionIdByDescriptionTag { return 'tag-id' } -ModuleName XDRConverter
            Mock Get-CustomDetection {
                return @{ id = 'tag-id'; displayName = 'Tagged Rule' }
            } -ModuleName XDRConverter
            Mock Invoke-MgGraphRequest {} -ModuleName XDRConverter

            Remove-CustomDetection -DescriptionTag 'some-tag-guid' -Confirm:$false

            Should -Invoke Get-CustomDetectionIdByDescriptionTag -ModuleName XDRConverter -ParameterFilter {
                $DescriptionTag -eq 'some-tag-guid'
            }
        }

        It 'Should write an error when DescriptionTag cannot be resolved' {
            Mock Get-CustomDetectionIdByDescriptionTag { return $null } -ModuleName XDRConverter

            $result = Remove-CustomDetection -DescriptionTag 'unknown-tag' -Confirm:$false -ErrorAction SilentlyContinue
            $result | Should -BeNullOrEmpty

            Should -Not -Invoke Invoke-MgGraphRequest -ModuleName XDRConverter -ParameterFilter {
                $Method -eq 'DELETE'
            }
        }
    }

    Context 'WhatIf Support' {

        It 'Should not call DELETE when -WhatIf is specified' {
            Mock Get-CustomDetection {
                return @{ id = 'rule-whatif'; displayName = 'WhatIf Rule' }
            } -ModuleName XDRConverter
            Mock Invoke-MgGraphRequest {} -ModuleName XDRConverter

            Remove-CustomDetection -Id 'rule-whatif' -WhatIf

            Should -Not -Invoke Invoke-MgGraphRequest -ModuleName XDRConverter -ParameterFilter {
                $Method -eq 'DELETE'
            }
        }

        It 'Should not return a result object when -WhatIf is specified' {
            Mock Get-CustomDetection {
                return @{ id = 'rule-whatif2'; displayName = 'WhatIf Rule 2' }
            } -ModuleName XDRConverter

            $result = Remove-CustomDetection -Id 'rule-whatif2' -WhatIf
            $result | Should -BeNullOrEmpty
        }
    }

    Context 'Error Handling' {

        It 'Should throw when the Graph API call fails' {
            Mock Get-CustomDetection {
                return @{ id = 'rule-err'; displayName = 'Error Rule' }
            } -ModuleName XDRConverter
            Mock Invoke-MgGraphRequest { throw 'Graph API error' } -ModuleName XDRConverter

            { Remove-CustomDetection -Id 'rule-err' -Confirm:$false } | Should -Throw
        }

        It 'Should call Assert-MgGraphConnection' {
            Mock Get-CustomDetection {
                return @{ id = 'rule-conn'; displayName = 'Connection Rule' }
            } -ModuleName XDRConverter
            Mock Invoke-MgGraphRequest {} -ModuleName XDRConverter

            Remove-CustomDetection -Id 'rule-conn' -Confirm:$false

            Should -Invoke Assert-MgGraphConnection -ModuleName XDRConverter
        }
    }

    Context 'Help Documentation' {

        It 'Should have help documentation' {
            $help = Get-Help -Name 'Remove-CustomDetection' -ErrorAction SilentlyContinue
            $help | Should -Not -BeNullOrEmpty
            $help.Synopsis | Should -Not -BeNullOrEmpty
        }

        It 'Should have examples' {
            $help = Get-Help -Name 'Remove-CustomDetection' -ErrorAction SilentlyContinue
            $help.Examples | Should -Not -BeNullOrEmpty
        }

        It 'Should have parameter descriptions' {
            $help = Get-Help -Name 'Remove-CustomDetection' -ErrorAction SilentlyContinue
            $help.Parameters.Parameter | Where-Object { $_.Name -eq 'Id' } | Should -Not -BeNullOrEmpty
            $help.Parameters.Parameter | Where-Object { $_.Name -eq 'DetectorId' } | Should -Not -BeNullOrEmpty
            $help.Parameters.Parameter | Where-Object { $_.Name -eq 'DescriptionTag' } | Should -Not -BeNullOrEmpty
        }
    }
}
