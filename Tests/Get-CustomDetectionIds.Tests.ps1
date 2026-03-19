BeforeAll {
    # Import the module
    $modulePath = Join-Path $PSScriptRoot '..' 'src' 'XDRConverter.psd1'
    Import-Module $modulePath -Force
}

AfterAll {
    # Remove the module to avoid state leaking between test runs
    Remove-Module XDRConverter -ErrorAction SilentlyContinue
}

Describe 'Get-CustomDetectionIds' {
    Context 'TagPrefix Extraction' {
        BeforeEach {
            # Mock the Graph API connection check
            Mock Assert-MgGraphConnection {} -ModuleName XDRConverter

            # Mock the Graph API call
            Mock Invoke-MgGraphRequestWithRetry {
                return @{
                    value = @(
                        @{
                            id = 'rule-with-prefix'
                            detectorId = 'detector-1'
                            detectionAction = @{
                                alertTemplate = @{
                                    description = 'This is a test alert [CUSTOM:12345678-1234-1234-1234-123456789abc] with a prefix'
                                }
                            }
                        },
                        @{
                            id = 'rule-without-prefix'
                            detectorId = 'detector-2'
                            detectionAction = @{
                                alertTemplate = @{
                                    description = 'This is a test alert [12345678-1234-1234-1234-123456789def] without a prefix'
                                }
                            }
                        },
                        @{
                            id = 'rule-no-tag'
                            detectorId = 'detector-3'
                            detectionAction = @{
                                alertTemplate = @{
                                    description = 'This is a test alert without any tag'
                                }
                            }
                        }
                    )
                    '@odata.nextLink' = $null
                }
            } -ModuleName XDRConverter

            # Clear the cache before each test
            $script:DetectionIdsCache = @{
                Data = $null
                ExpiresAt = [datetime]::MinValue
            }
        }

        AfterEach {
            # Clear the cache after each test to avoid interference
            $script:DetectionIdsCache = @{
                Data = $null
                ExpiresAt = [datetime]::MinValue
            }
        }

        It 'Should extract TagPrefix from description tag with prefix [CUSTOM:uuid]' {
            $result = Get-CustomDetectionIds

            $ruleWithPrefix = $result | Where-Object { $_.Id -eq 'rule-with-prefix' }
            $ruleWithPrefix.TagPrefix | Should -Be 'CUSTOM'
            $ruleWithPrefix.DescriptionTag | Should -Be '12345678-1234-1234-1234-123456789abc'
        }

        It 'Should have null TagPrefix when description tag has no prefix [uuid]' {
            $result = Get-CustomDetectionIds

            $ruleWithoutPrefix = $result | Where-Object { $_.Id -eq 'rule-without-prefix' }
            $ruleWithoutPrefix.TagPrefix | Should -BeNullOrEmpty
            $ruleWithoutPrefix.DescriptionTag | Should -Be '12345678-1234-1234-1234-123456789def'
        }

        It 'Should have null TagPrefix and DescriptionTag when no tag exists' {
            $result = Get-CustomDetectionIds

            $ruleNoTag = $result | Where-Object { $_.Id -eq 'rule-no-tag' }
            $ruleNoTag.TagPrefix | Should -BeNullOrEmpty
            $ruleNoTag.DescriptionTag | Should -BeNullOrEmpty
        }

        It 'Should return all expected properties' {
            $result = Get-CustomDetectionIds

            $result[0].PSObject.Properties.Name | Should -Contain 'Id'
            $result[0].PSObject.Properties.Name | Should -Contain 'DetectorId'
            $result[0].PSObject.Properties.Name | Should -Contain 'DescriptionTag'
            $result[0].PSObject.Properties.Name | Should -Contain 'TagPrefix'
        }
    }

    Context 'Caching Behavior' {
        BeforeEach {
            Mock Assert-MgGraphConnection {} -ModuleName XDRConverter
            
            # Clear the cache before each test
            $script:DetectionIdsCache = @{
                Data = $null
                ExpiresAt = [datetime]::MinValue
            }
        }

        It 'Should call API when cache is empty or expired' {
            Mock Invoke-MgGraphRequestWithRetry {
                return @{
                    value = @(
                        @{
                            id = 'test-rule'
                            detectorId = 'test-detector'
                            detectionAction = @{
                                alertTemplate = @{
                                    description = 'Test [12345678-1234-1234-1234-123456789abc]'
                                }
                            }
                        }
                    )
                    '@odata.nextLink' = $null
                }
            } -ModuleName XDRConverter

            $result = Get-CustomDetectionIds -Force
            $result | Should -Not -BeNullOrEmpty
            $result[0].Id | Should -Be 'test-rule'
        }

        It 'Should force API call with -Force parameter' {
            Mock Invoke-MgGraphRequestWithRetry {
                return @{
                    value = @(
                        @{
                            id = 'test-rule'
                            detectorId = 'test-detector'
                            detectionAction = @{
                                alertTemplate = @{
                                    description = 'Test [12345678-1234-1234-1234-123456789abc]'
                                }
                            }
                        }
                    )
                    '@odata.nextLink' = $null
                }
            } -ModuleName XDRConverter

            $result = Get-CustomDetectionIds -Force
            $result | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Parameter Validation' {
        It 'Should have CacheTtlMinutes parameter' {
            $cmd = Get-Command Get-CustomDetectionIds
            $cmd.Parameters.Keys | Should -Contain 'CacheTtlMinutes'
        }

        It 'Should have Force parameter' {
            $cmd = Get-Command Get-CustomDetectionIds
            $cmd.Parameters.Keys | Should -Contain 'Force'
        }

        It 'Should have default CacheTtlMinutes value of 60' {
            $cmd = Get-Command Get-CustomDetectionIds
            $param = $cmd.Parameters['CacheTtlMinutes']
            $param | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Help Documentation' {
        It 'Should have help documentation' {
            $help = Get-Help Get-CustomDetectionIds
            $help.Description | Should -Not -BeNullOrEmpty
        }

        It 'Should have examples' {
            $help = Get-Help Get-CustomDetectionIds -Examples
            $help.Examples.Example.Count | Should -BeGreaterThan 0
        }
    }
}
