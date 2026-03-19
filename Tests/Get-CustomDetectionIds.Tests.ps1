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
            InModuleScope XDRConverter {
                $script:DetectionIdsCache = @{
                    Data      = $null
                    ExpiresAt = [datetime]::MinValue
                }
            }
        }

        AfterEach {
            # Clear the cache after each test to avoid interference
            InModuleScope XDRConverter {
                $script:DetectionIdsCache = @{
                    Data      = $null
                    ExpiresAt = [datetime]::MinValue
                }
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

        It 'Should use cache on subsequent calls without -Force' {
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

            # First call should hit the API because the cache is empty
            $firstResult = Get-CustomDetectionIds

            # Second call should use the cached data and not hit the API again
            $secondResult = Get-CustomDetectionIds

            Assert-MockCalled Invoke-MgGraphRequestWithRetry -Times 1 -Exactly -ModuleName XDRConverter

            $firstResult  | Should -Not -BeNullOrEmpty
            $secondResult | Should -Not -BeNullOrEmpty
            $firstResult[0].Id  | Should -Be 'test-rule'
            $secondResult[0].Id | Should -Be 'test-rule'
        }

        It 'Should force API call with -Force parameter even when cache is populated' {
            # Track how many times the API is called and vary the response
            $script:CallCount = 0

            Mock Invoke-MgGraphRequestWithRetry {
                $script:CallCount++
                return @{
                    value = @(
                        @{
                            id = "test-rule-$script:CallCount"
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

            # First call populates the cache
            $cachedResult = Get-CustomDetectionIds

            # Second call with -Force should bypass cache and call API again
            $forcedResult = Get-CustomDetectionIds -Force

            Assert-MockCalled Invoke-MgGraphRequestWithRetry -Times 2 -Exactly -ModuleName XDRConverter

            $cachedResult  | Should -Not -BeNullOrEmpty
            $forcedResult  | Should -Not -BeNullOrEmpty
            $cachedResult[0].Id | Should -Be 'test-rule-1'
            $forcedResult[0].Id | Should -Be 'test-rule-2'
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
