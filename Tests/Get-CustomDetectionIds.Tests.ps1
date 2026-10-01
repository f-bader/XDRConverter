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

            # Clear the cache before each test inside the module scope,
            # because $script: refers to the module's script scope there.
            InModuleScope XDRConverter {
                $script:DetectionIdsCache = @{
                    Data      = $null
                    ExpiresAt = [datetime]::MinValue
                }
            }
        }

        AfterEach {
            InModuleScope XDRConverter {
                $script:DetectionIdsCache = @{
                    Data      = $null
                    ExpiresAt = [datetime]::MinValue
                }
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

            Should -Invoke Invoke-MgGraphRequestWithRetry -Times 1 -Exactly -ModuleName XDRConverter

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

            Should -Invoke Invoke-MgGraphRequestWithRetry -Times 2 -Exactly -ModuleName XDRConverter

            $cachedResult  | Should -Not -BeNullOrEmpty
            $forcedResult  | Should -Not -BeNullOrEmpty
            $cachedResult[0].Id | Should -Be 'test-rule-1'
            $forcedResult[0].Id | Should -Be 'test-rule-2'
        }
    }

    Context 'Projection' {
        BeforeEach {
            Mock Assert-MgGraphConnection {} -ModuleName XDRConverter
            Mock Invoke-MgGraphRequestWithRetry {
                $script:CapturedUri = $Uri
                return @{
                    value = @(
                        @{
                            id              = 'rule-new'
                            detectorId      = '7cb0d5af-690e-4f63-b4b9-6b40728cac5f'
                            displayName     = 'Rule New'
                            detectionAction = @{ alertTemplate = @{ description = 'Alert [12345678-1234-1234-1234-123456789abc]' } }
                        }
                    )
                    '@odata.nextLink' = $null
                }
            } -ModuleName XDRConverter
            InModuleScope XDRConverter {
                $script:DetectionIdsCache = @{ Data = $null; ExpiresAt = [datetime]::MinValue }
            }
        }

        It 'Should project the id, the detector id, the display name and the detection action' {
            Get-CustomDetectionIds | Out-Null
            $script:CapturedUri | Should -Match '\$select=id,detectorId,displayName,detectionAction'
        }

        It 'Should carry the display name' {
            (Get-CustomDetectionIds)[0].DisplayName | Should -Be 'Rule New'
        }

        It 'Should carry the detector id the API assigned' {
            $result = Get-CustomDetectionIds
            $result[0].DetectorId | Should -Be '7cb0d5af-690e-4f63-b4b9-6b40728cac5f'
            $result[0].DescriptionTag | Should -Be '12345678-1234-1234-1234-123456789abc'
        }
    }

    Context 'Cache entries' {
        BeforeEach {
            Mock Assert-MgGraphConnection {} -ModuleName XDRConverter
            Mock Invoke-MgGraphRequestWithRetry { return @{ value = @() } } -ModuleName XDRConverter
            InModuleScope XDRConverter {
                $script:DetectionIdsCache = @{
                    Data      = @([PSCustomObject]@{ Id = 'rule-a'; DetectorId = $null; DisplayName = 'A'; DescriptionTag = $null; TagPrefix = $null })
                    ExpiresAt = [datetime]::UtcNow.AddHours(1)
                }
            }
        }

        It 'Serves an appended entry without calling the API' {
            InModuleScope XDRConverter {
                Add-CustomDetectionIdsCacheEntry -Entry ([PSCustomObject]@{ Id = 'rule-b'; DetectorId = 'd-b'; DisplayName = 'B'; DescriptionTag = 'c0ffee00-1111-4222-8333-444455556666'; TagPrefix = $null })
            }
            $result = Get-CustomDetectionIds
            @($result).Id | Should -Be @('rule-a', 'rule-b')
            Should -Invoke Invoke-MgGraphRequestWithRetry -ModuleName XDRConverter -Times 0 -Exactly
        }

        It 'Replaces an entry that carries the same id' {
            InModuleScope XDRConverter {
                Add-CustomDetectionIdsCacheEntry -Entry ([PSCustomObject]@{ Id = 'rule-a'; DetectorId = 'd-a'; DisplayName = 'A2'; DescriptionTag = $null; TagPrefix = $null })
            }
            $result = Get-CustomDetectionIds
            @($result).Count | Should -Be 1
            $result[0].DisplayName | Should -Be 'A2'
        }

        It 'Builds an entry with the tag and its prefix from a rule' {
            InModuleScope XDRConverter {
                $entry = ConvertTo-CustomDetectionIdEntry -Rule @{ id = '9'; detectorId = 'd-9'; displayName = 'Nine'; detectionAction = @{ alertTemplate = @{ description = 'x [PREFIX:c0ffee00-1111-4222-8333-444455556666]' } } }
                $entry.Id | Should -Be '9'
                $entry.DetectorId | Should -Be 'd-9'
                $entry.DisplayName | Should -Be 'Nine'
                $entry.DescriptionTag | Should -Be 'c0ffee00-1111-4222-8333-444455556666'
                $entry.TagPrefix | Should -Be 'PREFIX'
            }
        }
    }

    Context 'List timeouts' {
        BeforeEach {
            Mock Assert-MgGraphConnection {} -ModuleName XDRConverter
            InModuleScope XDRConverter {
                $script:DetectionIdsCache = @{ Data = $null; ExpiresAt = [datetime]::MinValue; FailedAt = $null }
                $script:ListCalls = 0
            }
        }

        It 'Retries the list once when the first call times out' {
            Mock Invoke-MgGraphRequestWithRetry {
                $script:ListCalls++
                if ($script:ListCalls -eq 1) { throw 'The request was canceled due to the configured HttpClient.Timeout of 300 seconds elapsing.' }
                return @{ value = @(@{ id = 'rule-1'; displayName = 'A'; detectionAction = @{ alertTemplate = @{ description = 'x' } } }) }
            } -ModuleName XDRConverter

            $result = Get-CustomDetectionIds -WarningAction SilentlyContinue
            @($result).Count | Should -Be 1
            Should -Invoke Invoke-MgGraphRequestWithRetry -ModuleName XDRConverter -Times 2 -Exactly
        }

        It 'Fails fast for five minutes after the retry times out as well' {
            Mock Invoke-MgGraphRequestWithRetry { throw 'The request was canceled due to the configured HttpClient.Timeout of 300 seconds elapsing.' } -ModuleName XDRConverter

            { Get-CustomDetectionIds -WarningAction SilentlyContinue -ErrorAction SilentlyContinue } | Should -Throw '*HttpClient.Timeout*'
            Should -Invoke Invoke-MgGraphRequestWithRetry -ModuleName XDRConverter -Times 2 -Exactly
            { Get-CustomDetectionIds -WarningAction SilentlyContinue -ErrorAction SilentlyContinue } | Should -Throw '*rule list is unavailable*'
            Should -Invoke Invoke-MgGraphRequestWithRetry -ModuleName XDRConverter -Times 2 -Exactly
        }

        It 'Asks the API again with -Force inside the window' {
            InModuleScope XDRConverter { $script:DetectionIdsCache.FailedAt = [datetime]::UtcNow }
            Mock Invoke-MgGraphRequestWithRetry { return @{ value = @(@{ id = 'rule-1'; displayName = 'A'; detectionAction = @{ alertTemplate = @{ description = 'x' } } }) } } -ModuleName XDRConverter

            @(Get-CustomDetectionIds -Force).Count | Should -Be 1
            Should -Invoke Invoke-MgGraphRequestWithRetry -ModuleName XDRConverter -Times 1 -Exactly
            InModuleScope XDRConverter { $script:DetectionIdsCache.FailedAt | Should -BeNullOrEmpty }
        }

        It 'Asks the API again once the window has passed' {
            InModuleScope XDRConverter { $script:DetectionIdsCache.FailedAt = [datetime]::UtcNow.AddMinutes(-6) }
            Mock Invoke-MgGraphRequestWithRetry { return @{ value = @() } } -ModuleName XDRConverter

            Get-CustomDetectionIds | Out-Null
            Should -Invoke Invoke-MgGraphRequestWithRetry -ModuleName XDRConverter -Times 1 -Exactly
        }

        It 'Does not retry or open the window for a failure that is not a timeout' {
            Mock Invoke-MgGraphRequestWithRetry { throw 'Response status code does not indicate success: Forbidden (Forbidden).' } -ModuleName XDRConverter

            { Get-CustomDetectionIds -ErrorAction SilentlyContinue } | Should -Throw '*Forbidden*'
            Should -Invoke Invoke-MgGraphRequestWithRetry -ModuleName XDRConverter -Times 1 -Exactly
            InModuleScope XDRConverter { $script:DetectionIdsCache.FailedAt | Should -BeNullOrEmpty }
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
