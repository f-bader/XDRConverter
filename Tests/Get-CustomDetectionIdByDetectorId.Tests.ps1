BeforeAll {
    $modulePath = Join-Path $PSScriptRoot '..' 'src' 'XDRConverter.psd1'
    Import-Module $modulePath -Force
}

AfterAll {
    Remove-Module XDRConverter -ErrorAction SilentlyContinue
}

Describe 'Get-CustomDetectionIdByDetectorId' {
    BeforeEach {
        Mock Assert-MgGraphConnection {} -ModuleName XDRConverter
        Mock Get-CustomDetectionIds {
            return @(
                [PSCustomObject]@{ Id = 'rule-81fb771a-c57e-41b8-9905-63dbf267c13f'; DetectorId = $null; DisplayName = 'Current'; DescriptionTag = '81fb771a-c57e-41b8-9905-63dbf267c13f'; TagPrefix = $null }
                [PSCustomObject]@{ Id = '48'; DetectorId = $null; DisplayName = 'Legacy'; DescriptionTag = 'c0ffee00-1111-4222-8333-444455556666'; TagPrefix = 'PREFIX' }
                [PSCustomObject]@{ Id = 'a1b2c3d4-0000-4000-8000-000000000000'; DetectorId = $null; DisplayName = 'UuidId'; DescriptionTag = $null; TagPrefix = $null }
            )
        } -ModuleName XDRConverter
    }

    It 'Returns the rule id when the guid is the rule id behind the prefix' {
        Get-CustomDetectionIdByDetectorId -DetectorId '81fb771a-c57e-41b8-9905-63dbf267c13f' | Should -Be 'rule-81fb771a-c57e-41b8-9905-63dbf267c13f'
    }

    It 'Returns the rule id when the guid is the rule id itself' {
        Get-CustomDetectionIdByDetectorId -DetectorId 'a1b2c3d4-0000-4000-8000-000000000000' | Should -Be 'a1b2c3d4-0000-4000-8000-000000000000'
    }

    It 'Returns the rule id of a rule whose detectorId the API assigned equals the value' {
        Mock Get-CustomDetectionIds {
            return @([PSCustomObject]@{ Id = '61'; DetectorId = '7cb0d5af-690e-4f63-b4b9-6b40728cac5f'; DisplayName = 'Assigned'; DescriptionTag = $null; TagPrefix = $null })
        } -ModuleName XDRConverter
        Get-CustomDetectionIdByDetectorId -DetectorId '7cb0d5af-690e-4f63-b4b9-6b40728cac5f' | Should -Be '61'
    }

    It 'Returns the rule id of a rule that carries the guid only in its description tag' {
        Get-CustomDetectionIdByDetectorId -DetectorId 'c0ffee00-1111-4222-8333-444455556666' | Should -Be '48'
    }

    It 'Returns nothing when neither the rule id nor the tag carries the guid' {
        Get-CustomDetectionIdByDetectorId -DetectorId '00000000-0000-4000-8000-000000000000' | Should -BeNullOrEmpty
    }

    It 'Names every rule when a description tag is carried twice' {
        Mock Get-CustomDetectionIds {
            return @(
                [PSCustomObject]@{ Id = '48'; DetectorId = $null; DisplayName = 'One'; DescriptionTag = 'c0ffee00-1111-4222-8333-444455556666'; TagPrefix = $null }
                [PSCustomObject]@{ Id = '49'; DetectorId = $null; DisplayName = 'Two'; DescriptionTag = 'c0ffee00-1111-4222-8333-444455556666'; TagPrefix = $null }
            )
        } -ModuleName XDRConverter

        $result = Get-CustomDetectionIdByDetectorId -DetectorId 'c0ffee00-1111-4222-8333-444455556666' -WarningVariable warning -WarningAction SilentlyContinue

        $result | Should -BeExactly '48'
        "$warning" | Should -Match '48'
        "$warning" | Should -Match '49'
    }

    It 'Stays quiet when no rule carries the guid' {
        $warning = @()
        Get-CustomDetectionIdByDetectorId -DetectorId '00000000-0000-4000-8000-000000000000' -WarningVariable warning -WarningAction SilentlyContinue | Out-Null
        $warning.Count | Should -Be 0
    }
}
