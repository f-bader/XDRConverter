BeforeAll {
    $modulePath = Join-Path $PSScriptRoot '..' 'src' 'XDRConverter.psd1'
    Import-Module $modulePath -Force
}

AfterAll {
    Remove-Module XDRConverter -ErrorAction SilentlyContinue
}

Describe 'Get-CustomDetectionIdByDescriptionTag' {
    BeforeEach {
        Mock Assert-MgGraphConnection {} -ModuleName XDRConverter
    }

    It 'Returns the rule id of the rule that carries the tag' {
        Mock Get-CustomDetectionIds {
            return @([PSCustomObject]@{ Id = '48'; DetectorId = $null; DisplayName = 'One'; DescriptionTag = 'c0ffee00-1111-4222-8333-444455556666'; TagPrefix = $null })
        } -ModuleName XDRConverter
        Get-CustomDetectionIdByDescriptionTag -DescriptionTag 'c0ffee00-1111-4222-8333-444455556666' | Should -Be '48'
    }

    It 'Returns one id and warns when two rules carry the same tag' {
        Mock Get-CustomDetectionIds {
            return @(
                [PSCustomObject]@{ Id = '48'; DetectorId = $null; DisplayName = 'One'; DescriptionTag = 'c0ffee00-1111-4222-8333-444455556666'; TagPrefix = $null }
                [PSCustomObject]@{ Id = 'rule-c0ffee00-1111-4222-8333-444455556666'; DetectorId = $null; DisplayName = 'Two'; DescriptionTag = 'c0ffee00-1111-4222-8333-444455556666'; TagPrefix = $null }
            )
        } -ModuleName XDRConverter
        $result = Get-CustomDetectionIdByDescriptionTag -DescriptionTag 'c0ffee00-1111-4222-8333-444455556666' -WarningVariable warning -WarningAction SilentlyContinue
        $result | Should -BeOfType [string]
        $result | Should -Be '48'
        "$warning" | Should -Match '48'
        "$warning" | Should -Match 'rule-c0ffee00'
    }

    It 'Returns nothing and warns when no rule carries the tag' {
        Mock Get-CustomDetectionIds { return @() } -ModuleName XDRConverter
        Get-CustomDetectionIdByDescriptionTag -DescriptionTag 'c0ffee00-1111-4222-8333-444455556666' -WarningAction SilentlyContinue | Should -BeNullOrEmpty
    }
}
