Describe 'Compare-CustomDetection' {

    BeforeAll {
        $ModulePath = Split-Path -Path $PSScriptRoot -Parent
        $ModulePath = Join-Path -Path $ModulePath -ChildPath 'src' | Join-Path -ChildPath 'XDRConverter.psd1'
        Import-Module -Name $ModulePath -Force

        function New-LocalBody {
            param([hashtable]$Overrides = @{})
            $body = @{
                id              = '81fb771a-c57e-41b8-9905-63dbf267c13f'
                displayName     = 'TEST-Rule'
                status          = 'enabled'
                queryCondition  = @{ queryText = 'DeviceEvents | take 1' }
                schedule        = @{ frequency = 'PT1H' }
                detectionAction = @{
                    alertTemplate = @{
                        title          = 'Title'
                        description    = 'Desc [81fb771a-c57e-41b8-9905-63dbf267c13f]'
                        severity       = 'medium'
                        tactics        = @(@{ tactic = 'Execution'; techniques = @(@{ technique = 'T1059'; subTechniques = @('T1059.001') }) })
                        entityMappings = @{ hosts = @(@{ deviceIdColumn = 'DeviceId' }) }
                    }
                    automatedActions = @{ isolateDevices = @(@{ deviceIdColumn = 'DeviceId'; isolationType = 'full' }) }
                    organizationalScope = @{ deviceGroups = @('Servers') }
                }
            }
            foreach ($key in $Overrides.Keys) {
                $target = $body
                $segments = $key.Split('.')
                for ($i = 0; $i -lt $segments.Count - 1; $i++) { $target = $target[$segments[$i]] }
                $target[$segments[-1]] = $Overrides[$key]
            }
            return $body
        }

        function New-RemoteRule {
            # Mirrors the dual old-plus-new shape the Graph API returns today.
            return [PSCustomObject]@{
                id              = '48'
                detectorId      = 'f687512c-0654-4999-a0ac-d5906ffc3972'
                displayName     = 'TEST-Rule'
                isEnabled       = $true
                status          = 'enabled'
                createdBy       = 'someone'
                queryCondition  = [PSCustomObject]@{ queryText = 'DeviceEvents | take 1'; lastModifiedDateTime = '2026-01-01T00:00:00Z' }
                schedule        = [PSCustomObject]@{ period = '1H'; frequency = 'PT1H'; nextRunDateTime = '2026-01-01T00:00:00Z' }
                detectionAction = [PSCustomObject]@{
                    alertTemplate       = [PSCustomObject]@{
                        title              = 'Title'
                        description        = 'Desc [81fb771a-c57e-41b8-9905-63dbf267c13f]'
                        severity           = 'medium'
                        category           = 'Execution'
                        mitreTechniques    = @('T1059', 'T1059.001')
                        tactics            = @([PSCustomObject]@{ tactic = 'Execution'; techniques = @([PSCustomObject]@{ technique = 'T1059'; subTechniques = @('T1059.001') }) })
                        impactedAssets     = @([PSCustomObject]@{ '@odata.type' = '#microsoft.graph.security.impactedDeviceAsset'; identifier = 'deviceId' })
                        entityMappings     = [PSCustomObject]@{
                            accounts = $null
                            hosts    = @([PSCustomObject]@{ deviceIdColumn = 'DeviceId'; nameColumn = ''; ntDomainColumn = '' })
                            files    = $null
                        }
                        recommendedActions = $null
                        customDetails      = $null
                    }
                    responseActions     = @([PSCustomObject]@{ '@odata.type' = '#microsoft.graph.security.isolateDeviceResponseAction'; identifier = 'deviceId'; isolationType = 'full' })
                    automatedActions    = [PSCustomObject]@{
                        allowFiles     = $null
                        isolateDevices = @([PSCustomObject]@{ deviceIdColumn = 'DeviceId'; isolationType = 'full' })
                    }
                    organizationalScope = [PSCustomObject]@{ scopeType = 'deviceGroup'; scopeNames = @('Servers'); deviceGroups = @('Servers') }
                }
            }
        }
    }

    AfterAll {
        Remove-Module -Name XDRConverter -Force -ErrorAction SilentlyContinue
    }

    It 'Reports no change for an equivalent new-shape body against a dual-shape remote' {
        $local = New-LocalBody
        $remote = New-RemoteRule
        InModuleScope XDRConverter -Parameters @{ Local = $local; Remote = $remote } {
            Compare-CustomDetection -Local $Local -Remote $Remote | Should -Be $false
        }
    }

    It 'Reports no change for an equivalent legacy-shape body' {
        $local = @{
            detectorId      = '81fb771a-c57e-41b8-9905-63dbf267c13f'
            displayName     = 'TEST-Rule'
            isEnabled       = $true
            queryCondition  = @{ queryText = 'DeviceEvents | take 1' }
            schedule        = @{ period = '1H' }
            detectionAction = @{
                alertTemplate       = @{
                    title           = 'Title'
                    description     = 'Desc [81fb771a-c57e-41b8-9905-63dbf267c13f]'
                    severity        = 'medium'
                    category        = 'Execution'
                    mitreTechniques = @('T1059.001')
                    impactedAssets  = @(@{ '@odata.type' = '#microsoft.graph.security.impactedDeviceAsset'; identifier = 'deviceId' })
                }
                responseActions     = @(@{ '@odata.type' = '#microsoft.graph.security.isolateDeviceResponseAction'; identifier = 'deviceId'; isolationType = 'full' })
                organizationalScope = @('Servers')
            }
        }
        $remote = New-RemoteRule
        InModuleScope XDRConverter -Parameters @{ Local = $local; Remote = $remote } {
            Compare-CustomDetection -Local $Local -Remote $Remote | Should -Be $false
        }
    }

    It 'Detects a change in <Name>' -ForEach @(
        @{ Name = 'displayName'; Path = 'displayName'; Value = 'Other' }
        @{ Name = 'status'; Path = 'status'; Value = 'disabled' }
        @{ Name = 'query'; Path = 'queryCondition.queryText'; Value = 'DeviceEvents | take 2' }
        @{ Name = 'frequency'; Path = 'schedule.frequency'; Value = 'P1D' }
        @{ Name = 'severity'; Path = 'detectionAction.alertTemplate.severity'; Value = 'high' }
        @{ Name = 'sub-technique only'; Path = 'detectionAction.alertTemplate.tactics'; Value = @(@{ tactic = 'Execution'; techniques = @(@{ technique = 'T1059' }) }) }
        @{ Name = 'entity mapping only'; Path = 'detectionAction.alertTemplate.entityMappings'; Value = @{ hosts = @(@{ nameColumn = 'DeviceName' }) } }
        @{ Name = 'action only'; Path = 'detectionAction.automatedActions'; Value = @{ isolateDevices = @(@{ deviceIdColumn = 'DeviceId'; isolationType = 'selective' }) } }
        @{ Name = 'scope only'; Path = 'detectionAction.organizationalScope'; Value = @{ deviceGroups = @('Workstations') } }
        @{ Name = 'rule description'; Path = 'description'; Value = 'A note' }
    ) {
        $local = New-LocalBody -Overrides @{ $Path = $Value }
        $remote = New-RemoteRule
        InModuleScope XDRConverter -Parameters @{ Local = $local; Remote = $remote } {
            Compare-CustomDetection -Local $Local -Remote $Remote | Should -Be $true
        }
    }

    It 'Detects a case-only change in <Name>' -ForEach @(
        @{ Name = 'the query'; Path = 'queryCondition.queryText'; Value = 'deviceevents | take 1' }
        @{ Name = 'a column name'; Path = 'detectionAction.alertTemplate.entityMappings'; Value = @{ hosts = @(@{ deviceIdColumn = 'deviceid' }) } }
        @{ Name = 'an action column name'; Path = 'detectionAction.automatedActions'; Value = @{ isolateDevices = @(@{ deviceIdColumn = 'deviceid'; isolationType = 'full' }) } }
        @{ Name = 'the display name'; Path = 'displayName'; Value = 'test-rule' }
        @{ Name = 'the alert title'; Path = 'detectionAction.alertTemplate.title'; Value = 'title' }
    ) {
        $local = New-LocalBody -Overrides @{ $Path = $Value }
        $remote = New-RemoteRule
        InModuleScope XDRConverter -Parameters @{ Local = $local; Remote = $remote } {
            Compare-CustomDetection -Local $Local -Remote $Remote | Should -Be $true
        }
    }

    It 'Ignores a case-only difference in <Name>' -ForEach @(
        @{ Name = 'the status'; Path = 'status'; Value = 'Enabled' }
        @{ Name = 'the severity'; Path = 'detectionAction.alertTemplate.severity'; Value = 'Medium' }
        @{ Name = 'the tactic name'; Path = 'detectionAction.alertTemplate.tactics'; Value = @(@{ tactic = 'execution'; techniques = @(@{ technique = 't1059'; subTechniques = @('t1059.001') }) }) }
        @{ Name = 'a device group name'; Path = 'detectionAction.organizationalScope'; Value = @{ deviceGroups = @('servers') } }
    ) {
        $local = New-LocalBody -Overrides @{ $Path = $Value }
        $remote = New-RemoteRule
        InModuleScope XDRConverter -Parameters @{ Local = $local; Remote = $remote } {
            Compare-CustomDetection -Local $Local -Remote $Remote | Should -Be $false
        }
    }

    It 'Treats a removed action as a change' {
        $local = New-LocalBody -Overrides @{ 'detectionAction.automatedActions' = $null }
        $remote = New-RemoteRule
        InModuleScope XDRConverter -Parameters @{ Local = $local; Remote = $remote } {
            Compare-CustomDetection -Local $Local -Remote $Remote | Should -Be $true
        }
    }

    It 'Ignores ordering differences inside collections' {
        $local = New-LocalBody -Overrides @{
            'detectionAction.alertTemplate.tactics' = @(@{ tactic = 'Execution'; techniques = @('T1059.001', 'T1059') })
        }
        $remote = New-RemoteRule
        InModuleScope XDRConverter -Parameters @{ Local = $local; Remote = $remote } {
            Compare-CustomDetection -Local $Local -Remote $Remote | Should -Be $false
        }
    }

    It 'Ignores the order of <Name> that differ only by case' -ForEach @(
        @{ Name = 'entity mappings'; Path = 'detectionAction.alertTemplate.entityMappings'; Key = 'hosts'; Items = @(@{ deviceIdColumn = 'DeviceId' }, @{ deviceIdColumn = 'deviceid' }) }
        @{ Name = 'automated actions'; Path = 'detectionAction.automatedActions'; Key = 'isolateDevices'; Items = @(@{ deviceIdColumn = 'DeviceId'; isolationType = 'full' }, @{ deviceIdColumn = 'deviceid'; isolationType = 'full' }) }
    ) {
        $local = New-LocalBody -Overrides @{ $Path = @{ $Key = $Items } }
        $remote = New-LocalBody -Overrides @{ $Path = @{ $Key = @($Items[1], $Items[0]) } }
        InModuleScope XDRConverter -Parameters @{ Local = $local; Remote = $remote } {
            Compare-CustomDetection -Local $Local -Remote $Remote | Should -Be $false
        }
    }

    It 'Warns instead of reporting a change when the file has no customDetails but the rule does' {
        $local = New-LocalBody
        $remote = New-RemoteRule
        $remote.detectionAction.alertTemplate.customDetails = [PSCustomObject]@{ CommandLine = 'ProcessCommandLine' }
        InModuleScope XDRConverter -Parameters @{ Local = $local; Remote = $remote } {
            $result = Compare-CustomDetection -Local $Local -Remote $Remote -WarningVariable w -WarningAction SilentlyContinue
            $result | Should -Be $false
            $w | Should -Not -BeNullOrEmpty
        }
    }

    It 'Keeps a remote <Name> the file does not set without reporting a change' -ForEach @(
        @{ Name = 'description'; Path = 'description' }
        @{ Name = 'recommended action'; Path = 'detectionAction.alertTemplate.recommendedActions' }
    ) {
        $local = New-LocalBody
        $remote = New-RemoteRule
        if ($Path -eq 'description') {
            $remote | Add-Member -NotePropertyName description -NotePropertyValue 'Set in the portal'
        } else {
            $remote.detectionAction.alertTemplate.recommendedActions = 'Set in the portal'
        }
        InModuleScope XDRConverter -Parameters @{ Local = $local; Remote = $remote } {
            $result = Compare-CustomDetection -Local $Local -Remote $Remote -WarningVariable warning -WarningAction SilentlyContinue
            $result | Should -Be $false
            "$warning" | Should -Match 'cannot remove'
        }
    }

    It 'Still reports a change when the file sets a different <Name>' -ForEach @(
        @{ Name = 'description'; Path = 'description' }
        @{ Name = 'recommended action'; Path = 'detectionAction.alertTemplate.recommendedActions' }
    ) {
        $local = New-LocalBody -Overrides @{ $Path = 'From the file' }
        $remote = New-RemoteRule
        if ($Path -eq 'description') {
            $remote | Add-Member -NotePropertyName description -NotePropertyValue 'Set in the portal'
        } else {
            $remote.detectionAction.alertTemplate.recommendedActions = 'Set in the portal'
        }
        InModuleScope XDRConverter -Parameters @{ Local = $local; Remote = $remote } {
            Compare-CustomDetection -Local $Local -Remote $Remote | Should -Be $true
        }
    }

    It 'Treats a remote autoDisabled status as no change and warns' {
        $local = New-LocalBody
        $remote = New-RemoteRule
        $remote.status = 'autoDisabled'
        InModuleScope XDRConverter -Parameters @{ Local = $local; Remote = $remote } {
            $result = Compare-CustomDetection -Local $Local -Remote $Remote -WarningVariable w -WarningAction SilentlyContinue
            $result | Should -Be $false
            "$w" | Should -Match 'autoDisabled'
        }
    }

    It 'Still reports a change when the file disables an autoDisabled rule' {
        $local = New-LocalBody -Overrides @{ status = 'disabled' }
        $remote = New-RemoteRule
        $remote.status = 'autoDisabled'
        InModuleScope XDRConverter -Parameters @{ Local = $local; Remote = $remote } {
            Compare-CustomDetection -Local $Local -Remote $Remote -WarningAction SilentlyContinue | Should -Be $true
        }
    }

    It 'Still reports a change when customDetails differ on both sides' {
        $local = New-LocalBody -Overrides @{ 'detectionAction.alertTemplate.customDetails' = @{ CommandLine = 'Other' } }
        $remote = New-RemoteRule
        $remote.detectionAction.alertTemplate.customDetails = [PSCustomObject]@{ CommandLine = 'ProcessCommandLine' }
        InModuleScope XDRConverter -Parameters @{ Local = $local; Remote = $remote } {
            Compare-CustomDetection -Local $Local -Remote $Remote | Should -Be $true
        }
    }

    It 'Still compares when the remote frequency is not a known value' {
        $local = New-LocalBody
        $remote = New-RemoteRule
        $remote.schedule.frequency = 'SOMETHING-NEW'
        InModuleScope XDRConverter -Parameters @{ Local = $local; Remote = $remote } {
            Compare-CustomDetection -Local $Local -Remote $Remote | Should -Be $true
        }
    }

    It 'Treats an emptied remote account mapping and a local rule without accounts as equal' {
        $local = New-LocalBody
        $remote = New-RemoteRule
        $remote.detectionAction.alertTemplate.entityMappings.accounts = @([PSCustomObject]@{ aadUserIdColumn = ''; nameColumn = ''; ntDomainColumn = ''; sidColumn = ''; upnColumn = '' })
        InModuleScope XDRConverter -Parameters @{ Local = $local; Remote = $remote } {
            Compare-CustomDetection -Local $Local -Remote $Remote | Should -BeFalse
        }
    }

    It 'Treats an absent optional value and an empty remote value as equal' {
        $local = New-LocalBody -Overrides @{ 'detectionAction.organizationalScope' = $null }
        $remote = New-RemoteRule
        $remote.detectionAction.organizationalScope = $null
        InModuleScope XDRConverter -Parameters @{ Local = $local; Remote = $remote } {
            Compare-CustomDetection -Local $Local -Remote $Remote | Should -Be $false
        }
    }
}
