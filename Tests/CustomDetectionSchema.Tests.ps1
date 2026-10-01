BeforeAll {
    $modulePath = Join-Path $PSScriptRoot '..' 'src' 'XDRConverter.psd1'
    Import-Module $modulePath -Force
    $script:SchemaFile = Join-Path (Split-Path $PSScriptRoot -Parent) 'CustomDetection.schema.json'
    $script:BaseRule = @{ guid = '81fb771a-c57e-41b8-9905-63dbf267c13f'; ruleName = 'r'; alertTitle = 't'; frequency = 'PT1H'; alertSeverity = 'Low'; alertDescription = 'd'; alertCategory = 'Execution'; queryText = 'q' }
}

AfterAll {
    Remove-Module XDRConverter -ErrorAction SilentlyContinue
}

Describe 'CustomDetection schema' {

    It 'Accepts the id alias with and without the rule- prefix' {
        foreach ($id in @('81fb771a-c57e-41b8-9905-63dbf267c13f', 'rule-81fb771a-c57e-41b8-9905-63dbf267c13f')) {
            $rule = $script:BaseRule.Clone()
            $rule.Remove('guid')
            $rule.id = $id
            (Test-Json -Json ($rule | ConvertTo-Json) -SchemaFile $script:SchemaFile -ErrorAction SilentlyContinue) | Should -BeTrue -Because $id
        }
    }

    It 'Accepts a detectorId and rejects one that is not a uuid' {
        $rule = $script:BaseRule.Clone()
        $rule.detectorId = '7cb0d5af-690e-4f63-b4b9-6b40728cac5f'
        (Test-Json -Json ($rule | ConvertTo-Json) -SchemaFile $script:SchemaFile -ErrorAction SilentlyContinue) | Should -BeTrue
        $rule.detectorId = 'assigned-by-api'
        (Test-Json -Json ($rule | ConvertTo-Json) -SchemaFile $script:SchemaFile -ErrorAction SilentlyContinue) | Should -BeFalse
    }

    It 'Rejects an id that is not a uuid behind the prefix' {
        $rule = $script:BaseRule.Clone()
        $rule.Remove('guid')
        $rule.id = 'rule-not-a-uuid'
        (Test-Json -Json ($rule | ConvertTo-Json) -SchemaFile $script:SchemaFile -ErrorAction SilentlyContinue) | Should -BeFalse
    }

    It 'Lists the same columns per entity mapping collection as the module' {
        $schema = Get-Content $script:SchemaFile -Raw | ConvertFrom-Json -AsHashtable
        $collections = $schema.properties.entityMappings.properties
        $expected = InModuleScope XDRConverter { Get-CustomDetectionEntityMappingColumns }
        @($collections.Keys | Sort-Object) | Should -Be @($expected.Keys | Sort-Object)
        foreach ($name in $expected.Keys) {
            $schemaColumns = @($collections[$name].items.properties.Keys | Sort-Object)
            $schemaColumns | Should -Be @($expected[$name] | Sort-Object) -Because $name
            $collections[$name].items.additionalProperties | Should -BeFalse -Because $name
        }
    }

    It 'Accepts an empty mitreTechniques key the way the converter does' {
        $rule = $script:BaseRule.Clone()
        $rule.mitreTechniques = $null
        (Test-Json -Json ($rule | ConvertTo-Json) -SchemaFile $script:SchemaFile -ErrorAction SilentlyContinue) | Should -BeTrue
        InModuleScope XDRConverter -Parameters @{ Rule = $rule } {
            $body = ConvertFrom-CustomDetectionYamlToJson -YamlObject $Rule
            @($body.detectionAction.alertTemplate.tactics[0].Keys) | Should -Not -Contain 'techniques'
        }
    }

    It 'Rejects a column the collection does not document, as the converter does' {
        $rule = $script:BaseRule.Clone()
        $rule.entityMappings = @{ hosts = @(@{ bogusColumn = 'X' }) }
        (Test-Json -Json ($rule | ConvertTo-Json -Depth 5) -SchemaFile $script:SchemaFile -ErrorAction SilentlyContinue) | Should -BeFalse
        InModuleScope XDRConverter {
            { ConvertTo-CustomDetectionEntityMappings -EntityMappings @{ hosts = @(@{ bogusColumn = 'X' }) } } | Should -Throw '*bogusColumn*'
        }
    }

    It 'Rejects an empty device group name, as the converter does' {
        $rule = $script:BaseRule.Clone()
        $rule.organizationalScope = @('')
        (Test-Json -Json ($rule | ConvertTo-Json -Depth 5) -SchemaFile $script:SchemaFile -ErrorAction SilentlyContinue) | Should -BeFalse
        $rule.organizationalScope = @('Servers')
        (Test-Json -Json ($rule | ConvertTo-Json -Depth 5) -SchemaFile $script:SchemaFile -ErrorAction SilentlyContinue) | Should -BeTrue
    }

    It 'Rejects an account mapping without a key column, as the converter does' {
        $rule = $script:BaseRule.Clone()
        $rule.entityMappings = @{ accounts = @(@{ nameColumn = 'AccountName' }) }
        (Test-Json -Json ($rule | ConvertTo-Json -Depth 5) -SchemaFile $script:SchemaFile -ErrorAction SilentlyContinue) | Should -BeFalse
        InModuleScope XDRConverter {
            { ConvertTo-CustomDetectionEntityMappings -EntityMappings @{ accounts = @(@{ nameColumn = 'AccountName' }) } } | Should -Throw '*aadUserIdColumn*'
        }
    }

    It 'Accepts an account mapping the API accepts' -ForEach @(
        @{ Columns = @{ sidColumn = 'AccountSid' } }
        @{ Columns = @{ aadUserIdColumn = 'AccountObjectId' } }
        @{ Columns = @{ upnColumn = 'AccountUpn' } }
        @{ Columns = @{ nameColumn = 'AccountName'; ntDomainColumn = 'AccountDomain' } }
    ) {
        $rule = $script:BaseRule.Clone()
        $rule.entityMappings = @{ accounts = @($Columns) }
        (Test-Json -Json ($rule | ConvertTo-Json -Depth 5) -SchemaFile $script:SchemaFile -ErrorAction SilentlyContinue) | Should -BeTrue -Because ($Columns.Keys -join ', ')
    }

    It 'Rejects a field the action type does not document, as the converter does' -ForEach @(
        @{ ActionType = 'IsolateMachine'; Field = 'recipientColumn' }
        @{ ActionType = 'StopAndQuarantineFile'; Field = 'sha256Column' }
        @{ ActionType = 'DisableUser'; Field = 'deviceIdColumn' }
        @{ ActionType = 'RunAntivirusScan'; Field = 'isolationType' }
        @{ ActionType = 'HardDeleteEmail'; Field = 'accountSidColumn' }
    ) {
        $rule = $script:BaseRule.Clone()
        $rule.actions = @(@{ actionType = $ActionType; additionalFields = @{ $Field = 'X' } })
        (Test-Json -Json ($rule | ConvertTo-Json -Depth 5) -SchemaFile $script:SchemaFile -ErrorAction SilentlyContinue) | Should -BeFalse -Because "$ActionType with $Field"
        InModuleScope XDRConverter -Parameters @{ ActionType = $ActionType; Field = $Field } {
            { ConvertTo-CustomDetectionAutomatedActions -Actions @(@{ actionType = $ActionType; additionalFields = @{ $Field = 'X' } }) } | Should -Throw "*$Field*"
        }
    }

    It 'Accepts every field the module documents for an action' {
        $map = InModuleScope XDRConverter { Get-CustomDetectionActionMap }
        foreach ($entry in $map) {
            $fields = @{}
            foreach ($field in $entry.Fields) {
                # A file action carries one hash column, so the sample names sha1Column alone
                if ($field -eq 'sha256Column') { continue }
                if ($field -eq 'isolationType') { $fields[$field] = 'Full'; continue }
                if ($field -eq 'deviceGroupNames') { $fields[$field] = [string[]]@('Servers', 'Workstations'); continue }
                $fields[$field] = 'Col'
            }
            $rule = $script:BaseRule.Clone()
            $rule.actions = @(@{ actionType = $entry.ActionType; additionalFields = $fields })
            (Test-Json -Json ($rule | ConvertTo-Json -Depth 6) -SchemaFile $script:SchemaFile -ErrorAction SilentlyContinue) | Should -BeTrue -Because $entry.ActionType

            InModuleScope XDRConverter -Parameters @{ ActionType = $entry.ActionType; Fields = $fields } {
                { ConvertTo-CustomDetectionAutomatedActions -Actions @(@{ actionType = $ActionType; additionalFields = $Fields }) } | Should -Not -Throw
            }
        }
    }

    It 'Rejects a file action that names both hash columns, as the converter does' -ForEach @(
        @{ ActionType = 'AllowFile' }
        @{ ActionType = 'BlockFile' }
    ) {
        $rule = $script:BaseRule.Clone()
        $rule.actions = @(@{ actionType = $ActionType; additionalFields = @{ sha1Column = 'SHA1'; sha256Column = 'SHA256' } })
        (Test-Json -Json ($rule | ConvertTo-Json -Depth 6) -SchemaFile $script:SchemaFile -ErrorAction SilentlyContinue) | Should -BeFalse -Because $ActionType
        InModuleScope XDRConverter -Parameters @{ ActionType = $ActionType } {
            { ConvertTo-CustomDetectionAutomatedActions -Actions @(@{ actionType = $ActionType; additionalFields = @{ sha1Column = 'SHA1'; sha256Column = 'SHA256' } }) } | Should -Throw '*one hash column*'
        }
    }

    It 'Accepts an additionalFields key that carries no value, as the converter does' {
        $json = '{"guid":"81fb771a-c57e-41b8-9905-63dbf267c13f","ruleName":"r","alertTitle":"t","frequency":"PT1H","alertSeverity":"Low","alertDescription":"d","alertCategory":"Execution","queryText":"q","actions":[{"actionType":"IsolateMachine","additionalFields":null}]}'
        (Test-Json -Json $json -SchemaFile $script:SchemaFile -ErrorAction SilentlyContinue) | Should -BeTrue
        InModuleScope XDRConverter {
            $result = ConvertTo-CustomDetectionAutomatedActions -Actions @(@{ actionType = 'IsolateMachine'; additionalFields = $null })
            $result.isolateDevices[0].deviceIdColumn | Should -BeExactly 'DeviceId'
        }
    }

    It 'Accepts every documented column of every collection' {
        $expected = InModuleScope XDRConverter { Get-CustomDetectionEntityMappingColumns }
        foreach ($name in $expected.Keys) {
            $item = @{}
            foreach ($column in $expected[$name]) { $item[$column] = 'Col' }
            $rule = $script:BaseRule.Clone()
            $rule.entityMappings = @{ $name = @($item) }
            (Test-Json -Json ($rule | ConvertTo-Json -Depth 5) -SchemaFile $script:SchemaFile -ErrorAction SilentlyContinue) | Should -BeTrue -Because $name
        }
    }
}
