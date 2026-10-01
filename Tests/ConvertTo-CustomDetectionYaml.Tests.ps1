Describe 'ConvertTo-CustomDetectionYaml' {

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
      { ConvertTo-CustomDetectionYaml -InputFile 'C:\nonexistent\file.json' } | Should -Throw
    }

    It 'Should accept valid Severity parameter values' {
      $validValues = 'Informational', 'Low', 'Medium', 'High'
      foreach ($severity in $validValues) {
        $params = @{
          InputFile = $PSScriptRoot -replace 'Tests', '..'
          Severity  = $severity
        }
        $params | Should -Not -BeNullOrEmpty
      }
    }

    It 'Should reject invalid Severity parameter values' {
      { ConvertTo-CustomDetectionYaml -InputFile 'output.json' -Severity 'InvalidSeverity' } | Should -Throw
    }

    It 'Should accept boolean values for Enabled parameter' {
      $params = @{
        InputFile = $PSScriptRoot -replace 'Tests', '..'
        Enabled   = $false
      }
      $params.Enabled | Should -Be $false
    }
  }

  Context 'detectorId' {

    It 'Emits the detectorId the API assigned right after the guid' {
      $rule = [PSCustomObject]@{
        id              = 'rule-81fb771a-c57e-41b8-9905-63dbf267c13f'
        detectorId      = '7cb0d5af-690e-4f63-b4b9-6b40728cac5f'
        displayName     = 'WithDetector'
        status          = 'enabled'
        detectionAction = @{ alertTemplate = @{ title = 't'; description = 'd'; severity = 'low'; tactics = @(@{ tactic = 'Execution' }) } }
        queryCondition  = @{ queryText = 'DeviceEvents' }
        schedule        = @{ frequency = 'PT1H' }
      }
      $yaml = $rule | ConvertTo-CustomDetectionYaml
      $yaml | Should -Match '(?m)^guid: 81fb771a-c57e-41b8-9905-63dbf267c13f?
detectorId: 7cb0d5af-690e-4f63-b4b9-6b40728cac5f'
    }

    It 'Leaves detectorId out when the rule has none' {
      $rule = [PSCustomObject]@{
        id              = 'rule-81fb771a-c57e-41b8-9905-63dbf267c13f'
        displayName     = 'NoDetector'
        status          = 'enabled'
        detectionAction = @{ alertTemplate = @{ title = 't'; description = 'd'; severity = 'low'; tactics = @(@{ tactic = 'Execution' }) } }
        queryCondition  = @{ queryText = 'DeviceEvents' }
        schedule        = @{ frequency = 'PT1H' }
      }
      ($rule | ConvertTo-CustomDetectionYaml) | Should -Not -Match 'detectorId'
    }
  }

  Context 'Functionality' {

    It 'Should convert JSON to YAML string when no OutputFile specified' {
      $testJsonContent = @"
{
  "createdBy": "XDRConverter",
  "createdDateTime": "2024-01-16T12:39:02.6487368Z",
  "detectionAction": {
    "alertTemplate": {
      "category": "DefenseEvasion",
      "description": "Test description",
      "impactedAssets": [
        {
          "@odata.type": "#microsoft.graph.security.impactedDeviceAsset",
          "identifier": "deviceId"
        }
      ],
      "mitreTechniques": ["T1070.001"],
      "recommendedActions": "Hunt for malicious activity",
      "severity": "medium",
      "title": "Test Alert"
    },
    "organizationalScope": null,
    "responseActions": []
  },
  "detectorId": "81fb771a-c57e-41b8-9905-63dbf267c13f",
  "displayName": "PREFIX-TEST-Rule",
  "id": "1",
  "isEnabled": true,
  "lastModifiedBy": "XDRConverter",
  "queryCondition": {
    "queryText": "DeviceEvents | where ActionType == \"Test\""
  },
  "schedule": {
    "period": "0"
  }
}
"@
      $tempJsonFile = Join-Path TestDrive: 'yaml-basic.json'
      $testJsonContent | Out-File -FilePath $tempJsonFile -Encoding UTF8

      $result = ConvertTo-CustomDetectionYaml -InputFile $tempJsonFile
      $result | Should -Not -BeNullOrEmpty
      $result | Should -Match 'guid:'
      $result | Should -Match '81fb771a-c57e-41b8-9905-63dbf267c13f'
      $result | Should -Match 'PREFIX-TEST-Rule'
    }

    It 'Should create output file when OutputFile parameter is specified' {
      $testJsonContent = @"
{
  "createdBy": "XDRConverter",
  "createdDateTime": "2024-01-16T12:39:02.6487368Z",
  "detectionAction": {
    "alertTemplate": {
      "category": "DefenseEvasion",
      "description": "Test description",
      "impactedAssets": [],
      "severity": "medium",
      "title": "Test Alert"
    },
    "organizationalScope": null,
    "responseActions": []
  },
  "detectorId": "81fb771a-c57e-41b8-9905-63dbf267c13f",
  "displayName": "PREFIX-TEST-Rule",
  "id": "1",
  "isEnabled": true,
  "lastModifiedBy": "XDRConverter",
  "queryCondition": {
    "queryText": "DeviceEvents | where ActionType == \"Test\""
  },
  "schedule": {
    "period": "0"
  }
}
"@
      $tempJsonFile = Join-Path TestDrive: 'yaml-output-input.json'
      $tempYamlFile = Join-Path TestDrive: 'yaml-output-result.yaml'
      $testJsonContent | Out-File -FilePath $tempJsonFile -Encoding UTF8

      ConvertTo-CustomDetectionYaml -InputFile $tempJsonFile -OutputFile $tempYamlFile
      Test-Path -Path $tempYamlFile | Should -Be $true

      # Validate the output contains expected YAML fields
      $yamlContent = Get-Content -Path $tempYamlFile -Raw
      $yamlContent | Should -Match 'guid:'
      $yamlContent | Should -Match 'ruleName:'
      $yamlContent | Should -Match 'isEnabled:'
    }

    It 'Should apply Severity override during conversion' {
      $testJsonContent = @"
{
  "detectionAction": {
    "alertTemplate": {
      "category": "DefenseEvasion",
      "description": "Test description",
      "severity": "low",
      "title": "Test Alert"
    },
    "organizationalScope": null,
    "responseActions": []
  },
  "detectorId": "81fb771a-c57e-41b8-9905-63dbf267c13f",
  "displayName": "PREFIX-TEST-Rule",
  "isEnabled": true,
  "queryCondition": {
    "queryText": "Test query"
  },
  "schedule": {
    "period": "0"
  }
}
"@
      $tempJsonFile = Join-Path TestDrive: 'yaml-severity.json'
      $testJsonContent | Out-File -FilePath $tempJsonFile -Encoding UTF8

      $result = ConvertTo-CustomDetectionYaml -InputFile $tempJsonFile -Severity 'High'
      $result | Should -Match 'alertSeverity:\s*High'
    }

    It 'Should apply Enabled override during conversion' {
      $testJsonContent = @"
{
  "detectionAction": {
    "alertTemplate": {
      "category": "DefenseEvasion",
      "description": "Test description",
      "severity": "medium",
      "title": "Test Alert"
    },
    "organizationalScope": null,
    "responseActions": []
  },
  "detectorId": "81fb771a-c57e-41b8-9905-63dbf267c13f",
  "displayName": "PREFIX-TEST-Rule",
  "isEnabled": true,
  "queryCondition": {
    "queryText": "Test query"
  },
  "schedule": {
    "period": "0"
  }
}
"@
      $tempJsonFile = Join-Path TestDrive: 'yaml-enabled.json'
      $testJsonContent | Out-File -FilePath $tempJsonFile -Encoding UTF8

      $result = ConvertTo-CustomDetectionYaml -InputFile $tempJsonFile -Enabled $false
      $result | Should -Match 'isEnabled:\s*false'
    }

    It 'Should only include schema-defined properties in YAML output' {
      $testJsonContent = @"
{
  "createdBy": "ShouldNotAppear",
  "createdDateTime": "2024-01-16T12:39:02.6487368Z",
  "detectionAction": {
    "alertTemplate": {
      "category": "DefenseEvasion",
      "description": "Test description",
      "severity": "medium",
      "title": "Test Alert"
    },
    "organizationalScope": null,
    "responseActions": []
  },
  "detectorId": "81fb771a-c57e-41b8-9905-63dbf267c13f",
  "displayName": "PREFIX-TEST-Rule",
  "id": "1",
  "isEnabled": true,
  "lastModifiedBy": "ShouldNotAppear",
  "queryCondition": {
    "queryText": "Test query"
  },
  "schedule": {
    "period": "0"
  }
}
"@
      $tempJsonFile = Join-Path TestDrive: 'yaml-schema-only.json'
      $testJsonContent | Out-File -FilePath $tempJsonFile -Encoding UTF8

      $result = ConvertTo-CustomDetectionYaml -InputFile $tempJsonFile

      # Should include YAML schema properties
      $result | Should -Match 'guid:'
      $result | Should -Match 'ruleName:'
      $result | Should -Match 'alertTitle:'
      $result | Should -Match 'alertSeverity:'
      $result | Should -Match 'alertDescription:'
      $result | Should -Match 'tactics:'
      $result | Should -Match 'detectorId: 81fb771a-c57e-41b8-9905-63dbf267c13f'

      # Should NOT include JSON-specific or legacy properties
      $result | Should -Not -Match 'createdBy:'
      $result | Should -Not -Match 'createdDateTime:'
      $result | Should -Not -Match 'lastModifiedBy:'
      $result | Should -Not -Match 'alertCategory:'
    }

    It 'Should map JSON properties to correct YAML fields' {
      $testJsonContent = @"
{
  "detectionAction": {
    "alertTemplate": {
      "category": "DefenseEvasion",
      "description": "Test description",
      "impactedAssets": [
        {
          "@odata.type": "#microsoft.graph.security.impactedDeviceAsset",
          "identifier": "deviceId"
        }
      ],
      "mitreTechniques": ["T1070.001"],
      "recommendedActions": "Investigate",
      "severity": "high",
      "title": "Test Alert"
    },
    "organizationalScope": null,
    "responseActions": []
  },
  "detectorId": "81fb771a-c57e-41b8-9905-63dbf267c13f",
  "displayName": "PREFIX-TEST-Rule",
  "isEnabled": true,
  "queryCondition": {
    "queryText": "DeviceEvents"
  },
  "schedule": {
    "period": "0"
  }
}
"@
      $tempJsonFile = Join-Path TestDrive: 'yaml-mapping.json'
      $testJsonContent | Out-File -FilePath $tempJsonFile -Encoding UTF8

      $result = ConvertTo-CustomDetectionYaml -InputFile $tempJsonFile

      $result | Should -Match 'guid:\s*81fb771a-c57e-41b8-9905-63dbf267c13f'
      $result | Should -Match 'ruleName:\s*PREFIX-TEST-Rule'
      $result | Should -Match 'alertTitle:\s*Test Alert'
      $result | Should -Match 'alertSeverity:\s*High'
      $result | Should -Match 'alertDescription:\s*Test description'
      $result | Should -Match 'alertRecommendedAction:\s*Investigate'
      $result | Should -Match 'frequency:\s*PT0S'
      $result | Should -Match 'isEnabled:\s*true'
      $result | Should -Match 'tactic:\s*DefenseEvasion'
      $result | Should -Match 'technique:\s*T1070'
      $result | Should -Match 'T1070\.001'
      $result | Should -Match 'entityMappings:'
      $result | Should -Match 'deviceIdColumn:\s*DeviceId'
      $result | Should -Not -Match 'alertCategory:'
      $result | Should -Not -Match 'mitreTechniques:'
      $result | Should -Not -Match 'impactedEntities:'
    }

    It 'Should emit the current keys from a new-shape rule' {
      $testJsonContent = @"
{
  "id": "81fb771a-c57e-41b8-9905-63dbf267c13f",
  "displayName": "NEW-Rule",
  "description": "Rule note",
  "status": "enabled",
  "createdBy": "someone",
  "queryCondition": { "queryText": "DeviceEvents" },
  "schedule": { "frequency": "PT1H" },
  "detectionAction": {
    "alertTemplate": {
      "title": "Test Alert",
      "description": "Test description",
      "severity": "high",
      "tactics": [ { "tactic": "Execution", "techniques": [ { "technique": "T1059", "subTechniques": [ "T1059.001" ] } ] } ],
      "entityMappings": { "hosts": [ { "deviceIdColumn": "DeviceId" } ], "files": [ { "sha256Column": "SHA256" } ] },
      "customDetails": { "CommandLine": "ProcessCommandLine" }
    },
    "automatedActions": { "blockFiles": [ { "sha1Column": "SHA1", "sha256Column": "SHA256" } ] },
    "organizationalScope": { "deviceGroups": [ "Servers" ] }
  }
}
"@
      $tempJsonFile = Join-Path TestDrive: 'yaml-new-shape.json'
      $testJsonContent | Out-File -FilePath $tempJsonFile -Encoding UTF8

      $result = ConvertTo-CustomDetectionYaml -InputFile $tempJsonFile
      $yaml = $result | ConvertFrom-Yaml

      $yaml.guid | Should -Be '81fb771a-c57e-41b8-9905-63dbf267c13f'
      $yaml.ruleName | Should -Be 'NEW-Rule'
      $yaml.description | Should -Be 'Rule note'
      $yaml.isEnabled | Should -Be $true
      $yaml.Keys | Should -Not -Contain 'status'
      $yaml.frequency | Should -Be 'PT1H'
      $yaml.alertSeverity | Should -Be 'High'
      $yaml.tactics[0].tactic | Should -Be 'Execution'
      $yaml.tactics[0].techniques[0].technique | Should -Be 'T1059'
      @($yaml.tactics[0].techniques[0].subTechniques) | Should -Be @('T1059.001')
      $yaml.entityMappings.hosts[0].deviceIdColumn | Should -Be 'DeviceId'
      $yaml.entityMappings.files[0].sha256Column | Should -Be 'SHA256'
      $yaml.customDetails.CommandLine | Should -Be 'ProcessCommandLine'
      $yaml.actions[0].actionType | Should -Be 'BlockFile'
      $yaml.actions[0].additionalFields.sha1Column | Should -Be 'SHA1'
      @($yaml.organizationalScope) | Should -Be @('Servers')
      $result | Should -Match '^guid:'
    }

    It 'Should emit the legacy YAML keys with -LegacyKeys' {
      $testJsonContent = @"
{
  "id": "81fb771a-c57e-41b8-9905-63dbf267c13f",
  "displayName": "LEGACY-Rule",
  "status": "enabled",
  "queryCondition": { "queryText": "DeviceEvents" },
  "schedule": { "frequency": "P1D" },
  "detectionAction": {
    "alertTemplate": {
      "title": "Test Alert",
      "description": "Test description",
      "severity": "high",
      "tactics": [ { "tactic": "Execution", "techniques": [ { "technique": "T1059", "subTechniques": [ "T1059.001" ] } ] } ],
      "entityMappings": { "hosts": [ { "deviceIdColumn": "DeviceId" } ], "accounts": [ { "upnColumn": "InitiatingProcessAccountUpn" } ], "mailboxes": [ { "primaryAddressColumn": "RecipientEmailAddress" } ] }
    },
    "automatedActions": { "isolateDevices": [ { "deviceIdColumn": "DeviceId", "isolationType": "selective" } ], "restrictAppExecutions": [ { "deviceIdColumn": "DeviceId" } ] },
    "organizationalScope": { "deviceGroups": [ "Servers" ] }
  }
}
"@
      $tempJsonFile = Join-Path TestDrive: 'yaml-legacy-keys.json'
      $testJsonContent | Out-File -FilePath $tempJsonFile -Encoding UTF8

      $result = ConvertTo-CustomDetectionYaml -InputFile $tempJsonFile -LegacyKeys
      $yaml = $result | ConvertFrom-Yaml

      $yaml.guid | Should -Be '81fb771a-c57e-41b8-9905-63dbf267c13f'
      $yaml.frequency | Should -Be '24H'
      $yaml.isEnabled | Should -Be $true
      $yaml.alertCategory | Should -Be 'Execution'
      @($yaml.mitreTechniques) | Should -Be @('T1059', 'T1059.001')
      $yaml.impactedEntities.Count | Should -Be 3
      ($yaml.impactedEntities | Where-Object { $_.entityType -eq 'Machine' }).entityIdentifier | Should -Be 'deviceId'
      ($yaml.impactedEntities | Where-Object { $_.entityType -eq 'User' }).entityIdentifier | Should -Be 'initiatingProcessAccountUpn'
      ($yaml.impactedEntities | Where-Object { $_.entityType -eq 'Mailbox' }).entityIdentifier | Should -Be 'recipientEmailAddress'
      @($yaml.organizationalScope) | Should -Be @('Servers')
      $yaml.actions.Count | Should -Be 2
      ($yaml.actions | Where-Object { $_.actionType -eq 'IsolateMachine' }).additionalFields.isolationType | Should -Be 'Selective'
      ($yaml.actions | Where-Object { $_.actionType -eq 'IsolateMachine' }).additionalFields.Keys | Should -Not -Contain 'deviceIdColumn'
      ($yaml.actions | Where-Object { $_.actionType -eq 'RestrictAppExecution' }).Keys | Should -Not -Contain 'additionalFields'
      $yaml.Keys | Should -Not -Contain 'tactics'
      $yaml.Keys | Should -Not -Contain 'entityMappings'
    }

    It 'Should warn with -LegacyKeys when a value cannot be expressed in the legacy keys' {
      $testJsonContent = @"
{
  "id": "81fb771a-c57e-41b8-9905-63dbf267c13f",
  "displayName": "LEGACY-Lossy",
  "description": "note",
  "status": "enabled",
  "queryCondition": { "queryText": "DeviceEvents" },
  "schedule": { "frequency": "PT30M" },
  "detectionAction": {
    "alertTemplate": {
      "title": "T", "description": "D", "severity": "low",
      "tactics": [ { "tactic": "Execution" }, { "tactic": "Persistence" } ],
      "entityMappings": { "files": [ { "sha256Column": "SHA256" } ] },
      "customDetails": { "CommandLine": "ProcessCommandLine" }
    },
    "automatedActions": { "blockFiles": [ { "sha256Column": "SHA256" } ] }
  }
}
"@
      $tempJsonFile = Join-Path TestDrive: 'yaml-legacy-lossy.json'
      $testJsonContent | Out-File -FilePath $tempJsonFile -Encoding UTF8

      $result = ConvertTo-CustomDetectionYaml -InputFile $tempJsonFile -LegacyKeys -WarningVariable w -WarningAction SilentlyContinue
      $yaml = $result | ConvertFrom-Yaml

      $w.Count | Should -BeGreaterOrEqual 4
      $yaml.frequency | Should -Be 'PT30M'
      $yaml.alertCategory | Should -Be 'Execution'
      ($yaml.impactedEntities | Where-Object { $_.entityType -eq 'FileHash' }).entityIdentifier | Should -Be 'sHA256'
      $yaml.Keys | Should -Not -Contain 'customDetails'
      $yaml.Keys | Should -Not -Contain 'description'
      $yaml.Keys | Should -Not -Contain 'actions'
    }

    It 'Should keep status only for autoDisabled' {
      $testJsonContent = @"
{
  "id": "81fb771a-c57e-41b8-9905-63dbf267c13f",
  "displayName": "AUTO-Rule",
  "status": "autoDisabled",
  "queryCondition": { "queryText": "DeviceEvents" },
  "schedule": { "frequency": "PT1H" },
  "detectionAction": { "alertTemplate": { "title": "T", "description": "D", "severity": "low", "tactics": [ { "tactic": "Execution" } ] } }
}
"@
      $tempJsonFile = Join-Path TestDrive: 'yaml-autodisabled.json'
      $testJsonContent | Out-File -FilePath $tempJsonFile -Encoding UTF8

      $yaml = ConvertTo-CustomDetectionYaml -InputFile $tempJsonFile | ConvertFrom-Yaml
      $yaml.isEnabled | Should -Be $false
      $yaml.status | Should -Be 'autoDisabled'
    }

    It 'Should clean a dual-shape API response with empty columns and null collections' {
      $testJsonContent = @"
{
  "id": "48",
  "detectorId": "f687512c-0654-4999-a0ac-d5906ffc3972",
  "displayName": "DUAL-Rule",
  "isEnabled": true,
  "status": "enabled",
  "queryCondition": { "queryText": "DeviceEvents", "lastModifiedDateTime": "2026-01-01T00:00:00Z" },
  "schedule": { "period": "1H", "frequency": "PT1H", "nextRunDateTime": "2026-01-01T00:00:00Z" },
  "lastRunDetails": { "status": "completed" },
  "detectionAction": {
    "alertTemplate": {
      "title": "T",
      "description": "D [PREFIX:81fb771a-c57e-41b8-9905-63dbf267c13f]",
      "severity": "medium",
      "category": "InitialAccess",
      "mitreTechniques": null,
      "tactics": { "tactic": "InitialAccess", "techniques": null },
      "impactedAssets": [ { "@odata.type": "#microsoft.graph.security.impactedDeviceAsset", "identifier": "deviceId" } ],
      "entityMappings": {
        "accounts": { "aadUserIdColumn": "", "nameColumn": "", "sidColumn": "", "upnColumn": "InitiatingProcessAccountUpn" },
        "hosts": { "deviceIdColumn": "DeviceId", "nameColumn": "" },
        "files": null
      },
      "customDetails": null
    },
    "responseActions": { "@odata.type": "#microsoft.graph.security.isolateDeviceResponseAction", "identifier": "deviceId", "isolationType": "full" },
    "automatedActions": { "allowFiles": null, "isolateDevices": { "deviceIdColumn": "DeviceId", "isolationType": "full" } },
    "organizationalScope": null
  }
}
"@
      $tempJsonFile = Join-Path TestDrive: 'yaml-dual.json'
      $testJsonContent | Out-File -FilePath $tempJsonFile -Encoding UTF8

      $result = ConvertTo-CustomDetectionYaml -InputFile $tempJsonFile
      $yaml = $result | ConvertFrom-Yaml

      $yaml.guid | Should -Be '81fb771a-c57e-41b8-9905-63dbf267c13f'
      $yaml.alertDescription | Should -Be 'D'
      $yaml.frequency | Should -Be 'PT1H'
      $yaml.tactics[0].tactic | Should -Be 'InitialAccess'
      $yaml.tactics[0].Keys | Should -Not -Contain 'techniques'
      @($yaml.entityMappings.Keys | Sort-Object) | Should -Be @('accounts', 'hosts')
      @($yaml.entityMappings.accounts[0].Keys) | Should -Be @('upnColumn')
      $yaml.entityMappings.hosts[0].deviceIdColumn | Should -Be 'DeviceId'
      $yaml.actions.Count | Should -Be 1
      $yaml.actions[0].actionType | Should -Be 'IsolateMachine'
      $yaml.actions[0].additionalFields.isolationType | Should -Be 'Full'
      $yaml.Keys | Should -Not -Contain 'organizationalScope'
      $result | Should -Not -Match 'lastRunDetails'
      $result | Should -Not -Match 'nextRunDateTime'
    }

    It 'Should convert Graph API response actions back to YAML action format' {
      $testJsonContent = @"
{
  "detectionAction": {
    "alertTemplate": {
      "category": "DefenseEvasion",
      "description": "Test description",
      "severity": "medium",
      "title": "Test Alert"
    },
    "organizationalScope": null,
    "responseActions": [
      {
        "@odata.type": "#microsoft.graph.security.isolateDeviceResponseAction",
        "identifier": "deviceId",
        "isolationType": "full"
      },
      {
        "@odata.type": "#microsoft.graph.security.collectInvestigationPackageResponseAction",
        "identifier": "deviceId"
      },
      {
        "@odata.type": "#microsoft.graph.security.runAntivirusScanResponseAction",
        "identifier": "deviceId"
      },
      {
        "@odata.type": "#microsoft.graph.security.initiateInvestigationResponseAction",
        "identifier": "deviceId"
      },
      {
        "@odata.type": "#microsoft.graph.security.restrictAppExecutionResponseAction",
        "identifier": "deviceId"
      }
    ]
  },
  "detectorId": "81fb771a-c57e-41b8-9905-63dbf267c13f",
  "displayName": "PREFIX-TEST-Actions",
  "isEnabled": true,
  "queryCondition": {
    "queryText": "DeviceEvents"
  },
  "schedule": {
    "period": "0"
  }
}
"@
      $tempJsonFile = Join-Path TestDrive: 'yaml-actions.json'
      $testJsonContent | Out-File -FilePath $tempJsonFile -Encoding UTF8

      $result = ConvertTo-CustomDetectionYaml -InputFile $tempJsonFile

      # Verify all actions are present in the YAML output
      $result | Should -Match 'actionType:\s*IsolateMachine'
      $result | Should -Match 'isolationType:\s*Full'
      $result | Should -Match 'actionType:\s*CollectInvestigationPackage'
      $result | Should -Match 'actionType:\s*RunAntivirusScan'
      $result | Should -Match 'actionType:\s*InitiateInvestigation'
      $result | Should -Match 'actionType:\s*RestrictAppExecution'

      $yaml = $result | ConvertFrom-Yaml
      $yaml.actions.Count | Should -Be 5
      ($yaml.actions | Where-Object { $_.actionType -eq 'IsolateMachine' }).additionalFields.deviceIdColumn | Should -Be 'DeviceId'
    }

    It 'Should not include actions key when no response actions exist' {
      $testJsonContent = @"
{
  "detectionAction": {
    "alertTemplate": {
      "category": "DefenseEvasion",
      "description": "Test description",
      "severity": "medium",
      "title": "Test Alert"
    },
    "organizationalScope": null,
    "responseActions": []
  },
  "detectorId": "81fb771a-c57e-41b8-9905-63dbf267c13f",
  "displayName": "PREFIX-TEST-NoActions",
  "isEnabled": true,
  "queryCondition": {
    "queryText": "DeviceEvents"
  },
  "schedule": {
    "period": "0"
  }
}
"@
      $tempJsonFile = Join-Path TestDrive: 'yaml-no-actions.json'
      $testJsonContent | Out-File -FilePath $tempJsonFile -Encoding UTF8

      $result = ConvertTo-CustomDetectionYaml -InputFile $tempJsonFile
      $result | Should -Not -Match 'actions:'
      $result | Should -Not -Match 'actionType:'
    }
  }

  Context 'UseDisplayNameAsFilename and UseIdAsFilename' {

    BeforeAll {
      $testJsonObject = [PSCustomObject]@{
        displayName     = 'PREFIX-TEST-Rule'
        detectorId      = '81fb771a-c57e-41b8-9905-63dbf267c13f'
        isEnabled       = $true
        detectionAction = @{
          alertTemplate       = @{
            title       = 'Test Alert'
            severity    = 'medium'
            description = 'Test description'
            category    = 'DefenseEvasion'
          }
          organizationalScope = $null
          responseActions     = @()
        }
        queryCondition  = @{
          queryText = 'DeviceEvents | where ActionType == "Test"'
        }
        schedule        = @{
          period = '0'
        }
      }
    }

    It 'Should write file using display name when -UseDisplayNameAsFilename is set' {
      $outputFolder = Join-Path TestDrive: 'yaml-displayname'
      $testJsonObject | ConvertTo-CustomDetectionYaml -UseDisplayNameAsFilename -OutputFolder $outputFolder

      $expectedFile = Join-Path $outputFolder 'PREFIX-TEST-Rule.yaml'
      Test-Path $expectedFile | Should -Be $true
      $content = Get-Content $expectedFile -Raw
      $content | Should -Match 'guid:'
      $content | Should -Match 'PREFIX-TEST-Rule'
    }

    It 'Should sanitize  invalid filename characters in display name' {
      $objWithBadName = $testJsonObject.PSObject.Copy()
      $objWithBadName.displayName = 'Rule:With/Bad<Chars'
      $outputFolder = Join-Path TestDrive: 'yaml-sanitize'
      New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
      $objWithBadName | ConvertTo-CustomDetectionYaml -UseDisplayNameAsFilename -OutputFolder $outputFolder

      $expectedFile = Join-Path $outputFolder 'Rule_With_Bad_Chars.yaml'
      Test-Path $expectedFile | Should -Be $true
    }

    It 'Should write file using detectorId when -UseIdAsFilename is set' {
      $outputFolder = Join-Path TestDrive: 'yaml-id'
      $testJsonObject | ConvertTo-CustomDetectionYaml -UseIdAsFilename -OutputFolder $outputFolder

      $expectedFile = Join-Path $outputFolder '81fb771a-c57e-41b8-9905-63dbf267c13f.yaml'
      Test-Path $expectedFile | Should -Be $true
      $content = Get-Content $expectedFile -Raw
      $content | Should -Match 'guid:'
    }

    It 'Should default to temp directory when -OutputFolder is not specified' {
      $tempPath = [System.IO.Path]::GetTempPath()
      $expectedFile = Join-Path $tempPath '81fb771a-c57e-41b8-9905-63dbf267c13f.yaml'

      # Clean up if it exists from a previous run
      if (Test-Path $expectedFile) { Remove-Item $expectedFile -Force }

      $testJsonObject | ConvertTo-CustomDetectionYaml -UseIdAsFilename

      Test-Path $expectedFile | Should -Be $true

      # Clean up
      Remove-Item $expectedFile -Force -ErrorAction SilentlyContinue
    }

    It 'Should create the output folder if it does not exist' {
      $outputFolder = Join-Path TestDrive: 'yaml-newdir' 'sub1' 'sub2'
      Test-Path $outputFolder | Should -Be $false

      $testJsonObject | ConvertTo-CustomDetectionYaml -UseIdAsFilename -OutputFolder $outputFolder

      Test-Path $outputFolder | Should -Be $true
    }

    It 'Should not allow -UseDisplayNameAsFilename and -UseIdAsFilename together' {
      {
        $testJsonObject | ConvertTo-CustomDetectionYaml -UseDisplayNameAsFilename -UseIdAsFilename -OutputFolder (Join-Path TestDrive: 'yaml-both')
      } | Should -Throw
    }

    It 'Should not allow -OutputFolder without a naming switch' {
      {
        ConvertTo-CustomDetectionYaml -InputObject $testJsonObject -OutputFolder (Join-Path TestDrive: 'yaml-noflag')
      } | Should -Throw
    }
  }
}

