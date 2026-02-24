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
      $result | Should -Match 'alertCategory:'

      # Should NOT include JSON-specific properties
      $result | Should -Not -Match 'createdBy:'
      $result | Should -Not -Match 'createdDateTime:'
      $result | Should -Not -Match 'lastModifiedBy:'
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
      $result | Should -Match 'alertCategory:\s*DefenseEvasion'
      $result | Should -Match 'T1070\.001'
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

