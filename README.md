![XDRConverter PowerShell Module logo](./XDRConvert.png)

# XDRConverter PowerShell Module

A PowerShell module for converting, managing, and deploying Defender XDR custom detection rules between YAML and JSON formats.

## Overview

The XDRConverter module provides cmdlets to work with Microsoft Defender XDR custom detection rules:

| Cmdlet | Description |
| --- | --- |
| `ConvertTo-CustomDetectionJson` | Converts YAML detection rules to JSON format |
| `ConvertTo-CustomDetectionYaml` | Converts JSON detection rules to YAML format (schema-compliant) |
| `Deploy-CustomDetection` | Deploys detection rules to Defender XDR via Microsoft Graph API |
| `Get-CustomDetection` | Retrieves detection rules from Defender XDR |
| `Get-CustomDetectionIds` | Lists detection rule IDs with detector IDs and description tags (cached) |
| `Get-CustomDetectionIdByDetectorId` | Looks up a detection rule ID by its detector ID |
| `Get-CustomDetectionIdByDescriptionTag` | Looks up a detection rule ID by its description tag UUID |
| `Remove-CustomDetection` | Removes a detection rule from Defender XDR |

## Prerequisites

- PowerShell 7.0 or later (PowerShell Core)
- The `powershell-yaml` module (automatically installed with the module)
- The `Microsoft.Graph.Authentication` module (required for `Deploy-CustomDetection`, `Get-CustomDetection*` cmdlets)

## Installation

### Install from local directory

```powershell
Import-Module .\src\XDRConverter.psd1
```

### Install from global modules directory

```powershell
# Copy the XDRConverter folder to one of the PSModulePath locations
Copy-Item -Path .\src -Destination "$PROFILE\..\Modules\XDRConverter" -Recurse
```

---

## Cmdlet Reference

### ConvertTo-CustomDetectionJson

Converts a YAML Defender XDR detection file to JSON format. Supports file input, pipeline input from `Get-CustomDetection`, and multiple output naming strategies.

#### Parameters

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| InputFile | String | Yes* | Path to the input YAML file (*File parameter set) |
| InputObject | PSObject | Yes* | JSON detection rule object; accepts pipeline input (*Object parameter sets) |
| OutputFile | String | No | Path to the output JSON file. If not specified, outputs to stdout |
| UseDisplayNameAsFilename | Switch | No | Use the rule's display name as the output filename (.json) |
| UseIdAsFilename | Switch | No | Use the rule's detectorId as the output filename (.json) |
| OutputFolder | String | No | Folder for output when using `-UseDisplayNameAsFilename` or `-UseIdAsFilename` (defaults to temp directory) |
| Enabled | Boolean | No | Set the `isEnabled` property to this value |
| Severity | String | No | Override the alert severity (`Informational`, `Low`, `Medium`, `High`) |
| SkipIdentifierValidation | Switch | No | Allow impacted entity identifiers not listed in the official documentation (emits a warning instead of throwing) |

#### Examples

```powershell
# Convert YAML to JSON and save to file
ConvertTo-CustomDetectionJson -InputFile .\input.yaml -OutputFile .\output.json

# Convert with severity override
ConvertTo-CustomDetectionJson -InputFile .\input.yaml -OutputFile .\output.json -Severity High

# Disable the rule during conversion and output to stdout
ConvertTo-CustomDetectionJson -InputFile .\input.yaml -Enabled $false

# Pipeline: export all rules from Defender XDR to JSON files named by display name
Get-CustomDetection | ConvertTo-CustomDetectionJson -UseDisplayNameAsFilename -OutputFolder 'C:\Detections'

# Pipeline: export all rules to JSON files named by detectorId
Get-CustomDetection | ConvertTo-CustomDetectionJson -UseIdAsFilename

# Parse the JSON output further
ConvertTo-CustomDetectionJson -InputFile .\input.yaml | ConvertFrom-Json
```

---

### ConvertTo-CustomDetectionYaml

Converts a JSON Defender XDR detection file to YAML format. Properties not defined in the YAML schema are automatically omitted.

#### Parameters

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| InputFile | String | Yes* | Path to the input JSON file (*File parameter set) |
| InputObject | PSObject | Yes* | JSON detection rule object; accepts pipeline input (*Object parameter sets) |
| OutputFile | String | No | Path to the output YAML file. If not specified, outputs to stdout |
| UseDisplayNameAsFilename | Switch | No | Use the rule's display name as the output filename (.yaml) |
| UseIdAsFilename | Switch | No | Use the rule's detectorId as the output filename (.yaml) |
| OutputFolder | String | No | Folder for output when using `-UseDisplayNameAsFilename` or `-UseIdAsFilename` (defaults to temp directory) |
| Enabled | Boolean | No | Set the `isEnabled` property to this value |
| Severity | String | No | Override the alert severity (`Informational`, `Low`, `Medium`, `High`) |

#### Examples

```powershell
# Convert JSON to YAML and save to file
ConvertTo-CustomDetectionYaml -InputFile .\output.json -OutputFile .\input.yaml

# Convert with severity override
ConvertTo-CustomDetectionYaml -InputFile .\output.json -OutputFile .\input.yaml -Severity Low

# Enable the rule during conversion
ConvertTo-CustomDetectionYaml -InputFile .\output.json -Enabled $true

# Pipeline: export all rules from Defender XDR to YAML files named by display name
Get-CustomDetection | ConvertTo-CustomDetectionYaml -UseDisplayNameAsFilename -OutputFolder 'C:\Detections'

# Pipeline: export all rules to YAML files named by detectorId
Get-CustomDetection | ConvertTo-CustomDetectionYaml -UseIdAsFilename
```

---

### Deploy-CustomDetection

Creates or updates a Defender XDR custom detection rule from a YAML or JSON file via the Microsoft Graph API. Automatically detects whether the rule already exists (by detectorId or description tag) and issues a PATCH (update) or POST (create) accordingly. Before updating, it compares the local rule against the remote version and skips the call when nothing changed.

#### Parameters

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| InputFile | String | Yes | Path to the input YAML (`.yaml`/`.yml`) or JSON (`.json`) file. Accepts pipeline input. |
| Severity | String | No | Override the alert severity (`Informational`, `Low`, `Medium`, `High`) |
| TitlePrefix | String | No | String prepended to the rule's `displayName` and `alertTitle` |
| Disabled | Switch | No | Deploy the rule with `isEnabled = $false` regardless of the file value |
| NoDescriptionTag | Switch | No | Do not append a `[<UUID>]` tag to the description |
| DescriptionTagPrefix | String | No | Prefix inside the description tag, e.g. `PREFIX` produces `[PREFIX:<UUID>]` |
| ParameterFile | String | No | Path to a YAML parameter file for query variable replacement (see below) |
| Force | Switch | No | Skip change-detection and always push the rule to the API |
| SkipIdentifierValidation | Switch | No | Allow impacted entity identifiers not listed in the official documentation (emits a warning instead of throwing) |
| WhatIf | Switch | No | Shows what changes would be made without applying them |
| Confirm | Switch | No | Prompts for confirmation before creating or updating each rule |

#### Parameter File Format

The parameter file is a YAML file that can contain:

```yaml
PrependQuery: |
  let lookback = 7d;
AppendQuery: |
  | where Timestamp > ago(lookback)
ReplaceQueryVariables:
  TenantId: "contoso.onmicrosoft.com"
  StatusCodes:
    - 403
    - 404
```

Query variables use `%%VARIABLE%%` or `%%VARIABLE:DEFAULT%%` syntax in the KQL query. Variables with defaults resolve to the default value when no parameter file is provided.

#### Examples

```powershell
# Deploy a rule (appends [<guid>] tag to description)
Deploy-CustomDetection -InputFile .\input.yaml

# Deploy with a prefixed description tag: [PREFIX:<guid>]
Deploy-CustomDetection -InputFile .\input.yaml -DescriptionTagPrefix 'PREFIX'

# Deploy in disabled mode without a description tag
Deploy-CustomDetection -InputFile .\input.yaml -NoDescriptionTag -Disabled

# Deploy with severity override and title prefix
Deploy-CustomDetection -InputFile .\input.yaml -Severity High -TitlePrefix '[PROD] '

# Deploy with query variable replacement from a parameter file
Deploy-CustomDetection -InputFile .\input.yaml -ParameterFile .\params.yaml

# Preview changes without applying them
Deploy-CustomDetection -InputFile .\input.yaml -WhatIf

# Force re-deploy even when no changes are detected
Deploy-CustomDetection -InputFile .\input.yaml -Force
```

---

### Get-CustomDetection

Retrieves custom detection rules from Microsoft Defender XDR via the Microsoft Graph API. Can return a single rule by ID or all rules.

#### Parameters

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| DetectionId | String | No | The detection rule ID. If omitted, all detection rules are returned. Accepts pipeline input. |

#### Examples

```powershell
# Get all detection rules
Get-CustomDetection

# Get a specific detection rule by ID
Get-CustomDetection -DetectionId '81fb771a-c57e-41b8-9905-63dbf267c13f'

# Pipeline: get a rule and convert it to YAML
Get-CustomDetection -DetectionId '81fb771a-c57e-41b8-9905-63dbf267c13f' |
    ConvertTo-CustomDetectionYaml -OutputFile .\rule.yaml
```

---

### Get-CustomDetectionIds

Lists detection rule IDs with their detector IDs and description tags. Results are cached for the specified duration (default: 60 minutes) to reduce API calls.

#### Parameters

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| CacheTtlMinutes | Int | No | How long (in minutes) to cache results. Defaults to `60`. |
| Force | Switch | No | Bypass the cache and force a fresh API call. |

#### Examples

```powershell
# List all detection rule IDs (cached for 60 min)
Get-CustomDetectionIds

# Force a fresh API call, ignoring cache
Get-CustomDetectionIds -Force

# Cache results for 10 minutes
Get-CustomDetectionIds -CacheTtlMinutes 10
```

---

### Get-CustomDetectionIdByDetectorId

Returns the detection rule ID for a given detector ID (GUID). Uses the cached output of `Get-CustomDetectionIds`.

#### Parameters

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| DetectorId | String | Yes | The detectorId (GUID) to look up. Accepts pipeline input. |

#### Examples

```powershell
# Look up a detection rule ID by its detector ID
Get-CustomDetectionIdByDetectorId -DetectorId '81fb771a-c57e-41b8-9905-63dbf267c13f'
```

---

### Get-CustomDetectionIdByDescriptionTag

Returns the detection rule ID for a given UUID that was embedded in the alert description as a tag (e.g. `[UUID]` or `[PREFIX:UUID]`). Uses the cached output of `Get-CustomDetectionIds`.

#### Parameters

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| DescriptionTag | String | Yes | The UUID to search for in description tags. Accepts pipeline input. |

#### Examples

```powershell
# Look up a detection rule by its description tag UUID
Get-CustomDetectionIdByDescriptionTag -DescriptionTag '81fb771a-c57e-41b8-9905-63dbf267c13f'
```

---

### Remove-CustomDetection

Deletes a custom detection rule from Microsoft Defender XDR. The rule can be identified by its detection rule ID, its DetectorId (the GUID from the source file), or by the DescriptionTag UUID appended to the alert description during deployment.

#### Parameters

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| Id | String | Yes* | The detection rule ID as returned by the Graph API (*ById parameter set) |
| DetectorId | String | Yes* | The detector ID (GUID from the source file) (*ByDetectorId parameter set) |
| DescriptionTag | String | Yes* | The UUID tag embedded in the alert description (*ByDescriptionTag parameter set) |
| WhatIf | Switch | No | Shows what changes would be made without applying them |
| Confirm | Switch | No | Prompts for confirmation before deleting the rule |

#### Examples

```powershell
# Delete a detection rule by its ID
Remove-CustomDetection -Id '12345'

# Delete by detector ID (GUID from the YAML/JSON source)
Remove-CustomDetection -DetectorId '81fb771a-c57e-41b8-9905-63dbf267c13f'

# Delete by description tag UUID
Remove-CustomDetection -DescriptionTag '81fb771a-c57e-41b8-9905-63dbf267c13f'
```

---

## Property Mapping

### YAML to JSON

| YAML Property          | JSON Path                                        |
| ---------------------- | ------------------------------------------------ |
| guid                   | detectorId                                       |
| ruleName               | displayName                                      |
| isEnabled              | isEnabled                                        |
| alertTitle             | detectionAction.alertTemplate.title              |
| frequency              | schedule.period                                  |
| alertSeverity          | detectionAction.alertTemplate.severity           |
| alertDescription       | detectionAction.alertTemplate.description        |
| alertRecommendedAction | detectionAction.alertTemplate.recommendedActions |
| alertCategory          | detectionAction.alertTemplate.category           |
| mitreTechniques        | detectionAction.alertTemplate.mitreTechniques    |
| impactedEntities       | detectionAction.alertTemplate.impactedAssets     |
| organizationalScope    | detectionAction.organizationalScope              |
| actions                | detectionAction.responseActions                  |
| queryText              | queryCondition.queryText                         |

## Common Workflows

### Round-trip Conversion

Convert YAML → JSON → YAML (with modifications):

```powershell
# Convert YAML to JSON
ConvertTo-CustomDetectionJson -InputFile .\input.yaml -OutputFile .\temp.json

# Convert back to YAML with low severity
ConvertTo-CustomDetectionYaml -InputFile .\temp.json -OutputFile .\output.yaml -Severity Low
```

### Export All Rules from Defender XDR

```powershell
# Connect to Microsoft Graph
Connect-MgGraph -Scopes 'CustomDetections.ReadWrite.All'

# Export all rules as YAML files
Get-CustomDetection | ConvertTo-CustomDetectionYaml -UseDisplayNameAsFilename -OutputFolder '.\Detections'

# Export all rules as JSON files
Get-CustomDetection | ConvertTo-CustomDetectionJson -UseIdAsFilename -OutputFolder '.\Detections'
```

### Deploy Rules with Environment-Specific Parameters

```powershell
# Deploy with production parameter file and title prefix
Deploy-CustomDetection -InputFile .\input.yaml -ParameterFile .\prod-params.yaml -TitlePrefix '[PROD] '

# Deploy in disabled mode for testing
Deploy-CustomDetection -InputFile .\input.yaml -ParameterFile .\test-params.yaml -Disabled
```

## Schema Compliance

When converting JSON to YAML, the module ensures:
- Only YAML schema-defined properties are included
- The output is valid according to the `customdetection.schema.json`
- Additional JSON-specific properties (createdBy, createdDateTime, id, etc.) are omitted
- Severity values are properly case-converted between JSON (lowercase) and YAML (Title Case)

## Troubleshooting

### Module not found error

If you get "The module 'XDRConverter' could not be loaded", ensure:
1. The module path is correct
2. The module folder contains both `.psd1` and `.psm1` files
3. PowerShell execution policy allows module loading

### YAML parsing errors

If you encounter YAML parsing errors:
1. Ensure the YAML file is valid YAML syntax
2. Check for proper indentation (use spaces, not tabs)
3. Verify the file is UTF-8 encoded

### powershell-yaml dependency

If the `powershell-yaml` module is not found:

```powershell
Install-Module powershell-yaml -Scope CurrentUser
```

### Microsoft Graph authentication

If you get authentication errors when using `Deploy-CustomDetection` or `Get-CustomDetection`:

```powershell
# Install the module if not present
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser

# Connect with the required scope
Connect-MgGraph -Scopes 'CustomDetections.ReadWrite.All'
```

## Changelog

### 1.1.0

- Added `-SkipIdentifierValidation` parameter to `ConvertTo-CustomDetectionJson` and `Deploy-CustomDetection` to allow non-standard impacted entity identifiers (emits a warning instead of throwing)
- Added `initiatingProcessAccountObjectId` and `initiatingProcessAccountSid` to the list of valid User entity identifiers
- Added `Remove-CustomDetection` cmdlet for deleting rules via Microsoft Graph API

### 1.0.0

- Initial release
- `ConvertTo-CustomDetectionJson` — convert YAML detection rules to JSON
- `ConvertTo-CustomDetectionYaml` — convert JSON detection rules to YAML
- Added comprehensive Pester tests
- Added `Deploy-CustomDetection` cmdlet for deploying rules via Microsoft Graph API
- Added `Get-CustomDetection` cmdlet for retrieving rules from Defender XDR
- Added `Get-CustomDetectionIds` cmdlet with caching support
- Added `Get-CustomDetectionIdByDetectorId` cmdlet
- Added `Get-CustomDetectionIdByDescriptionTag` cmdlet
- Added pipeline support and `InputObject` parameter to `ConvertTo-CustomDetectionJson` and `ConvertTo-CustomDetectionYaml`
- Added `-UseDisplayNameAsFilename` and `-UseIdAsFilename` output naming options
- Added query variable replacement with `%%VARIABLE%%` / `%%VARIABLE:DEFAULT%%` syntax
- Added parameter file support (`-ParameterFile`) for query transformations
- Added description tag support for tracking deployed rules
- Added change-detection to skip unnecessary API updates
- Added `-WhatIf` and `-Confirm` support for `Deploy-CustomDetection`

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Support

For issues or feature requests, please open an issue on the [GitHub repository](https://github.com/f-bader/XDRConverter).
