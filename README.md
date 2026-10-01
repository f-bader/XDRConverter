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
| `Get-CustomDetectionIds` | Lists detection rule IDs with their description tags (cached) |
| `Get-CustomDetectionIdByDetectorId` | Looks up a detection rule ID by its guid, by the detector ID the API assigned, or by its description tag |
| `Get-CustomDetectionIdByDescriptionTag` | Looks up a detection rule ID by its description tag UUID |
| `Remove-CustomDetection` | Removes a detection rule from Defender XDR |
| `Test-CustomDetectionMitreTechnique` | Validates MITRE ATT&CK techniques against XDR-supported categories |

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

Converts a YAML Defender XDR detection file to the JSON request body. Pipeline input from `Get-CustomDetection` is written as the API returned it, which is what an export of the tenant needs.

#### Parameters

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| InputFile | String | Yes* | Path to the input YAML file (*File parameter set) |
| InputObject | PSObject | Yes* | A rule object from `Get-CustomDetection`, written as the API returned it; accepts pipeline input (*Object parameter sets) |
| OutputFile | String | No | Path to the output JSON file. If not specified, outputs to stdout |
| UseDisplayNameAsFilename | Switch | No | Use the rule's display name as the output filename (.json) |
| UseIdAsFilename | Switch | No | Use the rule's guid as the output filename (.json). Taken from the description tag, then a UUID rule id, then the guid after the `rule-` prefix, then the detector ID the API assigned |
| OutputFolder | String | No | Folder for output when using `-UseDisplayNameAsFilename` or `-UseIdAsFilename` (defaults to temp directory) |
| Enabled | Boolean | No | Set the rule status to enabled (`$true`) or disabled (`$false`) |
| Severity | String | No | Override the alert severity (`Informational`, `Low`, `Medium`, `High`) |
| SkipIdentifierValidation | Switch | No | Allow entity identifiers and mapping columns not listed in the official documentation (emits a warning instead of throwing) |

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

# Pipeline: export all rules to JSON files named by guid
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
| UseIdAsFilename | Switch | No | Use the rule's guid as the output filename (.yaml). Taken from the description tag, then a UUID rule id, then the guid after the `rule-` prefix, then the detector ID the API assigned |
| OutputFolder | String | No | Folder for output when using `-UseDisplayNameAsFilename` or `-UseIdAsFilename` (defaults to temp directory) |
| Enabled | Boolean | No | Set the rule status to enabled (`$true`) or disabled (`$false`) |
| Severity | String | No | Override the alert severity (`Informational`, `Low`, `Medium`, `High`) |
| LegacyKeys | Switch | No | Emit the 1.4.1 YAML keys. Values the legacy keys cannot express are dropped with a warning |

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

# Pipeline: export all rules to YAML files named by guid
Get-CustomDetection | ConvertTo-CustomDetectionYaml -UseIdAsFilename
```

---

### Deploy-CustomDetection

Creates or updates a Defender XDR custom detection rule from a YAML or JSON file via the Microsoft Graph API. New rules are sent with the rule id `rule-<guid>`, and the YAML `guid` also travels in the description tag. The cmdlet requires a guid in the file. The API itself does not. The Graph reference marks the id as required, but live testing showed the API assigns one when none is sent and rejects one that starts with a digit. The cmdlet detects whether the rule already exists (by rule id, by description tag, or by display name with `-NoDescriptionTag`, and by a direct request for `rule-<guid>` when the rule list carries none of them) and issues a PATCH (update) or POST (create) accordingly. When the rule list does not answer, the rule is looked up by its client id only, and a rule not found that way is reported instead of created. Before updating, it compares the local rule against the remote version and skips the call when nothing changed. The comparison covers every managed property, including tactics, entity mappings, automated actions and device groups.

#### Parameters

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| InputFile | String | Yes | Path to the input YAML (`.yaml`/`.yml`) or JSON (`.json`) file. Accepts pipeline input. |
| Severity | String | No | Override the alert severity (`Informational`, `Low`, `Medium`, `High`) |
| TitlePrefix | String | No | String prepended to the rule's `displayName` and `alertTitle` |
| Disabled | Switch | No | Deploy the rule with `status = disabled` regardless of the file value |
| NoDescriptionTag | Switch | No | Do not append a `[<UUID>]` tag to the description. Without the tag, a rule that does not carry the `rule-<guid>` id is matched by display name alone |
| DescriptionTagPrefix | String | No | Prefix inside the description tag, e.g. `PREFIX` produces `[PREFIX:<UUID>]` |
| ParameterFile | String | No | Path to a YAML parameter file for query variable replacement (see below) |
| Force | Switch | No | Skip change-detection and always push the rule to the API |
| SkipIdentifierValidation | Switch | No | Allow entity identifiers and mapping columns not listed in the official documentation (emits a warning instead of throwing) |
| SkipMitreTechniqueValidation | Switch | No | Skip the pre-deployment check that verifies MITRE ATT&CK techniques are supported by XDR for each tactic |
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

# Deploy without validating MITRE techniques against the XDR category mapping
Deploy-CustomDetection -InputFile .\input.yaml -SkipMitreTechniqueValidation
```

---

### Test-CustomDetectionMitreTechnique

Validates that MITRE ATT&CK techniques listed in a detection rule are supported by Microsoft XDR for the selected alert category. The technique mapping is derived from the XDR portal's front-end data and reflects the actual techniques available in each alert category dropdown.

Categories not present in the XDR mapping (e.g. `SuspiciousActivity`) cannot be validated; in that case the function emits a warning and returns `IsValid = $true`.

#### Parameters

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| InputFile | String | Yes* | Path to a detection YAML (`.yaml`/`.yml`) file (*File parameter set) |
| InputObject | PSObject | Yes* | Parsed detection object; accepts pipeline input (*Object parameter set) |

#### Output

Returns a `PSCustomObject` with:

| Property | Type | Description |
| --- | --- | --- |
| IsValid | Boolean | `$true` if all listed techniques are supported for the category |
| Category | String | The tactic name, or a comma separated list when the rule lists several tactics |
| ValidTechniques | String[] | Techniques that are supported for the category |
| InvalidTechniques | String[] | Techniques that are NOT supported for the category |

#### Examples

```powershell
# Validate MITRE techniques in a YAML file
Test-CustomDetectionMitreTechnique -InputFile '.\detection.yaml'

# Validate all YAML files in a directory
Get-ChildItem '.\detections\*.yaml' | ForEach-Object { Test-CustomDetectionMitreTechnique -InputFile $_.FullName }

# Pipeline input from a parsed YAML object
ConvertFrom-Yaml (Get-Content '.\detection.yaml' -Raw) | Test-CustomDetectionMitreTechnique

# Check result and warn on unsupported techniques
$result = Test-CustomDetectionMitreTechnique -InputFile '.\detection.yaml'
if (-not $result.IsValid) {
    Write-Warning "Unsupported techniques: $($result.InvalidTechniques -join ', ')"
}
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

Lists detection rule IDs with their description tags and tag prefixes. Results are cached for the specified duration (default: 60 minutes) to reduce API calls. A created rule is added to the cache and a deleted rule is removed from it, so a run that creates many rules asks the list once. A list request that times out is asked once more. After a failed retry the cmdlet throws at once for five minutes, unless `-Force` is set.

The output includes:
- **Id**: The detection rule ID
- **DetectorId**: The detector ID the API assigned to the rule
- **DisplayName**: The rule name
- **DescriptionTag**: The UUID extracted from the description tag (e.g., from `[PREFIX:uuid]` or `[uuid]`)
- **TagPrefix**: The prefix text from the description tag (e.g., `PREFIX` from `[PREFIX:uuid]`, or `$null` if no prefix)

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

Returns the detection rule ID for a given guid. The guid is matched against the rule ID in its plain and `rule-` prefixed forms, then against the detector ID the API assigned, then against the description tag. Uses the cached output of `Get-CustomDetectionIds`.

#### Parameters

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| DetectorId | String | Yes | The guid to look up. Accepts pipeline input. |

#### Examples

```powershell
# Look up a detection rule ID by its guid
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

Deletes a custom detection rule from Microsoft Defender XDR. The rule can be identified by its detection rule ID, by the guid from the source file (matched against the rule ID with or without the `rule-` prefix), or by the DescriptionTag UUID appended to the alert description during deployment.

#### Parameters

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| Id | String | Yes* | The detection rule ID as returned by the Graph API (*ById parameter set) |
| DetectorId | String | Yes* | The guid from the source file (*ByDetectorId parameter set) |
| DescriptionTag | String | Yes* | The UUID tag embedded in the alert description (*ByDescriptionTag parameter set) |
| WhatIf | Switch | No | Shows what changes would be made without applying them |
| Confirm | Switch | No | Prompts for confirmation before deleting the rule |

#### Examples

```powershell
# Delete a detection rule by its ID
Remove-CustomDetection -Id '12345'

# Delete by the guid from the source file. Matches the rule id with or without the rule- prefix
Remove-CustomDetection -DetectorId '81fb771a-c57e-41b8-9905-63dbf267c13f'

# Delete by description tag UUID
Remove-CustomDetection -DescriptionTag '81fb771a-c57e-41b8-9905-63dbf267c13f'
```

---

## Property Mapping

The Graph API deprecated several `detectionRule` properties and removes them on 2026-10-01. The module writes only the current properties. Legacy YAML keys are still accepted and translated at conversion time, so existing rule files keep deploying. When a legacy key and its replacement are both present, the replacement wins.

### YAML to JSON

| YAML key | Required | Graph property | Notes |
| --- | --- | --- | --- |
| guid | Yes | `id` | Becomes `id: rule-<guid>` in the converted JSON, which is the value the create request carries, and the bare guid is the description tag. Not required by the API in live testing, whatever the reference says. `id` is accepted as an alias, with or without the `rule-` prefix |
| detectorId | No | `detectorId` | Assigned by the API. The YAML export writes it for reference, and a value in the file is sent back unchanged |
| ruleName | Yes | `displayName` | |
| description | No | `description` | Rule description shown in the portal rule list. A value the file does not set is left unchanged on the rule |
| status | No | `status` | `enabled`, `disabled` or `autoDisabled`. Wins over `isEnabled` |
| isEnabled | No | `status` | Legacy. `true` becomes `enabled`, `false` becomes `disabled`. Defaults to enabled |
| frequency | Yes | `schedule.frequency` | ISO 8601 duration of days, hours, minutes and seconds. Normalised to the form the API stores, so `PT1440M` and `P1DT0H` become `P1D` and `PT90M` becomes `PT1H30M`. Weeks, months and years are rejected. Legacy tokens `0`, `1H`, `3H`, `12H`, `24H` are translated |
| alertTitle | Yes | `detectionAction.alertTemplate.title` | |
| alertSeverity | Yes | `detectionAction.alertTemplate.severity` | |
| alertDescription | Yes | `detectionAction.alertTemplate.description` | The description tag is appended on deploy |
| alertRecommendedAction | No | `detectionAction.alertTemplate.recommendedActions` | A value the file does not set is left unchanged on the rule |
| tactics | One of | `detectionAction.alertTemplate.tactics` | One `{ tactic, techniques }` entry. The API rejects more than one tactic per rule. Techniques may be plain ids or `{ technique, subTechniques }`. Wins over `alertCategory` and `mitreTechniques` |
| alertCategory | One of | `detectionAction.alertTemplate.tactics[0].tactic` | Legacy. Becomes the single tactic |
| mitreTechniques | No | `detectionAction.alertTemplate.tactics[0].techniques` | Legacy flat list. Sub-techniques are grouped under their parent technique |
| entityMappings | No | `detectionAction.alertTemplate.entityMappings` | Object keyed by entity collection (`accounts`, `hosts`, `mailboxes`, `files`, `ips`, `urls`, ...) holding column mappings. Wins over `impactedEntities` |
| impactedEntities | No | `detectionAction.alertTemplate.entityMappings` | Legacy `{ entityType, entityIdentifier }` list. `Machine`/`Device` map to `hosts`, `User`/`Account` to `accounts`, `Mailbox` to `mailboxes` |
| customDetails | No | `detectionAction.alertTemplate.customDetails` | Up to 20 name to column pairs |
| organizationalScope | No | `detectionAction.organizationalScope.deviceGroups` | Device group names. An empty list is omitted |
| actions | No | `detectionAction.automatedActions` | List of `{ actionType, additionalFields }`. See the action table |
| queryText | Yes | `queryCondition.queryText` | |

### Legacy entity identifiers

Each `impactedEntities` entry becomes one column in the matching `entityMappings` collection. The column value is the identifier name with its first letter upper-cased, so `deviceId` becomes `DeviceId`. Entries whose identifiers share a prefix, such as `accountSid` and `accountDomain`, merge into one item. A different prefix, such as `initiatingAccountName`, starts another item, so the order of the entries does not matter. An account item needs `aadUserIdColumn`, `sidColumn`, `upnColumn`, or `nameColumn` together with a domain column. A legacy item that ends up with only a name or only a domain is dropped with a warning, which matches what the API did with the legacy property. An explicit `entityMappings.accounts` item with the same gap is an error, or a warning with `-SkipIdentifierValidation`.

| entityType | entityIdentifier | Collection and column |
| --- | --- | --- |
| Machine / Device | deviceId | `hosts.deviceIdColumn` |
| Machine / Device | deviceName, remoteDeviceName, targetDeviceName, destinationDeviceName | `hosts.nameColumn` |
| User / Account | accountObjectId, recipientObjectId, processAccountObjectId, initiatingProcessAccountObjectId, servicePrincipalId | `accounts.aadUserIdColumn` |
| User / Account | accountSid, requestAccountSid, initiatingAccountSid, initiatingProcessAccountSid | `accounts.sidColumn` |
| User / Account | accountUpn, initiatingProcessAccountUpn, targetAccountUpn | `accounts.upnColumn` |
| User / Account | accountName, requestAccountName, initiatingAccountName, servicePrincipalName, accountId | `accounts.nameColumn` |
| User / Account | accountDomain, requestAccountDomain, initiatingAccountDomain | `accounts.ntDomainColumn` |
| Mailbox | any documented mailbox identifier | `mailboxes.primaryAddressColumn` |
| IP | any query column | `ips.addressColumn` |
| URL | any query column | `urls.addressColumn` |
| FileHash | a column whose name contains SHA1 or SHA256 | `files.sha1Column` or `files.sha256Column` |
| Process | a column whose name contains SHA1 or SHA256 | `processes.sha1Column` or `processes.sha256Column` |
| RegistryKey | any query column | `registryValues.keyColumn` |
| RegistryValue | any query column | `registryValues.valueNameColumn` |

### Actions

`actionType` selects the `automatedActions` collection. `additionalFields` overrides the default columns.

| actionType | Collection | Default columns |
| --- | --- | --- |
| IsolateMachine | isolateDevices | `deviceIdColumn: DeviceId`, `isolationType: Full` |
| CollectInvestigationPackage | collectInvestigationPackages | `deviceIdColumn: DeviceId` |
| RunAntivirusScan | runAntivirusScans | `deviceIdColumn: DeviceId` |
| InitiateInvestigation | initiateInvestigations | `deviceIdColumn: DeviceId` |
| RestrictAppExecution | restrictAppExecutions | `deviceIdColumn: DeviceId` |
| StopAndQuarantineFile | stopAndQuarantineFiles | `deviceIdColumn: DeviceId`, `sha1Column: SHA1` |
| AllowFile | allowFiles | `sha1Column: SHA1`, optional `deviceGroupNames`. The API stores one hash column, so an explicit `sha256Column` replaces the default |
| BlockFile | blockFiles | `sha1Column: SHA1`, optional `deviceGroupNames`. The API stores one hash column, so an explicit `sha256Column` replaces the default |
| DisableUser | disableUsers | `accountSidColumn: AccountSid` |
| ForceUserPasswordReset | forceUserPasswordResets | `accountSidColumn: AccountSid` |
| MarkUserAsCompromised | markUsersAsCompromised | `accountObjectIdColumn: AccountObjectId` |
| HardDeleteEmail | hardDeleteEmails | `networkMessageIdColumn: NetworkMessageId`, `recipientColumn: RecipientEmailAddress` |
| SoftDeleteEmail | softDeleteEmails | as HardDeleteEmail |
| MoveEmailToInbox | moveEmailsToInbox | as HardDeleteEmail |
| MoveEmailToJunk | moveEmailsToJunk | as HardDeleteEmail |
| MoveEmailToDeletedItems | moveEmailsToDeletedItems | as HardDeleteEmail |

### Updates

The API keeps any collection that a PATCH omits. An update therefore sends an empty list for every collection the rule carries and the file does not, collections this module does not know included, and names each cleared collection in a warning. Empty device groups are sent only when the rule has device groups the file does not set. Collections neither side carries are left out. Removing an action, an entity mapping or a device group from the file removes it from the rule. Custom details are the exception. No PATCH shape clears them, so a rule keeps its custom details when the file stops setting them, and the deploy warns about it. Custom detail values must be columns the query projects.

### JSON to YAML

`ConvertTo-CustomDetectionYaml` always emits the current keys: `frequency` as an ISO 8601 duration, `tactics`, `entityMappings`, `actions` with their column mapping, `customDetails`, `description` and `organizationalScope` as a plain list. `isEnabled` is kept for compatibility and `status` is added only for `autoDisabled`. Rules returned with the legacy properties are translated, so converting an old rule upgrades its YAML file.

### Upgrading existing YAML files

No change is required. Legacy files deploy unchanged. To rewrite a file with the current keys, round-trip it:

```powershell
ConvertTo-CustomDetectionJson -InputFile .\rule.yaml -OutputFile .\rule.json
ConvertTo-CustomDetectionYaml -InputFile .\rule.json -OutputFile .\rule.yaml
```

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

### 2.0.0

- **Breaking change**: the JSON produced by `ConvertTo-CustomDetectionJson` and the YAML produced by `ConvertTo-CustomDetectionYaml` changed shape
- Request bodies now use the current Graph `detectionRule` properties: `status`, `schedule.frequency`, `tactics`, `entityMappings`, `automatedActions` and `organizationalScope.deviceGroups`. The deprecated `detectorId`, `isEnabled`, `period`, `category`, `mitreTechniques`, `impactedAssets` and `responseActions` properties are no longer written
- Legacy YAML keys are still accepted and translated. When a legacy key and its replacement are both present, the replacement wins
- New optional YAML keys: `description`, `status`, `tactics`, `entityMappings`, `customDetails` and ISO 8601 `frequency` values
- All 16 automated action types and all 17 entity mapping collections are supported
- New rules get the rule id `rule-<guid>`. Rules are found through that id, through the description tag, or through the display name with `-NoDescriptionTag`. When the rule list carries none of them, `rule-<guid>` is requested directly before a create, since the list can lag behind a create or a delete
- `ConvertTo-CustomDetectionYaml` emits the current keys and upgrades rules that still carry the legacy properties
- Change detection compares every managed property, so changes to actions, entity mappings, techniques or device groups trigger an update
- The detection id cache gains a created rule and loses a deleted one instead of being cleared, so a run that creates many rules asks the list once
- JSON input files are normalised before deployment, so legacy JSON exports deploy with the current body
- `Test-CustomDetectionMitreTechnique` accepts a `tactics` list and validates each tactic. The parent technique of a grouped entry is validated together with its sub-techniques
- `ConvertTo-CustomDetectionYaml -LegacyKeys` emits the legacy YAML keys for files that must stay in the old form. Column mappings the legacy identifiers cannot express are dropped with a warning
- The legacy entity types IP, URL, FileHash, Process, RegistryKey and RegistryValue now deploy. Version 1.4.1 turned them into impactedAsset types the API does not have
- With `-NoDescriptionTag`, an existing rule is found through its display name, which the API keeps unique
- `Get-CustomDetectionIds` carries the display name and the detector ID the API assigned. The list is projected to the id, the detector ID, the display name and the detection action
- With `-NoDescriptionTag`, a rule matched by its display name produces a warning, since a renamed file would create a new rule
- A rule the platform set to `autoDisabled` is not enabled again until the file changes or `-Force` is used, and a warning names it. A file that disables the rule sends `disabled` once, since the API rejects `autoDisabled` on write
- A file action that names both hash columns is rejected before the request
- An action field the Graph action type does not document is rejected before the request
- OData annotations on entity mappings and automated actions are ignored
- Request bodies are stripped of PowerShell object wrappers before they reach the Graph client, which rejected them with a self-referencing loop error
- Updates send an empty list for every collection the rule carries and the file does not, collections this module does not know included, so an action, entity mapping or device group removed from the file is removed from the rule
- `frequency` is normalised to the form the API stores before the change detection runs, so a value such as `PT1440M` no longer reports an update on every run
- A rule description or recommended action the file does not set is left unchanged and no longer reports an update on every run. A warning names the value the rule keeps
- Change detection is case-sensitive for text and column names, so a casing fix to a query or a column mapping now reaches the rule. Status, severity, tactic names and device group names are still compared without case
- Legacy `impactedEntities` entries are grouped by identifier prefix, so `deviceId` and `remoteDeviceName` become two hosts instead of one host with another device's name, and the order of the entries no longer changes the result
- Input the API rejects with an opaque message is rejected before the request with a named one: an empty device group name, a list as a column name, an action listed twice with the same fields, and an `isEnabled` value other than true or false. An action type listed twice with different fields produces a warning, since the rule keeps both
- `ConvertTo-CustomDetectionJson` emits `id: rule-<guid>`, the value the create request carries. A YAML `id` may carry the prefix, and an exported rule keeps whatever follows the prefix as its guid
- A plain string where a mapping is expected in `actions`, `impactedEntities` or an entity mapping list is rejected, as are an `isolationType` other than `Full` or `Selective`, a `customDetails` value that is not a string and an `organizationalScope` entry that is not a device group name. The item used to be skipped or defaulted without a word
- Every collection an update clears is named in a warning
- A file that carries both a legacy key and its replacement produces a warning naming the key that wins
- JSON input is validated like YAML input. An incomplete account mapping is rejected unless `-SkipIdentifierValidation` is set, and a `status` that contradicts `isEnabled` produces a warning
- `Get-CustomDetectionIdByDetectorId` falls back to the description tag, so `Remove-CustomDetection -DetectorId` finds a rule created before the rule id carried the guid
- Action fields in `additionalFields` are written under their documented name whatever the casing in the file, so `Sha256Column` no longer reports an update on every run
- The editor schema accepts the `rule-` prefix on `id` and lists the documented columns of every entity mapping collection, so it rejects the column names the converter rejects
- A rule list request that times out is asked once more and then left alone for five minutes. In that window `Deploy-CustomDetection` looks a rule up by its client id only and reports a rule it cannot find instead of creating it, so a slow list costs one timeout per run instead of one per rule
- `detectorId` is a YAML key. The YAML export writes the value the API assigned, the converter carries a value from the file into the request body, and `Get-CustomDetectionIdByDetectorId` matches it
- A legacy `RegistryKey` and `RegistryValue` pair becomes one registry value item with both columns, since the two identifiers describe one entity
- `Remove-CustomDetection -DetectorId` and `-DescriptionTag` ask for the client id `rule-<guid>` directly when the list does not carry the rule, as the deploy does before a create
- A description tag carried by more than one rule produces a warning naming the rules, and the first one is used. It used to hand the deploy a list of ids, which stopped it with a type error
- An `organizationalScope` whose only entry is empty is rejected. It used to deploy the rule without a scope
- A description tag carried by more than one rule is named in a warning whichever lookup finds the rule
- An `additionalFields` value that is not a mapping, and an entity mapping column that is not a single name, are rejected. They used to be ignored, so the action deployed with its defaults and the column went to the API as a number
- An `entityMappings` key that carries an empty mapping keeps a legacy `impactedEntities` list out of the request, since an empty mapping states that the rule maps no entity
- The identifier validation choice reaches legacy JSON assets, so a `.json` and a `.yaml` file holding the same unsupported identifier are judged alike
- A legacy registry key and value name pair into one registry value item whatever their order in the file
- `Remove-CustomDetection` asks for the client id when the rule list does not answer, which is when a rule most needs removing
- The editor schema rejects an empty device group name, an account mapping without a key column or a name and domain pair, a field the action type does not document, and a file action that names both hash columns
- The legacy export warns that the detector id is dropped, as it does for the values the other current keys carry
- An action field value that is not a single column name is rejected, and so is a device group name that is not a single name. Both used to reach the API unchanged
- Action fields follow their documented order, so the same fields give the same item whatever their order in the file, and an action listed twice is caught whichever order its fields are in
- The editor schema accepts an `additionalFields` key that carries no value, which the converter reads as absent
- Action types and field names are matched without case, which the editor schema cannot express. The schema lists the documented casing and names the leniency in its description
- Bugs/issues or undocumented behavior identified while testing: 
   - `PT0S` and non-MITRE tactic names such as `SuspiciousActivity` are accepted on create
   - `autoDisabled` is rejected on write and is sent as `disabled`
   - The API accepts one tactic per rule
   - File actions keep one hash column
   - Custom details cannot be cleared once set
   - The reference marks the rule id as required on create. Live testing showed the API assigns one when it is absent, and rejects a client id that starts with a digit, so a guid needs a prefix
   - An account entity mapping needs a key column or a name plus domain pair. A name-only mapping is rejected on write, while the legacy property was silently emptied
   - `schedule.frequency` is stored in a canonical form. `PT1440M` and `P1DT0H` come back as `P1D`, `PT0H` as `PT0S` and `PT90M` as `PT1H30M`. `P1W` is rejected as not an `Edm.Duration`
   - Entity mapping columns are matched against the query projection case-sensitively. `deviceid` is rejected when the query projects `DeviceId`
   - The rule list can omit a rule for a long time after its id was deleted and created again, while a create with that id answers Conflict
   - The list request can exceed the Graph client's 300 second timeout several times in a row. Four and five in a row were seen in one morning
   - `detectorId` is assigned by the API on create. A value sent with the request is not stored, so it never equals the file guid

### 1.4.1
- Included Graph API error details in deployment failure messages for easier troubleshooting
- Module version bumped to 1.4.1

### 1.4.0
- Added `TagPrefix` column to `Get-CustomDetectionIds` output to show the prefix from description tags (e.g., `CSOC` from `[CSOC:uuid]`)
- Improved test reliability by clearing `DetectionIdsCache` within module scope
- Module version bumped to 1.4.0

### 1.3.1
- Less verbose logging on deployment failure, added error details and debug output of the JSON object being deployed for easier troubleshooting
- Module version bumped to 1.3.1

### 1.3.0

- Added proper YAML-to-JSON and JSON-to-YAML mapping for response actions (`IsolateMachine`, `CollectInvestigationPackage`, `RunAntivirusScan`, `InitiateInvestigation`, `RestrictAppExecution`)
- Response actions are now converted to/from Microsoft Graph API `@odata.type` format
- Added validation that response action identifiers match defined impacted assets
- Added GitHub Actions workflow to auto-bump module version on PRs based on conventional commits
- Module version bumped to 1.3.0

### 1.2.0

- Added `Test-CustomDetectionMitreTechnique` cmdlet to validate MITRE ATT&CK techniques against XDR-supported categories per alert category
- Added `-SkipMitreTechniqueValidation` parameter to `Deploy-CustomDetection` to bypass the pre-deployment MITRE technique check
- `Deploy-CustomDetection` now validates MITRE techniques before deploying by default and throws if unsupported techniques are found
- Module version bumped to 1.2.0

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
