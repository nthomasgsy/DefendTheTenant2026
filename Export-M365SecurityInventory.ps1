#Requires -Version 7.2
<#
.SYNOPSIS
    Captures Microsoft 365 / Entra security configuration and activity evidence.

.DESCRIPTION
    Read-only collector covering:
      1. Conditional Access policies and named locations
      2. Authentication method registration coverage
      3. Interactive and non-interactive legacy authentication
      4. Active risky sign-ins and risky users
      5. User consent policy assignments and permission grants
      6. Teams meeting policies and user assignments
      7. Active and eligible Entra administrative role assignments
      8. Password reset registration/settings and password writeback indicators

    Output:
      - Full JSON exports
      - Selected CSV exports
      - Capture manifest
      - Errors and manual follow-up records

.NOTES
    Run in PowerShell 7.
    The account must hold suitable directory roles in addition to the Graph scopes.
    Some features require Microsoft Entra ID P1/P2 and appropriate log retention.

.EXAMPLE
    .\Export-M365SecurityInventory.ps1

.EXAMPLE
    .\Export-M365SecurityInventory.ps1 `
        -OutputPath C:\Evidence `
        -SignInLookbackDays 30
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath = (Join-Path $PWD 'M365-Security-Inventory'),

    [Parameter()]
    [ValidateRange(1, 30)]
    [int]$SignInLookbackDays = 30,

    [Parameter()]
    [ValidateSet(
        'ConditionalAccess',
        'AuthenticationRegistration',
        'LegacyAuthentication',
        'IdentityRisk',
        'ConsentAndGrants',
        'TeamsPolicies',
        'AdministrativeRoles',
        'PasswordReset'
    )]
    [string[]]$IncludeSection,

    [Parameter()]
    [switch]$SkipModuleInstallation
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-SectionEnabled {
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    if ($null -eq $IncludeSection -or $IncludeSection.Count -eq 0) {
        return $true
    }

    return $Name -in $IncludeSection
}

function Add-SkippedManifestEntry {
    param(
        [string]$Section,
        [string]$Path
    )

    Write-Status "$Section skipped." Warning

    Add-ManifestEntry `
        -Section $Section `
        -Status 'Skipped' `
        -File $Path `
        -Notes 'Not selected in IncludeSection parameter.'
}

# ---------------------------------------------------------------------------
# Initialisation
# ---------------------------------------------------------------------------

$script:CaptureStartedUtc = (Get-Date).ToUniversalTime()
$timestamp = $script:CaptureStartedUtc.ToString('yyyyMMdd-HHmmssZ')
$script:CaptureRoot = Join-Path $OutputPath $timestamp
$script:ErrorRecords = [System.Collections.Generic.List[object]]::new()
$script:ManifestRecords = [System.Collections.Generic.List[object]]::new()
$script:SignIns = $null
$script:RegistrationDetails = $null
$script:TeamsConnected = $false

$folders = @(
    $script:CaptureRoot
    (Join-Path $script:CaptureRoot '01-ConditionalAccess')
    (Join-Path $script:CaptureRoot '02-AuthenticationRegistration')
    (Join-Path $script:CaptureRoot '03-LegacyAuthentication')
    (Join-Path $script:CaptureRoot '04-IdentityRisk')
    (Join-Path $script:CaptureRoot '05-ConsentAndGrants')
    (Join-Path $script:CaptureRoot '06-TeamsMeetingPolicies')
    (Join-Path $script:CaptureRoot '07-AdministrativeRoles')
    (Join-Path $script:CaptureRoot '08-PasswordReset')
)

foreach ($folder in $folders) {
    $null = New-Item -Path $folder -ItemType Directory -Force
}

function Write-Status {
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [ValidateSet('Info', 'Success', 'Warning', 'Error')]
        [string]$Level = 'Info'
    )

    $colour = switch ($Level) {
        'Success' { 'Green' }
        'Warning' { 'Yellow' }
        'Error'   { 'Red' }
        default   { 'Cyan' }
    }

    Write-Host "[$Level] $Message" -ForegroundColor $colour
}

function Add-CaptureError {
    param(
        [Parameter(Mandatory)]
        [string]$Section,

        [Parameter(Mandatory)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    $script:ErrorRecords.Add([pscustomobject]@{
        TimestampUtc       = (Get-Date).ToUniversalTime().ToString('o')
        Section            = $Section
        Message            = $ErrorRecord.Exception.Message
        FullyQualifiedId   = $ErrorRecord.FullyQualifiedErrorId
        ScriptStackTrace   = $ErrorRecord.ScriptStackTrace
    })

    Write-Status "$Section failed: $($ErrorRecord.Exception.Message)" Error
}

function Add-ManifestEntry {
    param(
        [Parameter(Mandatory)]
        [string]$Section,

        [Parameter(Mandatory)]
        [string]$Status,

        [string]$File,

        [int]$RecordCount = 0,

        [string]$Notes
    )

    $script:ManifestRecords.Add([pscustomobject]@{
        Section     = $Section
        Status      = $Status
        RecordCount = $RecordCount
        File        = $File
        Notes       = $Notes
    })
}

function Export-JsonEvidence {
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        $InputObject,

        [Parameter(Mandatory)]
        [string]$Path,

        [int]$Depth = 100
    )

    $InputObject |
        ConvertTo-Json -Depth $Depth |
        Set-Content -Path $Path -Encoding utf8BOM
}

function Export-CsvEvidence {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$InputObject,

        [Parameter(Mandatory)]
        [string]$Path
    )

    @($InputObject) |
        Export-Csv -Path $Path -NoTypeInformation -Encoding utf8BOM
}

function ConvertTo-JsonCell {
    param([AllowNull()]$Value)

    if ($null -eq $Value) {
        return $null
    }

    return ($Value | ConvertTo-Json -Depth 30 -Compress)
}

function Ensure-Module {
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    if (-not (Get-Module -ListAvailable -Name $Name)) {
        if ($SkipModuleInstallation) {
            throw "Required module '$Name' is not installed."
        }

        Write-Status "Installing module $Name for the current user."
        Install-Module -Name $Name -Scope CurrentUser -Repository PSGallery -Force
    }

    Import-Module $Name -ErrorAction Stop
}

function Invoke-GraphCollection {
    <#
        Follows Microsoft Graph @odata.nextLink pagination
        and returns the complete collection.
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Uri
    )

    $items = [System.Collections.Generic.List[object]]::new()
    $nextLink = $Uri

    $pageNumber = 0
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    Write-Host ""
    Write-Host "[Graph] Starting collection" -ForegroundColor Cyan
    Write-Host "[Graph] URI: $Uri" -ForegroundColor DarkCyan

    do {
        $pageNumber++

        Write-Progress `
            -Activity "Microsoft Graph Collection" `
            -Status "Downloading page $pageNumber" `
            -PercentComplete -1

        Write-Host (
            "[Graph] Page {0} | Records so far: {1:N0}" -f
            $pageNumber,
            $items.Count
        ) -ForegroundColor Cyan

        $response = Invoke-MgGraphRequest `
            -Method GET `
            -Uri $nextLink `
            -OutputType PSObject

        $pageCount = 0

        $valueProperty = $response.PSObject.Properties['value']

        if ($null -ne $valueProperty) {

            foreach ($item in @($valueProperty.Value)) {

                if ($null -ne $item) {
                    $items.Add($item)
                    $pageCount++
                }
            }
        }
        else {

            $items.Add($response)
            $pageCount = 1
        }

        Write-Host (
            "[Graph] Page {0} returned {1:N0} records (Total: {2:N0})" -f
            $pageNumber,
            $pageCount,
            $items.Count
        ) -ForegroundColor Green

        $nextLinkProperty =
            $response.PSObject.Properties['@odata.nextLink']

        if ($null -ne $nextLinkProperty) {

            $nextLink = [string]$nextLinkProperty.Value

            Write-Verbose (
                "Next page detected after page {0}" -f $pageNumber
            )
        }
        else {

            $nextLink = $null

            Write-Host (
                "[Graph] Final page reached"
            ) -ForegroundColor Yellow
        }

    }
    while (-not [string]::IsNullOrWhiteSpace($nextLink))

    $stopwatch.Stop()

    Write-Progress `
        -Activity "Microsoft Graph Collection" `
        -Completed

    Write-Host ""
    Write-Host (
        "[Graph] Complete | Pages: {0} | Records: {1:N0} | Duration: {2}" -f
        $pageNumber,
        $items.Count,
        $stopwatch.Elapsed.ToString("hh\:mm\:ss")
    ) -ForegroundColor Magenta
    Write-Host ""

    return $items.ToArray()
}

function Resolve-DirectoryObject {
    param(
        [Parameter(Mandatory)]
        [string]$ObjectId
    )

    try {
        $object = Invoke-MgGraphRequest `
            -Method GET `
            -Uri "https://graph.microsoft.com/v1.0/directoryObjects/$ObjectId" `
            -OutputType PSObject

        return [pscustomobject]@{
            Id                = $ObjectId
            ObjectType        = $object.'@odata.type'
            DisplayName       = $object.displayName
            UserPrincipalName = $object.userPrincipalName
            AppId             = $object.appId
            Deleted           = $false
        }
    }
    catch {
        return [pscustomobject]@{
            Id                = $ObjectId
            ObjectType        = 'UnresolvedOrDeleted'
            DisplayName       = $null
            UserPrincipalName = $null
            AppId             = $null
            Deleted           = $true
        }
    }
}

function Get-SafeProperty {
    param(
        [object]$Object,
        [string]$PropertyName
    )

    if ($null -eq $Object) {
        return $null
    }

    $property =
        $Object.PSObject.Properties |
        Where-Object Name -eq $PropertyName |
        Select-Object -First 1

    if ($null -ne $property) {
        return $property.Value
    }

    return $null
}

# ---------------------------------------------------------------------------
# Modules and connections
# ---------------------------------------------------------------------------

Write-Status "Evidence directory: $script:CaptureRoot"

Ensure-Module -Name Microsoft.Graph.Authentication

$graphScopes = @(
    'Policy.Read.All'
    'Directory.Read.All'
    'AuditLog.Read.All'
    'IdentityRiskyUser.Read.All'
    'IdentityRiskEvent.Read.All'
    'Application.Read.All'
    'DelegatedPermissionGrant.Read.All'
    'RoleManagement.Read.Directory'
    'RoleEligibilitySchedule.Read.Directory'
    'UserAuthenticationMethod.Read.All'
    'Reports.Read.All'
    'Organization.Read.All'
    'OnPremDirectorySynchronization.Read.All'
)

Write-Status 'Connecting to Microsoft Graph.'

Connect-MgGraph `
    -Scopes $graphScopes `
    -NoWelcome

$context = Get-MgContext

if (-not $context.TenantId) {
    throw 'Microsoft Graph connection did not return a tenant identifier.'
}

$tenant = Invoke-MgGraphRequest `
    -Method GET `
    -Uri 'https://graph.microsoft.com/v1.0/organization?$select=id,displayName,verifiedDomains,onPremisesSyncEnabled' `
    -OutputType PSObject

$tenantDetails = @($tenant.value)[0]

$captureMetadata = [ordered]@{
    CaptureStartedUtc  = $script:CaptureStartedUtc.ToString('o')
    TenantId           = $context.TenantId
    TenantDisplayName  = $tenantDetails.displayName
    GraphAccount       = $context.Account
    GraphAuthType      = $context.AuthType
    GrantedScopes      = @($context.Scopes)
    PowerShellVersion  = $PSVersionTable.PSVersion.ToString()
    ComputerName       = [Environment]::MachineName
    SignInLookbackDays = $SignInLookbackDays
    OutputDirectory    = $script:CaptureRoot
}

Export-JsonEvidence `
    -InputObject $captureMetadata `
    -Path (Join-Path $script:CaptureRoot 'Capture-Metadata.json')

Write-Status "Connected to tenant '$($tenantDetails.displayName)' [$($context.TenantId)]." Success

if ($IncludeSection) {

    Write-Status (
        "Selected sections: {0}" -f
        ($IncludeSection -join ', ')
    )
}
else {

    Write-Status "No section filter specified. Running full inventory."
}

# ---------------------------------------------------------------------------
# 1. Conditional Access policies and named locations
# ---------------------------------------------------------------------------

$section = '1 - Conditional Access policies and named locations'
$sectionPath = Join-Path $script:CaptureRoot '01-ConditionalAccess'

if (Test-SectionEnabled 'ConditionalAccess') {

    try {
    Write-Status $section

    $caPolicies = Invoke-GraphCollection `
        -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies'

    $namedLocations = Invoke-GraphCollection `
        -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations'

    $authenticationStrengthPolicies = Invoke-GraphCollection `
        -Uri 'https://graph.microsoft.com/v1.0/policies/authenticationStrengthPolicies'

    Export-JsonEvidence $caPolicies `
        (Join-Path $sectionPath 'ConditionalAccessPolicies-Full.json')

    Export-JsonEvidence $namedLocations `
        (Join-Path $sectionPath 'NamedLocations-Full.json')

    Export-JsonEvidence $authenticationStrengthPolicies `
        (Join-Path $sectionPath 'AuthenticationStrengthPolicies-Full.json')

    $caSummary = foreach ($policy in $caPolicies) {
        [pscustomobject]@{
            Id                         = $policy.id
            DisplayName                = $policy.displayName
            State                      = $policy.state
            CreatedDateTime            = $policy.createdDateTime
            ModifiedDateTime           = $policy.modifiedDateTime
            IncludedUsers              = ConvertTo-JsonCell $policy.conditions.users.includeUsers
            ExcludedUsers              = ConvertTo-JsonCell $policy.conditions.users.excludeUsers
            IncludedGroups             = ConvertTo-JsonCell $policy.conditions.users.includeGroups
            ExcludedGroups             = ConvertTo-JsonCell $policy.conditions.users.excludeGroups
            IncludedRoles              = ConvertTo-JsonCell $policy.conditions.users.includeRoles
            ExcludedRoles              = ConvertTo-JsonCell $policy.conditions.users.excludeRoles
            IncludedApplications       = ConvertTo-JsonCell $policy.conditions.applications.includeApplications
            ExcludedApplications       = ConvertTo-JsonCell $policy.conditions.applications.excludeApplications
            IncludedUserActions        = ConvertTo-JsonCell $policy.conditions.applications.includeUserActions
            ClientAppTypes             = ConvertTo-JsonCell $policy.conditions.clientAppTypes
            Platforms                  = ConvertTo-JsonCell $policy.conditions.platforms
            Locations                  = ConvertTo-JsonCell $policy.conditions.locations
            Devices                    = ConvertTo-JsonCell $policy.conditions.devices
            SignInRiskLevels           = ConvertTo-JsonCell $policy.conditions.signInRiskLevels
            UserRiskLevels             = ConvertTo-JsonCell $policy.conditions.userRiskLevels
            ServicePrincipalRiskLevels = ConvertTo-JsonCell $policy.conditions.servicePrincipalRiskLevels
            GrantControls              = ConvertTo-JsonCell $policy.grantControls
            SessionControls            = ConvertTo-JsonCell $policy.sessionControls
        }
    }

    Export-CsvEvidence $caSummary `
        (Join-Path $sectionPath 'ConditionalAccessPolicies-Summary.csv')

    Add-ManifestEntry `
        -Section $section `
        -Status 'Success' `
        -File $sectionPath `
        -RecordCount $caPolicies.Count `
        -Notes "$($namedLocations.Count) named locations captured."
}
catch {
    Add-CaptureError -Section $section -ErrorRecord $_
    Add-ManifestEntry -Section $section -Status 'Failed' -File $sectionPath -Notes $_.Exception.Message
}
}
else {
    Add-SkippedManifestEntry `
        -Section $section `
        -Path $sectionPath
}

# ---------------------------------------------------------------------------
# 2. Authentication method registration coverage
# ---------------------------------------------------------------------------

$section = '2 - Authentication method registration coverage'
$sectionPath = Join-Path $script:CaptureRoot '02-AuthenticationRegistration'

if (Test-SectionEnabled 'AuthenticationRegistration') {

    try {
    Write-Status $section

    $script:RegistrationDetails = Invoke-GraphCollection `
        -Uri 'https://graph.microsoft.com/beta/reports/authenticationMethods/userRegistrationDetails'

    $authenticationMethodsPolicy = Invoke-MgGraphRequest `
        -Method GET `
        -Uri 'https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy' `
        -OutputType PSObject

    Export-JsonEvidence $script:RegistrationDetails `
        (Join-Path $sectionPath 'UserRegistrationDetails-Full.json')

    Export-JsonEvidence $authenticationMethodsPolicy `
        (Join-Path $sectionPath 'AuthenticationMethodsPolicy-Full.json')

    $registrationSummary = foreach ($record in $script:RegistrationDetails) {
        [pscustomobject]@{
            Id                      = $record.id
            UserPrincipalName       = $record.userPrincipalName
            UserDisplayName         = $record.userDisplayName
            UserType                = $record.userType
            IsAdmin                 = $record.isAdmin
            IsMfaRegistered         = $record.isMfaRegistered
            IsMfaCapable            = $record.isMfaCapable
            IsPasswordlessCapable   = $record.isPasswordlessCapable
            IsSsprRegistered        = $record.isSsprRegistered
            IsSsprEnabled           = $record.isSsprEnabled
            IsSsprCapable           = $record.isSsprCapable
            IsSystemPreferredEnabled = $record.isSystemPreferredAuthenticationMethodEnabled
            SystemPreferredMethod   = $record.systemPreferredAuthenticationMethods
            MethodsRegistered       = (@($record.methodsRegistered) -join ';')
            LastUpdatedDateTime     = $record.lastUpdatedDateTime
        }
    }

    Export-CsvEvidence $registrationSummary `
        (Join-Path $sectionPath 'UserRegistrationDetails-Summary.csv')

    $coverage = [pscustomobject]@{
        CapturedUsers             = $script:RegistrationDetails.Count
        MfaRegisteredUsers        = @($script:RegistrationDetails | Where-Object isMfaRegistered).Count
        MfaCapableUsers           = @($script:RegistrationDetails | Where-Object isMfaCapable).Count
        PasswordlessCapableUsers  = @($script:RegistrationDetails | Where-Object isPasswordlessCapable).Count
        SsprEnabledUsers          = @($script:RegistrationDetails | Where-Object isSsprEnabled).Count
        SsprRegisteredUsers       = @($script:RegistrationDetails | Where-Object isSsprRegistered).Count
        SsprCapableUsers          = @($script:RegistrationDetails | Where-Object isSsprCapable).Count
    }

    Export-JsonEvidence $coverage `
        (Join-Path $sectionPath 'RegistrationCoverage-Counts.json')

    Add-ManifestEntry `
        -Section $section `
        -Status 'Success' `
        -File $sectionPath `
        -RecordCount $script:RegistrationDetails.Count
}
catch {
    Add-CaptureError -Section $section -ErrorRecord $_
    Add-ManifestEntry -Section $section -Status 'Failed' -File $sectionPath -Notes $_.Exception.Message
}
}
else {
    Add-SkippedManifestEntry `
        -Section $section `
        -Path $sectionPath
}

# ---------------------------------------------------------------------------
# 3. Interactive and non-interactive legacy authentication
# ---------------------------------------------------------------------------

$section = '3 - Interactive and non-interactive legacy authentication'
$sectionPath = Join-Path $script:CaptureRoot '03-LegacyAuthentication'

if (Test-SectionEnabled 'LegacyAuthentication') {

    try {
    Write-Status $section

    $startDateUtc = $script:CaptureStartedUtc.AddDays(-$SignInLookbackDays)
    $startDateText = $startDateUtc.ToString('yyyy-MM-ddTHH:mm:ssZ')
    $signInUri = "https://graph.microsoft.com/beta/auditLogs/signIns?`$filter=createdDateTime ge $startDateText"

    $script:SignIns = Invoke-GraphCollection -Uri $signInUri

    # Graph clientAppUsed values vary by workload and reporting generation.
    # Retain the full capture and select recognised legacy/basic categories locally.
    $legacyClientPatterns = @(
        'Exchange ActiveSync'
        'Other clients'
        'Authenticated SMTP'
        'IMAP'
        'POP'
        'MAPI'
        'AutoDiscover'
        'Exchange Online PowerShell'
        'Reporting Web Services'
    )

    $legacySignIns = @(
        $script:SignIns | Where-Object {
            $client = [string]$_.clientAppUsed

            ($client -in $legacyClientPatterns) -or
            ($client -match 'SMTP|IMAP|POP|ActiveSync|Legacy|Other clients')
        }
    )

    Export-JsonEvidence $legacySignIns `
        (Join-Path $sectionPath 'LegacyAuthenticationSignIns-Full.json')

    $legacySummary = foreach ($signIn in $legacySignIns) {
        [pscustomobject]@{
            CreatedDateTime           = $signIn.createdDateTime
            IsInteractive             = $signIn.isInteractive
            UserDisplayName           = $signIn.userDisplayName
            UserPrincipalName         = $signIn.userPrincipalName
            UserId                    = $signIn.userId
            AppDisplayName            = $signIn.appDisplayName
            AppId                     = $signIn.appId
            ResourceDisplayName       = $signIn.resourceDisplayName
            ClientAppUsed             = $signIn.clientAppUsed
            IPAddress                 = $signIn.ipAddress
            CountryOrRegion           = $signIn.location.countryOrRegion
            State                     = $signIn.location.state
            City                      = $signIn.location.city
            DeviceOperatingSystem     = $signIn.deviceDetail.operatingSystem
            DeviceBrowser             = $signIn.deviceDetail.browser
            ConditionalAccessStatus   = $signIn.conditionalAccessStatus
            RiskLevelDuringSignIn     = $signIn.riskLevelDuringSignIn
            RiskLevelAggregated       = $signIn.riskLevelAggregated
            RiskState                 = $signIn.riskState
            StatusErrorCode           = $signIn.status.errorCode
            StatusFailureReason       = $signIn.status.failureReason
            CorrelationId             = $signIn.correlationId
            SignInId                  = $signIn.id
        }
    }

    Export-CsvEvidence $legacySummary `
        (Join-Path $sectionPath 'LegacyAuthenticationSignIns-Summary.csv')

    $legacyBreakdown = $legacySummary |
        Group-Object IsInteractive, ClientAppUsed |
        ForEach-Object {
            [pscustomobject]@{
                Classification = $_.Name
                Count          = $_.Count
            }
        } |
        Sort-Object Count -Descending

    Export-CsvEvidence $legacyBreakdown `
        (Join-Path $sectionPath 'LegacyAuthentication-Breakdown.csv')

    Add-ManifestEntry `
        -Section $section `
        -Status 'Success' `
        -File $sectionPath `
        -RecordCount $legacySignIns.Count `
        -Notes "Queried from $startDateText. Actual availability depends on tenant log retention."
}
catch {
    Add-CaptureError -Section $section -ErrorRecord $_
    Add-ManifestEntry -Section $section -Status 'Failed' -File $sectionPath -Notes $_.Exception.Message
}
}
else {
    Add-SkippedManifestEntry `
        -Section $section `
        -Path $sectionPath
}

# ---------------------------------------------------------------------------
# 4. Active risky sign-ins and risky users
# ---------------------------------------------------------------------------

$section = '4 - Active risky sign-ins and risky users'
$sectionPath = Join-Path $script:CaptureRoot '04-IdentityRisk'

if (Test-SectionEnabled 'IdentityRisk') {

    try {
    Write-Status $section
    
    $atRiskSignIns = @(
        if ($null -ne $script:SignIns) {
            $script:SignIns | Where-Object {
                $_.riskState -eq 'atRisk' -or
                $_.riskLevelAggregated -in @('medium','high')
            }
        }
        else {
            $riskStart = $script:CaptureStartedUtc.AddDays(-$SignInLookbackDays).ToString('yyyy-MM-ddTHH:mm:ssZ')
            Invoke-GraphCollection `
                -Uri "https://graph.microsoft.com/beta/auditLogs/signIns?`$filter=createdDateTime ge $riskStart" |
                Where-Object {
                    $_.riskState -eq 'atRisk' -or
                    $_.riskLevelAggregated -in @('medium', 'high')
                }
        }
    )

    $riskyUsers = Invoke-GraphCollection `
        -Uri "https://graph.microsoft.com/beta/identityProtection/riskyUsers?`$filter=riskState eq 'atRisk'"

    $riskDetections = Invoke-GraphCollection `
        -Uri "https://graph.microsoft.com/beta/identityProtection/riskDetections?`$filter=riskState eq 'atRisk'"

    Export-JsonEvidence $atRiskSignIns `
        (Join-Path $sectionPath 'ActiveRiskySignIns-Full.json')

    Export-JsonEvidence $riskyUsers `
        (Join-Path $sectionPath 'ActiveRiskyUsers-Full.json')

    Export-JsonEvidence $riskDetections `
        (Join-Path $sectionPath 'ActiveRiskDetections-Full.json')

    $riskyUserSummary = foreach ($user in $riskyUsers) {
        [pscustomobject]@{
            Id                    = $user.id
            UserDisplayName       = $user.userDisplayName
            UserPrincipalName     = $user.userPrincipalName
            RiskLevel             = $user.riskLevel
            RiskState             = $user.riskState
            RiskDetail            = $user.riskDetail
            RiskLastUpdatedDateTime = $user.riskLastUpdatedDateTime
            IsDeleted             = $user.isDeleted
            IsProcessing          = $user.isProcessing
        }
    }

    Export-CsvEvidence $riskyUserSummary `
        (Join-Path $sectionPath 'ActiveRiskyUsers-Summary.csv')

    Add-ManifestEntry `
        -Section $section `
        -Status 'Success' `
        -File $sectionPath `
        -RecordCount ($atRiskSignIns.Count + $riskyUsers.Count) `
        -Notes "$($atRiskSignIns.Count) risky sign-ins; $($riskyUsers.Count) risky users."
}
catch {
    Add-CaptureError -Section $section -ErrorRecord $_
    Add-ManifestEntry -Section $section -Status 'Failed' -File $sectionPath -Notes $_.Exception.Message
}
}
else {
    Add-SkippedManifestEntry `
        -Section $section `
        -Path $sectionPath
}

# ---------------------------------------------------------------------------
# 5. User consent policy and existing permission grants
# ---------------------------------------------------------------------------

$section = '5 - User consent policy and existing permission grants'
$sectionPath = Join-Path $script:CaptureRoot '05-ConsentAndGrants'

if (Test-SectionEnabled 'ConsentAndGrants') {

    try {
    Write-Status $section

    $authorisationPolicy = Invoke-MgGraphRequest `
        -Method GET `
        -Uri 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy' `
        -OutputType PSObject

    $permissionGrantPolicies = Invoke-GraphCollection `
        -Uri 'https://graph.microsoft.com/v1.0/policies/permissionGrantPolicies'

    $oauth2PermissionGrants = Invoke-GraphCollection `
        -Uri 'https://graph.microsoft.com/v1.0/oauth2PermissionGrants'

    $servicePrincipals = Invoke-GraphCollection `
        -Uri 'https://graph.microsoft.com/v1.0/servicePrincipals?$select=id,appId,displayName,accountEnabled,servicePrincipalType'

    $spLookup = @{}
    foreach ($sp in $servicePrincipals) {
        $spLookup[$sp.id] = $sp
    }

    Export-JsonEvidence $authorisationPolicy `
        (Join-Path $sectionPath 'AuthorizationPolicy-Full.json')

    Export-JsonEvidence $permissionGrantPolicies `
        (Join-Path $sectionPath 'PermissionGrantPolicies-Full.json')

    Export-JsonEvidence $oauth2PermissionGrants `
        (Join-Path $sectionPath 'OAuth2PermissionGrants-Full.json')

    $oauthGrantSummary = foreach ($grant in $oauth2PermissionGrants) {
        $client = $spLookup[$grant.clientId]
        $resource = $spLookup[$grant.resourceId]

        [pscustomobject]@{
            GrantId             = $grant.id
            ConsentType         = $grant.consentType
            PrincipalId         = $grant.principalId
            ClientServicePrincipalId = $grant.clientId
            ClientDisplayName   = $client.displayName
            ClientAppId         = $client.appId
            ResourceServicePrincipalId = $grant.resourceId
            ResourceDisplayName = $resource.displayName
            ResourceAppId       = $resource.appId
            Scope               = $grant.scope
        }
    }

    Export-CsvEvidence $oauthGrantSummary `
        (Join-Path $sectionPath 'OAuth2PermissionGrants-Summary.csv')

    # Application permissions are represented by app-role assignments made
    # to service principals. Capture these separately from delegated grants.
    $applicationRoleAssignments = [System.Collections.Generic.List[object]]::new()

    foreach ($sp in $servicePrincipals) {
        try {
            $assignments = Invoke-GraphCollection `
                -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($sp.id)/appRoleAssignments"

            foreach ($assignment in $assignments) {
                $resource = $spLookup[$assignment.resourceId]

                $applicationRoleAssignments.Add([pscustomobject]@{
                    AssignmentId       = $assignment.id
                    CreatedDateTime     = $assignment.createdDateTime
                    PrincipalId         = $assignment.principalId
                    PrincipalDisplayName = $assignment.principalDisplayName
                    PrincipalType       = $assignment.principalType
                    PrincipalAppId      = $sp.appId
                    ResourceId          = $assignment.resourceId
                    ResourceDisplayName = $resource.displayName
                    ResourceAppId       = $resource.appId
                    AppRoleId           = $assignment.appRoleId
                })
            }
        }
        catch {
            $script:ErrorRecords.Add([pscustomobject]@{
                TimestampUtc     = (Get-Date).ToUniversalTime().ToString('o')
                Section          = "$section - Service principal $($sp.id)"
                Message          = $_.Exception.Message
                FullyQualifiedId = $_.FullyQualifiedErrorId
                ScriptStackTrace = $_.ScriptStackTrace
            })
        }
    }

    Export-JsonEvidence @($applicationRoleAssignments) `
        (Join-Path $sectionPath 'ApplicationRoleAssignments-Full.json')

    Export-CsvEvidence @($applicationRoleAssignments) `
        (Join-Path $sectionPath 'ApplicationRoleAssignments-Summary.csv')

    Add-ManifestEntry `
        -Section $section `
        -Status 'Success' `
        -File $sectionPath `
        -RecordCount ($oauth2PermissionGrants.Count + $applicationRoleAssignments.Count) `
        -Notes "$($oauth2PermissionGrants.Count) delegated grants; $($applicationRoleAssignments.Count) application role assignments."
}
catch {
    Add-CaptureError -Section $section -ErrorRecord $_
    Add-ManifestEntry -Section $section -Status 'Failed' -File $sectionPath -Notes $_.Exception.Message
}
}
else {
    Add-SkippedManifestEntry `
        -Section $section `
        -Path $sectionPath
}

# ---------------------------------------------------------------------------
# 6. Teams meeting policies and user assignments
# ---------------------------------------------------------------------------

$section = '6 - Teams meeting policies and user assignments'
$sectionPath = Join-Path $script:CaptureRoot '06-TeamsMeetingPolicies'

if (Test-SectionEnabled 'TeamsPolicies') {

    try {
        Write-Status $section

        Ensure-Module -Name MicrosoftTeams

        Connect-MicrosoftTeams

        $script:TeamsConnected = $true

        $meetingPolicies = @(Get-CsTeamsMeetingPolicy)
        $meetingConfiguration = @(Get-CsTeamsMeetingConfiguration)

        Export-JsonEvidence $meetingPolicies `
            (Join-Path $sectionPath 'TeamsMeetingPolicies-Full.json')

        Export-JsonEvidence $meetingConfiguration `
            (Join-Path $sectionPath 'TeamsMeetingConfiguration-Full.json')

        $meetingPolicySummary = foreach ($policy in $meetingPolicies) {
            [pscustomobject]@{
                Identity                              = $policy.Identity
                Description                           = $policy.Description
                AutoAdmittedUsers                     = $policy.AutoAdmittedUsers
                AllowAnonymousUsersToJoinMeeting      = $policy.AllowAnonymousUsersToJoinMeeting
                AllowAnonymousUsersToStartMeeting     = $policy.AllowAnonymousUsersToStartMeeting
                DesignatedPresenterRoleMode           = $policy.DesignatedPresenterRoleMode
                ScreenSharingMode                     = $policy.ScreenSharingMode
                AllowMeetNow                          = $policy.AllowMeetNow
                AllowPrivateMeetNow                   = $policy.AllowPrivateMeetNow
                AllowCloudRecording                   = $policy.AllowCloudRecording
                AllowTranscription                    = $policy.AllowTranscription
                AllowRecordingStorageOutsideRegion   = $policy.AllowRecordingStorageOutsideRegion
                AllowIPAudio                          = $policy.AllowIPAudio
                AllowIPVideo                          = $policy.AllowIPVideo
                MediaBitRateKb                        = $policy.MediaBitRateKb
                AllowParticipantGiveRequestControl    = $policy.AllowParticipantGiveRequestControl
                AllowExternalParticipantGiveRequestControl = $policy.AllowExternalParticipantGiveRequestControl
                AllowPowerPointSharing                = $policy.AllowPowerPointSharing
                AllowWhiteboard                       = $policy.AllowWhiteboard
                AllowSharedNotes                      = $policy.AllowSharedNotes
                MeetingChatEnabledType                = $policy.MeetingChatEnabledType
                LiveCaptionsEnabledType               = $policy.LiveCaptionsEnabledType
                AllowMeetingReactions                 = $policy.AllowMeetingReactions
                Copilot                               = $policy.Copilot
            }
        }

        Export-CsvEvidence $meetingPolicySummary `
            (Join-Path $sectionPath 'TeamsMeetingPolicies-Summary.csv')

        Write-Status 'Reading Teams users and meeting-policy assignments.'

        $teamsUsers = @(Get-CsOnlineUser -ResultSize 100000)

        $teamsAssignments = foreach ($user in $teamsUsers) {
            [pscustomobject]@{
                ObjectId                   = $user.Identity
                DisplayName                = $user.DisplayName
                UserPrincipalName          = $user.UserPrincipalName
                AccountEnabled             = $user.AccountEnabled
                TeamsMeetingPolicy         = $user.TeamsMeetingPolicy
                EffectiveMeetingPolicy     = if ($user.TeamsMeetingPolicy) {
                    $user.TeamsMeetingPolicy
                }
                else {
                    'Global'
                }
                TeamsMessagingPolicy       = $user.TeamsMessagingPolicy
                TeamsCallingPolicy         = $user.TeamsCallingPolicy
                TeamsAppPermissionPolicy   = $user.TeamsAppPermissionPolicy
                TeamsAppSetupPolicy        = $user.TeamsAppSetupPolicy
            }
        }

        Export-CsvEvidence $teamsAssignments `
            (Join-Path $sectionPath 'TeamsUserPolicyAssignments.csv')

        Export-JsonEvidence $teamsAssignments `
            (Join-Path $sectionPath 'TeamsUserPolicyAssignments.json')

        Add-ManifestEntry `
            -Section $section `
            -Status 'Success' `
            -File $sectionPath `
            -RecordCount ($meetingPolicies.Count + $teamsAssignments.Count) `
            -Notes "$($meetingPolicies.Count) meeting policies; $($teamsAssignments.Count) Teams users."
    }
    catch {
        Add-CaptureError -Section $section -ErrorRecord $_
        Add-ManifestEntry -Section $section -Status 'Failed' -File $sectionPath -Notes $_.Exception.Message
    }
}
else {
    Add-SkippedManifestEntry `
        -Section $section `
        -Path $sectionPath
}

# ---------------------------------------------------------------------------
# 7. Active and eligible administrative role assignments
# ---------------------------------------------------------------------------

$section = '7 - Active and eligible administrative role assignments'
$sectionPath = Join-Path $script:CaptureRoot '07-AdministrativeRoles'

if (Test-SectionEnabled 'AdministrativeRoles') {

    try {
    Write-Status $section

    $roleDefinitions = Invoke-GraphCollection `
        -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions'

    $activeAssignments = Invoke-GraphCollection `
        -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments'

    $activeSchedules = Invoke-GraphCollection `
        -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleInstances'

    $eligibleSchedules = Invoke-GraphCollection `
        -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances'

    $principalIds = @()

    $principalIds += @(
        $activeAssignments |
            Where-Object { $_.PSObject.Properties['principalId'] } |
            Select-Object -ExpandProperty principalId
    )

    $principalIds += @(
        $activeSchedules |
            Where-Object { $_.PSObject.Properties['principalId'] } |
            Select-Object -ExpandProperty principalId
    )

    $principalIds += @(
        $eligibleSchedules |
            Where-Object { $_.PSObject.Properties['principalId'] } |
            Select-Object -ExpandProperty principalId
    )

    $principalIds =
        $principalIds |
        Where-Object { $_ } |
        Sort-Object -Unique

    $principalLookup = @{}
    foreach ($principalId in $principalIds) {
        $principalLookup[$principalId] = Resolve-DirectoryObject -ObjectId $principalId
    }

    Export-JsonEvidence $roleDefinitions `
        (Join-Path $sectionPath 'RoleDefinitions-Full.json')

    Export-JsonEvidence $activeAssignments `
        (Join-Path $sectionPath 'ActiveRoleAssignments-Full.json')

    Export-JsonEvidence $activeSchedules `
        (Join-Path $sectionPath 'ActiveRoleScheduleInstances-Full.json')

    Export-JsonEvidence $eligibleSchedules `
        (Join-Path $sectionPath 'EligibleRoleScheduleInstances-Full.json')

    $roleLookup = @{}

    <#
    foreach ($role in $roleDefinitions) {
        $roleLookup[$role.id] = $role.displayName
    }
    #>

    foreach ($roleDefinition in $roleDefinitions) {
        $roleLookup[$roleDefinition.id] = $roleDefinition
    }

    $activeSummary = @(
        foreach ($assignment in $activeAssignments) {

            $principal = $principalLookup[$assignment.principalId]
            $roleDefinition = $roleLookup[$assignment.roleDefinitionId]

            [pscustomobject]@{
                AssignmentId     = $assignment.id
                PrincipalId      = $assignment.principalId
                RoleDefinitionId = $assignment.roleDefinitionId
                RoleDisplayName = $roleLookup[$assignment.roleDefinitionId]
                #RoleDisplayName = $roleLookup[$assignment.roleDefinitionId].displayName
                DirectoryScopeId =
                    Get-SafeProperty `
                        $assignment `
                        'directoryScopeId'
                AssignmentType     = 'Active'
                IsBuiltInRole      = Get-SafeProperty $roleDefinition 'isBuiltIn'
                AppScopeId       = Get-SafeProperty $assignment 'appScopeId'
                Condition        = Get-SafeProperty $assignment 'condition'
                ConditionVersion = Get-SafeProperty $assignment 'conditionVersion'
                PrincipalType      = $principal.ObjectType
                PrincipalName      = $principal.DisplayName
                UserPrincipalName  = $principal.UserPrincipalName
                PrincipalAppId     = $principal.AppId
            }
        }
    )

    $eligibleSummary = @()

    if (@($eligibleSchedules).Count -gt 0) {

        $eligibleSummary = @(
            foreach ($assignment in $eligibleSchedules) {
                
                $principal = $principalLookup[$assignment.principalId]
                $roleDefinition = $roleLookup[$assignment.roleDefinitionId]

                [pscustomobject]@{
                    AssignmentId     = $assignment.id
                    PrincipalId      = $assignment.principalId
                    RoleDefinitionId = $assignment.roleDefinitionId
                    RoleDisplayName =
                        $roleLookup[$assignment.roleDefinitionId]
                    DirectoryScopeId =
                        Get-SafeProperty `
                            $assignment `
                            'directoryScopeId'
                    AssignmentType     = 'Eligible'
                    IsBuiltInRole      = Get-SafeProperty $roleDefinition 'isBuiltIn'
                    AppScopeId       = Get-SafeProperty $assignment 'appScopeId'
                    Condition        = Get-SafeProperty $assignment 'condition'
                    ConditionVersion = Get-SafeProperty $assignment 'conditionVersion'
                    PrincipalType      = Get-SafeProperty $principal 'ObjectType'
                    PrincipalName      = Get-SafeProperty $principal 'DisplayName'
                    UserPrincipalName  = Get-SafeProperty $principal 'UserPrincipalName'
                    PrincipalAppId     = Get-SafeProperty $principal 'AppId'
                }
            }
        )

        Export-CsvEvidence `
            -InputObject @($eligibleSummary) `
            -Path (
                Join-Path `
                    $sectionPath `
                    'EligibleRoleAssignments-Summary.csv'
            )
    }
    else {

        Write-Status "No eligible role assignments found."
    }

    <#

    $eligibleSummary = @(
        foreach ($assignment in $eligibleSchedules) {

            $role = $roleLookup[$assignment.roleDefinitionId]
            $principal = $principalLookup[$assignment.principalId]

            [pscustomobject]@{
                AssignmentId       = $assignment.id
                AssignmentType     = 'Eligible'
                RoleDefinitionId   = $assignment.roleDefinitionId
                RoleDisplayName    = Get-SafeProperty $role 'displayName'
                IsBuiltInRole      = Get-SafeProperty $role 'isBuiltIn'
                PrincipalId        = $assignment.principalId
                PrincipalType      = Get-SafeProperty $principal 'ObjectType'
                PrincipalName      = Get-SafeProperty $principal 'DisplayName'
                UserPrincipalName  = Get-SafeProperty $principal 'UserPrincipalName'
                PrincipalAppId     = Get-SafeProperty $principal 'AppId'
                DirectoryScopeId   = Get-SafeProperty $assignment 'directoryScopeId'
                AppScopeId         = Get-SafeProperty $assignment 'appScopeId'
                MemberType         = $assignment.memberType
                AssignmentTypeRaw  = $assignment.assignmentType
                StartDateTime      = $assignment.startDateTime
                EndDateTime        = $assignment.endDateTime
                RoleEligibilityScheduleId = $assignment.roleEligibilityScheduleId
            }
        }        
    )

    #>

    Write-Host "Active Summary Count   : $(@($activeSummary).Count)"
    Write-Host "Eligible Summary Count : $(@($eligibleSummary).Count)"

    Write-Host "Active Summary Null    : $($null -eq $activeSummary)"
    Write-Host "Eligible Summary Null  : $($null -eq $eligibleSummary)"

    Export-CsvEvidence `
        -InputObject @($activeSummary) `
        -Path (Join-Path $sectionPath 'ActiveRoleAssignments-Summary.csv')

    if (@($eligibleSummary).Count -gt 0) {

        Export-CsvEvidence `
            -InputObject @($eligibleSummary) `
            -Path (
                Join-Path `
                    $sectionPath `
                    'EligibleRoleAssignments-Summary.csv'
            )
    }

    Write-Host "activeAssignments count: $(@($activeAssignments).Count)"
    Write-Host "eligibleSchedules count: $(@($eligibleSchedules).Count)"

    Add-ManifestEntry `
        -Section $section `
        -Status 'Success' `
        -File $sectionPath `
        -RecordCount (
            @($activeAssignments).Count +
            @($eligibleSchedules).Count
        ) `
        -Notes "$(@($activeAssignments).Count) active assignments; $(@($eligibleSchedules).Count) eligible schedule instances."
}
catch {
    Add-CaptureError -Section $section -ErrorRecord $_
    Add-ManifestEntry -Section $section -Status 'Failed' -File $sectionPath -Notes $_.Exception.Message
}
}
else {
    Add-SkippedManifestEntry `
        -Section $section `
        -Path $sectionPath
}

# ---------------------------------------------------------------------------
# 8. Password reset configuration and password writeback
# ---------------------------------------------------------------------------

$section = '8 - Password reset configuration and password writeback'
$sectionPath = Join-Path $script:CaptureRoot '08-PasswordReset'

if (Test-SectionEnabled 'PasswordReset') {

    try {
    Write-Status $section

    $ssprAuthorisationPolicy = Invoke-MgGraphRequest `
        -Method GET `
        -Uri 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy' `
        -OutputType PSObject

    $authenticationMethodsPolicyForSspr = Invoke-MgGraphRequest `
        -Method GET `
        -Uri 'https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy' `
        -OutputType PSObject

    $onPremisesSyncConfiguration = $null

    try {
        $onPremisesSyncConfiguration = Invoke-GraphCollection `
            -Uri 'https://graph.microsoft.com/beta/directory/onPremisesSynchronization'
    }
    catch {
        $script:ErrorRecords.Add([pscustomobject]@{
            TimestampUtc     = (Get-Date).ToUniversalTime().ToString('o')
            Section          = "$section - On-premises synchronisation configuration"
            Message          = $_.Exception.Message
            FullyQualifiedId = $_.FullyQualifiedErrorId
            ScriptStackTrace = $_.ScriptStackTrace
        })
    }

    if ($null -eq $script:RegistrationDetails) {

    throw (
        "PasswordReset depends on AuthenticationRegistration. " +
        "Run:" +
        "-IncludeSection AuthenticationRegistration,PasswordReset"
        )
    }

    $passwordResetRegistration = @(
        $script:RegistrationDetails | Select-Object `
            id,
            userDisplayName,
            userPrincipalName,
            userType,
            isAdmin,
            isSsprEnabled,
            isSsprRegistered,
            isSsprCapable,
            methodsRegistered,
            lastUpdatedDateTime
    )

    Export-JsonEvidence $ssprAuthorisationPolicy `
        (Join-Path $sectionPath 'AuthorizationPolicy-SSPR-Full.json')

    Export-JsonEvidence $authenticationMethodsPolicyForSspr `
        (Join-Path $sectionPath 'AuthenticationMethodsPolicy-SSPR-Full.json')

    Export-JsonEvidence $onPremisesSyncConfiguration `
        (Join-Path $sectionPath 'OnPremisesSynchronization-Full.json')

    Export-JsonEvidence $passwordResetRegistration `
        (Join-Path $sectionPath 'PasswordResetRegistration-Full.json')

    $passwordResetSummary = foreach ($user in $passwordResetRegistration) {
        [pscustomobject]@{
            Id                  = $user.id
            UserDisplayName     = $user.userDisplayName
            UserPrincipalName   = $user.userPrincipalName
            UserType            = $user.userType
            IsAdmin             = $user.isAdmin
            IsSsprEnabled       = $user.isSsprEnabled
            IsSsprRegistered    = $user.isSsprRegistered
            IsSsprCapable       = $user.isSsprCapable
            MethodsRegistered   = (@($user.methodsRegistered) -join ';')
            LastUpdatedDateTime = $user.lastUpdatedDateTime
        }
    }

    Export-CsvEvidence $passwordResetSummary `
        (Join-Path $sectionPath 'PasswordResetRegistration-Summary.csv')

    $manualCapture = @"
PASSWORD RESET MANUAL CAPTURE REQUIREMENT
=========================================

Capture date UTC:
$((Get-Date).ToUniversalTime().ToString('o'))

Tenant:
$($tenantDetails.displayName)

Microsoft Graph does not expose the non-administrator Self-Service Password
Reset scope, None / Selected / All, as a supported PowerShell setting.

Manually capture the following from the Microsoft Entra admin centre:

1. Entra ID > Password reset > Properties
   - Self service password reset enabled: None, Selected, or All
   - If Selected, record the selected group name and object ID

2. Entra ID > Password reset > Registration
   - Require users to register when signing in
   - Number of days before users are asked to reconfirm authentication information

3. Entra ID > Password reset > Notifications
   - Notify users on password resets
   - Notify administrators when other administrators reset passwords

4. Entra ID > Password reset > On-premises integration
   - Write back passwords to the on-premises directory
   - Allow users to unlock accounts without resetting their password

5. Entra ID > Authentication methods > Policies
   - Confirm method enablement, target groups and exclusions

Do not treat authorizationPolicy.allowedToUseSSPR as the all-user SSPR scope.
That property relates to administrator self-service reset availability.
"@

    $manualCapture |
        Set-Content `
            -Path (Join-Path $sectionPath 'MANUAL-CAPTURE-REQUIRED.txt') `
            -Encoding utf8BOM

    Add-ManifestEntry `
        -Section $section `
        -Status 'Partial - manual scope capture required' `
        -File $sectionPath `
        -RecordCount $passwordResetRegistration.Count `
        -Notes 'Registration, methods and synchronisation features captured. None/Selected/All SSPR scope requires portal evidence.'
}
catch {
    Add-CaptureError -Section $section -ErrorRecord $_
    Add-ManifestEntry -Section $section -Status 'Failed' -File $sectionPath -Notes $_.Exception.Message
}
}
else {
    Add-SkippedManifestEntry `
        -Section $section `
        -Path $sectionPath
}

# ---------------------------------------------------------------------------
# Finalise evidence package
# ---------------------------------------------------------------------------

$script:CaptureCompletedUtc = (Get-Date).ToUniversalTime()

$completionMetadata = [ordered]@{
    CaptureStartedUtc   = $script:CaptureStartedUtc.ToString('o')
    CaptureCompletedUtc = $script:CaptureCompletedUtc.ToString('o')
    TenantId            = $context.TenantId
    TenantDisplayName   = $tenantDetails.displayName
    ErrorCount          = $script:ErrorRecords.Count
    SectionCount        = $script:ManifestRecords.Count
}

Export-JsonEvidence `
    -InputObject $completionMetadata `
    -Path (Join-Path $script:CaptureRoot 'Capture-Completion.json')

Export-CsvEvidence `
    -InputObject @($script:ManifestRecords) `
    -Path (Join-Path $script:CaptureRoot 'Capture-Manifest.csv')

Export-JsonEvidence `
    -InputObject @($script:ManifestRecords) `
    -Path (Join-Path $script:CaptureRoot 'Capture-Manifest.json')

Export-CsvEvidence `
    -InputObject @($script:ErrorRecords) `
    -Path (Join-Path $script:CaptureRoot 'Capture-Errors.csv')

Export-JsonEvidence `
    -InputObject @($script:ErrorRecords) `
    -Path (Join-Path $script:CaptureRoot 'Capture-Errors.json')

# Create file hashes so the evidence set can be checked for later alteration.
$hashes = Get-ChildItem -Path $script:CaptureRoot -File -Recurse |
    Where-Object Name -ne 'SHA256SUMS.csv' |
    ForEach-Object {
        $hash = Get-FileHash -Path $_.FullName -Algorithm SHA256

        [pscustomobject]@{
            RelativePath = [System.IO.Path]::GetRelativePath(
                $script:CaptureRoot,
                $_.FullName
            )
            SHA256 = $hash.Hash
            Length = $_.Length
        }
    }

Export-CsvEvidence `
    -InputObject @($hashes) `
    -Path (Join-Path $script:CaptureRoot 'SHA256SUMS.csv')

Write-Host ''
Write-Status 'Capture completed.' Success
Write-Status "Tenant: $($tenantDetails.displayName) [$($context.TenantId)]"
Write-Status "Evidence: $script:CaptureRoot"
Write-Status "Recorded errors: $($script:ErrorRecords.Count)" `
    -Level $(if ($script:ErrorRecords.Count) { 'Warning' } else { 'Success' })

Disconnect-MgGraph | Out-Null

if ($script:TeamsConnected) {
    try {
        Disconnect-MicrosoftTeams -ErrorAction SilentlyContinue
    }
    catch {
        # Connection was already closed or unavailable.
    }
}