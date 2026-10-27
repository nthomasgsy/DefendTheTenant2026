#Install-Module Microsoft.Graph -Scope CurrentUser
#Install-Module MicrosoftTeams -Scope CurrentUser

Write-Host("Importing Modules")

#Import-Module Microsoft.Graph
Import-Module MicrosoftTeams

Write-Host("Modules Imported")

# The following code interactively signs you into Microsoft Graph with delegated permissions 
# to manage Conditional Access and authorization policies, administer Entra roles, and read directory, application, and audit-log data. 
# These highly privileged scopes require administrator consent and remain limited by the signed-in user’s own roles. 

#Update-MgGraphEnvironment -EnableLoginByWAM $false
#Set-MgGraphOption -DisableLoginByWAM $true

# Device Code may be required when running in Powershell ISE.

Write-Host("Connecting Graph")

Connect-MgGraph -Scopes @(
    'Policy.ReadWrite.ConditionalAccess',
    'Policy.ReadWrite.Authorization',
    'RoleManagement.ReadWrite.Directory',
    'Directory.Read.All',
    'Application.Read.All',
    'AuditLog.Read.All'
) #-UseDeviceCode

Write-Host("Connected Graph")

# Connect-MicrosoftTeams establishes a separate authenticated session for Microsoft Teams PowerShell commands.

Write-Host("Connecting Teams")

Connect-MicrosoftTeams #-UseDeviceAuthentication

Write-Host("Connected Teams")

# The following code allows you to specify your emergency-access accounts. 
# $breakGlassObjectIds must be replaced with at least two real emergency-access account object IDs:

# Uncomment and provide values:
<#
$breakGlassObjectIds = @(
    '<emergency-account-object-id-1>',
    '<emergency-account-object-id-2>'
)

$teamsPolicy = 'Global'

# The following ensures that you've specified your emergency-access accounts before creating policy:

if (
    $breakGlassObjectIds.Count -lt 2 -or
    $breakGlassObjectIds -match '^<'
) {
    throw 'Provide at least two verified emergency access object identifiers.'
}
#>

# You can confirm the signed-in Microsoft Graph context with the following commands:

Get-MgContext | Select-Object Account, TenantId, AuthType, Scopes