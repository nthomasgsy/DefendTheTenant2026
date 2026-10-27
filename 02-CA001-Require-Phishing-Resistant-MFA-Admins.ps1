# 2 - Enforce phishing-resistant administrative authentication

Write-Host "Enforce phishing-resistant administrative authentication"

# first resolve role template identifiers. this is because Conditional Access role targeting uses role template identifiers, 
# not active role instance identifiers.

$adminRoleNames = @(
    'Global Administrator',
    'Application Administrator',
    'Authentication Administrator',
    'Billing Administrator',
    'Cloud Application Administrator',
    'Conditional Access Administrator',
    'Exchange Administrator',
    'Helpdesk Administrator',
    'Password Administrator',
    'Privileged Authentication Administrator',
    'Privileged Role Administrator',
    'Security Administrator',
    'SharePoint Administrator',
    'User Administrator'
)

$adminRoleTemplates = @(
    Get-MgDirectoryRoleTemplate -All |
        Where-Object DisplayName -In $adminRoleNames
)

$missingRoleNames = @(
    $adminRoleNames |
        Where-Object { $_ -notin $adminRoleTemplates.DisplayName }
)

if ($missingRoleNames.Count -gt 0) {
    throw "Role templates not found: $($missingRoleNames -join ', ')"
}

$adminRoleTemplateIds = @(
    $adminRoleTemplates |
        Select-Object -ExpandProperty Id
)

# To create a report-only policy, run the following script:

$params = @{
    displayName = 'CA001-Require-Phishing-Resistant-MFA-Admins'
    state = 'enabledForReportingButNotEnforced'
    conditions = @{
        clientAppTypes = @('all')
        users = @{
            includeRoles = $adminRoleTemplateIds
            excludeUsers = $breakGlassObjectIds
        }
        applications = @{
            includeApplications = @('All')
        }
    }
    grantControls = @{
        operator = 'OR'
        authenticationStrength = @{
            id = '00000000-0000-0000-0000-000000000004'
        }
    }
}

# The built-in phishing-resistant authentication strength identifier is 00000000-0000-0000-0000-000000000004. 
# You'll need to resolve custom authentication strength identifiers from the tenant instead of embedding an assumed value.

$adminPolicy = New-MgIdentityConditionalAccessPolicy `
    -BodyParameter $params

$adminPolicy |
    Select-Object Id, DisplayName, State

# Enable the policy during a monitored window:
<#
Update-MgIdentityConditionalAccessPolicy `
    -ConditionalAccessPolicyId $adminPolicy.Id `
    -State enabled
#>