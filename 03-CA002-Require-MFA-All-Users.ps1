# 3 - Enforce universal multifactor authentication

Write-Host "Enforce universal multifactor authentication"

# Read authentication method registration before enforcement:

Get-MgReportAuthenticationMethodUserRegistrationDetail -All |
    Select-Object `
        UserPrincipalName,
        IsMfaRegistered,
        IsMfaCapable,
        IsPasswordlessCapable |
    Sort-Object UserPrincipalName

# Find users who can't satisfy the policy:

Get-MgReportAuthenticationMethodUserRegistrationDetail -All |
    Where-Object { -not $_.IsMfaCapable } |
    Select-Object UserPrincipalName, IsMfaRegistered, IsMfaCapable

# IsMfaRegistered indicates registration. 
# IsMfaCapable indicates that registered methods can satisfy multifactor authentication. 

# Resolve the directory synchronization role template:

$directorySyncRoleId = (
    Get-MgDirectoryRoleTemplate -All |
        Where-Object DisplayName -EQ 'Directory Synchronization Accounts'
).Id

if (-not $directorySyncRoleId) {
    throw 'Directory Synchronization Accounts role template was not found.'
}

# Create the report-only policy:

$params = @{
    displayName = 'CA002-Require-MFA-All-Users'
    state = 'enabledForReportingButNotEnforced'
    conditions = @{
        clientAppTypes = @('all')
        users = @{
            includeUsers = @('All')
            excludeUsers = $breakGlassObjectIds

            # If no synchronization account requires exclusion, omit excludeRoles. Every exclusion must map to a verified dependency.
            excludeRoles = @($directorySyncRoleId)
        }
        applications = @{
            includeApplications = @('All')
        }
    }
    grantControls = @{
        operator = 'OR'
        authenticationStrength = @{
            id = '00000000-0000-0000-0000-000000000002'
        }
    }
}

# The built-in multifactor authentication strength identifier is 00000000-0000-0000-0000-000000000002.

$allUserPolicy = New-MgIdentityConditionalAccessPolicy `
    -BodyParameter $params

$allUserPolicy |
    Select-Object Id, DisplayName, State