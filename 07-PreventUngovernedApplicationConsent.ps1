# 7 - Prevent ungoverned application consent

Write-Host "7 - Prevent ungoverned application consent"

# The default user role contains permission grant policy assignments. 
# Remove every assignment beginning with ManagePermissionGrantsForSelf.. 
# Preserve ManagePermissionGrantsForOwnedResource.* assignments when application owners still need them. 
# To accomplish this, use the following PowerShell script:

Connect-MgGraph -Scopes 'Policy.ReadWrite.Authorization'

$authorizationPolicy = Get-MgPolicyAuthorizationPolicy

$currentGrantPolicies = @(
    $authorizationPolicy.DefaultUserRolePermissions.PermissionGrantPoliciesAssigned
)

$policiesToPreserve = @(
    $currentGrantPolicies |
        Where-Object {
            $_ -like 'managePermissionGrantsForOwnedResource.*'
        }
)

$params = @{
    defaultUserRolePermissions = @{
        permissionGrantPoliciesAssigned = $policiesToPreserve
    }
}

Update-MgPolicyAuthorizationPolicy -BodyParameter $params

# To verify the result, use the following PowerShell script:

$assignedGrantPolicies = @(
    (Get-MgPolicyAuthorizationPolicy).DefaultUserRolePermissions.PermissionGrantPoliciesAssigned
)

$assignedGrantPolicies

if (
    $assignedGrantPolicies |
        Where-Object { $_ -like 'managePermissionGrantsForSelf.*' }
) {
    throw 'A self-consent permission grant policy remains assigned.'
}

# Note
# Remember that this change affects future consent decisions. It doesn't revoke grants already stored on service principals.

# Inventory existing delegated grants
# Read existing OAuth 2.0 permission grants:

Get-MgOauth2PermissionGrant -All |
    Select-Object `
        Id,
        ClientId,
        ConsentType,
        PrincipalId,
        ResourceId,
        Scope |
    Sort-Object ClientId, ResourceId

# Interpret:
# •	ClientId identifies the client service principal.
# •	ResourceId identifies the resource service principal.
# •	ConsentType distinguishes tenant-wide and principal-specific grants.
# •	PrincipalId identifies the user for principal-specific consent.
# •	Scope lists delegated permissions.

# Resolve identifiers to service principal and user names before review. 
# Treat broad mail, file, directory, offline access, and tenant-wide grants as high priority. 
# Don't revoke a grant until the application owner and business dependency are known.