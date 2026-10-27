# 11 - Apply least-privileged administrative roles

Write-Host "Apply least-privileged administrative roles - Inventory"

# Inventory active assignments
# Build a role definition lookup, then list assignments:

$roleDefinitions = @{}

Get-MgRoleManagementDirectoryRoleDefinition -All |
    ForEach-Object {
        $roleDefinitions[$_.Id] = $_.DisplayName
    }

$activeAssignments = @(
    Get-MgRoleManagementDirectoryRoleAssignment -All |
        Select-Object `
            Id,
            PrincipalId,
            DirectoryScopeId,
            @{
                Name = 'Role'
                Expression = {
                    $roleDefinitions[$_.RoleDefinitionId]
                }
            }
)

$activeAssignments |
    Sort-Object Role, PrincipalId

# The inventory contains identifiers. Resolve each principal to a user, group, or service principal. 
# Investigate deleted or unknown principals. Review group membership when a role is group-assigned.