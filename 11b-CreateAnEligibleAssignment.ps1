# 11b - Apply least-privileged administrative roles

Write-Host "Apply least-privileged administrative roles - Create Assignment"

# Create an eligible assignment with Microsoft Graph PowerShell
# To configure eligible access using PowerShell, resolve one principal and one role:

$principal = Get-MgUser -UserId '<user-principal-name>'

$roles = @(
    Get-MgRoleManagementDirectoryRoleDefinition `
        -Filter "displayName eq 'Helpdesk Administrator'"
)

if ($roles.Count -ne 1) {
    throw 'Expected one Helpdesk Administrator role definition.'
}

$role = $roles[0]

# You can create a 180-day eligible assignment using the following script:

$params = @{
    action = 'adminAssign'
    principalId = $principal.Id
    roleDefinitionId = $role.Id
    directoryScopeId = '/'
    justification = 'Replace standing broad privilege with eligible task-specific access'
    scheduleInfo = @{
        startDateTime = (Get-Date).ToUniversalTime()
        expiration = @{
            type = 'afterDuration'
            duration = 'P180D'
        }
    }
}

$eligibilityRequest = `
    New-MgRoleManagementDirectoryRoleEligibilityScheduleRequest `
        -BodyParameter $params

$eligibilityRequest |
    Select-Object Id, Status, Action, PrincipalId, RoleDefinitionId

# The request creates eligibility. Role settings determine activation requirements. 
# Confirm approval, duration, authentication, and notification settings separately.

# Only once you've confirmed that the time limited eligible assignment functions as expected, 
# you can remove the obsolete direct assignment using the following PowerShell command:

<#
Remove-MgRoleManagementDirectoryRoleAssignment `
    -UnifiedRoleAssignmentId '<obsolete-assignment-id>'
#>