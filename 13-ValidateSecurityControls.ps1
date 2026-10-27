# 13 - Validate Security Controls

# Validate Conditional Access
Write-Host "Validate Conditional Access"

# To validate conditional access, list the module policies:

$modulePolicies = @(
    Get-MgIdentityConditionalAccessPolicy -All |
        Where-Object DisplayName -Like 'CA00*'
)

$modulePolicies |
    Select-Object Id, DisplayName, State |
    Sort-Object DisplayName

# Confirm that expected policies exist once and are in the intended state. 
# Duplicate policies can create unexpected cumulative requirements.

# Enable one verified policy by exact identifier:

<#
Update-MgIdentityConditionalAccessPolicy `
    -ConditionalAccessPolicyId '<policy-id>' `
    -State enabled
#>

# Don't enable every report-only policy in one bulk command. 
# Performing changes incrementally, preserve attribution, and the ability to rollback.

# If a policy causes harm, you can disable it using PowerShell similar to the following:

<#
Update-MgIdentityConditionalAccessPolicy `
    -ConditionalAccessPolicyId '<policy-id>' `
    -State disabled
#>

# Investigate a malfunctioning policy before editing or deleting it.

# Validate Microsoft Teams

Write-Host "Validate Microsoft Teams"

# To validate that Microsoft Teams policies are functioning as expected, first read the configured meeting policy:

Get-CsTeamsMeetingPolicy -Identity $teamsPolicy |
    Select-Object `
        Identity,
        AutoAdmittedUsers,
        DesignatedPresenterRoleMode,
        AllowAnonymousUsersToJoinMeeting
