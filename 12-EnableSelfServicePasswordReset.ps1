# 12 - Enable self-service password reset

Write-Host "Enable self-service password reset - Assessment only"

# Assess rollout coverage
# To assess the success of rollout of this policy, connect with reporting permission using the following command:

Connect-MgGraph -Scopes 'AuditLog.Read.All'

# Then query user registration state with the following command:

$registrationDetails = @(
    Get-MgReportAuthenticationMethodUserRegistrationDetail -All
)

$registrationDetails |
    Select-Object `
        UserPrincipalName,
        IsSsprEnabled,
        IsSsprRegistered,
        IsSsprCapable |
    Sort-Object UserPrincipalName

# To find gaps, run the following PowerShell script:

$registrationDetails |
    Where-Object {
        -not $_.IsSsprEnabled -or
        -not $_.IsSsprRegistered -or
        -not $_.IsSsprCapable
    } |
    Select-Object `
        UserPrincipalName,
        IsSsprEnabled,
        IsSsprRegistered,
        IsSsprCapable

# Interpret the properties separately:
# •	IsSsprEnabled: The user is in scope.
# •	IsSsprRegistered: The user registered recovery data.
# •	IsSsprCapable: The registered methods satisfy the current reset policy.

# A user can be enabled without being capable. Closing this gap requires registration or method remediation.