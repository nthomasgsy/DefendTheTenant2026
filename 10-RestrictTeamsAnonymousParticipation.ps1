# 10 - Restrict Microsoft Teams anonymous participation

Write-Host "Restrict Microsoft Teams anonymous participation"

# starting with recording the original meeting policy value:

$originalAnonymousJoin = (
    Get-CsTeamsMeetingPolicy -Identity $teamsPolicy
).AllowAnonymousUsersToJoinMeeting

Write-Host "Original Value:"
$originalAnonymousJoin

# Then block anonymous participants for organizers assigned the policy:

Set-CsTeamsMeetingPolicy `
    -Identity $teamsPolicy `
    -AllowAnonymousUsersToJoinMeeting $false

# Then verify using the following commands:

Get-CsTeamsMeetingPolicy -Identity $teamsPolicy |
    Select-Object Identity, AllowAnonymousUsersToJoinMeeting

# In the event that current tenant requirements justify the control being applied organization-wide, run the following command:

Set-CsTeamsMeetingConfiguration `
    -Identity Global `
    -DisableAnonymousJoin $true