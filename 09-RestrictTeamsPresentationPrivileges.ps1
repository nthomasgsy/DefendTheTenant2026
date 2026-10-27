# 9 - Restrict Microsoft Teams presentation privileges

Write-Host "Restrict Microsoft Teams presentation privileges"

# Record the current value:

$originalPresenterMode = (
    Get-CsTeamsMeetingPolicy -Identity $teamsPolicy
).DesignatedPresenterRoleMode

Write-Host "Original Value:"
$originalPresenterMode

# Apply the restrictive organizer-controlled default:

Set-CsTeamsMeetingPolicy `
    -Identity $teamsPolicy `
    -DesignatedPresenterRoleMode OrganizerOnlyUserOverride

# Verify with the following command:

Get-CsTeamsMeetingPolicy -Identity $teamsPolicy |
    Select-Object Identity, DesignatedPresenterRoleMode

# OrganizerOnlyUserOverride sets the restrictive default while permitting organizer override. 
# Use a supported template or sensitivity label when the value must be enforced.