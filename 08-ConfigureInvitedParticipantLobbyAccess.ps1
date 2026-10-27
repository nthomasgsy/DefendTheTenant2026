# 8 - Configure invited-participant lobby access

Write-Host "8 - Configure invited-participant lobby access"

# first record the original value:

$originalLobbyValue = (
    Get-CsTeamsMeetingPolicy -Identity $teamsPolicy
).AutoAdmittedUsers

Write-Host "Original Value:"
$originalLobbyValue

# Then set the invited-user default:

Set-CsTeamsMeetingPolicy `
    -Identity $teamsPolicy `
    -AutoAdmittedUsers InvitedUsers

# Verify with the following command:

Get-CsTeamsMeetingPolicy -Identity $teamsPolicy |
    Select-Object Identity, AutoAdmittedUsers

# Changes can take up to 24 hours to take effect.