# DefendTheTenant2026
Files for Defend The Tenant Challenge

## Approach Taken
I started by running a [PowerShell script](Export-M365SecurityInventory.ps1) to gather an Inventory of the Current State, as recommended by the [Microsoft Learn Module](https://learn.microsoft.com/en-gb/training/modules/harden-microsoft-365-secure-score/2-prepare-safe-administrative-environment).  The Powershell commands to use with this script are found [here](Export-M365SecurityInventoryCommands.txt).

This then produced a [ZIP](20261023-115728Z.zip) with various files documenting the existing set up of the tenant.

I then followed by using PowerShell scripts that I had generated from the Microsoft Learn module:

- [01PreparePowershell.ps1](01PreparePowershell.ps1)
- [02-CA001-Require-Phishing-Resistant-MFA-Admins.ps1](02-CA001-Require-Phishing-Resistant-MFA-Admins.ps1)
- [03-CA002-Require-MFA-All-Users.ps1](03-CA002-Require-MFA-All-Users.ps1)
- [04-CA003-Block-Legacy-Authentication.ps1](04-CA003-Block-Legacy-Authentication.ps1)
- [05-CA004-Require-MFA-Medium-High-SignIn-Risk.ps1](05-CA004-Require-MFA-Medium-High-SignIn-Risk.ps1)
- [06-CA005-Remediate-High-User-Risk.ps1](06-CA005-Remediate-High-User-Risk.ps1)
- [07-PreventUngovernedApplicationConsent.ps1](07-PreventUngovernedApplicationConsent.ps1)
- [08-ConfigureInvitedParticipantLobbyAccess.ps1](08-ConfigureInvitedParticipantLobbyAccess.ps1)
- [09-RestrictTeamsPresentationPrivileges.ps1](09-RestrictTeamsPresentationPrivileges.ps1)
- [10-RestrictTeamsAnonymousParticipation.ps1](10-RestrictTeamsAnonymousParticipation.ps1)
- [11-ApplyLeastPrivilegedAdministrativeRoles.ps1](11-ApplyLeastPrivilegedAdministrativeRoles.ps1)
- [11b-CreateAnEligibleAssignment.ps1](11b-CreateAnEligibleAssignment.ps1)
- [12-EnableSelfServicePasswordReset.ps1](12-EnableSelfServicePasswordReset.ps1)
- [13-ValidateSecurityControls.ps1](13-ValidateSecurityControls.ps1)

assess.ps1
hardening-results.txt
