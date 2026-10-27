# DefendTheTenant2026
Files for Defend The Tenant Challenge

## Approach Taken
I started by running a [PowerShell script](Export-M365SecurityInventory.ps1) to gather an Inventory of the Current State, as recommended by the [Microsoft Learn Module](https://learn.microsoft.com/en-gb/training/modules/harden-microsoft-365-secure-score/2-prepare-safe-administrative-environment).  The Powershell commands to use with this script are found [here](Export-M365SecurityInventoryCommands.txt).

This then produced a [ZIP](20261023-115728Z.zip) with various files documenting the existing set up of the tenant.

I then followed by using PowerShell scripts that I had generated from the Microsoft Learn module:

- [01PreparePowershell.ps1](01PreparePowershell.ps1) - [Prepare a safe administrative environment](https://learn.microsoft.com/en-gb/training/modules/harden-microsoft-365-secure-score/2-prepare-safe-administrative-environment): I found that I had to copy out these commands and run them in the Terminal, as running them from within a script meant that they were unavailable for use with the following scripts.  The statements connect to Microsoft Graph and Teams and define the breakglass accounts.  It is necessary to retrieve Object IDs for the breakglass accounts from Entra before starting.

- [02-CA001-Require-Phishing-Resistant-MFA-Admins.ps1](02-CA001-Require-Phishing-Resistant-MFA-Admins.ps1) - [Enforce phishing-resistant administrative authentication](https://learn.microsoft.com/en-gb/training/modules/harden-microsoft-365-secure-score/3-enforce-phishing-resistant-administrative-authentication): Creates a Conditional Access Policy in Report Only mode.

- [03-CA002-Require-MFA-All-Users.ps1](03-CA002-Require-MFA-All-Users.ps1) - [Enforce universal multifactor authentication](https://learn.microsoft.com/en-gb/training/modules/harden-microsoft-365-secure-score/4-enforce-universal-multifactor-authentication): Creates a Conditional Access Policy in Report Only mode.

- [04-CA003-Block-Legacy-Authentication.ps1](04-CA003-Block-Legacy-Authentication.ps1) - [Block legacy authentication](https://learn.microsoft.com/en-gb/training/modules/harden-microsoft-365-secure-score/5-block-legacy-authentication): Creates a Conditional Access Policy in Report Only mode.

- [05-CA004-Require-MFA-Medium-High-SignIn-Risk.ps1](05-CA004-Require-MFA-Medium-High-SignIn-Risk.ps1) - [Sign-in risk protection](https://learn.microsoft.com/en-gb/training/modules/harden-microsoft-365-secure-score/6-sign-risk-protection): Creates a Conditional Access Policy in Report Only mode.

- [06-CA005-Remediate-High-User-Risk.ps1](06-CA005-Remediate-High-User-Risk.ps1) - [User risk protection](https://learn.microsoft.com/en-gb/training/modules/harden-microsoft-365-secure-score/7-user-risk-protection): Creates a Conditional Access Policy in Report Only mode.

- [07-PreventUngovernedApplicationConsent.ps1](07-PreventUngovernedApplicationConsent.ps1) - [Prevent ungoverned application consent](https://learn.microsoft.com/en-gb/training/modules/harden-microsoft-365-secure-score/8-prevent-ungoverned-application-consent): Adjusts Entra User consent setting.

- [08-ConfigureInvitedParticipantLobbyAccess.ps1](08-ConfigureInvitedParticipantLobbyAccess.ps1) - [Configure invited-participant lobby access](https://learn.microsoft.com/en-gb/training/modules/harden-microsoft-365-secure-score/9-configure-invited-participant-lobby-access): Configures Teams Policy.

- [09-RestrictTeamsPresentationPrivileges.ps1](09-RestrictTeamsPresentationPrivileges.ps1) - [Restrict Microsoft Teams presentation privileges](https://learn.microsoft.com/en-gb/training/modules/harden-microsoft-365-secure-score/10-restrict-microsoft-teams-presentation-privileges): Configures Teams Policy.

- [10-RestrictTeamsAnonymousParticipation.ps1](10-RestrictTeamsAnonymousParticipation.ps1) - [Restrict Microsoft Teams anonymous participation](https://learn.microsoft.com/en-gb/training/modules/harden-microsoft-365-secure-score/11-restrict-microsoft-teams-anonymous-participation): Configures Teams Policy.

- [11-ApplyLeastPrivilegedAdministrativeRoles.ps1](11-ApplyLeastPrivilegedAdministrativeRoles.ps1) - [Apply least-privileged administrative roles](https://learn.microsoft.com/en-gb/training/modules/harden-microsoft-365-secure-score/12-apply-least-privileged-administrative-roles): Unused in challenge.
- [11b-CreateAnEligibleAssignment.ps1](11b-CreateAnEligibleAssignment.ps1) - [Apply least-privileged administrative roles](https://learn.microsoft.com/en-gb/training/modules/harden-microsoft-365-secure-score/12-apply-least-privileged-administrative-roles): Unused in challenge.

- [12-EnableSelfServicePasswordReset.ps1](12-EnableSelfServicePasswordReset.ps1) - [Enable self-service password reset](https://learn.microsoft.com/en-gb/training/modules/harden-microsoft-365-secure-score/13-enable-self-service-password-reset): Configures Entra SSPR Setting.

- [13-ValidateSecurityControls.ps1](13-ValidateSecurityControls.ps1) - [Validate security controls](https://learn.microsoft.com/en-gb/training/modules/harden-microsoft-365-secure-score/14-validate-security-controls): not used to create anything, but contains PowerShell commands to assess policies.  Instead of running this, I would instead look to re-run the [Export Inventory PowerShell script](Export-M365SecurityInventory.ps1)

assess.ps1
hardening-results.txt
