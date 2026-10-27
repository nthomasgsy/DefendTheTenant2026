# 6 - User risk protection

Write-Host "User risk protection"

$params = @{
    displayName = 'CA005-Remediate-High-User-Risk'
    state = 'enabledForReportingButNotEnforced'
    conditions = @{
        clientAppTypes = @('all')
        userRiskLevels = @('high')
        users = @{
            includeUsers = @('All')
            excludeUsers = $breakGlassObjectIds
        }
        applications = @{
            includeApplications = @('All')
        }
    }
    grantControls = @{
        operator = 'AND'
        builtInControls = @(
            'mfa',
            'passwordChange'
        )
    }
    sessionControls = @{
        signInFrequency = @{
            authenticationType = 'primaryAndSecondaryAuthentication'
            frequencyInterval = 'everyTime'
            isEnabled = $true
        }
    }
}

$userRiskPolicy = New-MgIdentityConditionalAccessPolicy `
    -BodyParameter $params

$userRiskPolicy |
    Select-Object Id, DisplayName, State