# 5 - Sign-in risk protection

Write-Host "Sign-in risk protection"

$params = @{
    displayName = 'CA004-Require-MFA-Medium-High-SignIn-Risk'
    state = 'enabledForReportingButNotEnforced'
    conditions = @{
        clientAppTypes = @('all')
        signInRiskLevels = @(
            'medium',
            'high'
        )
        users = @{
            includeUsers = @('All')
            excludeUsers = $breakGlassObjectIds
        }
        applications = @{
            includeApplications = @('All')
        }
    }
    grantControls = @{
        operator = 'OR'
        authenticationStrength = @{
            id = '00000000-0000-0000-0000-000000000002'
        }
    }
    sessionControls = @{
        signInFrequency = @{
            authenticationType = 'primaryAndSecondaryAuthentication'
            frequencyInterval = 'everyTime'
            isEnabled = $true
        }
    }
}

$signInRiskPolicy = New-MgIdentityConditionalAccessPolicy `
    -BodyParameter $params

$signInRiskPolicy |
    Select-Object Id, DisplayName, State