# 4 - Block legacy authentication

Write-Host "Block legacy authentication"

$params = @{
    displayName = 'CA003-Block-Legacy-Authentication'
    state = 'enabledForReportingButNotEnforced'
    conditions = @{
        clientAppTypes = @(
            'exchangeActiveSync',
            'other'
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
        builtInControls = @('block')
    }
}

$legacyPolicy = New-MgIdentityConditionalAccessPolicy `
    -BodyParameter $params

$legacyPolicy |
    Select-Object Id, DisplayName, State