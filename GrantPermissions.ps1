<#
.SYNOPSIS
    Grant Microsoft Graph API permissions to Azure Automation Managed Identity
    
.DESCRIPTION
    Assigns the required Microsoft Graph API permissions to an Azure Automation Account's
    Managed Identity for the Intune Policy Changes Report script.
    
.NOTES
    Required Permissions for this script:
    - Application.ReadWrite.All
    - AppRoleAssignment.ReadWrite.All
    - Directory.Read.All
    
    Run this script once to configure permissions for your automation account.
#>

# Connect to Microsoft Graph with sufficient permissions
Connect-MgGraph -Scopes "Application.ReadWrite.All", "AppRoleAssignment.ReadWrite.All", "Directory.Read.All"

# Set the display name of the Azure Automation Account's Managed Identity
$automationDisplayName = "YOUR AZURE AUTOMATION ACCOUNT NAME"  # ⚠️ UPDATE THIS

# Retrieve the Managed Identity's service principal
$managedIdentity = Get-MgServicePrincipal -Filter "displayName eq '$automationDisplayName'"
if (-not $managedIdentity) {
    throw "Service Principal for '$automationDisplayName' not found."
}

Write-Host "Found Managed Identity: $($managedIdentity.DisplayName)" -ForegroundColor Green
Write-Host "Service Principal ID: $($managedIdentity.Id)" -ForegroundColor Cyan
Write-Host ""

# Get the Microsoft Graph service principal
$graphSp = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"

# Define all required permissions for the Intune Policy Changes Report
$requiredPermissions = @(
    "DeviceManagementConfiguration.Read.All",  # Read configuration policies, settings catalog, custom profiles
    "DeviceManagementApps.Read.All",          # Read app protection/configuration policies
    "Group.Read.All",                          # Resolve group IDs to friendly names
    "Mail.Send"                                # Send email reports
)

Write-Host "Checking and granting required permissions..." -ForegroundColor Yellow
Write-Host ""

foreach ($permission in $requiredPermissions) {
    Write-Host "Processing: $permission" -ForegroundColor Cyan
    
    # Find the permission in Graph API
    $role = $graphSp.AppRoles | Where-Object {
        $_.Value -eq $permission -and $_.AllowedMemberTypes -contains "Application"
    }
    
    if (-not $role) {
        Write-Warning "Permission not found in Graph API: $permission"
        continue
    }
    
    # Check if already assigned
    $alreadyAssigned = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $managedIdentity.Id |
        Where-Object { $_.AppRoleId -eq $role.Id }
    
    if ($alreadyAssigned) {
        Write-Host "  ✓ Already assigned: $permission" -ForegroundColor Green
    } else {
        try {
            New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $managedIdentity.Id `
                -PrincipalId $managedIdentity.Id `
                -ResourceId $graphSp.Id `
                -AppRoleId $role.Id
            Write-Host "  ✓ GRANTED: $permission" -ForegroundColor Green
        }
        catch {
            Write-Host "  ✗ FAILED: $permission - $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    Write-Host ""
}

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "Permission Configuration Complete!" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Permissions Summary:" -ForegroundColor Yellow
Write-Host "  DeviceManagementConfiguration.Read.All" -ForegroundColor White
Write-Host "    - Settings Catalog policies" -ForegroundColor Gray
Write-Host "    - Custom Configuration Profiles" -ForegroundColor Gray
Write-Host "    - Compliance Policies" -ForegroundColor Gray
Write-Host "    - Security Baselines" -ForegroundColor Gray
Write-Host "    - PowerShell/Shell Scripts" -ForegroundColor Gray
Write-Host ""
Write-Host "  DeviceManagementApps.Read.All" -ForegroundColor White
Write-Host "    - App Protection Policies" -ForegroundColor Gray
Write-Host "    - App Configuration Policies" -ForegroundColor Gray
Write-Host ""
Write-Host "  Group.Read.All" -ForegroundColor White
Write-Host "    - Resolve group GUIDs to friendly names" -ForegroundColor Gray
Write-Host ""
Write-Host "  Mail.Send" -ForegroundColor White
Write-Host "    - Send HTML email reports with CSV attachments" -ForegroundColor Gray
Write-Host ""
Write-Host "Next Steps:" -ForegroundColor Yellow
Write-Host "1. Update the script's EmailRecipient parameter (line 66)" -ForegroundColor White
Write-Host "2. Update the sender email address (line 975)" -ForegroundColor White
Write-Host "3. Run the automation to receive your first report!" -ForegroundColor White
Write-Host ""