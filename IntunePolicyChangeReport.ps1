<#
.SYNOPSIS
    Intune Policy Change Report - Azure Automation Runbook
    
.DESCRIPTION
    Monitors and reports on recent changes to Policies in Microsoft Intune.
    Generates a comprehensive HTML report with CSV attachments via email.
    
    This script retrieves audit logs from Microsoft Intune for:
    - Configuration Policies (Settings Catalog)
    - Custom Configuration Profiles
    - Compliance Policies
    - Security Baselines
    - PowerShell/Shell Scripts
    - App Protection Policies
    - App Configuration Policies
    
    Features:
    - Automatic group ID resolution (converts GUIDs to friendly group names)
    - Severity-based categorization (High/Medium/Low)
    - Beautiful HTML email report with dark theme
    - CSV export attachment for detailed analysis
    - Configurable lookback period (1-90 days)
    
.PARAMETER EmailRecipient
    Comma-separated list of email addresses to receive reports.
    Default: 'your.email@company.com'
    
.PARAMETER DaysBack
    Number of days to look back for policy changes
    Default: 30
    Valid Range: 1-90
    
.PARAMETER OnlyShowChanges
    Only include policies that were modified (excludes creates/deletes)
    
.NOTES
    Author: Eddie Jimenez
    GitHub: github.com/eddie-jimenez
    Version: 2.1
    Last Updated: 2025-01-16
    
.PREREQUISITES
    - Azure Automation Account with Managed Identity enabled
    - Microsoft Graph API Permissions (Application):
        * DeviceManagementConfiguration.Read.All
        * DeviceManagementApps.Read.All
        * Group.Read.All
        * Mail.Send (for the automation account to send emails)
    - Shared mailbox or service account for sending emails
    
.CONFIGURATION
    Before running this script, update the following:
    1. Line 66: Change default email recipient to your email
    2. Line 925: Update the sender email address in $emailUri variable
    
.EXAMPLE
    # Run with default settings (last 30 days)
    .\IntunePolicyChangeReport.ps1
    
.EXAMPLE
    # Run for last 7 days and send to multiple recipients
    .\IntunePolicyChangeReport.ps1 -DaysBack 7 -EmailRecipient "admin1@company.com,admin2@company.com"
    
.EXAMPLE
    # Only show modifications (exclude creates and deletes)
    .\IntunePolicyChangeReport.ps1 -OnlyShowChanges
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$EmailRecipient = 'your.email@company.com',  # ⚠️ UPDATE THIS: Default recipient email address
    
    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 90)]
    [int]$DaysBack = 30,
    
    [Parameter(Mandatory = $false)]
    [switch]$OnlyShowChanges
)

# Store Start Time
$scriptStart = Get-Date

# Environment check
if (-not $PSPrivateMetadata.JobId.Guid) {
    Write-Error "This script requires Azure Automation"
    exit 1
}

Write-Output "Running Policy Changes Report in Azure Automation"
Write-Output "Reporting Period: $DaysBack days"

# ============================================================================
# AUTHENTICATION
# ============================================================================

Write-Output "=== Authentication ==="
$script:headers = $null
try {
    $resourceURI = "https://graph.microsoft.com"
    $tokenAuthURI = $env:IDENTITY_ENDPOINT + "?resource=$resourceURI&api-version=2019-08-01"
    $tokenResponse = Invoke-RestMethod -Method Get -Headers @{"X-IDENTITY-HEADER" = $env:IDENTITY_HEADER} -Uri $tokenAuthURI
    $accessToken = $tokenResponse.access_token
    
    $script:headers = @{
        "Authorization" = "Bearer $accessToken"
        "Content-Type" = "application/json"
    }
    
    Write-Output "Authentication successful"
} catch {
    Write-Error "Authentication failed: $($_.Exception.Message)"
    exit 1
}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

function Get-MgGraphAllPages {
    <#
    .SYNOPSIS
        Retrieves all pages from a Microsoft Graph API endpoint with automatic pagination
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri
    )
    
    $allResults = @()
    $nextLink = $Uri
    $pageCount = 0
    
    do {
        try {
            $pageCount++
            Write-Output "  Fetching page $pageCount..."
            $response = Invoke-RestMethod -Uri $nextLink -Headers $script:headers -Method GET
            
            if ($response.value) {
                $allResults += $response.value
                Write-Output "  Retrieved $($response.value.Count) items"
            }
            
            $nextLink = $response.'@odata.nextLink'
            
            if ($pageCount -gt 0) {
                Start-Sleep -Milliseconds 100
            }
        } catch {
            if ($_.Exception.Message -like "*429*" -or $_.Exception.Message -like "*throttled*") {
                Write-Output "  Rate limit hit, waiting 60 seconds..."
                Start-Sleep -Seconds 60
                continue
            }
            Write-Output "  API Error: $($_.Exception.Message)"
            break
        }
    } while ($nextLink)
    
    return $allResults
}

# Cache for group names to avoid repeated API calls
$script:groupNameCache = @{}

function Get-GroupNameFromId {
    <#
    .SYNOPSIS
        Resolves Azure AD Group ID (GUID) to friendly display name
    .DESCRIPTION
        Queries Microsoft Graph to get the displayName for a group.
        Results are cached to improve performance and reduce API calls.
    #>
    param([string]$GroupId)
    
    if ([string]::IsNullOrWhiteSpace($GroupId)) {
        return $GroupId
    }
    
    # Check cache first
    if ($script:groupNameCache.ContainsKey($GroupId)) {
        return $script:groupNameCache[$GroupId]
    }
    
    try {
        $groupUri = "https://graph.microsoft.com/v1.0/groups/$GroupId`?`$select=displayName"
        $group = Invoke-RestMethod -Uri $groupUri -Headers $script:headers -Method GET
        $groupName = $group.displayName
        
        # Cache it for future lookups
        $script:groupNameCache[$GroupId] = $groupName
        return $groupName
    }
    catch {
        # Group doesn't exist or no permission - return GUID with note
        $friendlyError = "$GroupId (not found)"
        $script:groupNameCache[$GroupId] = $friendlyError
        return $friendlyError
    }
}

function Parse-AssignmentJson {
    <#
    .SYNOPSIS
        Parses assignment JSON from audit logs and resolves group IDs to friendly names
    .DESCRIPTION
        Extracts all GUIDs from assignment JSON, resolves them to group names,
        and formats them as "Include: GroupName" or "Exclude: GroupName"
    #>
    param([string]$JsonString)
    
    if ([string]::IsNullOrWhiteSpace($JsonString)) {
        return $JsonString
    }
    
    # Extract all GUIDs from the JSON
    $guidPattern = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
    $guids = [regex]::Matches($JsonString, $guidPattern) | ForEach-Object { $_.Value } | Select-Object -Unique
    
    if ($guids.Count -eq 0) {
        return $JsonString
    }
    
    # Resolve all GUIDs to group names
    $resolvedGroups = @()
    foreach ($guid in $guids) {
        $groupName = Get-GroupNameFromId -GroupId $guid
        
        # Determine if this is an Include or Exclude assignment
        $targetType = "Include"
        if ($JsonString -match "ExclusionGroupAssignmentTarget.*?$guid") {
            $targetType = "Exclude"
        }
        
        $resolvedGroups += "$targetType`: $groupName"
    }
    
    if ($resolvedGroups.Count -gt 0) {
        return $resolvedGroups -join " | "
    }
    
    return $JsonString
}

function Get-ChangeSeverity {
    <#
    .SYNOPSIS
        Determines severity level (High/Medium/Low) based on activity type and result
    #>
    param(
        [string]$Activity,
        [string]$Result
    )
    
    if ($Result -eq "failure") {
        return "High"
    }
    
    # Deleting an assignment is LOW (just removing assignment)
    # Deleting a policy itself is HIGH (removing entire policy)
    if ($Activity -match "^Delete") {
        if ($Activity -match "Assignment") {
            return "Low"
        }
        else {
            return "High"
        }
    }
    
    # Creating/Patching assignments is LOW
    if ($Activity -match "Assignment") {
        return "Low"
    }
    
    # Creating or updating policies is MEDIUM
    if ($Activity -match "^Create|^Patch|^Update|^Modify") {
        return "Medium"
    }
    
    return "Low"
}

function Get-ChangeIcon {
    <#
    .SYNOPSIS
        Returns appropriate emoji icon based on activity type for visual identification
    #>
    param([string]$Activity)
    
    if ($Activity -match "^Delete") {
        return "🗑️"
    }
    elseif ($Activity -match "^Create") {
        if ($Activity -match "Assignment") {
            return "👤"
        }
        else {
            return "➕"
        }
    }
    elseif ($Activity -match "^Patch|^Update|^Modify") {
        if ($Activity -match "Assignment") {
            return "👤"
        }
        else {
            return "✏️"
        }
    }
    
    return "📝"
}

function Export-CsvWithBOM {
    <#
    .SYNOPSIS
        Exports data to CSV with UTF-8 BOM encoding for Excel compatibility
    #>
    param(
        [Parameter(Mandatory=$true)]
        $Data
    )
    
    $csvContent = $Data | ConvertTo-Csv -NoTypeInformation
    $csvString = $csvContent -join "`r`n"
    
    $utf8BOM = [byte[]]@(0xEF, 0xBB, 0xBF)
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    $csvUtf8Bytes = $utf8NoBom.GetBytes($csvString)
    
    $finalBytes = $utf8BOM + $csvUtf8Bytes
    
    return [Convert]::ToBase64String($finalBytes)
}

function Generate-HtmlReport {
    <#
    .SYNOPSIS
        Generates beautiful HTML email report with dark theme and modern design
    #>
    param(
        [array]$PolicyChanges,
        [hashtable]$Stats
    )
    
    $recentChanges = $PolicyChanges | Select-Object -First 10
    
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Policy Changes Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #0078d4 0%, #00bcf2 100%);
            color: #e0e0e0;
            padding: 20px;
            min-height: 100vh;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: rgba(20, 35, 55, 0.95);
            border-radius: 20px;
            padding: 30px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
        }
        .header {
            display: flex;
            align-items: center;
            gap: 15px;
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }
        .header-icon {
            width: 40px;
            height: 40px;
            background: white;
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 8px;
        }
        .header-icon img {
            width: 100%;
            height: 100%;
            object-fit: contain;
        }
        h1 {
            font-size: 28px;
            font-weight: 600;
            background: linear-gradient(135deg, #0078d4, #00bcf2);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .export-info {
            margin-left: auto;
            font-size: 14px;
            color: #9ca3af;
        }
        .kpi-row {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .kpi-card {
            background: linear-gradient(135deg, rgba(0, 120, 212, 0.15), transparent);
            border-radius: 14px;
            padding: 20px;
            border: 1px solid rgba(0, 120, 212, 0.2);
        }
        .kpi-title {
            font-size: 12px;
            color: #9ca3af;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 8px;
        }
        .kpi-value {
            font-size: 32px;
            font-weight: 700;
            color: #0078d4;
        }
        .severity-high { color: #ef4444; }
        .severity-medium { color: #f59e0b; }
        .severity-low { color: #10b981; }
        .attachment-note {
            margin-bottom: 20px;
            padding: 15px;
            background: rgba(0, 120, 212, 0.1);
            border: 1px solid rgba(0, 120, 212, 0.3);
            border-radius: 8px;
            text-align: center;
        }
        .attachment-note strong {
            color: #5ba3d0;
        }
        .legend {
            background: rgba(255, 255, 255, 0.05);
            border-radius: 14px;
            padding: 20px;
            margin-bottom: 20px;
        }
        .legend-title {
            font-size: 16px;
            font-weight: 600;
            color: #5ba3d0;
            margin-bottom: 15px;
        }
        .legend-section-title {
            margin-bottom: 10px;
            color: #9ca3af;
            font-size: 14px;
            font-weight: 600;
        }
        .legend-grid {
            display: flex;
            flex-direction: column;
            gap: 10px;
        }
        .legend-item {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 10px;
            background: rgba(0, 0, 0, 0.2);
            border-radius: 8px;
        }
        .legend-icon {
            font-size: 20px;
            width: 30px;
            text-align: center;
        }
        .legend-text {
            flex: 1;
        }
        .legend-label {
            font-weight: 600;
            color: #e0e0e0;
            font-size: 14px;
        }
        .legend-desc {
            font-size: 12px;
            color: #9ca3af;
        }
        .severity-legend {
            display: flex;
            flex-direction: column;
            gap: 10px;
        }
        .severity-item {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 8px 12px;
            background: rgba(0, 0, 0, 0.2);
            border-radius: 6px;
        }
        .severity-dot {
            width: 12px;
            height: 12px;
            border-radius: 50%;
        }
        .dot-high { background-color: #ef4444; }
        .dot-medium { background-color: #f59e0b; }
        .dot-low { background-color: #10b981; }
        .changes-section {
            background: rgba(255, 255, 255, 0.05);
            border-radius: 14px;
            padding: 20px;
            margin-bottom: 20px;
        }
        .section-header {
            font-size: 18px;
            font-weight: 600;
            color: #5ba3d0;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }
        .change-item {
            background: rgba(0, 0, 0, 0.2);
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 12px;
            border-left: 4px solid #666;
        }
        .border-high { border-left-color: #ef4444 !important; }
        .border-medium { border-left-color: #f59e0b !important; }
        .border-low { border-left-color: #10b981 !important; }
        .change-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }
        .change-title {
            font-size: 16px;
            font-weight: 600;
            color: #e0e0e0;
        }
        .change-meta {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 10px;
            margin-top: 10px;
        }
        .meta-item {
            font-size: 13px;
        }
        .meta-label {
            color: #6b7280;
            display: inline-block;
            min-width: 80px;
        }
        .meta-value {
            color: #e0e0e0;
        }
        .change-details {
            margin-top: 10px;
            padding: 10px;
            background: rgba(255, 255, 255, 0.05);
            border-radius: 6px;
            font-size: 13px;
        }
        .detail-item {
            padding: 5px 0;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
        }
        .detail-item:last-child {
            border-bottom: none;
        }
        .property-name {
            color: #5ba3d0;
            font-weight: 600;
        }
        .value-change {
            color: #9ca3af;
            margin-left: 10px;
        }
        .summary {
            margin-top: 30px;
            padding: 20px;
            background: rgba(255, 255, 255, 0.05);
            border-radius: 12px;
            font-size: 14px;
            color: #9ca3af;
            text-align: center;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="header-icon">
                <img src="https://upload.wikimedia.org/wikipedia/commons/thumb/8/89/Microsoft-intune.svg/250px-Microsoft-intune.svg.png" alt="Intune">
            </div>
            <h1>Intune Policy Changes Report</h1>
            <div class="export-info">
                <div>Period: Last $DaysBack days</div>
                <div>Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</div>
                <div style="font-size: 12px; margin-top: 4px;">Total Changes: $($Stats.TotalChanges)</div>
            </div>
        </div>
        
        <div class="attachment-note">
            📎 <strong>CSV file attached</strong> - Check email attachment for complete policy changes data export
        </div>
        
        <div class="legend">
            <div class="legend-title">📖 Report Legend</div>
            <table style="width: 100%; border-collapse: collapse;">
                <tr style="vertical-align: top;">
                    <td style="width: 50%; padding-right: 15px;">
                        <div class="legend-section-title">Action Types:</div>
                        <div class="legend-grid">
                            <div class="legend-item">
                                <div class="legend-icon">➕</div>
                                <div class="legend-text">
                                    <div class="legend-label">Create Policy</div>
                                    <div class="legend-desc">New policy created</div>
                                </div>
                            </div>
                            <div class="legend-item">
                                <div class="legend-icon">✏️</div>
                                <div class="legend-text">
                                    <div class="legend-label">Patch Policy</div>
                                    <div class="legend-desc">Policy settings modified</div>
                                </div>
                            </div>
                            <div class="legend-item">
                                <div class="legend-icon">🗑️</div>
                                <div class="legend-text">
                                    <div class="legend-label">Delete</div>
                                    <div class="legend-desc">Policy or assignment removed</div>
                                </div>
                            </div>
                            <div class="legend-item">
                                <div class="legend-icon">👤</div>
                                <div class="legend-text">
                                    <div class="legend-label">Assignment Action</div>
                                    <div class="legend-desc">Adding/updating policy assignments</div>
                                </div>
                            </div>
                            <div class="legend-item">
                                <div class="legend-icon">📝</div>
                                <div class="legend-text">
                                    <div class="legend-label">Other</div>
                                    <div class="legend-desc">Other policy actions</div>
                                </div>
                            </div>
                        </div>
                    </td>
                    <td style="width: 50%; padding-left: 15px;">
                        <div class="legend-section-title">Severity Levels:</div>
                        <div class="severity-legend">
                            <div class="severity-item">
                                <div class="severity-dot dot-high"></div>
                                <div>
                                    <div style="font-weight: 600; color: #ef4444;">High</div>
                                    <div style="font-size: 11px; color: #9ca3af;">Policy deletions or failures</div>
                                </div>
                            </div>
                            <div class="severity-item">
                                <div class="severity-dot dot-medium"></div>
                                <div>
                                    <div style="font-weight: 600; color: #f59e0b;">Medium</div>
                                    <div style="font-size: 11px; color: #9ca3af;">Policy creates or updates</div>
                                </div>
                            </div>
                            <div class="severity-item">
                                <div class="severity-dot dot-low"></div>
                                <div>
                                    <div style="font-weight: 600; color: #10b981;">Low</div>
                                    <div style="font-size: 11px; color: #9ca3af;">Assignment changes</div>
                                </div>
                            </div>
                        </div>
                    </td>
                </tr>
            </table>
        </div>
        
        <div class="kpi-row">
            <div class="kpi-card">
                <div class="kpi-title">Total Changes</div>
                <div class="kpi-value">$($Stats.TotalChanges)</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-title">High Severity</div>
                <div class="kpi-value severity-high">$($Stats.HighSeverity)</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-title">Medium Severity</div>
                <div class="kpi-value severity-medium">$($Stats.MediumSeverity)</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-title">Low Severity</div>
                <div class="kpi-value severity-low">$($Stats.LowSeverity)</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-title">Unique Policies</div>
                <div class="kpi-value">$($Stats.UniquePolicies)</div>
            </div>
        </div>
        
        <div class="changes-section">
            <div class="section-header">Recent Policy Changes (Last 10)</div>
"@
    
    foreach ($change in $recentChanges) {
        $icon = Get-ChangeIcon -Activity $change.Action
        $severityLower = $change.Severity.ToLower()
        $severityClass = "severity-$severityLower"
        $borderClass = "border-$severityLower"

        switch ($severityLower) {
            'high' { $borderColor = '#ef4444' }
            'medium' { $borderColor = '#f59e0b' }
            default { $borderColor = '#10b981' }
        }
        
        try {
            $timestamp = [datetime]::Parse($change.DateTime).ToString('MM/dd/yyyy HH:mm')
        } catch {
            $timestamp = $change.DateTime
        }
        
        $html += @"
            <div class="change-item $borderClass" style="border-left-color: $borderColor;">
                <div class="change-header">
                    <div class="change-title">$icon $($change.PolicyName)</div>
                    <div class="$severityClass" style="font-weight: 600;">$($change.Severity)</div>
                </div>
                <div class="change-meta">
                    <div class="meta-item">
                        <span class="meta-label">Type:</span>
                        <span class="meta-value">$($change.PolicyType)</span>
                    </div>
                    <div class="meta-item">
                        <span class="meta-label">Action:</span>
                        <span class="meta-value">$($change.Action)</span>
                    </div>
                    <div class="meta-item">
                        <span class="meta-label">User:</span>
                        <span class="meta-value">$($change.User)</span>
                    </div>
                    <div class="meta-item">
                        <span class="meta-label">Timestamp:</span>
                        <span class="meta-value">$timestamp</span>
                    </div>
                    <div class="meta-item">
                        <span class="meta-label">Policy ID:</span>
                        <span class="meta-value" style="font-size: 11px; word-break: break-all;">$($change.PolicyId)</span>
                    </div>
                    <div class="meta-item">
                        <span class="meta-label">Result:</span>
                        <span class="meta-value">$($change.Result)</span>
                    </div>
                </div>
"@
        
        if ($change.Details) {
            $html += @"
                <div class="change-details">
                    <div style="color: #9ca3af; margin-bottom: 8px; font-weight: 600;">Modified Properties:</div>
"@
            
            $details = $change.Details -split '; '
            foreach ($detail in $details) {
                if ($detail) {
                    if ($detail -match '^([^:]+):\s*(.+)$') {
                        $propName = $matches[1]
                        $propValue = $matches[2]
                        $html += @"
                    <div class="detail-item">
                        <span class="property-name">$propName</span>
                        <span class="value-change">$propValue</span>
                    </div>
"@
                    }
                }
            }
            
            $html += @"
                </div>
"@
        }
        
        $html += @"
            </div>
"@
    }
    
    $duration = (Get-Date) - $scriptStart
    $durationFormatted = "{0:hh\:mm\:ss}" -f $duration
    
    $html += @"
        </div>
        
        <div class="summary">
            Generated by Azure Automation • $($Stats.TotalChanges) policy changes detected from $DaysBack days • Runtime: $durationFormatted
        </div>
    </div>
</body>
</html>
"@
    
    return $html
}

# ============================================================================
# MAIN SCRIPT LOGIC
# ============================================================================

try {
    Write-Output "=== Starting Policy Changes Analysis ==="
    
    $startDate = (Get-Date).AddDays(-$DaysBack)
    $startDateFormatted = $startDate.ToString("yyyy-MM-ddTHH:mm:ssZ")
    
    Write-Output "Analyzing changes from: $($startDate.ToString('yyyy-MM-dd HH:mm:ss'))"
    
    # ========================================================================
    # GET AUDIT LOGS FOR ALL POLICY CHANGES
    # ========================================================================
    
    Write-Output "=== Retrieving Audit Logs ==="
    
    try {
        $allAuditLogs = @()
        
        # 1. DeviceConfiguration - Settings Catalog, Custom Profiles, Scripts
        Write-Output "  Fetching DeviceConfiguration events..."
        try {
            $deviceConfigUri = "https://graph.microsoft.com/beta/deviceManagement/auditEvents?`$filter=activityDateTime ge $startDateFormatted and category eq 'DeviceConfiguration'&`$orderby=activityDateTime desc"
            $deviceConfigLogs = Get-MgGraphAllPages -Uri $deviceConfigUri
            $allAuditLogs += $deviceConfigLogs
            Write-Output "  Retrieved $($deviceConfigLogs.Count) DeviceConfiguration events"
        } catch {
            Write-Output "  Error fetching DeviceConfiguration: $($_.Exception.Message)"
        }
        
        # 2. Compliance - Compliance Policies
        Write-Output "  Fetching Compliance events..."
        try {
            $complianceUri = "https://graph.microsoft.com/beta/deviceManagement/auditEvents?`$filter=activityDateTime ge $startDateFormatted and category eq 'Compliance'&`$orderby=activityDateTime desc"
            $complianceLogs = Get-MgGraphAllPages -Uri $complianceUri
            $allAuditLogs += $complianceLogs
            Write-Output "  Retrieved $($complianceLogs.Count) Compliance events"
        } catch {
            Write-Output "  Error fetching Compliance: $($_.Exception.Message)"
        }
        
        # 3. DeviceIntent - Security Baselines
        Write-Output "  Fetching DeviceIntent events..."
        try {
            $intentUri = "https://graph.microsoft.com/beta/deviceManagement/auditEvents?`$filter=activityDateTime ge $startDateFormatted and category eq 'DeviceIntent'&`$orderby=activityDateTime desc"
            $intentLogs = Get-MgGraphAllPages -Uri $intentUri
            $allAuditLogs += $intentLogs
            Write-Output "  Retrieved $($intentLogs.Count) DeviceIntent events"
        } catch {
            Write-Output "  Error fetching DeviceIntent: $($_.Exception.Message)"
        }
        
        # 4. Application - App Protection/Configuration Policies
        Write-Output "  Fetching Application events (with filtering)..."
        try {
            $appUri = "https://graph.microsoft.com/beta/deviceManagement/auditEvents?`$filter=activityDateTime ge $startDateFormatted and category eq 'Application'&`$orderby=activityDateTime desc&`$top=50"
            
            $appAllResults = @()
            $appNextLink = $appUri
            $appPageCount = 0
            $maxAppPages = 20
            $maxAppTime = 120
            $appStartTime = Get-Date
            
            Write-Output "    Paginating through Application events (filtering out MobileApp activities)..."
            
            while ($appNextLink -and $appPageCount -lt $maxAppPages) {
                if (((Get-Date) - $appStartTime).TotalSeconds -gt $maxAppTime) {
                    Write-Output "    Reached time limit, stopping pagination"
                    break
                }
                
                $appPageCount++
                $response = Invoke-RestMethod -Uri $appNextLink -Headers $script:headers -Method GET
                
                # Filter OUT MobileApp activities, keep only policy-related activities
                $filteredPage = $response.value | Where-Object {
                    $_.activityType -notlike "*MobileApp*" -and
                    ($_.activityType -like "*ManagedAppPolicy*" -or 
                     $_.activityType -like "*ManagedAppProtection*" -or
                     $_.activityType -like "*ManagedAppConfiguration*" -or
                     $_.activityType -like "*AppProtection*" -or
                     $_.activityType -like "*AppConfiguration*")
                }
                
                if ($filteredPage) {
                    $appAllResults += $filteredPage
                    Write-Output "    Page $appPageCount : Found $($filteredPage.Count) policy events"
                }
                
                $appNextLink = $response.'@odata.nextLink'
                
                if ($appPageCount -gt 0) {
                    Start-Sleep -Milliseconds 100
                }
            }
            
            $allAuditLogs += $appAllResults
            Write-Output "  Retrieved $($appAllResults.Count) Application policy events"
        } catch {
            Write-Output "  Error fetching Application: $($_.Exception.Message)"
        }
        
        Write-Output "  Total events retrieved: $($allAuditLogs.Count)"
        
        $policyActivities = $allAuditLogs
        
        Write-Output "Processing $($policyActivities.Count) audit events"
    }
    catch {
        Write-Output "Failed to retrieve audit logs: $($_.Exception.Message)"
        $policyActivities = @()
    }
    
    # Filter if OnlyShowChanges specified
    if ($OnlyShowChanges) {
        $policyActivities = $policyActivities | Where-Object {
            $_.activityType -like "*Update*" -or $_.activityType -like "*Modify*"
        }
        Write-Output "Filtered to show only modifications: $($policyActivities.Count) changes"
    }
    
    if ($policyActivities.Count -eq 0) {
        Write-Output "No policy changes found in the specified time period"
        exit 0
    }
    
    # ========================================================================
    # PROCESS CHANGES
    # ========================================================================
    
    Write-Output "=== Processing Policy Changes ==="
    
    $csvData = @()
    $uniquePolicies = @{}
    $severityCounts = @{
        High = 0
        Medium = 0
        Low = 0
    }
    
    foreach ($change in $policyActivities) {
        try {
            $policyName = "Unknown Policy"
            $userName = "System"
            $policyId = "N/A"
            $policyType = "Configuration Policy"
            
            # Check if resources exist and have data
            if ($change.resources -and $change.resources.Count -gt 0 -and $change.resources[0]) {
                if ($change.resources[0].displayName) {
                    $policyName = $change.resources[0].displayName
                }
                $uniquePolicies[$policyName] = $true
                
                if ($change.resources[0].resourceId) {
                    $policyId = $change.resources[0].resourceId
                }
                
                # Determine policy type from activity type
                if ($change.activityType -like "*DeviceManagementConfigurationPolicy*") {
                    $policyType = "Settings Catalog"
                }
                elseif ($change.activityType -like "*DeviceConfiguration*") {
                    $policyType = "Custom Configuration Profile"
                }
                elseif ($change.activityType -like "*Script*") {
                    if ($change.activityType -like "*DeviceManagementScript*" -or $change.activityType -like "*PowerShell*") {
                        $policyType = "PowerShell Script"
                    }
                    else {
                        $policyType = "Shell Script"
                    }
                }
                elseif ($change.activityType -like "*CompliancePolicy*") {
                    $policyType = "Compliance Policy"
                }
                elseif ($change.activityType -like "*DeviceManagementIntent*") {
                    $policyType = "Security Baseline"
                }
                elseif ($change.activityType -like "*ManagedAppPolicy*" -or $change.activityType -like "*ManagedAppProtection*") {
                    $policyType = "App Protection Policy"
                }
                elseif ($change.activityType -like "*ManagedAppConfiguration*") {
                    $policyType = "App Configuration Policy"
                }
            }
            else {
                continue
            }
            
            if ($change.actor -and $change.actor.userPrincipalName) {
                $userName = $change.actor.userPrincipalName
            }
            
            $severity = Get-ChangeSeverity -Activity $change.activityType -Result $change.activityResult
            $severityCounts[$severity]++
            
            # Check for assignment information
            $assignmentInfo = ""
            if ($change.activityType -like "*Assignment*") {
                if ($change.resources[0].modifiedProperties) {
                    foreach ($prop in $change.resources[0].modifiedProperties) {
                        if ($prop.displayName -like "*Target*" -or $prop.displayName -like "*Group*") {
                            $assignmentInfo += "$($prop.displayName): $($prop.newValue); "
                        }
                    }
                }
                
                if ($change.activityOperationType) {
                    $assignmentInfo += "Operation: $($change.activityOperationType); "
                }
            }
            
            $changeDetails = ""
            if ($change.resources[0].modifiedProperties) {
                $changeDetailsList = @()
                foreach ($property in $change.resources[0].modifiedProperties) {
                    # Skip DeviceManagementAPIVersion as it's not useful
                    if ($property.displayName -eq "DeviceManagementAPIVersion") {
                        continue
                    }
                    
                    # Map technical property names to friendly names
                    $friendlyName = switch ($property.displayName) {
                        '$Collection.RoleScopeTagIds[0]' { "Scope Tag" }
                        'assignments' { "Assignments" }
                        'PayloadName' { "Payload Name" }
                        'PayloadFileName' { "Payload File Name" }
                        'DeploymentChannel' { "Deployment Channel" }
                        'SupportsScopeTags' { "Supports Scope Tags" }
                        'CreatedDateTime' { "Created Date" }
                        'LastModifiedDateTime' { "Last Modified Date" }
                        'Description' { "Description" }
                        'Version' { "Version" }
                        'Id' { "ID" }
                        'SettingCount' { "Setting Count" }
                        default { 
                            $displayName = $property.displayName
                            $displayName = $displayName -replace 'DeviceManagementConfigurationPolicyAssignment', 'Configuration Policy Assignment'
                            $displayName = $displayName -replace 'DeviceManagementConfigurationPolicy', 'Configuration Policy'
                            $displayName = $displayName -replace 'DeviceConfigurationAssignment', 'Configuration Assignment'
                            $displayName = $displayName -replace 'DeviceConfiguration', 'Device Configuration'
                            $displayName = $displayName -replace 'DeviceManagementScript', 'Management Script'
                            $displayName = $displayName -replace 'CompliancePolicy', 'Compliance Policy'
                            $displayName -creplace '([a-z])([A-Z])', '$1 $2'
                        }
                    }
                    
                    $oldValue = if ($property.oldValue) { $property.oldValue } else { "(empty)" }
                    $newValue = if ($property.newValue) { $property.newValue } else { "(empty)" }
                    
                    # Special handling for assignments to resolve group IDs
                    if ($friendlyName -eq "Assignments" -and $newValue -ne "(empty)") {
                        $resolvedValue = Parse-AssignmentJson -JsonString $property.newValue
                        if ($resolvedValue -ne $property.newValue) {
                            $newValue = $resolvedValue
                        }
                    }
                    if ($friendlyName -eq "Assignments" -and $oldValue -ne "(empty)") {
                        $resolvedValue = Parse-AssignmentJson -JsonString $property.oldValue
                        if ($resolvedValue -ne $property.oldValue) {
                            $oldValue = $resolvedValue
                        }
                    }
                    
                    $changeDetailsList += "$($friendlyName): '$oldValue' → '$newValue'"
                }
                
                if ($assignmentInfo) {
                    $changeDetailsList += "Assignment: $assignmentInfo"
                }
                
                $changeDetails = $changeDetailsList -join "; "
            }
            else {
                if ($assignmentInfo) {
                    $changeDetails = "Assignment: $assignmentInfo"
                }
            }
            
            # Clean up the Action field for display
            $friendlyAction = $change.activityType
            $friendlyAction = $friendlyAction -replace 'DeviceManagementConfigurationPolicyAssignment', 'Policy Assignment'
            $friendlyAction = $friendlyAction -replace 'DeviceManagementConfigurationPolicy', 'Configuration Policy'
            $friendlyAction = $friendlyAction -replace 'DeviceConfigurationAssignment', 'Configuration Assignment'
            $friendlyAction = $friendlyAction -replace 'DeviceConfiguration', 'Configuration'
            $friendlyAction = $friendlyAction -replace 'DeviceManagementScript', 'Script'
            $friendlyAction = $friendlyAction -replace 'CompliancePolicy', 'Compliance'
            $friendlyAction = $friendlyAction -creplace '([a-z])([A-Z])', '$1 $2'
            
            $csvRecord = [PSCustomObject]@{
                DateTime = $change.activityDateTime
                PolicyName = $policyName
                PolicyType = $policyType
                PolicyId = $policyId
                Action = $friendlyAction
                User = $userName
                Result = $change.activityResult
                Severity = $severity
                Details = $changeDetails
            }
            $csvData += $csvRecord
            
        } catch {
            Write-Output "Error processing change: $($_.Exception.Message)"
            continue
        }
    }
    
    Write-Output "Processed $($csvData.Count) policy changes"
    Write-Output "Resolved $($script:groupNameCache.Count) unique group names"
    
    # Calculate statistics
    $stats = @{
        TotalChanges = $csvData.Count
        HighSeverity = $severityCounts.High
        MediumSeverity = $severityCounts.Medium
        LowSeverity = $severityCounts.Low
        UniquePolicies = $uniquePolicies.Count
    }
    
    # ========================================================================
    # GENERATE REPORT AND SEND EMAIL
    # ========================================================================
    
    Write-Output "=== Generating HTML Report ==="
    $htmlReport = Generate-HtmlReport -PolicyChanges $csvData -Stats $stats
    
    # Export CSV
    Write-Output "=== Preparing CSV Export ==="
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $csvFileName = "PolicyChanges_$timestamp.csv"
    $csvBase64 = Export-CsvWithBOM -Data $csvData
    
    $attachments = @(
        @{
            "@odata.type" = "#microsoft.graph.fileAttachment"
            name = $csvFileName
            contentType = "text/csv"
            contentBytes = $csvBase64
        }
    )
    
    # Send email
    Write-Output "=== Sending Email Report ==="
    
    $emailRecipients = $EmailRecipient -split ',' | ForEach-Object { $_.Trim() }
    
    foreach ($recipient in $emailRecipients) {
        $message = @{
            subject = "[Report] Intune Policy Changes - Last $DaysBack Days - $(Get-Date -Format 'yyyy-MM-dd')"
            body = @{
                contentType = "HTML"
                content = $htmlReport
            }
            toRecipients = @(
                @{ emailAddress = @{ address = $recipient } }
            )
            attachments = $attachments
        }
        
        $requestBody = @{ 
            message = $message
            saveToSentItems = $true
        } | ConvertTo-Json -Depth 10
        
        $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        $bodyBytes = $utf8NoBom.GetBytes($requestBody)
        
        # ⚠️ UPDATE THIS: Change to your automation account's email address or shared mailbox
        $emailUri = "https://graph.microsoft.com/v1.0/users/ITAutomation@yourcompany.com/sendMail"
        
        try {
            Invoke-RestMethod -Uri $emailUri -Headers $script:headers -Method POST -Body $bodyBytes -ContentType "application/json; charset=utf-8"
            Write-Output "Email sent to $recipient"
        } catch {
            Write-Error "Failed to send email: $($_.Exception.Message)"
            throw
        }
    }
    
    Write-Output "=== Report Complete ==="
    Write-Output "Total Changes: $($stats.TotalChanges)"
    Write-Output "High Severity: $($stats.HighSeverity)"
    Write-Output "Medium Severity: $($stats.MediumSeverity)"
    Write-Output "Low Severity: $($stats.LowSeverity)"
    Write-Output "Unique Policies: $($stats.UniquePolicies)"
    
} catch {
    Write-Error "Script failed: $($_.Exception.Message)"
    exit 1
}