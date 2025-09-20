# Enhanced AD Account Control Flags + Privileged Groups Audit Script
# Version 2.0 - Complete working script

#Requires -Module ActiveDirectory

# Configuration section
$CONFIG = @{
    SmtpServer     = ""  # "smtp.company.com"
    SmtpPort       = 587
    EmailFrom      = ""  # "adsecurity@company.com" 
    EmailTo        = ""  # "admin@company.com"
    EmailSubject   = "AD Security Audit Report - $(Get-Date -Format 'yyyy-MM-dd')"
    UseSSL         = $true
    MaxPrivilegedUsers = 10
    MaxHighRiskFlags   = 5
    AnalyzeStaleAccounts = $true
    StaleAccountDays     = 90
    CheckServiceAccounts = $true
    OutputDirectory = "C:\Temp\AD_Reports"
    KeepReportsForDays = 30
}

# Functions
function Write-Log {
    param([string]$Message, [string]$Level = "Info")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    Write-Host $logMessage
    $logMessage | Out-File -FilePath $logPath -Append -Encoding utf8
}

function Send-EmailReport {
    param([string]$HtmlPath, [string]$Summary)
    if (!$CONFIG.SmtpServer -or !$CONFIG.EmailFrom -or !$CONFIG.EmailTo) {
        Write-Log "Email not configured, skipping email report"
        return
    }
    try {
        $htmlContent = Get-Content -Path $HtmlPath -Raw
        $mailParams = @{
            SmtpServer  = $CONFIG.SmtpServer
            Port        = $CONFIG.SmtpPort
            From        = $CONFIG.EmailFrom
            To          = $CONFIG.EmailTo
            Subject     = $CONFIG.EmailSubject
            Body        = $htmlContent
            BodyAsHtml  = $true
            UseSsl      = $CONFIG.UseSSL
        }
        Send-MailMessage @mailParams
        Write-Log "Email report sent successfully to $($CONFIG.EmailTo)"
    }
    catch {
        Write-Log "Failed to send email report: $($_.Exception.Message)" "Error"
    }
}

function Get-StaleAccounts {
    if (!$CONFIG.AnalyzeStaleAccounts) { return @() }
    Write-Log "Analyzing stale accounts (inactive for $($CONFIG.StaleAccountDays) days)..."
    $cutoffDate = (Get-Date).AddDays(-$CONFIG.StaleAccountDays)
    try {
        $staleAccounts = Get-ADUser -Filter * -Properties LastLogonDate, PasswordLastSet, Enabled |
            Where-Object { 
                $_.Enabled -eq $true -and 
                ($_.LastLogonDate -lt $cutoffDate -or $_.LastLogonDate -eq $null) -and
                $_.PasswordLastSet -lt $cutoffDate
            }
        Write-Log "Found $($staleAccounts.Count) stale accounts"
        return $staleAccounts
    }
    catch {
        Write-Log "Error analyzing stale accounts: $($_.Exception.Message)" "Error"
        return @()
    }
}

function Get-ServiceAccounts {
    if (!$CONFIG.CheckServiceAccounts) { return @() }
    Write-Log "Identifying potential service accounts..."
    try {
        $serviceAccounts = Get-ADUser -Filter * -Properties Description, ServicePrincipalName |
            Where-Object { 
                $_.Description -match "(service|svc|app|system)" -or
                $_.SamAccountName -match "(svc|service|app|system)" -or
                $_.ServicePrincipalName.Count -gt 0
            }
        Write-Log "Found $($serviceAccounts.Count) potential service accounts"
        return $serviceAccounts
    }
    catch {
        Write-Log "Error analyzing service accounts: $($_.Exception.Message)" "Error"
        return @()
    }
}

function Remove-OldReports {
    if ($CONFIG.KeepReportsForDays -le 0) { return }
    try {
        $cutoffDate = (Get-Date).AddDays(-$CONFIG.KeepReportsForDays)
        $oldFiles = Get-ChildItem -Path $CONFIG.OutputDirectory -File | 
            Where-Object { $_.CreationTime -lt $cutoffDate }
        if ($oldFiles) {
            $oldFiles | Remove-Item -Force
            Write-Log "Cleaned up $($oldFiles.Count) old report files"
        }
    }
    catch {
        Write-Log "Error cleaning up old reports: $($_.Exception.Message)" "Error"
    }
}

function Open-InBrowser {
    param([string]$FilePath)
    try {
        Start-Process $FilePath
        Write-Log "Opened $FilePath using Start-Process"
    }
    catch {
        try {
            cmd /c start '""' $FilePath
            Write-Log "Opened $FilePath using cmd /c start"
        }
        catch {
            Write-Log "Error opening browser: $($_.Exception.Message)" "Error"
        }
    }
}

# Initialize
$dateSuffix = Get-Date -Format 'yyyyMMdd_HHmm'
if (!(Test-Path $CONFIG.OutputDirectory)) {
    New-Item -ItemType Directory -Path $CONFIG.OutputDirectory -Force | Out-Null
}
$logPath = "$($CONFIG.OutputDirectory)\AD_Audit_Log_$dateSuffix.txt"
Write-Log "Starting enhanced AD Account Control Flags audit v2.0"

# Data definitions
$flags = @{
    AccountDisabled         = @{ Bit = 2;        Description = "Disabled accounts"; Risk = "Low" }
    Lockout                = @{ Bit = 16;       Description = "Locked-out accounts"; Risk = "Medium" }
    PasswordNotRequired    = @{ Bit = 32;       Description = "Password not required"; Risk = "High" }
    PasswordCantChange     = @{ Bit = 64;       Description = "Password cannot change"; Risk = "Medium" }
    DontExpirePassword     = @{ Bit = 65536;    Description = "Password never expires"; Risk = "Medium" }
    DONT_REQ_PREAUTH       = @{ Bit = 4194304;  Description = "No Kerberos PreAuth required"; Risk = "High" }
    UseDesKey              = @{ Bit = 2097152;  Description = "Use DES encryption (weak)"; Risk = "High" }
    TrustedForDelegation   = @{ Bit = 524288;   Description = "Trusted for delegation"; Risk = "High" }
}

$privilegedGroups = @{
    'Domain Admins'           = @{ Description = 'Full domain control'; Risk = 'Critical' }
    'Enterprise Admins'       = @{ Description = 'Full forest control'; Risk = 'Critical' }
    'Schema Admins'          = @{ Description = 'Schema modification rights'; Risk = 'Critical' }
    'Account Operators'      = @{ Description = 'User/Group management'; Risk = 'High' }
    'Server Operators'       = @{ Description = 'Server management'; Risk = 'High' }
    'Backup Operators'       = @{ Description = 'Backup/Restore privileges'; Risk = 'High' }
    'Print Operators'        = @{ Description = 'Printer management'; Risk = 'Medium' }
    'Administrators'         = @{ Description = 'Local admin rights'; Risk = 'High' }
    'DNSAdmins'             = @{ Description = 'DNS management'; Risk = 'High' }
}

# Main execution
try {
    # Test AD connectivity
    Write-Log "Testing Active Directory connectivity..."
    $domain = Get-ADDomain -ErrorAction Stop
    Write-Log "AD connectivity successful for domain: $($domain.DNSRoot)"

    # Collect flags data
    Write-Log "Collecting account data for each flag..."
    $flagsData = foreach ($key in $flags.Keys) {
        $bit = $flags[$key].Bit
        $filter = "userAccountControl -band $bit"
        Write-Log "Scanning for flag: $key (bit $bit)"
        try {
            $results = @(Get-ADUser -Filter $filter -Properties SamAccountName -ErrorAction Stop)
            Write-Log "Found $($results.Count) accounts with flag: $key"
            [PSCustomObject]@{
                Flag        = $key
                Description = $flags[$key].Description
                RiskLevel   = $flags[$key].Risk
                Count       = $results.Count
                Accounts    = @($results | Select-Object -ExpandProperty SamAccountName)
            }
        }
        catch {
            Write-Log "Error scanning flag $key : $($_.Exception.Message)" "Error"
            [PSCustomObject]@{
                Flag        = $key
                Description = $flags[$key].Description + " (Error during scan)"
                RiskLevel   = $flags[$key].Risk
                Count       = 0
                Accounts    = @()
            }
        }
    }

    # Collect privileged groups data
    Write-Log "Collecting privileged group memberships..."
    $privilegedData = foreach ($groupName in $privilegedGroups.Keys) {
        Write-Log "Scanning group: $groupName"
        try {
            $group = Get-ADGroup -Identity $groupName -ErrorAction Stop
            $members = @(Get-ADGroupMember -Identity $group -Recursive -ErrorAction Stop | 
                        Where-Object { $_.objectClass -eq 'user' } |
                        Get-ADUser -Properties SamAccountName, Enabled -ErrorAction Stop)
            
            $enabledMembers = @($members | Where-Object { $_.Enabled -eq $true })
            $disabledMembers = @($members | Where-Object { $_.Enabled -eq $false })
            
            Write-Log "Found $($members.Count) total members in $groupName"
            
            [PSCustomObject]@{
                GroupName     = $groupName
                Description   = $privilegedGroups[$groupName].Description
                RiskLevel     = $privilegedGroups[$groupName].Risk
                TotalMembers  = $members.Count
                EnabledMembers = $enabledMembers.Count
                DisabledMembers = $disabledMembers.Count
                MemberNames   = @($enabledMembers | Select-Object -ExpandProperty SamAccountName)
            }
        }
        catch {
            Write-Log "Error scanning group $groupName : $($_.Exception.Message)" "Error"
            [PSCustomObject]@{
                GroupName     = $groupName
                Description   = $privilegedGroups[$groupName].Description + " (Error/Not Found)"
                RiskLevel     = $privilegedGroups[$groupName].Risk
                TotalMembers  = 0
                EnabledMembers = 0
                DisabledMembers = 0
                MemberNames   = @()
            }
        }
    }

    # Additional analysis
    Remove-OldReports
    $staleAccounts = Get-StaleAccounts
    $serviceAccounts = Get-ServiceAccounts
    
    # Create security summary
    $totalFlagged = ($flagsData | Measure-Object -Property Count -Sum).Sum
    $totalPrivileged = ($privilegedData | Measure-Object -Property EnabledMembers -Sum).Sum
    $highRiskFlags = ($flagsData | Where-Object { $_.RiskLevel -eq "High" -and $_.Count -gt 0 }).Count
    $criticalGroups = ($privilegedData | Where-Object { $_.RiskLevel -eq "Critical" -and $_.EnabledMembers -gt 0 }).Count
    
    # Generate alerts
    $alerts = @()
    if ($totalPrivileged -gt $CONFIG.MaxPrivilegedUsers) {
        $alerts += "⚠️ High privileged user count: $totalPrivileged (threshold: $($CONFIG.MaxPrivilegedUsers))"
    }
    if ($highRiskFlags -gt $CONFIG.MaxHighRiskFlags) {
        $alerts += "⚠️ Multiple high-risk flags detected: $highRiskFlags flags"
    }
    if ($staleAccounts.Count -gt 0) {
        $alerts += "⚠️ Stale accounts detected: $($staleAccounts.Count) accounts"
    }
    if ($criticalGroups -gt 0) {
        $alerts += "🔴 Critical groups with members: $criticalGroups groups need review"
    }

    # Build HTML report
    $html = @"
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8" />
  <title>AD Security Dashboard</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@3.9.1/dist/chart.min.js"></script>
  <style>
    body { font-family: 'Segoe UI', Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
    .container { max-width: 1400px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
    h1 { text-align: center; color: #2c3e50; margin-bottom: 10px; font-size: 2.5em; }
    .subtitle { text-align: center; color: #666; margin-bottom: 40px; }
    .summary-stats { display: flex; justify-content: space-around; margin: 30px 0; text-align: center; }
    .stat-box { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; min-width: 150px; }
    .stat-number { font-size: 2em; font-weight: bold; margin-bottom: 5px; }
    .stat-label { font-size: 0.9em; opacity: 0.9; }
    .dashboard-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 30px; margin: 30px 0; }
    .chart-section { background: #fafafa; padding: 20px; border-radius: 8px; border: 1px solid #e0e0e0; }
    .chart-title { font-size: 1.5em; font-weight: bold; margin-bottom: 20px; text-align: center; color: #2c3e50; }
    .chart-container { position: relative; height: 400px; margin: 20px 0; }
    table { width: 100%; margin: 20px 0; border-collapse: collapse; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
    th, td { border: 1px solid #ddd; padding: 12px; vertical-align: top; text-align: left; }
    th { background: #34495e; color: white; font-weight: bold; }
    tr:nth-child(even) { background-color: #f9f9f9; }
    .risk-badge { padding: 4px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; text-transform: uppercase; }
    .badge-critical { background-color: #d32f2f; color: white; }
    .badge-high { background-color: #f44336; color: white; }
    .badge-medium { background-color: #ff9800; color: white; }
    .badge-low { background-color: #4caf50; color: white; }
    .export-btn { background: #2196F3; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; margin: 5px; }
    .export-btn:hover { background: #1976D2; }
    @media (max-width: 768px) { .dashboard-grid { grid-template-columns: 1fr; } }
  </style>
</head>
<body>
  <div class="container">
    <h1>Active Directory Security Dashboard</h1>
    <p class="subtitle">Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | Domain: $($domain.DNSRoot)</p>
    
    <div class="summary-stats">
      <div class="stat-box">
        <div class="stat-number">$totalFlagged</div>
        <div class="stat-label">Total Flagged</div>
      </div>
      <div class="stat-box">
        <div class="stat-number">$totalPrivileged</div>
        <div class="stat-label">Privileged Users</div>
      </div>
      <div class="stat-box">
        <div class="stat-number">$($highRiskFlags + $criticalGroups)</div>
        <div class="stat-label">Critical Issues</div>
      </div>
      <div class="stat-box">
        <div class="stat-number">$($staleAccounts.Count)</div>
        <div class="stat-label">Stale Accounts</div>
      </div>
    </div>
"@

    if ($alerts.Count -gt 0) {
        $html += @"
    <div style="background: #fff3cd; border: 1px solid #ffeaa7; border-radius: 5px; padding: 20px; margin: 20px 0;">
      <h3 style="color: #856404; margin-top: 0;">🚨 Security Alerts</h3>
      <ul style="color: #856404; margin-bottom: 0;">
"@
        foreach ($alert in $alerts) {
            $html += "        <li>$alert</li>`n"
        }
        $html += "      </ul></div>`n"
    }

    $html += @"
    <div class="dashboard-grid">
      <div class="chart-section">
        <div class="chart-title">Account Control Flags</div>
        <div class="chart-container">
          <canvas id="flagsChart"></canvas>
        </div>
      </div>
      <div class="chart-section">
        <div class="chart-title">Privileged Groups</div>
        <div class="chart-container">
          <canvas id="groupsChart"></canvas>
        </div>
      </div>
    </div>
    
    <div style="text-align: center; margin: 30px 0;">
      <button class="export-btn" onclick="exportFlagsCSV()">Export Flags CSV</button>
      <button class="export-btn" onclick="exportGroupsCSV()">Export Groups CSV</button>
      <button class="export-btn" onclick="window.print()">Print Report</button>
    </div>
    
    <h2 style="color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px;">Account Control Flags</h2>
    <table>
      <tr><th>Flag</th><th>Risk</th><th>Description</th><th>Count</th><th>Sample Accounts</th></tr>
"@

    foreach ($item in $flagsData) {
        $riskClass = switch ($item.RiskLevel) {
            "Critical" { "badge-critical" }
            "High" { "badge-high" }
            "Medium" { "badge-medium" }
            default { "badge-low" }
        }
        
        $samples = if ($item.Accounts.Count -gt 5) {
            ($item.Accounts[0..4] -join ", ") + ", ... (+$($item.Accounts.Count - 5) more)"
        } elseif ($item.Accounts.Count -eq 0) {
            "(none)"
        } else {
            $item.Accounts -join ", "
        }
        
        $html += @"
      <tr>
        <td><strong>$($item.Flag)</strong></td>
        <td><span class="risk-badge $riskClass">$($item.RiskLevel)</span></td>
        <td>$($item.Description)</td>
        <td style="text-align:right"><strong>$($item.Count)</strong></td>
        <td>$samples</td>
      </tr>
"@
    }

    $html += @"
    </table>
    
    <h2 style="color: #2c3e50; border-bottom: 2px solid #e74c3c; padding-bottom: 10px;">Privileged Groups</h2>
    <table>
      <tr><th>Group</th><th>Risk</th><th>Description</th><th>Enabled</th><th>Disabled</th><th>Sample Members</th></tr>
"@

    foreach ($item in $privilegedData) {
        $riskClass = switch ($item.RiskLevel) {
            "Critical" { "badge-critical" }
            "High" { "badge-high" }
            "Medium" { "badge-medium" }
            default { "badge-low" }
        }
        
        $samples = if ($item.MemberNames.Count -gt 5) {
            ($item.MemberNames[0..4] -join ", ") + ", ... (+$($item.MemberNames.Count - 5) more)"
        } elseif ($item.MemberNames.Count -eq 0) {
            "(none)"
        } else {
            $item.MemberNames -join ", "
        }
        
        $html += @"
      <tr>
        <td><strong>$($item.GroupName)</strong></td>
        <td><span class="risk-badge $riskClass">$($item.RiskLevel)</span></td>
        <td>$($item.Description)</td>
        <td style="text-align:right"><strong>$($item.EnabledMembers)</strong></td>
        <td style="text-align:right">$($item.DisabledMembers)</td>
        <td>$samples</td>
      </tr>
"@
    }
    $html += "</table>"

    # Add stale accounts if any
    if ($staleAccounts.Count -gt 0) {
        $html += @"
    <h2 style="color: #2c3e50; border-bottom: 2px solid #f39c12; padding-bottom: 10px;">⚠️ Stale Accounts (Top 20)</h2>
    <table>
      <tr><th>Account</th><th>Last Logon</th><th>Password Set</th><th>Days Inactive</th></tr>
"@
        foreach ($account in ($staleAccounts | Select-Object -First 20)) {
            $lastLogon = if ($account.LastLogonDate) { $account.LastLogonDate.ToString('yyyy-MM-dd') } else { "Never" }
            $passwordSet = if ($account.PasswordLastSet) { $account.PasswordLastSet.ToString('yyyy-MM-dd') } else { "Unknown" }
            $daysInactive = if ($account.LastLogonDate) { [math]::Round((Get-Date).Subtract($account.LastLogonDate).TotalDays) } else { "Never" }
            
            $html += @"
      <tr>
        <td>$($account.SamAccountName)</td>
        <td>$lastLogon</td>
        <td>$passwordSet</td>
        <td>$daysInactive</td>
      </tr>
"@
        }
        $html += "</table>"
    }

    # JavaScript for charts
    $html += @"
  </div>
  <script>
    window.addEventListener('load', function() {
      // Flags chart data
      var flagsLabels = [
"@

    foreach ($item in $flagsData) {
        $cleanFlag = $item.Flag -replace "'", "\\'"
        $html += "        '$cleanFlag',`n"
    }

    $html += "      ];"
    $html += "`n      var flagsCounts = ["

    foreach ($item in $flagsData) {
        $html += "$($item.Count),"
    }

    $html += "];"
    $html += "`n      var flagsColors = ["

    foreach ($item in $flagsData) {
        $color = switch ($item.RiskLevel) {
            "Critical" { "#d32f2f" }
            "High" { "#f44336" }
            "Medium" { "#ff9800" }
            default { "#4caf50" }
        }
        $html += "'$color',"
    }

    $html += @"
      ];

      // Groups chart data
      var groupsLabels = [
"@

    foreach ($item in $privilegedData) {
        $cleanGroup = $item.GroupName -replace "'", "\\'"
        $html += "        '$cleanGroup',`n"
    }

    $html += "      ];"
    $html += "`n      var groupsCounts = ["

    foreach ($item in $privilegedData) {
        $html += "$($item.EnabledMembers),"
    }

    $html += "];"
    $html += "`n      var groupsColors = ["

    foreach ($item in $privilegedData) {
        $color = switch ($item.RiskLevel) {
            "Critical" { "#d32f2f" }
            "High" { "#f44336" }
            "Medium" { "#ff9800" }
            default { "#4caf50" }
        }
        $html += "'$color',"
    }

    $html += @"
      ];

      // Create charts
      try {
        var flagsCtx = document.getElementById('flagsChart');
        new Chart(flagsCtx, {
          type: 'bar',
          data: {
            labels: flagsLabels,
            datasets: [{
              data: flagsCounts,
              backgroundColor: flagsColors.map(c => c + '80'),
              borderColor: flagsColors,
              borderWidth: 2
            }]
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: { 
              y: { 
                beginAtZero: true,
                ticks: {
                  stepSize: 1,
                  callback: function(value) {
                    if (Number.isInteger(value)) {
                      return value;
                    }
                  }
                }
              } 
            }
          }
        });

        var groupsCtx = document.getElementById('groupsChart');
        new Chart(groupsCtx, {
          type: 'bar',
          data: {
            labels: groupsLabels,
            datasets: [{
              data: groupsCounts,
              backgroundColor: groupsColors.map(c => c + '80'),
              borderColor: groupsColors,
              borderWidth: 2
            }]
          },
          options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: { 
              x: { 
                beginAtZero: true,
                ticks: {
                  stepSize: 1,
                  callback: function(value) {
                    if (Number.isInteger(value)) {
                      return value;
                    }
                  }
                }
              } 
            }
          }
        });
      } catch (e) {
        console.error('Chart error:', e);
      }
    });

    function exportFlagsCSV() {
      var csv = 'Flag,Risk,Description,Count\\n';
      for (var i = 0; i < flagsLabels.length; i++) {
        csv += flagsLabels[i] + ',' + flagsColors[i] + ',Flag ' + i + ',' + flagsCounts[i] + '\\n';
      }
      downloadCSV(csv, 'AD_Flags.csv');
    }

    function exportGroupsCSV() {
      var csv = 'Group,Risk,Members\\n';
      for (var i = 0; i < groupsLabels.length; i++) {
        csv += groupsLabels[i] + ',' + groupsColors[i] + ',' + groupsCounts[i] + '\\n';
      }
      downloadCSV(csv, 'AD_Groups.csv');
    }

    function downloadCSV(csv, filename) {
      var blob = new Blob([csv], {type: 'text/csv'});
      var url = URL.createObjectURL(blob);
      var a = document.createElement('a');
      a.href = url;
      a.download = filename;
      a.click();
      URL.revokeObjectURL(url);
    }
  </script>
</body>
</html>
"@

    # Save files
    $outputDir = $CONFIG.OutputDirectory
    $dashboardPath = "$outputDir\AD_Security_Dashboard_$dateSuffix.html"
    $html | Out-File -FilePath $dashboardPath -Encoding utf8
    Write-Log "HTML dashboard saved to: $dashboardPath"

    # Generate markdown report
    $mdContent = @"
# AD Security Audit Report

**Generated:** $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  
**Domain:** $($domain.DNSRoot)  

## Summary
- **Flagged Accounts:** $totalFlagged
- **Privileged Users:** $totalPrivileged  
- **High Risk Flags:** $highRiskFlags
- **Critical Groups:** $criticalGroups
- **Stale Accounts:** $($staleAccounts.Count)

## Account Control Flags
| Flag | Risk | Count | Description |
|------|------|-------|-------------|
"@

    foreach ($item in $flagsData) {
        $mdContent += "| $($item.Flag) | $($item.RiskLevel) | $($item.Count) | $($item.Description) |`n"
    }

    $mdContent += @"

## Privileged Groups
| Group | Risk | Enabled | Description |
|-------|------|---------|-------------|
"@

    foreach ($item in $privilegedData) {
        $mdContent += "| $($item.GroupName) | $($item.RiskLevel) | $($item.EnabledMembers) | $($item.Description) |`n"
    }

    if ($alerts.Count -gt 0) {
        $mdContent += "`n## Alerts`n"
        foreach ($alert in $alerts) {
            $mdContent += "- $alert`n"
        }
    }

    $mdPath = "$outputDir\AD_Security_Report_$dateSuffix.md"
    $mdContent | Out-File -FilePath $mdPath -Encoding utf8

    # Export CSV files
    $flagsData | Export-Csv -Path "$outputDir\AD_Flags_$dateSuffix.csv" -NoTypeInformation
    $privilegedData | Export-Csv -Path "$outputDir\AD_Groups_$dateSuffix.csv" -NoTypeInformation

    if ($staleAccounts.Count -gt 0) {
        $staleAccounts | Select-Object SamAccountName, LastLogonDate, PasswordLastSet, Enabled |
            Export-Csv -Path "$outputDir\AD_Stale_$dateSuffix.csv" -NoTypeInformation
    }

    # Open reports
    Open-InBrowser -FilePath $dashboardPath
    Open-InBrowser -FilePath $mdPath

    # Send email if configured
    Send-EmailReport -HtmlPath $dashboardPath -Summary "AD audit completed"

    # Display results
    Write-Host "`n=== AD SECURITY AUDIT COMPLETED ===" -ForegroundColor Green
    Write-Host "📊 Summary:" -ForegroundColor Yellow
    Write-Host "  Flagged Accounts: $totalFlagged" -ForegroundColor $(if($totalFlagged -eq 0){'Green'}else{'Yellow'})
    Write-Host "  Privileged Users: $totalPrivileged" -ForegroundColor $(if($totalPrivileged -lt $CONFIG.MaxPrivilegedUsers){'Green'}else{'Red'})
    Write-Host "  High Risk Flags: $highRiskFlags" -ForegroundColor $(if($highRiskFlags -eq 0){'Green'}else{'Red'})
    Write-Host "  Critical Groups: $criticalGroups" -ForegroundColor $(if($criticalGroups -eq 0){'Green'}else{'Red'})
    Write-Host "  Stale Accounts: $($staleAccounts.Count)" -ForegroundColor $(if($staleAccounts.Count -eq 0){'Green'}else{'Yellow'})
    
    if ($alerts.Count -gt 0) {
        Write-Host "`n🚨 ALERTS:" -ForegroundColor Red
        foreach ($alert in $alerts) {
            Write-Host "  $alert" -ForegroundColor Red
        }
    } else {
        Write-Host "`n✅ No critical alerts!" -ForegroundColor Green
    }

    Write-Host "`n📁 Files Generated:" -ForegroundColor Cyan
    Write-Host "  HTML Dashboard: $dashboardPath" -ForegroundColor White
    Write-Host "  Markdown Report: $mdPath" -ForegroundColor White
    Write-Host "  Flags CSV: $outputDir\AD_Flags_$dateSuffix.csv" -ForegroundColor White
    Write-Host "  Groups CSV: $outputDir\AD_Groups_$dateSuffix.csv" -ForegroundColor White
    if ($staleAccounts.Count -gt 0) {
        Write-Host "  Stale Accounts CSV: $outputDir\AD_Stale_$dateSuffix.csv" -ForegroundColor White
    }
    Write-Host "  Log File: $logPath" -ForegroundColor White
    
    Write-Host "`n🎯 Next Steps:" -ForegroundColor Magenta
    if ($criticalGroups -gt 0) {
        Write-Host "  1. 🔴 URGENT: Review critical group memberships" -ForegroundColor Red
    }
    if ($highRiskFlags -gt 0) {
        Write-Host "  2. ⚠️ Address high-risk account flags" -ForegroundColor Yellow
    }
    if ($staleAccounts.Count -gt 10) {
        Write-Host "  3. 🧹 Clean up stale accounts" -ForegroundColor Yellow
    }
    Write-Host "  4. 📅 Schedule regular audits (monthly recommended)" -ForegroundColor Cyan

    Write-Log "Audit completed successfully"

}
catch {
    Write-Log "Critical error: $($_.Exception.Message)" "Error"
    Write-Host "`n❌ ERROR:" -ForegroundColor Red
    Write-Host "  $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "  Check log: $logPath" -ForegroundColor Yellow
    
    Write-Host "`n🔧 Troubleshooting:" -ForegroundColor Cyan
    Write-Host "  • Ensure ActiveDirectory module is installed" -ForegroundColor White
    Write-Host "  • Run with AD read permissions" -ForegroundColor White
    Write-Host "  • Check domain controller connectivity" -ForegroundColor White
    
    throw
}

# Optional: Create scheduled task function
function New-ADAuditScheduledTask {
    param(
        [string]$ScriptPath = $MyInvocation.MyCommand.Path,
        [string]$TaskName = "AD Security Audit",
        [ValidateSet("Daily","Weekly","Monthly")]
        [string]$Schedule = "Monthly"
    )
    
    try {
        $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -File `"$ScriptPath`""
        
        $trigger = switch ($Schedule) {
            "Daily"   { New-ScheduledTaskTrigger -Daily -At "6:00 AM" }
            "Weekly"  { New-ScheduledTaskTrigger -Weekly -At "6:00 AM" -DaysOfWeek Monday }
            "Monthly" { New-ScheduledTaskTrigger -Weekly -WeeksInterval 4 -At "6:00 AM" -DaysOfWeek Monday }
        }
        
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
        
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force
        
        Write-Host "✅ Scheduled task '$TaskName' created for $Schedule execution" -ForegroundColor Green
        Write-Host "   Task will run as SYSTEM with highest privileges" -ForegroundColor Cyan
        Write-Host "   Use 'Get-ScheduledTask -TaskName `"$TaskName`"' to verify" -ForegroundColor Cyan
    }
    catch {
        Write-Host "❌ Failed to create scheduled task: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "   Try running as Administrator" -ForegroundColor Yellow
    }
}

# Uncomment to create a monthly scheduled task
# New-ADAuditScheduledTask -Schedule "Monthly"

Write-Host "`n💡 Tips:" -ForegroundColor Green
Write-Host "• Edit CONFIG section at top to customize settings" -ForegroundColor White
Write-Host "• Configure SMTP settings for email reports" -ForegroundColor White
Write-Host "• Uncomment last line to auto-create scheduled task" -ForegroundColor White
Write-Host "• Run with -Verbose for detailed output" -ForegroundColor White
