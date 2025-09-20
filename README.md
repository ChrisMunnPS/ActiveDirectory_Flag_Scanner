# Active Directory Security Audit Script

## Executive Summary

This PowerShell script provides **automated security auditing** for Microsoft Active Directory environments. It identifies potential security risks, generates professional reports with visual dashboards, and helps organizations maintain compliance with security best practices.

**Key Business Value:**
- 🛡️ **Proactive Security**: Identifies vulnerabilities before they become breaches
- 📊 **Executive Reporting**: Clear dashboards and metrics for leadership
- 🤖 **Automation Ready**: Reduces manual audit time from days to minutes
- 📈 **Compliance Support**: Helps meet regulatory requirements and security frameworks

---

## What It Does

The script automatically scans your Active Directory and generates comprehensive security reports identifying:

- **High-Risk Account Configurations** (weak passwords, excessive privileges)
- **Privileged User Analysis** (Domain Admins, critical groups)
- **Stale Account Detection** (inactive users that should be disabled)
- **Service Account Inventory** (special accounts requiring monitoring)

## Sample Output

### Interactive Dashboard
![Dashboard Preview](https://github.com/ChrisMunnPS/ActiveDirectory_Flag_Scanner/blob/main/AD%20Security%20Dashboard%20Example.png)

### Executive Summary Report
```
📊 AD SECURITY AUDIT SUMMARY
• Total Flagged Accounts: 23
• Privileged Users: 8
• High Risk Flags: 3
• Critical Groups: 2 groups need review
• Stale Accounts: 15 accounts inactive 90+ days

🚨 CRITICAL ALERTS:
• High privileged user count: 12 (threshold: 10)
• Critical groups with members: 2 groups need immediate review
```

---

## Technical Details

### Requirements
- **Windows Server/Client** with PowerShell 5.1+
- **Active Directory PowerShell Module**
- **Domain Read Permissions** for the executing user
- **Network Access** to Domain Controllers

### Features
- ✅ **8 Security Flag Checks** (account control settings)
- ✅ **9 Privileged Group Analysis** (Domain Admins, Enterprise Admins, etc.)
- ✅ **Interactive Charts** (Chart.js powered visualizations)
- ✅ **Multiple Export Formats** (HTML, Markdown, CSV)
- ✅ **Email Reports** (SMTP configuration)
- ✅ **Automated Scheduling** (Task Scheduler integration)
- ✅ **Configurable Thresholds** (customize alerting levels)

### Security Checks Performed

| Category | Check | Risk Level |
|----------|-------|------------|
| **Account Flags** | Password Not Required | High |
| | No Kerberos Pre-Auth | High |
| | Weak DES Encryption | High |
| | Trusted for Delegation | High |
| | Password Never Expires | Medium |
| | Account Disabled | Low |
| **Privileged Groups** | Domain Admins | Critical |
| | Enterprise Admins | Critical |
| | Schema Admins | Critical |
| | Account/Server Operators | High |
| **Account Health** | Stale Accounts (90+ days) | Medium |
| | Service Account Detection | Info |

---

## Quick Start

### 1. Basic Execution
```powershell
# Run with default settings
.\AD-Security-Audit.ps1
```

### 2. Configure Settings
Edit the `$CONFIG` section at the top of the script:
```powershell
$CONFIG = @{
    # Email settings (optional)
    SmtpServer     = "smtp.company.com"
    EmailFrom      = "security@company.com"
    EmailTo        = "admin@company.com"
    
    # Alerting thresholds
    MaxPrivilegedUsers = 10
    StaleAccountDays   = 90
    
    # Output preferences
    OutputDirectory = "C:\Reports\AD_Security"
}
```

### 3. Automated Scheduling
```powershell
# Create monthly scheduled task (run as Administrator)
New-ADAuditScheduledTask -Schedule "Monthly"
```

---

## Output Files

The script generates multiple report formats:

| File Type | Purpose | Audience |
|-----------|---------|----------|
| **HTML Dashboard** | Interactive charts and tables | Technical teams, Management |
| **Markdown Report** | Executive summary with recommendations | Leadership, Compliance |
| **CSV Exports** | Raw data for analysis | Security analysts, Auditors |
| **Log Files** | Detailed execution logs | IT Operations, Troubleshooting |

### Sample File Names
```
AD_Security_Dashboard_20241220_1430.html
AD_Security_Report_20241220_1430.md
AD_Flags_20241220_1430.csv
AD_Groups_20241220_1430.csv
AD_Stale_20241220_1430.csv
AD_Audit_Log_20241220_1430.txt
```

---

## Advanced Configuration

### Email Notifications
Configure SMTP settings for automated report delivery:
```powershell
$CONFIG = @{
    SmtpServer = "smtp.office365.com"
    SmtpPort   = 587
    EmailFrom  = "security-reports@company.com"
    EmailTo    = "security-team@company.com;management@company.com"
    UseSSL     = $true
}
```

### Custom Thresholds
Adjust alerting levels for your environment:
```powershell
$CONFIG = @{
    MaxPrivilegedUsers = 15      # Alert if more privileged users
    MaxHighRiskFlags   = 5       # Alert if multiple risk flags
    StaleAccountDays   = 60      # Consider accounts stale after 60 days
}
```

### Analysis Options
Enable/disable specific checks:
```powershell
$CONFIG = @{
    AnalyzeStaleAccounts = $true   # Find inactive accounts
    CheckServiceAccounts = $true   # Identify service accounts
    KeepReportsForDays   = 90     # Retention policy
}
```

---

## Troubleshooting

### Common Issues

**Permission Denied**
- Ensure account has Domain Read permissions
- Run PowerShell as Administrator if creating scheduled tasks

**Module Not Found**
```powershell
# Install Active Directory module
Install-WindowsFeature RSAT-AD-PowerShell
# Or on Windows 10/11
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools
```

**Charts Not Displaying**
- Verify internet connection (CDN access required)
- Try different browser
- Check browser console for JavaScript errors

**Email Reports Failing**
- Verify SMTP settings and credentials
- Check firewall/network connectivity
- Test with simple Send-MailMessage command first

---

## Security Considerations

- **Read-Only Access**: Script only requires AD read permissions
- **No Data Modification**: Script never changes AD objects
- **Sensitive Data**: Reports may contain privileged account names
- **Network Traffic**: Minimal impact on domain controllers
- **Audit Logging**: All actions logged for compliance

---

## Use Cases

### 🏢 Enterprise Security
- Monthly security posture assessments
- Compliance reporting (SOX, PCI-DSS, etc.)
- Risk management dashboards
- Incident response preparation

### 🔍 Security Operations
- Privileged access governance
- Account lifecycle management
- Security baseline validation
- Threat hunting preparation

### 📋 Compliance & Audit
- Regulatory requirement evidence
- Internal audit support
- Risk assessment documentation
- Security control validation

---

## Support & Customization

This script can be customized for specific organizational needs:

- **Additional Security Checks**: Add custom AD queries
- **Integration**: Connect with SIEM/monitoring systems
- **Branding**: Customize reports with company logos
- **Automation**: Integrate with CI/CD pipelines

For support or customization requests, refer to your IT security team or system administrators.
---

*This tool helps organizations maintain strong Active Directory security posture through automated monitoring and professional reporting.*
