# Entire script: scan AD flags, build HTML dashboard & Markdown report, open both in browser,
# with each bar in a different color

# 1. Define flags and descriptions
$flags = @{
    AccountDisabled     = @{ Bit = 2;        Description = "Disabled accounts" }
    Lockout             = @{ Bit = 16;       Description = "Locked-out accounts" }
    PasswordNotRequired = @{ Bit = 32;       Description = "Password not required" }
    PasswordCantChange  = @{ Bit = 64;       Description = "Password cannot change" }
    DontExpirePassword  = @{ Bit = 65536;    Description = "Password never expires" }
    DONT_REQ_PREAUTH    = @{ Bit = 4194304;  Description = "No Kerberos PreAuth required" }
}

# 2. Collect data for each flag (including list of SamAccountName)
$dashboardData = foreach ($key in $flags.Keys) {
    $bit     = $flags[$key].Bit
    $filter  = "userAccountControl -band $bit"
    $results = @(Get-ADUser -Filter $filter -Properties SamAccountName)

    [PSCustomObject]@{
        Flag        = $key
        Description = $flags[$key].Description
        Count       = $results.Count
        Accounts    = $results | Select-Object -ExpandProperty SamAccountName
    }
}

# 3. Convert data to JSON for Chart.js
$jsonData = $dashboardData | ConvertTo-Json

# 4. Build HTML dashboard with Chart.js and detailed table
$html = @"
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8" />
  <title>AD Flags Dashboard</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    body { font-family: Arial, sans-serif; margin: 20px; }
    h2 { text-align: center; color: #333; }
    .chart-container { width: 80%; margin: 0 auto; }
    table { width: 80%; margin: 20px auto; border-collapse: collapse; }
    th, td { border: 1px solid #ccc; padding: 8px 12px; vertical-align: top; }
    th { background: #f4f4f4; }
  </style>
</head>
<body>
  <h2>Active Directory Account Control Flags Dashboard</h2>
  <div class="chart-container">
    <canvas id="flagsChart"></canvas>
  </div>
  <table>
    <thead>
      <tr>
        <th>Flag</th>
        <th>Description</th>
        <th>Count</th>
        <th>Accounts</th>
      </tr>
    </thead>
    <tbody>
"@

foreach ($item in $dashboardData) {
    $accountsHtml = $item.Accounts -join "<br>"
    $html += "      <tr>
        <td>$($item.Flag)</td>
        <td>$($item.Description)</td>
        <td style='text-align:right'>$($item.Count)</td>
        <td>$accountsHtml</td>
      </tr>`n"
}

$html += @"
    </tbody>
  </table>
  <script>
    const data = $jsonData;
    const ctx  = document.getElementById('flagsChart').getContext('2d');

    // Define distinct colors for each bar
    const bgColors = [
      'rgba(54, 162, 235, 0.6)',
      'rgba(255, 99, 132, 0.6)',
      'rgba(255, 206, 86, 0.6)',
      'rgba(75, 192, 192, 0.6)',
      'rgba(153, 102, 255, 0.6)',
      'rgba(255, 159, 64, 0.6)'
    ];
    const borderColors = bgColors.map(color => color.replace('0.6', '1'));

    new Chart(ctx, {
      type: 'bar',
      data: {
        labels: data.map(x => x.Flag),
        datasets: [{
          label: 'Account Count',
          data:  data.map(x => x.Count),
          backgroundColor: bgColors,
          borderColor:     borderColors,
          borderWidth: 1,
          accounts: data.map(x => x.Accounts)
        }]
      },
      options: {
        responsive: true,
        plugins: {
          tooltip: {
            callbacks: {
              afterLabel: function(ctx) {
                const accts = ctx.dataset.accounts[ctx.dataIndex];
                return accts.length
                  ? ['','Accounts:'].concat(accts)
                  : ['','(none)'];
              }
            }
          }
        },
        scales: {
          y: { beginAtZero: true }
        }
      }
    });
  </script>
</body>
</html>
"@

# 5. Save and launch HTML dashboard
$dashboardPath = "C:\Temp\AD_Flags_Dashboard.html"
$html | Out-File -FilePath $dashboardPath -Encoding utf8
Start-Process $dashboardPath

# 6. Generate Markdown report with YYYYddMM timestamp in filename
$dateSuffix = Get-Date -Format 'yyyyddMM'
$mdHeader  = "# Active Directory Account Control Flags Report`n`n"
$mdHeader += "Generated on $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n`n"
$mdHeader += "| Flag | Description | Count | Accounts |`n"
$mdHeader += "| --- | --- | ---:| --- |`n"

$mdRows = ""
foreach ($item in $dashboardData) {
    $accountsCsv = $item.Accounts -join ", "
    $mdRows     += "| $($item.Flag) | $($item.Description) | $($item.Count) | $accountsCsv |`n"
}

$mdContent = $mdHeader + $mdRows
$mdPath    = "C:\Temp\AD_Flags_Report_$dateSuffix.md"
$mdContent | Out-File -FilePath $mdPath -Encoding utf8

# 7. Open the Markdown report in browser (Edge if available)
$edge = "msedge.exe"
if (Get-Command $edge -ErrorAction SilentlyContinue) {
  Start-Process $edge -ArgumentList $mdPath
} else {
  Start-Process $mdPath
}
