# ActiveDirectory_Flag_Scanner

## Active Directory Flags Dashboard & Report Script

### Description

This PowerShell script connects to your Active Directory environment, inspects a predefined set of `userAccountControl` flags on user objects, and produces two complementary outputs: an interactive HTML dashboard and a timestamped Markdown report. The HTML dashboard uses Chart.js to display each flag as a uniquely colored bar and includes a detailed table of affected accounts. The Markdown report mirrors the same data in a text-friendly format for version control or quick review.

### Detailed Workflow

1. Flag Definition and Metadata  
   - A hashtable (`$flags`) maps six common AD flags (Disabled, Locked-out, Password never expires, etc.) to their numeric bit values and descriptive labels.

2. Data Collection  
   - For each defined flag, the script runs `Get-ADUser -Filter "userAccountControl -band <BitValue>"` to count matching accounts and gather their `SamAccountName`s.

3. JSON Conversion  
   - Converts the collected data into JSON (`$jsonData`) for seamless integration with Chart.js on the front end.

4. HTML Dashboard Generation  
   - Builds a self-contained HTML file that:
     - Loads Chart.js from a CDN.
     - Renders a bar chart with distinct RGBA colors for each flag.
     - Attaches tooltips listing individual accounts per bar.
     - Displays a static HTML table of flags, counts, and account names.
   - Saves the file as `C:\Temp\AD_Flags_Dashboard.html` and launches it in your default browser.

5. Markdown Report Generation  
   - Constructs a Markdown table duplicating the HTML table’s contents.
   - Names the output `AD_Flags_Report_YYYYddMM.md` (with today’s date) under `C:\Temp`.
   - Opens the Markdown file in Edge (if installed) or your default Markdown viewer.

### Outputs

- `C:\Temp\AD_Flags_Dashboard.html`  
  Interactive, chart-driven dashboard with per-flag counts and account lists.

- `C:\Temp\AD_Flags_Report_YYYYddMM.md`  
  Versionable Markdown report summarizing the same data in table form.

### Customization Points

- Modify the `$flags` hashtable to add, remove, or rename AD flags.  
- Change the output paths (`$dashboardPath` and `$mdPath`) to suit your environment.  
- Tweak the `bgColors` and `borderColors` arrays in the Chart.js section to adjust bar colors.  

### Prerequisites

- PowerShell (5.1+) with the ActiveDirectory module installed.  
- Read permissions on user objects in your AD domain.  
- Internet access (or local copy) to load Chart.js for the HTML dashboard.  
