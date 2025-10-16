# Intune Policy Change Report

PowerShell runbook that monitors Microsoft Intune policy changes and sends an HTML + CSV report via email.

<img width="2769" height="1241" alt="image" src="https://github.com/user-attachments/assets/c332f307-a874-4b60-92a6-e1619ac0191d" />



---

## 🧭 Overview

This script connects to Microsoft Graph (using managed identity) and retrieves audit logs for Intune policies over a configurable lookback period. It transforms the raw data into a reader-friendly HTML summary plus a full CSV export, resolves group GUIDs to display names (if available), and emails it to stakeholders.

Key features:

- Aggregates changes across **Settings Catalog**, **Custom configuration profiles**, **Compliance policies**, **Security baselines**, **App protection/configuration policies**, and scripts  
- Friendly labels for actions, properties, and severity (High / Medium / Low)  
- Automatic **GUID → group name** resolution for assignment changes (with Include/Exclude)  
- Dark-themed HTML email with KPIs, legend, and 10 most recent changes  
- CSV download attachment (UTF-8 + BOM) for deeper analysis  
- Configurable lookback (`DaysBack`) and optional “only modifications” mode  
- Fully runs in Azure Automation using Managed Identity — no secrets needed  

---

## 🎯 Purpose

Provide visibility and auditability into Intune policy changes:

- **What changed**, **when**, and **by whom**  
- Quickly flag risky actions (deletions, failures)  
- Make assignment changes human‐readable  
- Retain a detailed CSV for archive, review, or trend analysis  
- Automate reporting with minimal maintenance  

---

## ⚙️ Prerequisites

- Azure Automation Account with **System-Assigned Managed Identity**  
- Service mailbox or shared mailbox (e.g. `ITAutomation@yourcompany.com`)  
- The following Graph API application permissions granted to the Automation Identity:
  - `DeviceManagementConfiguration.Read.All`
  - `DeviceManagementApps.Read.All`
  - `Group.Read.All`
  - `Mail.Send`
  - (Optional/tenant-dependent: `Directory.Read.All`, `AuditLog.Read.All`)  
- Modules loaded in Automation: at minimum `Az.Accounts`, `Az.Resources`, and Graph modules or HTTP invocation capability  

---

## 🚀 Installation

1. Create or use an existing Azure Automation Account.  
2. Enable the **System-Assigned Managed Identity** on the Automation Account.  
3. Assign Graph permissions (see Prerequisites) to the managed identity in Entra ID / Azure AD.  
4. Add a new **PowerShell runbook** and paste the script. Publish it.  
5. Update default recipients and sender mailbox inside the script (see Configuration).  
6. Add a schedule (e.g. "monthly, last day at 11:55 AM ET") to trigger the runbook.

---

## 🛠 Configuration

Inside the script, locate and adjust:

- Default **EmailRecipient** in the `param()` block (line ~ where `$EmailRecipient` is defined)  
- The `sendMail` endpoint (`$emailUri`) — set to your service mailbox or shared account  
- Optionally adjust default `DaysBack`, or toggle `OnlyShowChanges` for filtered runs  

All other parts (token fetching, paging, HTML generation) are handled automatically.

---

## 📥 Usage Examples

<pre><code class="language-powershell">
# Default run (last 30 days)
.\IntunePolicyChangeReport.ps1

# Last 7 days, send to two recipients
.\IntunePolicyChangeReport.ps1 -DaysBack 7 -EmailRecipient "admin1@company.com,admin2@company.com"

# Only show modifications (exclude creates/deletes)
.\IntunePolicyChangeReport.ps1 -OnlyShowChanges
</code></pre>

## 📊 Report Output

✅ **HTML Email (dark theme)**  
- KPI summary (Total / High / Medium / Low / Unique Policies)  
- Legend for actions & severity  
- 10 most recent changes with:  
  - Icons (➕ ✏️ 🗑️ 👤 📝)  
  - Severity colors & left-border emphasis  
  - Policy name, user, timestamp, result  
  - Modified properties (friendly names)  
  - Assignment changes with resolved group names  

✅ **CSV Attachment (full dataset)**  
- UTF-8 with BOM (Excel friendly)  
- Columns:  
  - `DateTime`  
  - `PolicyName`  
  - `PolicyType`  
  - `PolicyId`  
  - `Action`  
  - `User`  
  - `Result`  
  - `Severity`  
  - `Details`  

---

## 🌡️ Severity Levels

| Severity | Description |
|----------|-------------|
|🔴 **High** | Policy deletion or failed action |
|🟠 **Medium** | Policy created or updated |
|🟢 **Low** | Assignment changes (add/remove/include/exclude) |

---

## 👥 Group Resolution (Friendly Names)

When assignment JSON includes GUIDs, the script:

1. Extracts GUIDs using regex  
2. Queries Microsoft Graph: `/v1.0/groups/{id}?$select=displayName`  
3. Caches names to reduce API calls  
4. Detects Include vs Exclude based on JSON context  
5. Outputs readable format, e.g.:  
   - `Include: Finance Laptops`  
   - `Exclude: Contractors (not found)`  

---

## ✅ Severity Logic Summary

- Failed action → **High**
- Delete policy → **High**
- Create/Update policy → **Medium**
- Assignment add/remove/update → **Low**
- Delete assignment only → **Low**

---

## 🧠 How It Works (High-Level Flow)

1. Authenticate to Microsoft Graph using Managed Identity  
2. Calculate `startDate = Now - DaysBack`  
3. Retrieve all audit events from:
   - DeviceConfiguration  
   - Compliance  
   - DeviceIntent (Security Baselines)  
   - Application (App Protection / Configuration, filtering out MobileApp noise)  
4. Normalize and enrich data (policy name, user, severity, friendly action)  
5. Resolve group GUIDs to names in assignment change details  
6. Build:
   - HTML summary (top 10 changes + KPIs + legend)  
   - CSV export (full dataset)  
7. Email both (HTML inline + CSV attachment)  

---

## 📅 Scheduling Recommendation

**Azure Automation Schedule Example:**
- Frequency: Monthly  
- Day: Last  
- Time: 11:55 AM (Eastern Time)  
- Runbook: `IntunePolicyChangeReport`  
- Parameters:
  - `DaysBack = 30`
  - `EmailRecipient = "you@company.com"`

---

## 🧪 Testing Locally

To test outside Azure Automation:

```powershell
# Temporarily disable the environment check:
# if (-not $PSPrivateMetadata.JobId.Guid) { ... }

# Sign in manually
Connect-MgGraph -Scopes "DeviceManagementConfiguration.Read.All","DeviceManagementApps.Read.All","Group.Read.All","Mail.Send"
```

> ✅ Remember to re-enable the environment check before publishing!

---

## ❓ Support & FAQ

### Common Issues

**Q: Scripts fail with authentication errors**
A: Ensure you have the required Microsoft Graph permissions and modules installed.

**Q: Can I use these scripts with GCC High/DoD tenants?**
A: Yes, but you may need to modify the Graph API endpoints for government clouds.

**Q: Are these scripts suitable for production use?**
A: Yes, but always test in a lab environment first and follow your organization's change management processes.

## 🤝 Contributing

Pull requests and improvements are welcome!  
Feel free to submit PRs for:
- New policy types
- UI/report enhancements
- Performance optimizations
- Bug fixes

---

## 🙏 Thanks & Inspiration

This runbook was inspired by the excellent **Policy Changes Monitor** script created by **Uğur Koç**:  
https://www.intuneautomation.com/scripts?script=policy-changes-monitor

Uğur’s work in the Intune automation space (via **IntuneAutomation.com** and his GitHub projects) helped shape the idea, structure, and reporting style used here. 
His contributions to the community are outstanding, and this project builds on many of the same goals:

✅ Better visibility into Intune changes  
✅ Automated reporting for governance and compliance  
✅ Making raw audit data human-readable  
✅ Sharing practical, real-world Intune solutions with the community

---

## 🧾 License

This project is licensed under the **GNU General Public License v3.0**.  
See the [LICENSE](./LICENSE) file for details.

[![PowerShell](https://img.shields.io/badge/PowerShell-7.x-blue.svg)](https://github.com/PowerShell/PowerShell)  
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](./LICENSE)

---

## 👤 Author

**Eddie Jimenez**  
- [![GitHub](https://img.shields.io/badge/GitHub-eddie--jimenez-black?logo=github&logoColor=white)](https://github.com/eddie-jimenez)  
- [![LinkedIn](https://img.shields.io/badge/LinkedIn-eddie_p_jimenez-blue?logo=linkedin&logoColor=white)](https://www.linkedin.com/in/eddie-p-jimenez/)


---

<p align="center">
  <strong>⭐ If this project helps you, please give it a star! ⭐</strong>
</p>







