# M57-Jean — Corporate Espionage Investigation

A disk forensics investigation into suspected data exfiltration by a corporate executive. Conducted using FTK Imager on a real forensic image from Digital Corpora; documented in accordance with RFC 3227.

---

## Scenario

Jean Jones; CFO of M57.biz; was suspected of stealing sensitive company data from her work laptop. A forensic disk image of her machine was submitted to the laboratory for examination. The case mirrors real-world insider threat scenarios involving privileged access abuse and data theft.

---

## Objective

- Maintain a proper chain of custody compliant with RFC 3227
- Acquire and verify a forensic disk image using FTK Imager
- Analyse recovered artefacts for presentation in a court of law

---

## Evidence Collection

| Field | Details |
|---|---|
| Evidence | nps-2009-m57-jean.E01 / .E02 |
| Source | Digital Corpora |
| File System | NTFS |
| Partition Size | 10;228 MB |
| Suspect OS | Windows XP SP3 |
| Tool | FTK Imager 8.2.0.59 SP1 |

**Hash Verification — Pre-Analysis (RFC 3227)**

| File | Algorithm | Hash |
|---|---|---|
| nps-2009-m57-jean.E01 | MD5 |647F22836426E071D8E1CCAC6DA54BAF |
| nps-2009-m57-jean.E01 | SHA256 | DF3A995C7A594E0BA6D95B9AAE735A444313FAE435A87E7536F9DAD3DB2769CE |
| nps-2009-m57-jean.E02 | MD5 | E8845C20BDD2C24E734B7C0BCD1A8EAB |
| nps-2009-m57-jean.E02 | SHA256 | 07F1F78C857D5B5809AC7A68E1467D36872FA74F047EE2C799D37B18AAD4F5AA |

All analysis was performed on a working copy. The original image was never modified.

---

## Analysis

Navigated to `\Documents and Settings\Jean\Desktop` and recovered the following artefacts:

**m57biz.xls**
Found on Jean's desktop. The file contains the full M57.biz employee directory — names; positions; salaries; and Social Security Numbers. Metadata showed it was originally created by Alison Smith (President) on 12 June 2008 and last saved by Jean User at 01:28 AM on 20 July 2008 — an unusual hour.

**IPH.PH**
An AOL Instant Messenger (AIM v6.8.10.1) installer log found at the root level. AIM was installed at 04:26 AM on 18 July 2008 — two days before the spreadsheet was last saved. Two AIM sessions ran within minutes of installation. AIM supports direct file transfer; making it the likely exfiltration channel.

**Wiped log files**
`msmqinst.log` and `WindowsUpdate.log` were both 0 KB — consistent with deliberate log clearing to conceal activity after the fact.

**Artefact Integrity**

| Artefact | MD5 | SHA256 |
|---|---|---|
| m57biz.xls | `E23A4EB7F2562F53E88C9DCA8B26A153` | `34456B5F714DC9D8DD23C742D54C3F5F582ECB042BC1C4D3042B88203863779F` |

---

## Findings

Jean Jones is not innocent.

The evidence tells a clear story. Jean accessed a confidential HR spreadsheet containing every employee's salary and SSN — a file she had no business reason to save to her personal desktop. She installed a consumer messaging app capable of file transfers at 4 AM and ran two sessions within minutes. Two days later she saved the spreadsheet at 1:28 AM. After the fact; system log files were wiped.

**Attack Timeline**

| Date | Time (UTC) | Event |
|---|---|---|
| 12 June 2008 | 15:13 | Alison Smith creates m57biz.xls |
| 18 July 2008 | 04:26 | Jean installs AIM; runs two sessions |
| 20 July 2008 | 01:28 | Jean saves m57biz.xls to her desktop |
| Post July 2008 | — | Log files wiped; system entries deleted |

---

## MITRE ATT&CK Mapping

| Technique ID | Name | Observation |
|---|---|---|
| T1005 | Data from Local System | m57biz.xls recovered from Jean's desktop |
| T1048.003 | Exfiltration over Unencrypted Protocol | AIM used to transfer file externally |
| T1070.004 | File Deletion | System logs wiped post-exfiltration |
| T1078 | Valid Accounts | Jean used her own CFO credentials throughout |

---

## Recommendations

1. **DLP controls** — Flag and block copying of files containing SSNs or salary data to personal desktops
2. **File access auditing** — Audit logs on sensitive directories would have flagged the 1:28 AM access immediately
3. **Least privilege** — CFOs should not have unrestricted access to all HR data
4. **Endpoint monitoring** — A SIEM would detect off-hours logins and unauthorised application installs
5. **Block consumer messaging apps** — AIM; WhatsApp; Telegram and similar tools should be restricted on corporate endpoints

---

## Tools Used

| Tool | Purpose |
|---|---|
| FTK Imager 8.2.0.59 SP1 | Disk image acquisition; verification; and artefact analysis |
| Microsoft Excel | Spreadsheet content and metadata examination |
| PowerShell — Get-FileHash | Hash verification (MD5; SHA256) |

---

*Standard: RFC 3227 — Guidelines for Evidence Collection and Archiving*
