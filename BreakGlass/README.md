# Break-Glass — Windows Server / RHEL / CyberArk PAM

## Status: draft / pilot required

Implementation in branch feature/break-glass-windows-rhel. **Do not deploy to 300 servers before running the acceptance suite** described in TECHNICAL.md. Repo pcmkr/Tools is currently PUBLIC.

### Requirements
- Local bguser on 150 Windows Server member servers and 150 RHEL hosts.
- Same current password within an OS cohort; **different** passwords across Windows and RHEL.
- One Safe per chosen logical set, **two** native Account Groups (e.g. BG-PROD-WIN, BG-PROD-RHEL).
- No scheduled CPM change; privileged operator supplies a new group password, starts CPM change, validates all members.
- Independent offline escrow and console/out-of-band login when AD/PAM unavailable.

### Files

| File | Purpose |
|---|---|
| TECHNICAL.md | Architecture, implementation, operations, rotation, outage runbook, acceptance tests |
| MANAGEMENT.md | Management explanation, decision points, costs/risks, rollout stages |
| ansible/windows.yml | Create local Windows user and add to Administrators (SID) |
| ansible/rhel.yml | Create local RHEL user, sudo configuration |
| ansible/inventory.example.ini | Non-sensitive example; real inventory stays outside Git |
| ansible/requirements.yml | Ansible collection dependency |
| CyberArk-BreakGlassConfig.example.json | Example Safe, RBAC and CPM account config |
| manifest.example.csv | Example OS/address/target-platform mapping |
| Invoke-BreakGlassOnboarding.ps1 | Wrapper over existing New-CyberArkLocalAccount.ps1 and Add-CyberArkAccountsToGroup.ps1 |
| Test-BreakGlassDeployment.ps1 | Read-only membership audit against manifest; never reads secrets |

### Operational sequence (abridged)
1. Approve risk and provide independent offline escrow; verify OOB access.
2. Confirm platform IDs, group platform IDs, Master Policy exceptions and actual CyberArk version.
3. Generate **two different** 20+ character initial credentials in approved secret backend; prepare encrypted Ansible Vault. Ensure Windows and RHEL target password rules accept them. Never provide passwords in PowerShell command line or manifest.
4. Copy ansible/inventory.example.ini to ansible/inventory.ini and manifest.example.csv to manifest.csv. Populate the exact matching 150+150 hosts for production (2+2 for pilot).
5. Copy CyberArk-BreakGlassConfig.example.json to CyberArk-BreakGlassConfig.json. Verify actual PVWA URL, managingCPM, RADIUS authentication, account target platforms, group policies, Owner/Operator/Auditor and AD group names. Ensure all associated groups and target platforms already exist.
6. Install requirements, then run Windows and RHEL playbooks as in TECHNICAL.md. Initial password is set only at creation; later playbook re-runs won't clobber CyberArk CPM changes.
7. Run onboarding first with -WhatIf and **without** -AssignGroups. Confirm all accounts and native target platforms. Never permit the default Reconcile from underlying script — wrapper always sets -SkipReconcile.
8. Run onboarding with -AssignGroups -WindowsGroupName ... -RhelGroupName ... -WindowsGroupPlatformId ... -RhelGroupPlatformId ...; internally it looks up exact account IDs and invokes the existing Account Group script.
9. Run read-only audit; confirm 150 Windows / 150 RHEL members; verify all passwords (audit script does not test secrets).
10. Run group-rotation pilot using PVWA UI to specify next password **and** change **entire** account group. Test results on both pilot hosts, including offline login.
11. After passing tests, perform staged production rollout, finalize offline escrow, and train incident custodians.

#### Onboarding: small pilot

Run in Windows PowerShell 5.1+ from the repository root:

~~~powershell
$opts = @{
    ManifestCsv = '.\BreakGlass\manifest.csv'
    SafeName = 'BG-PROD-01'
    ConfigPath = '.\BreakGlass\CyberArk-BreakGlassConfig.json'
    ExpectedWindows = 2
    ExpectedRHEL = 2
}
.\BreakGlass\Invoke-BreakGlassOnboarding.ps1 @opts -WhatIf
.\BreakGlass\Invoke-BreakGlassOnboarding.ps1 @opts
.\BreakGlass\Invoke-BreakGlassOnboarding.ps1 @opts -AssignGroups -WindowsGroupName BG-PROD-WIN -RhelGroupName BG-PROD-RHEL -WindowsGroupPlatformId BG-Win-Group -RhelGroupPlatformId BG-RHEL-Group
~~~

#### Read-only audit

~~~powershell
.\BreakGlass\Test-BreakGlassDeployment.ps1 -SafeName BG-PROD-01 -ManifestCsv .\BreakGlass\manifest.csv -PVWAURL https://pvwa.example.invalid/PasswordVault -AuthType Radius -WindowsGroupName BG-PROD-WIN -RhelGroupName BG-PROD-RHEL -ExpectedWindows 2 -ExpectedRHEL 2 -ReportCsv C:\Temp\bg-audit.csv
~~~

Warning: same passwords throughout cohorts introduce a substantial lateral-movement risk. More granular group design is preferred if business permits.

### Limitations and unresolved deployment checks

- No real PVWA/CPM/Windows/RHEL infrastructure is accessible here. API requests and runbooks were researched but **not functionally exercised in your environment**.
- **Group-wide specified-password rotation** is version-dependent. The general REST SetNextPassword endpoint documents a new credential but does not itself establish group propagation; use validated PVWA flow and test before adopting any API automation.
- Tests of authentic offline local login, sudo, password expiry, GPO/LAPS and CPM change handlers are mandatory.
- Underlying script reconnects to PVWA for each account (potentially 300 sessions) and may be slow; this is a safe first-pass implementation rather than optimized batch onboarding.
- Membership audit verifies account names and group IDs, **not** actual passwords, login ability or completion of CPM activity.
- There is no automatic rollback of a partially completed 150-host password rotation; handle as an incident.

### Existing Tools scripts reused and amended

- New-CyberArkLocalAccount.ps1 (existing) — local Windows/RHEL account metadata, Windows LogonDomain mapping.
- New-CyberArkSafeAccount.ps1 (existing, improved) — duplicate detection now pages Accounts in large Safes.
- Add-CyberArkAccountsToGroup.ps1 (existing, improved) — validating target/group platforms, member collections, expected Safe before membership writes.
- CyberArk-SafeConfig.example.json (original unchanged) — new dedicated example provided for Break-Glass instead of altering legacy defaults.

### Security
- **No credentials, tokens, private key material, cleartext manifests or real offline recovery details belong in this repository.**
- Configure in a private, access-controlled deployment location. For online access use CyberArk RBAC and audit; for offline access use dual-control escrow and independent consoles.
