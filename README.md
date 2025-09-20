#SOC-HomeLab
This is a SOC lab that is being hosted on the cloud using DigitalOcean which uses the Wazuh SIEM and Sysmon on a Windows 10 VM client machine for detection purposes, log aggregations, and a simulation for Incident Response purposes.

#SOC Homelab (DigitalOcean) – Wazuh + Sysmon

> This is still a work in progress. In this lab I've demonstrated focuses on detection engineering, log pipeline validation, basic IR workflows

---

#Overview

This repo documents a cloud‑hosted SOC homelab hosted on DigitalOcean that collects important information regarding Windows telemetry with Sysmon, which then forwards it to a Wazuh manager running on DigitalOcean, and surfaces detections mapped to MITRE ATT\&CK. For this lab, my goal is to demonstrate hands‑on skills in SIEM integration, detection tuning, and incident response which should technically simulate real world events.

#Key outcomes

#Cloud‑hosted Wazuh manager on hardened Ubuntu (DigitalOcean)
#Windows 10 endpoint(s) with Sysmon + Wazuh agent
#Custom rules to detect credential‑dumping tools via `OriginalFileName` and other artifacts
#MITRE‑mapped alerts (for our specific case/lab "T1003 – OS Credential Dumping")
#Repeatable simulations + IR mini playbooks (containment, triage, scoping)

---

#Architecture

```
+---------------------+            Beats/Wazuh Agent (TLS)           +------------------------+
|  Windows 10 Client  |  Sysmon ->  Wazuh Agent  ==================> |  Wazuh Manager (DO VM) |
|  (VM / bare metal)  |            (Forward Sysmon logs)            |  Ubuntu 22.04 LTS       |
+----------+----------+                                              +-----------+------------+
           |                                                                      |
           | Local tests (Atomic/benign)                                         | Dashboards, rules, alerts
           v                                                                      v
   Process/Net/File events                                              Analyst console + API
```

#Components

#DigitalOcean Droplet: Ubuntu LTS, user firewall hardened, SSH locked down (password‑based)
#Wazuh Manager: indexer/dashboard/manager (modern packages)
#Windows 10 Endpoint(s): Using VirtualBox, downloaded Sysmon, Wazuh agent

---

#Repo Structure

```
.
├─ README.md                          # This document
├─ diagrams/
│  └─ soc-architecture.png            # (Optional) draw.io/diagram image
├─ configs/
│  ├─ sysmon/
│  │  └─ sysmon-config.xml            # SwiftOnSecurity-derived (doc link referenced)
│  ├─ wazuh/
│  │  ├─ local_rules.xml              # Custom detection rules (T1003, suspicious LOLBins, etc.)
│  │  └─ ossec.conf                   # Agent/manager snippets (sanitized)
├─ detections/
│  ├─ t1003-cred-dumping.yml          # Rule notes + sample alert JSON
│  └─ queries.md                      # Saved searches (process name, OriginalFileName, command line)
├─ simulations/
│  ├─ atomic-red-team.md              # Safe tests, commands, revert steps
│  └─ ir-playbook-mini.md             # Containment, verification, scoping checklist
└─ hardening/
   ├─ ubuntu-baseline.md              # ufw, sshd_config, unattended-upgrades
   └─ windows-gpo-notes.md            # (If AD present) baseline controls
```

> **Note:** Where configs contain secrets/hostnames, place **sanitized snippets** and instructions rather than raw files.

---

## ☁️ DigitalOcean Deployment (Manager VM)

1. **Create droplet**: Ubuntu 22.04 LTS, 2GB+ RAM recommended, choose your region.
2. **Networking**: Enable VPC if desired; assign a **reserved IP** (optional) for stability.
3. **Access**: Upload SSH key; disable password auth.
4. **Baseline hardening**

   ```bash
   sudo apt update && sudo apt -y upgrade
   sudo ufw default deny incoming && sudo ufw default allow outgoing
   sudo ufw allow OpenSSH && sudo ufw enable
   sudo sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
   sudo systemctl restart ssh
   ```
5. **Install Wazuh (manager + indexer + dashboard)** – follow current Wazuh install guide for the consolidated stack. Capture version in README.

---

## 🖥️ Windows Endpoint Setup (Sysmon + Agent)

1. **Install Sysmon**

   * Download Sysmon from Microsoft Sysinternals
   * Use the popular SwiftOnSecurity configuration (or a minimal tuned variant)

   ```powershell
   sysmon64.exe -accepteula -i sysmon-config.xml
   ```
2. **Install Wazuh Agent**

   * Match agent version to manager; during install, set **manager IP/hostname** and registration key if required.
   * Confirm service is running and logs are forwarding (`ossec.log` on Windows, or Wazuh dashboard > Agents).

---

## 🔎 Validating the Log Pipeline

**Goal:** verify endpoint → agent → manager → indexer → dashboard path.

Quick checks:

* Generate benign events (e.g., `whoami`, `ipconfig`, `curl` to localhost)
* Confirm new **process creation** (Sysmon Event ID 1) appears in Wazuh
* Filter by host, image path, and `OriginalFileName`

Example saved search (pseudocode):

```
rule.level: * AND data.win.eventdata.Image.keyword: *\\whoami.exe
```

---

## 🧭 MITRE ATT\&CK Mapping

| Technique                     | ID    | Signal(s) / Fields                                                    | Notes                            |
| ----------------------------- | ----- | --------------------------------------------------------------------- | -------------------------------- |
| OS Credential Dumping         | T1003 | `EventID=1` ProcessCreate; `CommandLine`, `OriginalFileName`, `Image` | Detect tools & LOLBins patterns  |
| Discovery (System Owner/User) | T1033 | `whoami.exe` process create                                           | Benign baseline → tuning example |
| Ingress Tool Transfer         | T1105 | Suspicious curl/powershell download                                   | Optional                         |

---

## 🧩 Custom Detection Rules (examples)

> Place final rules in `configs/wazuh/local_rules.xml` and document rationale under `detections/`.

**Credential dumping (rename‑resistant)**

```xml
<rule id="100300" level="10">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.OriginalFileName">(?i)mimikatz|procdump|lsass.*</field>
  <description>Cred dumping tool detected via OriginalFileName</description>
  <mitre>
    <id>T1003</id>
  </mitre>
  <options>no_full_log</options>
  <frequency>1</frequency>
</rule>
```

**Suspicious LSASS handle access (if using additional telemetry)** – placeholder for EDR/Sysmon ID 10/7 patterns.

---

## 🧪 Safe Simulations

See `simulations/atomic-red-team.md` for exact commands, scope, and revert steps.

**Examples**

* **Credential dumping simulation** (no real creds): execute benign test binary or ATT\&CK simulator that triggers detections by name/command line without exfiltration.
* **Discovery**: run `whoami`, `systeminfo`, `net user` to generate low‑signal events for tuning.

> **Safety note:** Only run tests on lab machines you own/control. Avoid real malware; prefer ATT\&CK emulators or signed simulators.

---

## 🧯 IR Mini Playbooks

**Containment (isolating a suspected host)**

1. Acknowledge alert in Wazuh and tag the host.
2. Quarantine options: remove VM NIC from vSwitch / DO VPC rule deny / security group lock‑down.
3. Preserve artifacts (event logs, suspicious binary hash/path).
4. Verify containment via failed egress & no new alerts.

**Triage & Scoping**

* Pivot on `ParentImage`, `CommandLine`, sibling processes, and host timeline.
* Search for same IOC across all agents.
* Document findings and remediation steps.

Templates live in `simulations/ir-playbook-mini.md`.

---

## 📊 Dashboards & Queries

* Process creation trends by host
* Top `OriginalFileName` values with rare‑value outliers
* Command line keyword heatmap (e.g., `-enc`, `-nop`, `lsass`, `sam`)
* Agent heartbeat/health view

Store saved searches in `detections/queries.md`.

---

## 🔐 Hardening Notes

See `hardening/ubuntu-baseline.md` and `hardening/windows-gpo-notes.md`.

* Ubuntu: ufw, fail2ban (optional), sshd\_config lockdown, unattended‑upgrades, limited sudo
* Windows: if AD present, baseline GPOs (password policy, lockout, removable storage), or local policies on standalone hosts

---

## 🧭 Roadmap

* [ ] Add second Windows endpoint to simulate lateral movement & isolation
* [ ] Build detection for suspicious LSASS access and dump patterns
* [ ] Add Sigma‑style rules and conversion notes
* [ ] Export sample alerts (JSON) for each detection technique
* [ ] Add architecture diagram image (diagrams/soc-architecture.png)

---

## 📚 How to Use This Repo

1. Read **hardening** → secure the manager VM
2. Deploy **Sysmon + agent** on Windows client(s)
3. Import **local\_rules.xml** into Wazuh and reload
4. Run **safe simulations**, observe alerts, tune
5. Document findings in **detections/** and **simulations/**

---

## ✅ What This Demonstrates (Resume bullets)

* Built a cloud‑hosted SOC lab (DigitalOcean) using Wazuh SIEM and Windows Sysmon to collect and analyze endpoint telemetry.
* Wrote custom rules to detect credential‑dumping tools by `OriginalFileName`; validated alerts against ATT\&CK‑aligned simulations (e.g., T1003).
* Tuned searches/dashboards to surface process‑creation anomalies and supported basic incident response (containment, triage, scoping).

---

## ⚠️ Disclaimer

For educational use on lab systems you own/control. Do not run offensive tooling on networks or systems without explicit authorization.

