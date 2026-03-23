# SSH Brute Force Detection with Splunk

A Security Information and Event Management (SIEM) project that detects SSH brute force attacks in real time using Splunk Enterprise and a Universal Forwarder ingesting Linux authentication logs.

---

## Project Overview

This project simulates a SOC (Security Operations Center) detection pipeline for one of the most common attack vectors — SSH brute force and credential stuffing. It demonstrates end-to-end log collection, parsing, threshold-based detection, dashboarding, and alerting using Splunk.

**Key detections built:**

- Repeated failed SSH login attempts from a single IP within a time window
- Successful login following multiple failures (attacker gained access)
- Whitelisted IP exclusion to reduce false positives
- Full attack timeline correlation for incident investigation
- GeoIP enrichment to map attacking IPs to countries

---

## Architecture

```
Attacker VM (WSL2)             Target Machine (WSL2)          Windows Host
+----------------+             +----------------------+        +------------------+
| hydra          |------------>| Ubuntu + OpenSSH     |        | Splunk Enterprise|
| brute force    | SSH :22     | /var/log/auth.log    |        | localhost:8000   |
| tool           |             |          |           |        |                  |
+----------------+             | Splunk Universal     |------->| index=main       |
                               | Forwarder            |port    | sourcetype=      |
                               +----------------------+9997    | linux_secure     |
                                                               +------------------+
```

**Components:**

- **Ubuntu on WSL2 (Target)** — Runs OpenSSH server and generates auth logs
- **Ubuntu on WSL2 (Attacker)** — Runs hydra to simulate real brute force attacks
- **Splunk Universal Forwarder** — Monitors `/var/log/auth.log` and ships events to Splunk
- **Splunk Enterprise (Free)** — Ingests, indexes, and analyzes log data

---

## Dashboard Panels

| Panel                                        | Type         | Purpose                                         |
| -------------------------------------------- | ------------ | ----------------------------------------------- |
| Success After Failure                        | Table        | IPs that failed then succeeded — critical alert |
| Brute Force Attempts Over Time               | Line Chart   | Attack volume over time                         |
| Top Attacking IPs (Whitelisted IPs Excluded) | Bar Chart    | Top attackers with safe IPs filtered out        |
| Top Targeted Usernames                       | Bar Chart    | Most targeted accounts (root, admin, etc.)      |
| Attacks by Hour of Day                       | Column Chart | When attacks peak throughout the day            |
| Attacker Geolocation                         | Cluster Map  | World map of attacking IP locations             |
| Attack Timeline                              | Table        | Full chronological kill chain for a specific IP |

---

## Detection Queries (SPL)

### 1. Brute Force Detection

Identifies IPs exceeding 10 failed SSH login attempts within a 5 minute window.

```spl
index=main sourcetype=linux_secure "Failed password"
| rex field=_raw "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| rex field=_raw "for (invalid user )?(?<username>\w+)"
| bucket _time span=5m
| stats count as failed_attempts by src_ip, username, _time
| where failed_attempts > 10
| sort -failed_attempts
```

### 2. Success After Failure (Critical)

Detects IPs that failed multiple times but eventually authenticated — highest priority alert.

```spl
index=main sourcetype=linux_secure ("Failed password" OR "Accepted password")
| rex field=_raw "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| eval status=if(match(_raw,"Failed"),"failed","success")
| stats count(eval(status="failed")) as failures,
        count(eval(status="success")) as successes by src_ip
| where failures > 3 AND successes > 0
```

### 3. Brute Force Detection with Whitelist

Same as query 1 but excludes known safe IPs to reduce false positives.

```spl
index=main sourcetype=linux_secure "Failed password"
| rex field=_raw "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| lookup whitelist_lookup src_ip OUTPUTNEW description as whitelist_reason
| where isnull(whitelist_reason)
| rex field=_raw "for (invalid user )?(?<username>\w+)"
| bucket _time span=5m
| stats count as failed_attempts by src_ip, username, _time
| where failed_attempts > 3
| sort -failed_attempts
```

### 4. Top Targeted Usernames

Ranks usernames by how many times they were targeted.

```spl
index=main sourcetype=linux_secure "Failed password"
| rex field=_raw "for (invalid user )?(?<username>\w+)"
| stats count as attempts by username
| sort -attempts
| head 10
```

### 5. Attacks by Hour of Day

Shows what time of day attacks peak.

```spl
index=main sourcetype=linux_secure "Failed password"
| eval hour=strftime(_time, "%H")
| stats count as attempts by hour
| sort hour
```

### 6. GeoIP Enrichment

Maps attacking IPs to countries using Splunk's built-in iplocation command.

```spl
index=main sourcetype=linux_secure "Failed password"
| rex field=_raw "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| iplocation src_ip
| stats count as attempts by src_ip, Country, Region, City
| sort -attempts
```

### 7. Attack Timeline Correlation

Builds a full chronological kill chain for a specific attacker IP.

```spl
index=main sourcetype=linux_secure
| rex field=_raw "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| rex field=_raw "for (invalid user )?(?<username>\w+)"
| eval action=case(
    match(_raw,"Failed password"), "FAILED LOGIN",
    match(_raw,"Accepted password"), "SUCCESSFUL LOGIN",
    match(_raw,"Invalid user"), "INVALID USER",
    match(_raw,"Connection closed"), "CONNECTION CLOSED",
    true(), "OTHER"
  )
| where src_ip="<ATTACKER_IP>"
| table _time, src_ip, username, action
| sort _time
```

---

## Alerts

| Setting           | Value                     |
| ----------------- | ------------------------- |
| Alert Name        | SSH Brute Force Detection |
| Alert Type        | Scheduled — every hour    |
| Trigger Condition | Number of results > 0     |
| Throttle          | 60 minutes                |
| Action            | Add to Triggered Alerts   |

---

## Whitelist

Known safe IPs are maintained in a Splunk lookup table (`whitelist.csv`) and automatically excluded from detection queries.

```csv
src_ip,description
127.0.0.1,localhost
172.29.16.1,windows host gateway
```

---

## Setup Instructions

### Prerequisites

- Windows 10/11 with WSL2 enabled
- Ubuntu installed via WSL2 (x2 — one target, one attacker)
- Splunk Enterprise (Free) installed on Windows

### Step 1 — Configure Splunk to Receive Data

1. Settings → Forwarding and receiving → Configure receiving
2. Add receiving port: **9997**
3. Restart Splunk

### Step 2 — Install Splunk Universal Forwarder on Ubuntu

```bash
sudo dpkg -i splunkforwarder-<version>-linux-amd64.deb
sudo /opt/splunkforwarder/bin/splunk start --accept-license
```

### Step 3 — Point Forwarder at Splunk

```bash
# Get your Windows host IP from WSL2
ip route show | grep default | awk '{print $3}'

sudo /opt/splunkforwarder/bin/splunk add forward-server <WINDOWS_IP>:9997
sudo /opt/splunkforwarder/bin/splunk add monitor /var/log/auth.log -index main -sourcetype linux_secure
sudo /opt/splunkforwarder/bin/splunk restart
```

### Step 4 — Set Up Attacker VM

```bash
# In PowerShell
wsl --install -d Ubuntu-22.04 --name attacker-vm

# In attacker-vm
sudo apt install hydra -y
hydra -l root -P ~/passwords.txt <TARGET_IP> ssh -t 4 -I
```

### Step 5 — Configure Lookups

Upload the following CSV files to Splunk under Settings → Lookups:

- `whitelist.csv` — known safe IPs to exclude from alerts
- `geoip.csv` — MaxMind GeoLite2 IP blocks for geolocation
- `geoip_locations.csv` — MaxMind GeoLite2 location names

---

## Tuning Notes

- **Threshold (> 10 failures):** Reduces false positives from legitimate mistyped passwords while catching automated attacks
- **5 minute window:** Catches fast automated attacks while also detecting slow-and-low attempts
- **Throttle (60 min):** Prevents alert fatigue from repeat notifications for the same ongoing attack
- **Whitelist:** Known safe IPs (localhost, gateways, monitoring tools) are excluded from all detections
- **WSL2 networking:** The Universal Forwarder must use the WSL2 gateway IP, not 127.0.0.1

---

## Skills Demonstrated

- SIEM log ingestion and pipeline configuration
- SPL (Splunk Processing Language) — regex, stats, eval, timechart, geostats
- Threshold-based detection engineering
- False positive reduction via whitelisting
- GeoIP enrichment and map visualization
- Simulated adversary techniques using hydra
- Incident investigation via attack timeline correlation
- Dashboard creation and visualization
- Scheduled alerting and tuning
- Linux authentication log analysis

---

## Tools Used

| Tool                              | Purpose                              |
| --------------------------------- | ------------------------------------ |
| Splunk Enterprise (Free)          | SIEM platform                        |
| Splunk Universal Forwarder        | Log shipping agent                   |
| Ubuntu 22.04 (WSL2)               | Target machine — generates auth logs |
| Ubuntu 22.04 (WSL2 - attacker-vm) | Attacker machine — runs hydra        |
| OpenSSH Server                    | Generates SSH auth log events        |
| Hydra                             | Brute force simulation tool          |
| MaxMind GeoLite2                  | IP geolocation database              |
