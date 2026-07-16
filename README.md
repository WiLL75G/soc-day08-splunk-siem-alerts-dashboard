# Splunk Alert Engineering and SOC Dashboard

Building four real time alerts and a four panel monitoring dashboard on live authentication telemetry from an Ubuntu endpoint, then baselining what normal actually looks like.

## At a Glance

| Field | Detail |
| --- | --- |
| Build Type | SIEM detection engineering and monitoring |
| Platform | Splunk Enterprise, Splunk Universal Forwarder v10.2.2 |
| Log Source | /var/log/auth.log, live Ubuntu endpoint |
| Index and Sourcetype | main, linux_secure |
| Delivered | 4 real time alerts, 4 panel dashboard |
| Outcome | Pipeline validated end to end, baseline established, no anomalous access observed |

## What Happened

An Ubuntu endpoint was connected to Splunk via the Universal Forwarder, streaming real authentication logs. Four SPL alerts were written against that feed, and a four panel dashboard was built on top of it.

The data is not synthetic. That matters, because synthetic data only ever contains the attack you put in it. Live telemetry contains the mess, and learning to read the mess is the job.

The finding here is not an attack. It is a baseline. Knowing what normal looks like on this host is the prerequisite for ever calling something abnormal.

## Log Source Configuration

![Splunk Auth Logs](./screenshots/splunk_auth_logs.png)

The forwarder was configured on the Ubuntu host to monitor the auth log in real time.

```
[monitor:///var/log/auth.log]
disabled = false
index = main
sourcetype = syslog
```

Ingestion was verified before any detection work began.

```spl
index=main source="/var/log/auth.log"
```

Confirmed live in search: session open and close events, sudo privilege escalation, CRON job execution, and gdm desktop logins. Rules written against an unverified feed are decoration.

## Alert 1, Session Opened

![Alert 1 Session Opened](./screenshots/alert1_session_opened.png)

```spl
index=main source="/var/log/auth.log" "session opened"
```

Real time, triggers on results greater than zero.

Detects any new authenticated session on the endpoint. This is the access auditing layer, the raw material for building a user activity timeline.

## Alert 2, Sudo Privilege Escalation

![Alert 2 Sudo Escalation](./screenshots/alert2_sudo_escalation.png)

```spl
index=main source="/var/log/auth.log" "sudo"
```

Real time, triggers on results greater than zero.

Detects elevation beyond standard user scope. Sudo is legitimate most of the time, which is precisely why it is worth watching. An attacker who lands as a normal user needs it, and it is the step between having access and being able to use it.

## Alert 3, Root Access

![Alert 3 Root Access](./screenshots/alert3_root_access.png)

```spl
index=main source="/var/log/auth.log" "user root"
```

Real time, triggers on results greater than zero.

Detects direct root account activity. Root gets investigated every time. The question is never whether root did something, it is whether the human behind it was authorised.

## Alert 4, CRON Job Execution

![Alert 4 CRON Detection](./screenshots/alert4_cron_detection.png)

```spl
index=main source="/var/log/auth.log" "CRON"
```

Real time, triggers on results greater than zero.

Detects scheduled job execution. CRON is one of the most abused persistence mechanisms on Linux because it is built in, it survives reboot, and it looks like housekeeping. An attacker does not need to install anything, they just need a line in a file.

## Dashboard Panel 1, Authentication Events Over Time

![Dashboard Panel 1](./screenshots/dashboard_panel1.png)

```spl
index=main source="/var/log/auth.log"
| timechart count by host
```

Authentication volume across a 24 hour window, broken down per host.

Volume over time is the fastest anomaly detector there is. Brute force does not look like a bad event, it looks like a spike.

## Dashboard Panel 2, Top Authentication Services

![Dashboard Panel 2](./screenshots/dashboard_panel2.png)

```spl
index=main source="/var/log/auth.log"
| rex "pam_unix\((?<service>[^:]+)"
| stats count by service
| sort -count
```

Which authentication subsystems are generating the load.

Observed: cron 12, sudo 6, polkit-1 4.

The rex pulls the service name out of the pam_unix string, turning free text into a countable field. CRON dominance is consistent with scheduled system activity. Sudo reflects the lab user. Polkit correlates with desktop authorisation prompts.

## Dashboard Panel 3, Session Activity by User

![Dashboard Panel 3](./screenshots/dashboard_panel3.png)

```spl
index=main source="/var/log/auth.log" "session opened"
| rex "for user (?<username>\S+)\("
| stats count by username
| sort -count
```

Session counts per user.

Observed: root 13, gdm 2, james 2.

Root at 13 looks alarming out of context. Panel 4 explains it.

## Dashboard Panel 4, CRON Activity by User

![Dashboard Panel 4](./screenshots/dashboard_panel4.png)

```spl
index=main source="/var/log/auth.log" "CRON"
| rex "for user (?<username>\S+)\("
| stats count by username
| sort -count
```

Which users are executing scheduled jobs.

Root is the dominant CRON executor, which accounts for the root session count in Panel 3. Scheduled maintenance jobs run as root by design. That is the baseline, not the incident.

The alert this panel really exists for is the inverse. A non root user appearing in this panel has no innocent explanation, and that is what persistence looks like.

## Dashboard Deployment

![SOC Dashboard Final 1](./screenshots/soc_dashboard_final_1.png)

![SOC Dashboard Final 2](./screenshots/soc_dashboard_final_2.png)

All four panels consolidated into a single view driven by live telemetry, with real time refresh enabled.

The pipeline is validated end to end, forwarder to index to search to alert to panel. Every panel corresponds to an active alert rule, so what an analyst sees on screen and what fires in the background are the same logic.

## Behavioural Baseline Observed

| Type | Pattern | Source |
| --- | --- | --- |
| Scheduled activity | Continuous CRON execution as root | Panel 4 |
| Privilege escalation | Sudo invocations by user james | Alert 2 |
| Root sessions | 13 observed, attributable to CRON | Panel 3 |
| Service distribution | pam_unix across cron, sudo, polkit-1 | Panel 2 |

Each of these is expected behaviour on this host. Documented as a baseline, not as indicators of compromise.

## MITRE ATT&CK Mapping

| Technique | Technique ID | Detection Coverage |
| --- | --- | --- |
| Abuse elevation control mechanism, sudo | T1548.003 | Alert 2 |
| Scheduled task or job, cron | T1053.003 | Alert 4 and Panel 4 |
| Valid accounts, local accounts | T1078.003 | Alert 1 and Alert 3 |

Mapping note: these are the techniques the rules provide coverage for. None were observed. This is a detection build against a clean host.

## Analyst Findings

Live Ubuntu authentication telemetry ingested and verified in Splunk.

Four real time detection rules deployed and confirmed firing against live events.

CRON executing exclusively as root, consistent with system scheduled activity.

Sudo escalation captured and attributable to the lab user james.

13 root sessions across the window, explained by scheduled jobs rather than interactive login.

No unauthorised access or anomalous authentication patterns present.

Pipeline validated from log source through to dashboard.

## Honest Assessment of These Rules

These alerts trigger on any match, which is correct for a lab and wrong for production. Alert 1 would fire on every login. Alert 4 would fire every time CRON runs, which on this host is constantly.

That is the point of running them on live data first. The baseline in Panel 2 and Panel 4 is what a real threshold gets built from, and rules tuned before you know the normal volume are rules tuned on a guess.

## Recommended Next Steps

Convert real time alerts to scheduled correlation searches with volume thresholds drawn from the observed baseline.

Suppress expected root CRON activity so the signal is the exception, not the routine.

Alert specifically on non root users appearing in CRON, which is the persistence case Panel 4 exists to catch.

Cross reference root activity against the authorised administrator list.

Build user behaviour baselining on top of the session and sudo telemetry.

## What This Lab Demonstrates

Configuring a Universal Forwarder and validating ingestion before writing a single rule.

Writing SPL with rex field extraction to turn raw log text into countable fields.

Building real time alerts and mapping each one to a technique it covers.

Constructing a dashboard where every panel answers a triage question.

Reading a baseline and explaining an alarming looking number rather than escalating it.

Knowing the difference between a rule that fires and a rule that is tuned.

## Repository Structure

```
splunk-siem-alert-rules-dashboard/
├── README.md
├── spl-queries/
│   ├── alert1_session_opened.spl
│   ├── alert2_sudo_escalation.spl
│   ├── alert3_root_access.spl
│   └── alert4_cron_detection.spl
└── screenshots/
    ├── splunk_auth_logs.png
    ├── alert1_session_opened.png
    ├── alert2_sudo_escalation.png
    ├── alert3_root_access.png
    ├── alert4_cron_detection.png
    ├── dashboard_panel1.png
    ├── dashboard_panel2.png
    ├── dashboard_panel3.png
    ├── dashboard_panel4.png
    ├── soc_dashboard_final_1.png
    └── soc_dashboard_final_2.png
```

---

[![LinkedIn](https://img.shields.io/badge/LinkedIn-WilliamInCyber-blue?style=flat&logo=linkedin)](https://linkedin.com/in/WilliamInCyber)
[![X](https://img.shields.io/badge/X-WilliamInCyber-black?style=flat&logo=x)](https://x.com/WilliamInCyber)
