# IR-2026-001 — Event forwarding from WS01 silently dead for 4 days

**Severity:** SEV-2 (a security control was down: the collector was blind to WS01) · **Status:** closed 2026-11-05 · **Handler:** Angel Diaz Freytes

## Summary
From 2026-11-01 to 2026-11-05, no events from WS01 reached the collector on DC01. Sysmon and the Security log on WS01 kept recording; only forwarding stopped. Nobody noticed for three days. Had WS01 been compromised in that window, the central log would have shown nothing.

## Timeline (local time, AST)
| When | What |
|---|---|
| 11-01 ~10:08 | Last heartbeat and last event from WS01 at the collector |
| 11-01 11:45–11:46 | WS01's forwarder logs errors 105 talking to DC01 (DC01 briefly unavailable) |
| 11-01 21:12 | WS01 reboots; the forwarder does not try again |
| 11-04 12:52 | Found by accident while taking screenshots for the week 7 write-up: `wecutil gr LabForward` shows WS01 `Inactive`, `LastHeartbeatTime 2026-11-01T10:08` |
| 11-04 12:55–13:20 | Diagnosis (below). `wecutil rs` and a WinRM restart do not recover it |
| 11-05 15:16 | Subscription deleted and recreated (`12-event-forwarding.ps1`); WS01 `Active`, fresh events within seconds |
| 11-05 ~16:30 | Verified again after the week 11 isolation test |

## Detection
Not detected by any control: found by chance. **Time to detect: about 3 days.**

## Root cause
The subscription is source-initiated. While DC01 was unavailable, WS01's connection attempts failed; the collector used up its retries and marked WS01 as an inactive source ("All retries have been performed… the subscription will remain inactive"). From then on DC01 rejected WS01 ("The event source of the push subscription is in disable or inactive on the Event controller server", WS01 `Forwarding/Operational` error 105). Neither side recovers on its own.

## Diagnosis path
1. Network: `Test-NetConnection dc01.lab.local -Port 5985` from WS01 → True.
2. Services: WinRM Running/Automatic, Sysmon Running, GPO with the collector address present.
3. Source log `Microsoft-Windows-Forwarding/Operational` on WS01 → error 105 with the "inactive" message: the cause.

## What worked, what did not
- Did not: `wecutil rs LabForward` (retry); restarting WinRM on WS01.
- Did: deleting and recreating the subscription (`wecutil ds` + `wecutil cs`, i.e. re-running script 12).
- Trap: script 12's own final check looks for "events from WS01 in ForwardedEvents". With thousands of old events stored, it passes even when nothing new arrives. Freshness must be checked by comparing the newest event's time with the current time.

## Actions
| Action | Status |
|---|---|
| Recreate the subscription and verify with fresh events | Done 11-05 |
| Weekly source-health check written into the IR plan (section 4) | Done 11-05 |
| After any WS01 network change (isolation test), verify forwarding resumed | Done 11-05, see week 11 |
| Alert on silent log sources ("no events from host X in N hours") | Week 14, Wazuh |
| Fix script 12's verification to require events newer than the run | Done 11-05 |

## Lesson
A logging pipeline that fails silently is worse than none, because you believe you can see. Every monitor has to alert on its own failure (silent source), not only on what it is looking for. Same lesson as week 10: the Greenbone disk filled up and a watcher that matched only success said nothing for hours.
