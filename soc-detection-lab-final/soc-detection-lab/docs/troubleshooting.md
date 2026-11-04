# Troubleshooting log: missing Defender events 1116/1117

## Symptom
Windows Event Viewer showed Defender events 1116 (threat detected) and 1117 (action taken), but they were not in the
Wazuh archive.

## Causes and fixes

| Problem | Cause | Fix |
|---|---|---|
| Events seemed missing | Windows VM on Pacific time, manager on IST | Set the VM to India Standard Time |
| Searches "found" events that were not Defender events | Keyword searches matched my own `sudo` commands and PowerShell events with the same record IDs | Filter by `location` and `providerName`, compare record IDs |
| Oct 28 20:51 events never archived | The agent only started reading the Defender channel at 21:01 IST | Not recoverable in Wazuh; still in Event Viewer |
| Events delayed about 28 minutes | Agent restarted while the manager was down; the Defender reader stalled until the service was restarted (exact cause not proven) | Restart the agent after any manager outage, then run a test |
| No new events after a VM reboot | The manager did not start again | `systemctl start` and `enable` the manager |
| Custom rules never fired | Custom and built-in rules shared the same parent; the built-in rule matched first | Make the custom rule a child with `<if_sid>` |

## Method that worked
1. Confirm the event exists on the endpoint (record ID and time).
2. Convert every timestamp to one time zone.
3. Check the archive by record ID, not by keyword.
4. Check the alerts file for what rule, if any, fired.
5. If an event is archived but no custom alert appears, find the built-in rule that matches it first.
6. After any change, restart the agent and test with a fresh event.

## Defender fix in detail
Built-in rules 62123 (1116) and 62124 (1117) matched first. Custom rules 100201 and 100202 were rewritten as
children (`<if_sid>62123</if_sid>` and `<if_sid>62124</if_sid>`) and then fired.
