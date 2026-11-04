# Setup

## Machines
| Machine | OS | Purpose |
|---|---|---|
| Wazuh manager | Ubuntu, Wazuh 4.14.7 | Decodes events, applies rules, raises alerts |
| Windows endpoint | Windows 10 Pro | Monitored host with Sysmon and the Wazuh agent |

All machines are VMware Workstation VMs on the same network.

## Steps
1. Install the Wazuh manager and dashboard on the Ubuntu VM.
2. Install the Wazuh agent on Windows and enrol it with the manager.
3. Install Sysmon on Windows with a configuration that logs process creation (Event ID 1).
4. Add the channels in `config/agent-ossec-localfile.xml` to the agent's `ossec.conf` and restart the agent.
5. Turn on JSON archives on the manager (`config/manager-ossec-global.xml`).
6. Copy `rules/local_rules.xml` to `/var/ossec/etc/rules/local_rules.xml` on the manager.
7. Validate and restart:
   ```bash
   sudo /var/ossec/bin/wazuh-analysisd -t && sudo systemctl restart wazuh-manager
   ```
8. Restart the Windows agent after the manager is back up:
   ```powershell
   Restart-Service WazuhSvc
   ```
9. Run the test commands in `validation.md` and check `/var/ossec/logs/alerts/alerts.json`.

## Operating habits
- Start the manager before the agent.
- After any manager outage or reboot, restart the agent and run a quick test event.
- Back up `local_rules.xml` before editing it.
- Keep the Windows VM's time zone aligned with the manager's.
