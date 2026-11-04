# Useful commands

Run these on the Wazuh manager unless stated otherwise.

## Latest alert for each rule, with its MITRE ID
```bash
sudo sh -c 'cat /var/ossec/logs/alerts/alerts.json' | jq -r 'select(.rule.id? as $i | ["100100","100120","100130","100140","100150","92027","92031","92032","92033","100201","100202"] | index($i)) | [.rule.id, .timestamp, (.rule.mitre.id // [] | join(","))] | @tsv' 2>/dev/null | awk -F'\t' '{last[$1]=$0} END{for(k in last) print last[k]}' | sort
```

## Alerts per rule by parent process (find false positives)
```bash
sudo sh -c 'cat /var/ossec/logs/alerts/alerts.json' | jq -r 'select(.rule.id? as $i | ["100100","100120","100130","100140","100150","92027","92031","92033"] | index($i)) | [.rule.id, (.data.win.eventdata.parentImage // "none")] | @tsv' 2>/dev/null | sort | uniq -c
```

## Alerts since a start time
```bash
START="2026-10-30T16:13:00"
sudo sh -c 'cat /var/ossec/logs/alerts/alerts.json' | jq -r --arg s "$START" 'select(.timestamp >= $s) | select((.data.win.eventdata.parentImage // "") | test("wazuh-agent") | not) | select(.rule.id | test("^(100100|100120|100130|100140|100150|92027|92031|92032|92033)$")) | [.timestamp, .rule.id, (.rule.mitre.id // [] | join(",")), (.data.win.eventdata.image // "" | split("\\\\") | last), (.data.win.eventdata.commandLine // "")] | @tsv' 2>/dev/null
```

## Agent-launched commands that reached the archive
```bash
sudo sh -c 'tail -n 8000 /var/ossec/logs/archives/archives.json' | jq -r 'select((.data.win.eventdata.parentImage? // "") | test("wazuh-agent")) | select((.data.win.eventdata.image? // "") | test("(?i)net1?\\.exe|reg\\.exe")) | [.timestamp, .data.win.eventdata.image, .data.win.eventdata.commandLine] | @tsv' 2>/dev/null | tail -n 8
```

## Defender events in the archive, by record ID
```bash
sudo sh -c 'grep -h "\"location\":\"EventChannel\"" /var/ossec/logs/archives/archives.json' | jq -r 'select(.data.win.system.providerName=="Microsoft-Windows-Windows Defender") | [.timestamp, .data.win.system.eventID, .data.win.system.eventRecordID] | @tsv'
```

## Validate rules and check the manager
```bash
sudo /var/ossec/bin/wazuh-analysisd -t
sudo /var/ossec/bin/wazuh-control status
```

## Windows (PowerShell)
```powershell
# Restart the agent after a manager restart
Restart-Service WazuhSvc

# Defender events with their record IDs and UTC times
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; Id=1116,1117} -MaxEvents 5 | Select-Object Id, RecordId, TimeCreated, @{n='UTC';e={$_.TimeCreated.ToUniversalTime()}}

# Harmless Defender detection test (EICAR)
Set-Content -Path "$env:TEMP\eicar.txt" -Value 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
```
