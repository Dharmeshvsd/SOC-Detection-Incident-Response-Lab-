# Detection validation

Every technique was tested by running a command, noting the start time, and matching the command to the alert that Wazuh raised.

## Results

| MITRE ID | Technique | Rule | Type | Trigger |
|---|---|---|---|---|
| T1082 | System Information Discovery | 100100 | Custom | `systeminfo` |
| T1057 | Process Discovery | 100120 | Custom | `tasklist` |
| T1059.003 | Windows Command Shell | 92032 | Built-in | Atomic Red Team T1059.003 test 2 |
| T1016 | System Network Configuration Discovery | 100130 | Custom | `ipconfig /all` |
| T1049 | System Network Connections Discovery | 100140 | Custom | `netstat -ano` |
| T1059.001 | PowerShell | 92027 | Built-in | `powershell -NoProfile -Command Get-Date` |
| T1087.001 | Local Account Discovery | 92031, 92033 | Built-in | `net user` |
| T1012 | Query Registry | 100150 | Custom | `reg.exe query ...` |
| - | Defender threat detected (1116) | 100201 | Custom | EICAR test file |
| - | Defender action taken (1117) | 100202 | Custom | EICAR test file |

## Controlled run

Commands run manually in one PowerShell session on 2026-10-30. Start time recorded as 16:13:48 IST.

```powershell
Get-Date -Format "yyyy-MM-ddTHH:mm:ss"
systeminfo | Out-Null
tasklist | Out-Null
ipconfig /all | Out-Null
netstat -ano | Out-Null
net user | Out-Null
powershell -NoProfile -Command "Get-Date" | Out-Null
reg.exe query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" | Out-Null
```

| Time (IST) | Command | Rule | MITRE tag |
|---|---|---|---|
| 16:13:50 | `systeminfo` | 100100 | T1082 |
| 16:13:52 | `tasklist` | 100120 | T1057 |
| 16:13:52 | `ipconfig /all` | 100130 | T1016 |
| 16:13:52 | `netstat -ano` | 100140 | T1049 |
| 16:13:52 | `net user` | 92033, 92031 | T1087, T1059.001 |
| 16:13:52 | `powershell -NoProfile -Command Get-Date` | 92027 | T1059.001 |
| 16:13:54 | `reg.exe query ...` | 100150 | T1012 |

`cmd /c echo test` did not alert 92032 in this run, because piping to `Out-Null` probably prevented a console from being created. T1059.003 evidence comes from the Atomic Red Team test.

## Caveats
- Only T1059.003 was validated with Atomic Red Team; the other techniques used manual commands.
- Built-in account-discovery rules tag the parent technique T1087, not T1087.001.
- Built-in rule 92032 carries two tags (T1087 and T1059.003), so it is broader than the technique.
- Defender rules 100201 and 100202 carry no MITRE tag.

Evidence table: [`evidence/Wazuh_Alert_Validation.xlsx`](evidence/Wazuh_Alert_Validation.xlsx)
