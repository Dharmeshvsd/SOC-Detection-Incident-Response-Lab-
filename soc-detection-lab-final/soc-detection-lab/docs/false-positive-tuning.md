# False-positive tuning

## Problem
Rules 92031 (account discovery) and 100150 (query registry) kept alerting on commands nobody had run.

## Investigation
Counting alerts by parent process showed the source:

| Rule | Alerts by parent |
|---|---|
| 92031 | 18 from `wazuh-agent.exe`, 18 from `SysWOW64\net.exe`, 6 from `System32\net.exe` (my own tests) |
| 100150 | 4 from `wazuh-agent.exe`, 2 from `powershell.exe` (my own tests) |

A raw event showed the agent running `net user` as SYSTEM, with `net1.exe` as the child process. The agent also ran
`reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system /v legalnoticetext`, which looks like a
Security Configuration Assessment check. The module behind `net user` is not confirmed.

## Fix
Three level-0 child rules in `rules/local_rules.xml`: 100301, 100302, 100303.

| Rule | Parent | Suppresses |
|---|---|---|
| 100301 | 92031 | `net.exe` launched by `wazuh-agent.exe` |
| 100302 | 92031 | `SysWOW64\net1.exe` run as SYSTEM |
| 100303 | 100150 | `reg.exe` launched by `wazuh-agent.exe` |

## Verification
After the tuning, the agent ran `net user` twice and `reg query` twice. The events reached `archives.json` but raised
no alerts, while a manual `net user` and `reg query` from PowerShell still alerted.

## Limitation
Rule 100302 cannot check that the event came from the agent, because the parent of `net1.exe` is `net.exe`.
It would also hide a SYSTEM-run 32-bit `net1.exe user`. Narrow it further for production use.
