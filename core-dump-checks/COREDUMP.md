## How to Generate NSPPE Core Dump on NetScaler
> [!WARNING]  
> **HIGH TRAFFIC IMPACT INTERRUPTION**  
> Running a `kill -6` command on the Packet Engine (`NSPPE`) process will cause the process to crash intentionally. This results in **immediate service disruption, dropped connections, and a failover event** if the NetScaler is configured in a High Availability (HA) pair. Only perform this action during an approved maintenance window.

### Citrix NetScaler (ADC) Packet Engines (NSPPE)

1. Disable the pitboss policy abort override via the NetScaler CLI:
```shell
local ~ $ ssh nsroot@<YOUR-NETSCALER-IP> "pb_policy -o abort"
```

2. Locate the Process ID (PID) for the packet engine by wrapping the bash pipeline in quotes:
```shell
local ~ $ ssh nsroot@<YOUR-NETSCALER-IP> "shell 'ps -aux | grep -i ppe'"
```

3. Force a core dump by sending a `kill -6` (SIGABRT) signal to the specific PID (Note: **This will restart the packet engine process and will interrupt traffic**):
```shell
local ~ $ ssh nsroot@<YOUR-NETSCALER-IP> "shell kill -6 <PID>"
```

4. Once the system recovers, restore the default policy via the NetScaler CLI:
```shell
local ~ $ ssh nsroot@<YOUR-NETSCALER-IP> "pb_policy -d"
``` 

5. The resulting files are typically written to `/var/core/`.

Referrence: https://support.citrix.com/external/article/CTX207598/how-to-generate-nsppe-core-dump-on-netsc.html
