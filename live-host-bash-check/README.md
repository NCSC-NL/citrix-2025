# Webshell Detection Script for Citrix Netscaler appliances
## Author: NCSC-NL

### Disclaimer
This script is provided without any guarantees regarding its effectiveness.  
The detection capabilities of this script are based on a limited set of detection rules.  
Make sure to follow instructions from the vendor and information listed in advisories regarding vulnerabilities.  
Make sure no sensitive information is disclosed when sharing the output of this script.

### Point of contact
For interpretation of the output from this scanning script, please forward this information  
to your national cybersecurity entity (national CSIRT or otherwise).  

### Instructions
The check script looks for specific files on a netscaler environment that give indication for compromise. 
For usage, refer to the instructions below:
1. Upload the detection script `TLPCLEAR_check_script_cve-2025-6543-v1.8.sh` to a directory on your netscaler appliance such as /tmp (e.g. using the scp command)
2. Open a (SSH) shell to the appliance and navigate to the directory containing the detection script
3. Run the script as follows: `/bin/sh TLPCLEAR_check_script_cve-2025-6543-v1.8.sh`
4. Transfer the following file from the netscaler: `/var/log/custom_checks.log`
5. Inspect the logfile for output. Everything not marked as a "low confidence indicator" should be considered an indicator of compromise and followed up on immediately. 
6. Share the logfile with your  national cyber security incident response entity (CSIRT) such as a NCSC or Govcert for further assistance, for EU: https://csirtsnetwork.eu

### Follow this repository 
Please monitor this repository for changes, additional checks could follow. 
Feedback and improvements are very much welcomed and can be suggested by opening a Github issue.  
