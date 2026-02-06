# wazuh-eol-integration
## How It Works
<img width="372" height="614" alt="Screenshot 2026-02-06 143743" src="https://github.com/user-attachments/assets/f25ea655-e00e-49a5-aa17-6f8cd1ff4cdd" />



## Installation Summary (From INSTALLATION.md)

### Quick Install
```bash
# 1. Copy script to Wazuh Manager
#creating dictionary 
sudo mkdir -p /var/ossec/integrations/eol_checker
sudo nano /var/ossec/integrations/eol_checker/wazuh_eol_checker.py
#at this step copy paste the script from wazuh_eol_checker.py
save the changes 

# 2. Install dependencies
sudo pip3 install requests --break-system-packages

# 3. Create inventory 
sudo nano /var/ossec/etc/software_inventory.csv

# 4. Test it
sudo -u wazuh /usr/bin/python3 /var/ossec/integrations/eol_checker/wazuh_eol_checker.py
```

## Sample Output

When you run the script, Wazuh will receive events like this:
make sure its only printing the json
```json
{
  "timestamp": "2024-02-05T10:30:00Z",
  "eol_check": {
    "product": "mysql",
    "version": "5.7",
    "system": "Legacy Database",
    "criticality": "Critical",
    "eol_date": "2023-10-31",
    "is_eol": true,
    "support_status": "End of Life",
    "days_until_eol": 0,
    "risk_score": 80
  }
}
```
## Risk Score Calculation

The script calculates a risk score (0-100) based on:

| Factor | Score Addition |
|--------|----------------|
| Already EOL | +50 |
| EOL Soon (<90 days) | +35 |
| EOL Approaching (<6 months) | +20 |
| Criticality: Critical | +30 |
| Criticality: High | +20 |
| Criticality: Medium | +10 |
| EOL in <30 days | +20 |
| EOL in <90 days | +10 |

## Steps 2

# Configure Wazuh Manager
- Add Wodle configuration to ossec.conf
 ```bash 
  sudo nano /var/ossec/etc/ossec.conf
#then paste this set the interval to your need
<!-- EOL Checker Integration -->
  <wodle name="command">
    <disabled>no</disabled>
    <tag>eol_checker</tag>
    <command>/usr/bin/python3 /var/ossec/integrations/eol_checker/wazuh_eol_checker.py</command>
    <interval>90d</interval>
    <ignore_output>no</ignore_output>
    <run_on_start>yes</run_on_start>
    <timeout>600</timeout>
  </wodle>
  ```
## Step 3: Create Custom Decoder
```bash
create a file in this path
sudo nano /var/ossec/etc/decoders/local_decoder.xml
##then paste this
<!-- EOL Checker Decoder -->
<decoder name="eol_checker">
  <prematch>eol_check</prematch>
</decoder>

<decoder name="eol_checker_json">
  <parent>eol_checker</parent>
  <plugin_decoder>JSON_Decoder</plugin_decoder>
</decoder>
```
save and exit

Step 4: Create Custom Rules
```bash
add or copy and paste these rule at
sudo nano /var/ossec/etc/rules/local_rules.xml
 
  <!-- Base rule for all EOL events -->
  <rule id="100100" level="3">
    <field name="eol_check.product">\.+</field>
    <description>EOL Checker: Software inventory check</description>
  </rule>

  <!-- CRITICAL: EOL software on Critical systems -->
  <rule id="100101" level="12">
    <if_sid>100100</if_sid>
    <field name="eol_check.is_eol">true</field>
    <field name="eol_check.criticality">Critical</field>
    <description>EOL Checker: CRITICAL - $(eol_check.criticality) system running EOL software - $(eol_check.product) $(eol_check.version) on $(eol_check.system)</description>
    <group>gdpr_IV_35.7.d,hipaa_164.312.b,nist_800_53_SI.2,pci_dss_6.2,tsc_CC7.1,</group>
  </rule>

  <!-- HIGH: EOL software on High priority systems -->
  <rule id="100102" level="10">
    <if_sid>100100</if_sid>
    <field name="eol_check.is_eol">true</field>
    <field name="eol_check.criticality">High</field>
    <description>EOL Checker: HIGH - $(eol_check.criticality) system running EOL software - $(eol_check.product) $(eol_check.version) on $(eol_check.system)</description>
    <group>gdpr_IV_35.7.d,hipaa_164.312.b,nist_800_53_SI.2,pci_dss_6.2,</group>
  </rule>

  <!-- WARNING: EOL Soon (<90 days) -->
  <rule id="100103" level="7">
    <if_sid>100100</if_sid>
    <field name="eol_check.support_status">EOL Soon</field>
    <description>EOL Checker: WARNING - Software approaching EOL - $(eol_check.product) $(eol_check.version) EOL in $(eol_check.days_until_eol) days on $(eol_check.system)</description>
  </rule>

  <!-- WARNING: EOL Approaching (<6 months) -->
  <rule id="100104" level="5">
    <if_sid>100100</if_sid>
    <field name="eol_check.support_status">EOL Approaching</field>
    <description>EOL Checker: WARNING - Software EOL approaching - $(eol_check.product) $(eol_check.version) EOL in $(eol_check.days_until_eol) days on $(eol_check.system)</description>
  </rule>

  <!-- MEDIUM: End of Life detected (Medium priority) -->
  <rule id="100105" level="7">
    <if_sid>100100</if_sid>
    <field name="eol_check.is_eol">true</field>
    <field name="eol_check.criticality">Medium</field>
    <description>EOL Checker: Medium priority EOL software - $(eol_check.product) $(eol_check.version) on $(eol_check.system)</description>
  </rule>

  <!-- LOW: End of Life detected (Low priority) -->
  <rule id="100106" level="5">
    <if_sid>100100</if_sid>
    <field name="eol_check.is_eol">true</field>
    <field name="eol_check.criticality">Low</field>
    <description>EOL Checker: Low priority EOL software - $(eol_check.product) $(eol_check.version) on $(eol_check.system)</description>
  </rule>

  <!-- End of Support (even if not fully EOL) -->
  <rule id="100107" level="8">
    <if_sid>100100</if_sid>
    <field name="eol_check.support_status">End of Support</field>
    <description>EOL Checker: End of Support - $(eol_check.product) $(eol_check.version) on $(eol_check.system)</description>
  </rule>

  <!-- INFO: Actively supported software -->
  <rule id="100108" level="1">
    <if_sid>100100</if_sid>
    <field name="eol_check.support_status">Actively Supported</field>
    <description>EOL Checker: Software actively supported - $(eol_check.product) $(eol_check.version)</description>
  </rule>

  <!-- Summary/Completion event -->
  <rule id="100109" level="3">
    <if_sid>100100</if_sid>
    <field name="eol_check.status">completed</field>
    <description>EOL Checker: Scan completed - $(eol_check.total_checked) items checked, $(eol_check.eol_count) EOL detected</description>
  </rule>

  <!-- Error event -->
  <rule id="100110" level="5">
    <if_sid>100100</if_sid>
    <field name="eol_check.status">error</field>
    <description>EOL Checker: ERROR - $(eol_check.message)</description>
  </rule>

</group>
```
| rule id | rule level | severity |
|----------|------|------------|
| 100100| 3 |BASE(INFO) |
| 100101| 12 |CRITICAL +EOL|
| 100102 | 10 |HIGH +EOL|
| 100103| 7 |EOL Soon <than 90 days|
| 100104| 5 |EOL Approching|
| 100105| 7 |medium+EOL|
| 100106| 5 |LOW+EOL|
| 100107| 8 |HIGH(END OF SUPPORT)|
|100108 | 1 |ACTIVELY SUPPORTED)|
## Step 5: Restart Wazuh
Apply configurations
Verify wodle execution
Check logs

## Step 6: Build Dashboard
Create visualizations
Build comprehensive dashboard
Set up email/Slack notifications

