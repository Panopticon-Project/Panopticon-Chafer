![alt tag](https://user-images.githubusercontent.com/24201238/29351849-9c3087b4-82b8-11e7-8fed-350e3b8b4945.png)

## Name - Chafer
* Label - Advanced Persistent Threat (APT) 

## Aliases
* [No information](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)

## Overview 
* Chafer is believed to be an Iranian APT and appears to be primarily engaged in surveillance and tracking of individuals, with most of its attacks likely carried out to gather information on targets or facilitate surveillance. Targeting occurs within Iran, elsewhere in the Middle East, Africa, and multinational corporations across the world.

## Campaign or Date Range
* Date Range
* About - [Targeting airlines, aitcraft services, software, IT services, telecom Services, payroll and engineering services in the Middle East](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
* Active from - 01 January 2015
* Active to - 31 December 2015

### Attributes
* Resource level - [Government](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
* Sophistication - [Expert](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
* Primary activities - Chafer appears to be primarily engaged in surveillance and tracking of individuals, with most of its attacks likely carried out to gather information on targets or facilitate surveillance.

### Attack Pattern
* Initial Access 
  * [Exploit Public-Facing Application](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * In the earlier attacks from 2015, Symantec found evidence that Chafer had been compromising targeted organizations by attacking their web servers, likely through SQL injection attacks, in order to drop malware onto them.
* Execution
  * No information
* Persistence
  * No information
* Privilege Escalation 
  * No information
* Defence Evasion 
  * No information
* Credential Access
  * No information
* Discovery
  * No information
* Lateral Movement
  * No information
* Collection
  * No information
* Exfiltration 
  * No information
* Command and Control 
  * No information

### Vulnerabilities
* [No information](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)

### Identity

#### Individuals 
[No information](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)

#### Affiliated organisations
* [Islamic Republic of Iran](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * Attribution - Symantec attributes this APT to Iran.

#### Affiliated groups
* [OilRig](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * Attribution - Symantec note that Chafer’s activities have some links to Oilrig. Both groups have been observed using the same IP address for command and control purposes. In addition to this, both groups have been seen using a similar infection vector, an Excel document which drops a malicious VBS file. Both VBS files reference the same file path, containing the same misspelling: “schtasks.exe /create/ F /sc minute /mo 2 /tn "UpdatMachine" /tr %LOCALAPPDATA%\microsoft\Feed\Y658123.vbs”

### Intrusion Set

#### Malware
* Names - [Remexi, Remexi.B](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * Functionality - Backdoor
  * Hash - N/A
  * Notes - The malware is simply described as a backdoor by Symantic, there are later writeups covering functionality of Remexi.

#### Website 
* Name - [No information](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * About - N/A
  * URL - N/A
  * IP - N/A
  * Valid from - N/A
  * Valid to - N/A

#### Command and Control Server or Domain
* IP - [No information](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
* Domain - [No information](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * Valid from - N/A
  * Valid to - N/A
  * SSH host key
    * RSA - N/A
    * ECDSA - N/A
    * ED25519 - N/A
  * SSL Certificate
    * Issuer - N/A
    * Public key type - N/A
    * Public key bits - N/A
    * Signature algorithm - N/A
    * Not valid before - N/A
    * Not valid after - N/A
    * MD5 - N/A
    * SHA-1 - N/A
  * Notes - N/A

#### Documents
* Filename - [No information](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * About - N/A
  * Hash - N/A
  * Notes - N/A

#### Tools
* Names - [PsExec](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * Functionality - PsExec is a light-weight telnet-replacement that lets you execute processes on other systems, complete with full interactivity for console applications, without having to manually install client software. 
  * URL - https://docs.microsoft.com/en-us/sysinternals/downloads/psexec

* Names - [Mimikatz](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * Functionality - Mimikatz can extract plaintexts passwords, hash, PIN code and kerberos tickets on a Windows system from memory. Mimikatz can also perform pass-the-hash, pass-the-ticket or build Golden tickets.
  * URL - https://github.com/gentilkiwi/mimikatz
  
* Names - [Plink (PuTTY Link)](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * Functionality - PuTTY is a free implementation of SSH and Telnet for Windows and Unix platforms, along with an xterm terminal emulator.
  * URL - https://www.chiark.greenend.org.uk/~sgtatham/putty/
  
## Campaign or Date Range
* Date Range
* About - [Targeting airlines, aitcraft services, software, IT services, telecom Services, payroll and engineering services in the Middle East](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
* Active from - 01 January 2017
* Active to - 31 December 2017

### Attributes
* Resource level - [Government](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
* Sophistication - [Expert](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
* Primary activities - Chafer appears to be primarily engaged in surveillance and tracking of individuals, with most of its attacks likely carried out to gather information on targets or facilitate surveillance.

### Attack Pattern
* Initial Access 
  * [Exploit Public-Facing Application](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * In the earlier attacks from 2015, Symantec found evidence that Chafer had been compromising targeted organizations by attacking their web servers, likely through SQL injection attacks, in order to drop malware onto them.
  * [Spearphishing Attachment](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * In 2017, the group added a new infection method to its toolkit, using malicious documents which are likely circulated using spear-phishing emails sent to individuals working in targeted organizations.
* Execution
  * [PowerShell](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * The documents used in spearphishing were Excel spreadsheets. When opened, they downloaded a malicious VBS file that in turn ran a PowerShell script. Several hours later, a dropper would appear on the compromised computer. This would install three files on the computer, an information stealer, a screen capture utility, and an empty executable.
  * [Scripting](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * The documents used in spearphishing were Excel spreadsheets. When opened, they downloaded a malicious VBS file that in turn ran a PowerShell script. Several hours later, a dropper would appear on the compromised computer. This would install three files on the computer, an information stealer, a screen capture utility, and an empty executable.
  * [Service Execution](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * Remcom, PsExec used to start and stop services. NSSM used to install and remove services.
* Persistence
  * [New Service](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * The group has recently adopted NSSM to maintain persistence and install the service which runs Plink on the compromised computer. Plink is then used to open reverse SSH sessions from the attacker's server to the RDP port on the victim computer. 
  * [Scheduled Task](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * The group has recently adopted NSSM to maintain persistence and install the service which runs Plink on the compromised computer. Plink is then used to open reverse SSH sessions from the attacker's server to the RDP port on the victim computer. 
* Privilege Escalation 
  * No information
* Defence Evasion 
  * No information
* Credential Access
  * [Input Capture](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * The information stealer was capable of stealing the contents of the clipboard, taking screenshots, recording keystrokes and stealing files and user credentials.
  * [Forced Authentication](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * SMB hacking tools where used in conjunction with other tools to traverse target networks. These tools include the EternalBlue exploit.
* Discovery
  * [System Network Configuration Discovery](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * NBTScan was used to find share drives and devices on a network.
* Lateral Movement
  * [Pass the Hash](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * Mimikatz part of toolset.
  * [Pass the Ticket](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * Mimikatz part of toolset.
  * [Remote Desktop Protocol](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * Plink part of toolset, used in conjunction with NSSM to keep PLink running and maintain persistence.
* Collection
  * [Clipboard Data]
  * The information stealer was capable of stealing the contents of the clipboard, taking screenshots, recording keystrokes and stealing files and user credentials.
  * [Input Capture](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * The information stealer was capable of stealing the contents of the clipboard, taking screenshots, recording keystrokes and stealing files and user credentials.
  * [Screen Capture](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * The screen capture utility appeared to be used for initial information gathering, as it was only used briefly at the beginning of each infection and not seen again. 
* Exfiltration 
  * No information
* Command and Control 
  * [Remote Access Tools](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * GNU HTTPTunnel and UltraVNC part of toolset.

### Vulnerabilities
* [MS17-010](https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2017/ms17-010) is exploited by SMB hacking tools. [1](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)

### Identity

#### Individuals 
[No information](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)

#### Affiliated organisations
* [Islamic Republic of Iran](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * Attribution - Symantec attributes this APT to Iran.

#### Affiliated groups
* [OilRig](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * Attribution - Symantec note that Chafer’s activities have some links to Oilrig. Both groups have been observed using the same IP address for command and control purposes. In addition to this, both groups have been seen using a similar infection vector, an Excel document which drops a malicious VBS file. Both VBS files reference the same file path, containing the same misspelling: “schtasks.exe /create/ F /sc minute /mo 2 /tn "UpdatMachine" /tr %LOCALAPPDATA%\microsoft\Feed\Y658123.vbs”

### Intrusion Set

#### Malware
* Names - [Remexi, Remexi.B](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * Functionality - Backdoor
  * Hash - N/A
  * Notes - The malware is simply described as a backdoor by Symantic, there are later writeups covering functionality of Remexi.

#### Website 
* Name - No information
  * About - N/A
  * URL - N/A
  * IP - N/A
  * Valid from - N/A
  * Valid to - N/A

#### Command and Control Server or Domain
* Domain - [win7-updates[.]com](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * Valid from - [01 January 2017](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * Valid to - [31 Decemeber 2017](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * [SSH host key]
    * RSA - N/A
    * ECDSA - N/A
    * ED25519 - N/A
  * [SSL Certificate]
    * Issuer - N/A
    * Public key type - N/A
    * Public key bits - N/A
    * Signature algorithm - N/A
    * Not valid before - N/A
    * Not valid after - N/A
    * MD5 - N/A
    * SHA-1 - N/A
  * Notes
    * One article dated 28 February 2018 details the domain win7-updates[.]com, stating only that the domain was used by the attacker. As such the date range is imprecise.

* IP - [107.191.62[.]45](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * Valid from - [01 January 2017](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * Valid to - [31 Decemeber 2017](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * SSH host key
    * RSA - N/A
    * ECDSA - N/A
    * ED25519 - N/A
  * SSL Certificate
    * Issuer - N/A
    * Public key type - N/A
    * Public key bits - N/A
    * Signature algorithm - N/A
    * Not valid before - N/A
    * Not valid after - N/A
    * MD5 - N/A
    * SHA-1 - N/A
  * Notes
    * One article dated 28 February 2018 details the domain win7-updates[.]com, stating only that the domain was used by the attacker. As such the date range is imprecise.
    * It is unclear whether these were leased or hijacked, but the fact that many of them appear to follow a pattern—with the latter three numbers of each address often running in sequence—makes it likely they were deliberately selected by the attackers.

* IP - [94.100.21[.]213](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * Valid from - [01 January 2017](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * Valid to - [31 Decemeber 2017](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * SSH host key
    * RSA - N/A
    * ECDSA - N/A
    * ED25519 - N/A
  * SSL Certificate
    * Issuer - N/A
    * Public key type - N/A
    * Public key bits - N/A
    * Signature algorithm - N/A
    * Not valid before - N/A
    * Not valid after - N/A
    * MD5 - N/A
    * SHA-1 - N/A
  * Notes
    * One article dated 28 February 2018 details the domain win7-updates[.]com, stating only that the domain was used by the attacker. As such the date range is imprecise.
    * It is unclear whether these were leased or hijacked, but the fact that many of them appear to follow a pattern—with the latter three numbers of each address often running in sequence—makes it likely they were deliberately selected by the attackers.

* IP - [89.38.97[.]112](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * Valid from - [01 January 2017](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * Valid to - [31 Decemeber 2017](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * SSH host key
    * RSA - N/A
    * ECDSA - N/A
    * ED25519 - N/A
  * SSL Certificate
    * Issuer - N/A
    * Public key type - N/A
    * Public key bits - N/A
    * Signature algorithm - N/A
    * Not valid before - N/A
    * Not valid after - N/A
    * MD5 - N/A
    * SHA-1 - N/A
  * Notes
    * One article dated 28 February 2018 details the domain win7-updates[.]com, stating only that the domain was used by the attacker. As such the date range is imprecise.
    * It is unclear whether these were leased or hijacked, but the fact that many of them appear to follow a pattern—with the latter three numbers of each address often running in sequence—makes it likely they were deliberately selected by the attackers.

* IP - [148.251.197[.]113](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * Valid from - [01 January 2017](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * Valid to - [31 Decemeber 2017](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * SSH host key
    * RSA - N/A
    * ECDSA - N/A
    * ED25519 - N/A
  * SSL Certificate
    * Issuer - N/A
    * Public key type - N/A
    * Public key bits - N/A
    * Signature algorithm - N/A
    * Not valid before - N/A
    * Not valid after - N/A
    * MD5 - N/A
    * SHA-1 - N/A
  * Notes
    * One article dated 28 February 2018 details the domain win7-updates[.]com, stating only that the domain was used by the attacker. As such the date range is imprecise.
    * It is unclear whether these were leased or hijacked, but the fact that many of them appear to follow a pattern—with the latter three numbers of each address often running in sequence—makes it likely they were deliberately selected by the attackers.

* IP - [83.142.230[.]113](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * Valid from - [01 January 2017](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * Valid 
  to - [31 Decemeber 2017](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * SSH host key
    * RSA - N/A
    * ECDSA - N/A
    * ED25519 - N/A
  * SSL Certificate
    * Issuer - N/A
    * Public key type - N/A
    * Public key bits - N/A
    * Signature algorithm - N/A
    * Not valid before - N/A
    * Not valid after - N/A
    * MD5 - N/A
    * SHA-1 - N/A
  * Notes
    * One article dated 28 February 2018 details the domain win7-updates[.]com, stating only that the domain was used by the attacker. As such the date range is imprecise.
    * It is unclear whether these were leased or hijacked, but the fact that many of them appear to follow a pattern—with the latter three numbers of each address often running in sequence—makes it likely they were deliberately selected by the attackers.
    
* IP - [87.117.204[.]113](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * Valid from - [01 January 2017](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * Valid 
  to - [31 Decemeber 2017](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * SSH host key
    * RSA - N/A
    * ECDSA - N/A
    * ED25519 - N/A
  * SSL Certificate
    * Issuer - N/A
    * Public key type - N/A
    * Public key bits - N/A
    * Signature algorithm - N/A
    * Not valid before - N/A
    * Not valid after - N/A
    * MD5 - N/A
    * SHA-1 - N/A
  * Notes
    * One article dated 28 February 2018 details the domain win7-updates[.]com, stating only that the domain was used by the attacker. As such the date range is imprecise.
    * It is unclear whether these were leased or hijacked, but the fact that many of them appear to follow a pattern—with the latter three numbers of each address often running in sequence—makes it likely they were deliberately selected by the attackers.

* IP - [89.38.97[.]115](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * Valid from - [01 January 2017](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * Valid 
  to - [31 Decemeber 2017](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * SSH host key
    * RSA - N/A
    * ECDSA - N/A
    * ED25519 - N/A
  * SSL Certificate
    * Issuer - N/A
    * Public key type - N/A
    * Public key bits - N/A
    * Signature algorithm - N/A
    * Not valid before - N/A
    * Not valid after - N/A
    * MD5 - N/A
    * SHA-1 - N/A
  * Notes
    * One article dated 28 February 2018 details the domain win7-updates[.]com, stating only that the domain was used by the attacker. As such the date range is imprecise.
    * It is unclear whether these were leased or hijacked, but the fact that many of them appear to follow a pattern—with the latter three numbers of each address often running in sequence—makes it likely they were deliberately selected by the attackers.

* IP - [87.117.204[.]115](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * Valid from - [01 January 2017](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * Valid 
  to - [31 Decemeber 2017](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * SSH host key
    * RSA - N/A
    * ECDSA - N/A
    * ED25519 - N/A
  * SSL Certificate
    * Issuer - N/A
    * Public key type - N/A
    * Public key bits - N/A
    * Signature algorithm - N/A
    * Not valid before - N/A
    * Not valid after - N/A
    * MD5 - N/A
    * SHA-1 - N/A
  * Notes
    * One article dated 28 February 2018 details the domain win7-updates[.]com, stating only that the domain was used by the attacker. As such the date range is imprecise.
    * It is unclear whether these were leased or hijacked, but the fact that many of them appear to follow a pattern—with the latter three numbers of each address often running in sequence—makes it likely they were deliberately selected by the attackers.

* IP - [185.22.172[.]40](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * Valid from - [01 January 2017](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * Valid 
  to - [31 Decemeber 2017](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * SSH host key
    * RSA - N/A
    * ECDSA - N/A
    * ED25519 - N/A
  * SSL Certificate
    * Issuer - N/A
    * Public key type - N/A
    * Public key bits - N/A
    * Signature algorithm - N/A
    * Not valid before - N/A
    * Not valid after - N/A
    * MD5 - N/A
    * SHA-1 - N/A
  * Notes
    * One article dated 28 February 2018 details the domain win7-updates[.]com, stating only that the domain was used by the attacker. As such the date range is imprecise.
    * It is unclear whether these were leased or hijacked, but the fact that many of them appear to follow a pattern—with the latter three numbers of each address often running in sequence—makes it likely they were deliberately selected by the attackers.

* IP - [92.243.95[.]203](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * Valid from - [01 January 2017](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * Valid 
  to - [31 Decemeber 2017](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * SSH host key
    * RSA - N/A
    * ECDSA - N/A
    * ED25519 - N/A
  * SSL Certificate
    * Issuer - N/A
    * Public key type - N/A
    * Public key bits - N/A
    * Signature algorithm - N/A
    * Not valid before - N/A
    * Not valid after - N/A
    * MD5 - N/A
    * SHA-1 - N/A
  * Notes
    * One article dated 28 February 2018 details the domain win7-updates[.]com, stating only that the domain was used by the attacker. As such the date range is imprecise.
    * It is unclear whether these were leased or hijacked, but the fact that many of them appear to follow a pattern—with the latter three numbers of each address often running in sequence—makes it likely they were deliberately selected by the attackers.

* IP - [91.218.114[.]204](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * Valid from - [01 January 2017](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * Valid 
  to - [31 Decemeber 2017](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * SSH host key
    * RSA - N/A
    * ECDSA - N/A
    * ED25519 - N/A
  * SSL Certificate
    * Issuer - N/A
    * Public key type - N/A
    * Public key bits - N/A
    * Signature algorithm - N/A
    * Not valid before - N/A
    * Not valid after - N/A
    * MD5 - N/A
    * SHA-1 - N/A
  * Notes
    * One article dated 28 February 2018 details the domain win7-updates[.]com, stating only that the domain was used by the attacker. As such the date range is imprecise.
    * It is unclear whether these were leased or hijacked, but the fact that many of them appear to follow a pattern—with the latter three numbers of each address often running in sequence—makes it likely they were deliberately selected by the attackers.

* IP - [86.105.227[.]224](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * Valid from - [01 January 2017](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * Valid 
  to - [31 Decemeber 2017](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * SSH host key
    * RSA - N/A
    * ECDSA - N/A
    * ED25519 - N/A
  * SSL Certificate
    * Issuer - N/A
    * Public key type - N/A
    * Public key bits - N/A
    * Signature algorithm - N/A
    * Not valid before - N/A
    * Not valid after - N/A
    * MD5 - N/A
    * SHA-1 - N/A
  * Notes
    * One article dated 28 February 2018 details the domain win7-updates[.]com, stating only that the domain was used by the attacker. As such the date range is imprecise.
    * It is unclear whether these were leased or hijacked, but the fact that many of them appear to follow a pattern—with the latter three numbers of each address often running in sequence—makes it likely they were deliberately selected by the attackers.
    

* IP - [91.218.114[.]225](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * Valid from - [01 January 2017](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * Valid 
  to - [31 Decemeber 2017](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * SSH host key
    * RSA - N/A
    * ECDSA - N/A
    * ED25519 - N/A
  * SSL Certificate
    * Issuer - N/A
    * Public key type - N/A
    * Public key bits - N/A
    * Signature algorithm - N/A
    * Not valid before - N/A
    * Not valid after - N/A
    * MD5 - N/A
    * SHA-1 - N/A
  * Notes
    * One article dated 28 February 2018 details the domain win7-updates[.]com, stating only that the domain was used by the attacker. As such the date range is imprecise.
    * It is unclear whether these were leased or hijacked, but the fact that many of them appear to follow a pattern—with the latter three numbers of each address often running in sequence—makes it likely they were deliberately selected by the attackers.                           

* IP - [134.119.217[.]84](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * Valid from - [01 January 2017](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * Valid 
  to - [31 Decemeber 2017](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * SSH host key
    * RSA - N/A
    * ECDSA - N/A
    * ED25519 - N/A
  * SSL Certificate
    * Issuer - N/A
    * Public key type - N/A
    * Public key bits - N/A
    * Signature algorithm - N/A
    * Not valid before - N/A
    * Not valid after - N/A
    * MD5 - N/A
    * SHA-1 - N/A
  * Notes
    * One article dated 28 February 2018 details the domain win7-updates[.]com, stating only that the domain was used by the attacker. As such the date range is imprecise.
    * It is unclear whether these were leased or hijacked, but the fact that many of them appear to follow a pattern—with the latter three numbers of each address often running in sequence—makes it likely they were deliberately selected by the attackers.   

#### Documents
* Filename - [No information](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * About - N/A
  * Hash - N/A
  * Notes - N/A

#### Tools
* Names - [PsExec](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * Functionality - PsExec is a light-weight telnet-replacement that lets you execute processes on other systems, complete with full interactivity for console applications, without having to manually install client software. 
  * URL - https://docs.microsoft.com/en-us/sysinternals/downloads/psexec

* Names - [Mimikatz](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * Functionality - Mimikatz can extract plaintexts passwords, hash, PIN code and kerberos tickets on a Windows system from memory. Mimikatz can also perform pass-the-hash, pass-the-ticket or build Golden tickets.
  * URL - https://github.com/gentilkiwi/mimikatz
  
* Names - [Plink (PuTTY Link)](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * Functionality - PuTTY is a free implementation of SSH and Telnet for Windows and Unix platforms, along with an xterm terminal emulator.
  * URL - https://www.chiark.greenend.org.uk/~sgtatham/putty/

* Names - [Remcom](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * Functionality - RemCom is a small (10KB upx packed) remoteshell / telnet replacement that lets you execute processes on remote windows systems, copy files on remote systems, process there output and stream it back. It allows execution of remote shell commands directly with full interactive console without having to install any client software. On local machines it is also able to impersonate so can be used as a silent replacement for Runas command.
  * URL - https://github.com/kavika13/RemCom

* Names - [Non-sucking Service Manager (NSSM)](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * Functionality - Nssm monitors the running service and will restart it if it dies. Nssm logs its progress to the system Event Log so you can get some idea of why an application isn't behaving as it should.
  * URL - https://nssm.cc/

* Names - [Custom screenshot and clipboard capture tool](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * Functionality - Screenshot and clipboard capture.
  * URL - N/A
  
* Names - [SMB hacking tools](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * Functionality - Tools include the EternalBlue exploit.
  * URL - N/A

* Names - [GNU HTTPTunnel](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * Functionality - Tools include the EternalBlue exploit.
  * URL - http://neophob.com/2006/10/gnu-httptunnel-v33-windows-binaries/

* Names - [UltraVNC](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * Functionality - UltraVNC, an open-source remote-administration/remote-desktop-software utility for Microsoft Windows, uses the VNC protocol to control/access another computer remotely over a network connection.
  * URL - https://www.uvnc.com/

* Names - [NBTScan](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * Functionality - A command-line tool that scans for open NETBIOS nameservers on a local or remote TCP/IP network, and is a first step in finding of open shares.
  * URL - http://unixwiz.net/tools/nbtscan.html
  
## Time context ends

### Detection 
* [Exploit Public-Facing Application](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * Monitor application logs for abnormal behavior that may indicate attempted or successful exploitation. 
  * Use deep packet inspection to look for artifacts of common exploit traffic, such as SQL injection. 
  * Web Application Firewalls may detect improper inputs attempting exploitation.
* [Spearphishing Attachment](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * Network intrusion detection systems can be used to detect spearphishing with malicious attachments in transit.
  * Email gateways can be used to detect spearphishing with malicious attachments in transit. 
  * Detonation chambers may also be used to identify malicious attachments.  
  * Anti-virus can potentially detect malicious documents and attachments as they're scanned to be stored on the email server or on the user's computer. 
  * Endpoint sensing or network sensing can potentially detect malicious events once the attachment is opened (such as a Microsoft Word document or PDF reaching out to the internet or spawning Powershell.exe) for techniques such as Exploitation for Client Execution and Scripting.
* [PowerShell](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * If proper execution policy is set, adversaries will likely be able to define their own execution policy if they obtain administrator or system access, either through the Registry or at the command line. This change in policy on a system may be a way to detect malicious use of PowerShell. 
  * If PowerShell is not used in an environment, then simply looking for PowerShell execution may detect malicious activity.
  * Monitor for loading and/or execution of artifacts associated with PowerShell specific assemblies, such as System.Management.Automation.dll (especially to unusual process names/locations). 
  * It is also beneficial to turn on PowerShell logging to gain increased fidelity in what occurs during execution (which is applied to .NET invocations). PowerShell 5.0 introduced enhanced logging capabilities, and some of those features have since been added to PowerShell 4.0. Earlier versions of PowerShell do not have many logging features. 
  * An organization can gather PowerShell execution details in a data analytic platform to supplement it with other data.
* [Scripting](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * Scripting may be common on admin, developer, or power user systems, depending on job function. If scripting is restricted for normal users, then any attempts to enable scripts running on a system would be considered suspicious. 
  * If scripts are not commonly used on a system, but enabled, scripts running out of cycle from patching or other administrator functions are suspicious. 
  * Scripts should be captured from the file system when possible to determine their actions and intent.
  * Scripts are likely to perform actions with various effects on a system that may generate events, depending on the types of monitoring used. Monitor processes and command-line arguments for script execution and subsequent behavior. Actions may be related to network and system information Discovery, Collection, or other scriptable post-compromise behaviors and could be used as indicators of detection leading back to the source script.
  * Analyze Office file attachments for potentially malicious macros. Execution of macros may create suspicious process trees depending on what the macro is designed to do. Office processes, such as winword.exe, spawning instances of cmd.exe, script application like wscript.exe or powershell.exe, or other suspicious processes may indicate malicious activity.
* [Attack Pattern or Vulnerability entry goes here](URL to source)
  * Description

### Course of Action 
An action taken to either prevent an attack or respond to an attack. These should address the Attack Patterns and Vulnerabilities listed above. If the course of action is connected to something in this report, such as a CVE for example, that should be referenced. Example: Apply patch 5678 to ICS systems to patch CVE-2019-0254. State no information if no information is available.
Use list
* [Attack Pattern or Vulnerability entry goes here](URL to source)
  * Description

### YARA rules
Rules for detecting indicators of compromise. State no information where the rule would be pasted if no information is available. Use douible spaces at the end of a line to force line breaks in Markdown.
Use list
* Rule - Paste on next line

* URL - http://address.com
  
### Reports 
Collections of threat intelligence focused on one or more topics, such as a description of a threat actor, malware, or attack technique, including contextual details. The description should be a short outline of the report.
Use list
* [Name of report](URL to pdf/blog post etc) - Description goes here
* [Name of report](URL to pdf/blog post etc) - Description goes here

## Raw Intelligence - start of footer

## Links - end of footer
https://www.securityweek.com/iran-linked-chafer-group-expands-toolset-targets-list

https://securelist.com/chafer-used-remexi-malware/89538/

https://www.securityweek.com/iran-linked-hackers-use-python-based-backdoor-recent-attacks

https://www.itsecuritynews.info/apt39-an-iranian-cyber-espionage-group-focused-on-personal-information-3

https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions

https://www.securityweek.com/apparently-linked-iran-spy-groups-target-middle-east

https://www.symantec.com/connect/blogs/iran-based-attackers-use-back-door-threats-spy-middle-eastern-targets

https://securelist.com/chafer-used-remexi-malware/89538/
