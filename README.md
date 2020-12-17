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
  * [Clipboard Data](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
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
* [Service Execution](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * Changes to service Registry entries and command-line invocation of tools capable of modifying services that do not correlate with known software, patch cycles, etc., may be suspicious. 
  * If a service is used only to execute a binary or script and not to persist, then it will likely be changed back to its original form shortly after the service is restarted so the service is not left broken, as is the case with the common administrator tool PsExec.
* [New Service](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * Monitor service creation through changes in the Registry and common utilities using command-line invocation. Creation of new services may generate an alterable event (ex: Event ID 4697 and/or 7045). New, benign services may be created during installation of new software. 
  * Data and events should not be viewed in isolation, but as part of a chain of behavior that could lead to other activities, such as network connections made for Command and Control, learning details about the environment through Discovery, and Lateral Movement.
  * Tools such as Sysinternals Autoruns may also be used to detect system changes that could be attempts at persistence. Look for changes to services that do not correlate with known software, patch cycles, etc. Suspicious program execution through services may show up as outlier processes that have not been seen before when compared against historical data.
  * Monitor processes and command-line arguments for actions that could create services. Remote access tools with built-in features may interact directly with the Windows API to perform these functions outside of typical system utilities. Services may also be created through Windows system management tools such as Windows Management Instrumentation and PowerShell, so additional logging may need to be configured to gather the appropriate data.
* [Scheduled Task](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * Monitor scheduled task creation from common utilities using command-line invocation. Legitimate scheduled tasks may be created during installation of new software or through system administration functions. Monitor process execution from the svchost.exe in Windows 10 and the Windows Task Scheduler taskeng.exe for older versions of Windows. 
  * If scheduled tasks are not used for persistence, then the adversary is likely to remove the task when the action is complete. Monitor Windows Task Scheduler stores in %systemroot%\System32\Tasks for change entries related to scheduled tasks that do not correlate with known software, patch cycles, etc. 
  * Data and events should not be viewed in isolation, but as part of a chain of behavior that could lead to other activities, such as network connections made for Command and Control, learning details about the environment through Discovery, and Lateral Movement.
  * Configure event logging for scheduled task creation and changes by enabling the "Microsoft-Windows-TaskScheduler/Operational" setting within the event logging service. Several events will then be logged on scheduled task activity, including:
    * Event ID 106 on Windows 7, Server 2008 R2 - Scheduled task registered
    * Event ID 140 on Windows 7, Server 2008 R2 / 4702 on Windows 10, Server 2016 - Scheduled task updated
    * Event ID 141 on Windows 7, Server 2008 R2 / 4699 on Windows 10, Server 2016 - Scheduled task deleted
    * Event ID 4698 on Windows 10, Server 2016 - Scheduled task created
    * Event ID 4700 on Windows 10, Server 2016 - Scheduled task enabled
    * Event ID 4701 on Windows 10, Server 2016 - Scheduled task disabled
  * Tools such as Sysinternals Autoruns may also be used to detect system changes that could be attempts at persistence, including listing current scheduled tasks. Look for changes to tasks that do not correlate with known software, patch cycles, etc. Suspicious program execution through scheduled tasks may show up as outlier processes that have not been seen before when compared against historical data.
  * Monitor processes and command-line arguments for actions that could be taken to create tasks. Remote access tools with built-in features may interact directly with the Windows API to perform these functions outside of typical system utilities. Tasks may also be created through Windows system management tools such as Windows Management Instrumentation and PowerShell, so additional logging may need to be configured to gather the appropriate data.
* [Input Capture](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * Keyloggers may take many forms, possibly involving modification to the Registry and installation of a driver, setting a hook, or polling to intercept keystrokes. Commonly used API calls include SetWindowsHook, GetKeyState, and GetAsyncKeyState. [1] Monitor the Registry and file system for such changes and detect driver installs, as well as looking for common keylogging API calls. 
  * API calls alone are not an indicator of keylogging, but may provide behavioral data that is useful when combined with other information such as new files written to disk and unusual processes.
  * Monitor the Registry for the addition of a Custom Credential Provider. Detection of compromised Valid Accounts in use by adversaries may help to catch the result of user input interception if new techniques are used.
* [Forced Authentication](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * Monitor for SMB traffic on TCP ports 139, 445 and UDP port 137 and WebDAV traffic attempting to exit the network to unknown external systems. 
  * If attempts are detected, then investigate endpoint data sources to find the root cause. For internal traffic, monitor the workstation-to-workstation unusual (vs. baseline) SMB traffic. For many networks there should not be any, but it depends on how systems on the network are configured and where resources are located.
  * Monitor creation and modification of .LNK, .SCF, or any other files on systems and within virtual environments that contain resources that point to external network resources as these could be used to gather credentials when the files are rendered.
* [System Network Configuration Discovery](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * System and network discovery techniques normally occur throughout an operation as an adversary learns the environment. Data and events should not be viewed in isolation, but as part of a chain of behavior that could lead to other activities, such as Lateral Movement, based on the information obtained.
* Monitor processes and command-line arguments for actions that could be taken to gather system and network information. Remote access tools with built-in features may interact directly with the Windows API to gather information. Information may also be acquired through Windows system management tools such as Windows Management Instrumentation and PowerShell.
* [Pass the Hash](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * Audit all logon and credential use events and review for discrepancies. 
  * Unusual remote logins that correlate with other suspicious activity (such as writing and executing binaries) may indicate malicious activity. 
  * NTLM LogonType 3 authentications that are not associated to a domain login and are not anonymous logins are suspicious. 
* [Pass the Ticket](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * Audit all Kerberos authentication and credential use events and review for discrepancies. 
  * Unusual remote authentication events that correlate with other suspicious activity (such as writing and executing binaries) may indicate malicious activity.
  * Event ID 4769 is generated on the Domain Controller when using a golden ticket after the KRBTGT password has been reset twice. The status code 0x1F indicates the action has failed due to "Integrity check on decrypted field failed" and indicates misuse by a previously invalidated golden ticket.
* [Remote Desktop Protocol](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * Use of RDP may be legitimate, depending on the network environment and how it is used. Other factors, such as access patterns and activity that occurs after a remote login, may indicate suspicious or malicious behavior with RDP. 
  * Monitor for user accounts logged into systems they would not normally access or access patterns to multiple systems over a relatively short period of time.
  * Set up process monitoring for tscon.exe usage and monitor service creation that uses cmd.exe /k or cmd.exe /c in its arguments to prevent RDP session hijacking.
* [Clipboard Data](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * Access to the clipboard is a legitimate function of many applications on a Windows system. If an organization chooses to monitor for this behavior, then the data will likely need to be correlated against other suspicious or non-user-driven activity.
* [Screen Capture](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * Monitoring for screen capture behavior will depend on the method used to obtain data from the operating system and write output files. Detection methods could include collecting information from unusual processes using API calls used to obtain image data, and monitoring for image files written to disk. 
  * The sensor data may need to be correlated with other events to identify malicious activity, depending on the legitimacy of this behavior within a given network environment.
* [Remote Access Tools](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * Monitor for applications and processes related to remote admin tools. Correlate activity with other suspicious behavior that may reduce false positives if these tools are used by legitimate users and administrators.
  * Analyze network data for uncommon data flows (e.g., a client sending significantly more data than it receives from a server). Processes utilizing the network that do not normally have network communication or have never been seen before are suspicious. 
  * Analyze packet contents to detect application layer protocols that do not follow the expected protocol for the port that is being used.
* Domain Fronting may be used in conjunction to avoid defenses. Adversaries will likely need to deploy and/or install these remote tools to compromised systems. It may be possible to detect or prevent the installation of these tools with host-based solutions. 
  
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

https://threatpost.com/chafer-apt-hits-middle-east-govs-with-latest-cyber-espionage-attacks/156002/

https://www.securityweek.com/us-imposes-sanctions-apt39-iranian-hackers

https://www.zdnet.com/article/us-sanctions-iranian-government-front-company-hiding-major-hacking-operations/#ftag=RSSbaffb68

https://malwaretips.com/threads/rana-android-malware-updates-allow-whatsapp-telegram-im-snooping.105577/
