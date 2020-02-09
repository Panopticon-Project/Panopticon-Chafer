![alt tag](https://user-images.githubusercontent.com/24201238/29351849-9c3087b4-82b8-11e7-8fed-350e3b8b4945.png)

## Name - Chafer
* Label - Advanced Persistent Threat (APT) 

## Aliases
* [Alias](URL to source)
* [Alias](URL to source)

## Overview 
* Chafer is believed to be an Iranian APT and appears to be primarily engaged in surveillance and tracking of individuals, with most of its attacks likely carried out to gather information on targets or facilitate surveillance. Targeting occurs within Iran, elsewhere in the Middle East, Africa, and outside the region in multinational corporations.

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
  * [Attack Pattern](URL to source)
  * Description
* Persistence
  * [Attack Pattern](URL to source)
  * Description
* Privilege Escalation 
  * [Attack Pattern](URL to source)
  * Description
* Defence Evasion 
  * [Attack Pattern](URL to source)
  * Description
* Credential Access
  * [Attack Pattern](URL to source)
  * Description
* Discovery
  * [Attack Pattern](URL to source)
  * Description
* Lateral Movement
  * [Attack Pattern](URL to source)
  * Description
* Collection
  * [Attack Pattern](URL to source)
  * Description
* Exfiltration 
  * [Attack Pattern](URL to source)
  * Description
* Command and Control 
  * [Attack Pattern](URL to source)
  * Description
* Malware - Description goes here

### Vulnerabilities
* [Vulnerability](URL to outline of how vulnerability is exploited) is exploited by name of malware / name of tool
* [Vulnerability](URL to outline of how vulnerability is exploited) is exploited by name of malware / name of tool

### Identity

#### Individuals 
[No information](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)

#### Affiliated organisations
* [Islamic Republic of Iran](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)

#### Affiliated groups
* [OilRig](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)

### Intrusion Set

#### Malware
* Names - [No information](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * Functionality - N/A
  * Hash - N/A
  * Notes - N/A

#### Website 
* Name - [No information](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * About - N/A
  * URL - N/A
  * IP - N/A
  * Valid from - N/A
  * Valid to - N/A

#### Command and Control Server
* IP - [No information](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * Valid from - N/A
  * Valid to - N/A
  * [SSH host key] (URL to source)
    * RSA - N/A
    * ECDSA - N/A
    * ED25519 - N/A
  * [SSL Certificate](URL to source)
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
  * [Spearphishing Attachment](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)
  * In 2017, the group added a new infection method to its toolkit, using malicious documents which are likely circulated using spear-phishing emails sent to individuals working in targeted organizations. These documents were Excel spreadsheets. When opened, they downloaded a malicious VBS file that in turn ran a PowerShell script. Several hours later, a dropper would appear on the compromised computer. This would install three files on the computer, an information stealer, a screen capture utility, and an empty executable.
* Execution
  * [Attack Pattern](URL to source)
  * Description
* Persistence
  * [Attack Pattern](URL to source)
  * Description
* Privilege Escalation 
  * [Attack Pattern](URL to source)
  * Description
* Defence Evasion 
  * [Attack Pattern](URL to source)
  * Description
* Credential Access
  * [Attack Pattern](URL to source)
  * Description
* Discovery
  * [Attack Pattern](URL to source)
  * Description
* Lateral Movement
  * [Attack Pattern](URL to source)
  * Description
* Collection
  * [Attack Pattern](URL to source)
  * Description
* Exfiltration 
  * [Attack Pattern](URL to source)
  * Description
* Command and Control 
  * [Attack Pattern](URL to source)
  * Description
* Malware - Description goes here

### Vulnerabilities
A mistake in software that can be directly used by an attacker to gain access to a system or network. Link to a writeup in the exploit repo where possible (example, CVEs) or to external sources. Format should be in the format of vulnerability is exploited by name of the thing exploiting it, usually malware or a hacking tool. State no information if no information is available.
Use list
* [Vulnerability](URL to outline of how vulnerability is exploited) is exploited by name of malware / name of tool
* [Vulnerability](URL to outline of how vulnerability is exploited) is exploited by name of malware / name of tool

### Identity
Individuals, organizations, or groups. These are represented as individual entries under the heading of Identity.

#### Individuals 
[No information](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)

#### Affiliated organisations
* [Islamic Republic of Iran](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)

#### Affiliated groups
* [OilRig](https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions)

### Intrusion Set
A grouped set of adversarial behaviours and resources with common properties believed to be orchestrated by a single threat actor. These are represented as individual categories under the heading of Intrusion Set. If an existing category does not cover what you need to add, contact a project maintainer on panopticonproject at protonmail dot com to add a section to Charon.

#### Malware
Details of malware used. Multiple names should be listed on the same line and separated by a comma. Functionality should be short, preferably one word. Example: keylogger. Multiple functionalities should be listed on the same line and separated by a comma. Hash should have a -, the type of hashing function used, another -, and the hash itself. Example: Hash - MD5 - 002ae76872d80801692ff942308c64t6. Notes should be a short description of anything else important, like the family the malware belongs to or variants. State no information for entries that don't yet have any information.
* Names - [Name of malware](URL to source)
  * Functionality - add functionality
  * Hash - [Function] - [Actual hash](URL to source)
  * Notes - Description goes here

#### Website 
A website used by the attacker. URLs should be in the format of hxxp so people don't accidentablly navigate to the URL by clicking on it. IP addresses shouldhave square brackets [] arond the last separator so people don't accidentally navigate to the address. Dates should be in the format of DD Month Year e.g. 01 January 2019. State no information for entries that don't yet have any information.
* Name - Name of website
  * About - Description goes here
  * URL - [hxxp://address[.]com](URL to source)
  * IP - [000.000.000[.]000](URL to source)
  * Valid from - [XX Month 20XX](URL to source)
  * Valid to - [XX Month 20XX](URL to source)

#### Command and Control Server
A server used by the attackers to send commands to malware and to receive commands and exfiltrated information from the malware.
* About - used by Even More Muffins malware to receive commands from and exfiltrate data to. IP addresses should have square brackets [] around the last separator so people don't accidentally navigate to the address. Dates should be in the format of DD Month Year e.g. 01 January 2019.
* IP - [000.000.000[.]000](URL to source)
  * Valid from - [XX Month 20XX](URL to source)
  * Valid to - [XX Month 20XX](URL to source)
  * [SSH host key] (URL to source)
    * RSA - fingerprint
    * ECDSA - fingerprint
    * ED25519 - fingerprint
  * [SSL Certificate](URL to source)
    * Issuer - Name
    * Public key type - RSA etc
    * Public key bits - Bit length
    * Signature algorithm - name of algorithm
    * Not valid before - XX Month 20XX
    * Not valid after - XX Month 20XX
    * MD5 - MD5 hash
    * SHA-1 - SHA-1 hash
  * Notes - notes go here.

#### Documents
A document used by the attackers, usually as part of phishing. About should be a short description of how the document was used. Hash should have a -, the type of hashing function used, another -, and the hash itself. Example: Hash - MD5 - 002ae76872d80801692ff942308c64t6.
* Filename - [Name](URL to source)
  * About - Description goes here
  * Hash - Function - Actual hash
  * Notes - Notes go here

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
  
## Time context ends

### Detection - end of repeatable time contextual section 
An action taken to detect an Attack Pattern entry. These should address the Attack Patterns listed above. State no information if no information is available.
Use list
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

## Copy and paste everything from Campaign or Date Range through to Reports for a new campaign or date range

## Raw Intelligence - start of footer
Any further notes to be added to the framework would be added here.

## Links - end of footer
Any new articles to be added here.


![alt tag](https://user-images.githubusercontent.com/24201238/29351849-9c3087b4-82b8-11e7-8fed-350e3b8b4945.png)

# Panopticon Project

## The Charon framework for sharing threat intelligence
Charon is a formatting standardisation using the markdown language and an intelligence framework based on [STIX](https://oasis-open.github.io/cti-documentation/) and [MITRE ATT&CK™](https://attack.mitre.org/). It is designed to be easier to approach than STIX. In Greek mythology Styx is a river and Charon is the person who gets people across it. STIX is the river as far as being muchh deeper than the Charon standardisation, but Charon is the tool used to bridge the gap for the newcomer. Charon is also a person, not an object, and the Charon framework was built with people in mind. 

As part of the roadmap for Panopticon Project (P2), it is planned to have a converter that can take a markup file containing Charon and generate a JSON file of STIX. Charon has been written specifically for APTs. As part of the roadmap for P2 it is planned to also have Charon framework for Corporations and Nation States.

### Using Charon
For APTs (Nation States and Corporations coming soon), copy and paste [this](https://github.com/Panopticon-Project/panopticon-admin/edit/master/FRAMEWORK.md) into the README for the repo if it's not there already. I've given you the link straight to the edited file to copy out the markdown as I've not figured out how to get markdown formatting to show without formatting the content, so you can just copy and paste. In case it doesn't work, you will need to edit this file to get the raw markdown code. Click the pencil in the upper right-hand order of the file. Then, copy and paste the code from FRAMEWORK.md into the README of your chosen repo.

Once you have your framework, start reading articles or perform your own research to fill the raw intelligence section. When you are ready, move the intelligence into its appropriate category. If an existing category does not cover what you need to add, contact a project maintainer on panopticonproject at protonmail dot com to add a section to Charon. When dealing with multiple campaigns or multiple timeframes, copy everything from Campaign or Date Range through to and including Reports and fill in those sections again. The sections at the beginning of the framework, Name, Aliases, Overview, and the sections at the end of the framework, Raw Intelligence and Links are static and form the header and footer. The sections from Campaign or Date Range through to Reports are contextual to time and therefore will continue to be repeated for different time frames. Try to keep timeframes to roughly one year in length unless there is a clear need to do otherwise.

### An example of Charon
Have a look [here](https://github.com/Panopticon-Project/panopticon-admin/blob/master/EXAMPLE_APT.md).

# Charon Framework

## Name - start of header
Common name of the threat actor. Use one of the listed labels.
* Label - Advanced Persistent Threat (APT) / Corporation / Nation State

## Aliases
Other names the threat actor is known by.
Use list
* [Alias](URL to source)
* [Alias](URL to source)

## Overview - end of header
A high-level summary of the threat actor.
Use list
* Description goes here
*

## Time context starts

## Campaign or Date Range - start of repeatable time contextual section 
Use either a campaign with a specific timeframe or a date range not associated with a specific campaign. About is a short description of the campaign and should be removed if using date range. Dates should be in the format of DD Month Year e.g. 01 January 2019.
* Campaign / Date Range
* About - [Targeting infrastructure in South East Asia](URL to source)
* Active from - XX Month 20XX
* Active to - XX Month 20XX

### Attributes
Listed after Campaign or Date Range as attributes can shift over time. Use one of the resource levels. Use one of the sophistication grades. Amateur is defined as using all prewritten tools and/or showing overall poor tradecraft. Expert is defined as using at least some self-written tools and/or showing overall good tradecraft. Advanced Expert is defined as consistently using self-written tools and showing consistently good tradecraft. Primary activity is a short description of what the groups mostly does.
* Resource level - [Individual / Group / Corporation / Government](URL to source)
* Sophistication - [Amateur / Expert / Advanced Expert](URL to source)
* Primary activities - Description goes here

### Attack Pattern
See the [Enterprise Matrix](https://attack.mitre.org/) for definitions of each of the below areas. Use in the order they occur and state no information for entries that don't yet have any information. Malware should have a short description and be detailed below.
Use list
* Initial Access 
  * [Attack Pattern](URL to source)
  * Description
* Execution
  * [Attack Pattern](URL to source)
  * Description
* Persistence
  * [Attack Pattern](URL to source)
  * Description
* Privilege Escalation 
  * [Attack Pattern](URL to source)
  * Description
* Defence Evasion 
  * [Attack Pattern](URL to source)
  * Description
* Credential Access
  * [Attack Pattern](URL to source)
  * Description
* Discovery
  * [Attack Pattern](URL to source)
  * Description
* Lateral Movement
  * [Attack Pattern](URL to source)
  * Description
* Collection
  * [Attack Pattern](URL to source)
  * Description
* Exfiltration 
  * [Attack Pattern](URL to source)
  * Description
* Command and Control 
  * [Attack Pattern](URL to source)
  * Description
* Malware - Description goes here

### Vulnerabilities
A mistake in software that can be directly used by an attacker to gain access to a system or network. Link to a writeup in the exploit repo where possible (example, CVEs) or to external sources. Format should be in the format of vulnerability is exploited by name of the thing exploiting it, usually malware or a hacking tool. State no information if no information is available.
Use list
* [Vulnerability](URL to outline of how vulnerability is exploited) is exploited by name of malware / name of tool
* [Vulnerability](URL to outline of how vulnerability is exploited) is exploited by name of malware / name of tool

### Identity
Individuals, organizations, or groups. These are represented as individual entries under the heading of Identity.

#### Individuals 
Specific members of threat actor. State no information for entries that don't yet have any information.
Use list
* [Name](URL to source)
* [Name](URL to source)

#### Affiliated organisations
Specific organisations the threat actor is connected to. State no information for entries that don't yet have any information.
Use list
* [Organisation](URL to source)
* [Organisation](URL to source)

#### Affiliated groups
Specific groups the threat actor is connected to. State no information for entries that don't yet have any information.
Use list
* [Group](URL to source)
* [Group](URL to source)

### Intrusion Set
A grouped set of adversarial behaviours and resources with common properties believed to be orchestrated by a single threat actor. These are represented as individual categories under the heading of Intrusion Set. If an existing category does not cover what you need to add, contact a project maintainer on panopticonproject at protonmail dot com to add a section to Charon.

#### Malware
Details of malware used. Multiple names should be listed on the same line and separated by a comma. Functionality should be short, preferably one word. Example: keylogger. Multiple functionalities should be listed on the same line and separated by a comma. Hash should have a -, the type of hashing function used, another -, and the hash itself. Example: Hash - MD5 - 002ae76872d80801692ff942308c64t6. Notes should be a short description of anything else important, like the family the malware belongs to or variants. State no information for entries that don't yet have any information.
* Names - [Name of malware](URL to source)
  * Functionality - add functionality
  * Hash - [Function] - [Actual hash](URL to source)
  * Notes - Description goes here

#### Website 
A website used by the attacker. URLs should be in the format of hxxp so people don't accidentablly navigate to the URL by clicking on it. IP addresses shouldhave square brackets [] arond the last separator so people don't accidentally navigate to the address. Dates should be in the format of DD Month Year e.g. 01 January 2019. State no information for entries that don't yet have any information.
* Name - Name of website
  * About - Description goes here
  * URL - [hxxp://address[.]com](URL to source)
  * IP - [000.000.000[.]000](URL to source)
  * Valid from - [XX Month 20XX](URL to source)
  * Valid to - [XX Month 20XX](URL to source)

#### Command and Control Server
A server used by the attackers to send commands to malware and to receive commands and exfiltrated information from the malware.
* About - used by Even More Muffins malware to receive commands from and exfiltrate data to. IP addresses should have square brackets [] around the last separator so people don't accidentally navigate to the address. Dates should be in the format of DD Month Year e.g. 01 January 2019.
* IP - [000.000.000[.]000](URL to source)
  * Valid from - [XX Month 20XX](URL to source)
  * Valid to - [XX Month 20XX](URL to source)
  * [SSH host key] (URL to source)
    * RSA - fingerprint
    * ECDSA - fingerprint
    * ED25519 - fingerprint
  * [SSL Certificate](URL to source)
    * Issuer - Name
    * Public key type - RSA etc
    * Public key bits - Bit length
    * Signature algorithm - name of algorithm
    * Not valid before - XX Month 20XX
    * Not valid after - XX Month 20XX
    * MD5 - MD5 hash
    * SHA-1 - SHA-1 hash
  * Notes - notes go here.

#### Documents
A document used by the attackers, usually as part of phishing. About should be a short description of how the document was used. Hash should have a -, the type of hashing function used, another -, and the hash itself. Example: Hash - MD5 - 002ae76872d80801692ff942308c64t6.
* Filename - [Name](URL to source)
  * About - Description goes here
  * Hash - Function - Actual hash
  * Notes - Notes go here

#### Tools
A tool used by the attacker. Multiple names should be listed on the same line and separated by a comma. functionalities should be short, preferably one word. Example: keylogger. Multiple functionalites should be listed on the same line and separated by a comma. URL should be the online address, if any, the tool can be publicly sourced from.
* Names - [Name of tool](URL to source)
  * Functionality - Functionality, functionality 
  * URL - http://address.com

## Time context ends

### Detection - end of repeatable time contextual section 
An action taken to detect an Attack Pattern entry. These should address the Attack Patterns listed above. State no information if no information is available.
Use list
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

## Copy and paste everything from Campaign or Date Range through to Reports for a new campaign or date range

## Raw Intelligence - start of footer
Any further notes to be added to the framework would be added here.

## Links - end of footer
Any new articles to be added here.


https://www.securityweek.com/iran-linked-chafer-group-expands-toolset-targets-list

https://securelist.com/chafer-used-remexi-malware/89538/

https://www.securityweek.com/iran-linked-hackers-use-python-based-backdoor-recent-attacks

https://www.itsecuritynews.info/apt39-an-iranian-cyber-espionage-group-focused-on-personal-information-3

https://www.symantec.com/blogs/threat-intelligence/chafer-latest-attacks-reveal-heightened-ambitions

https://www.securityweek.com/apparently-linked-iran-spy-groups-target-middle-east

https://www.symantec.com/connect/blogs/iran-based-attackers-use-back-door-threats-spy-middle-eastern-targets
