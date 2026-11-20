# From Vulnerability to Compliance: Securing Legacy and Cloud Systems at HanTech

**Professional Security Assessment Report**

| | |
|---|---|
| Project title | From Vulnerability to Compliance: Securing Legacy and Cloud Systems at HanTech |
| Prepared for | HanTech management and IT leadership |
| Prepared by | Fonyuy Berka Dzekem Jr. |
| Group number | Group 25 |
| Role | Junior Cybersecurity Consultant |
| System assessed | Metasploitable 2 host found running inside the HanTech environment |
| Report date | 20 November 2026 |
| Version | 1.0 |
| Classification | Confidential. For HanTech internal use only. |

<!-- pagebreak -->

## Contents

1. Executive summary
2. Vulnerability findings
3. Risk assessment
4. Recommended controls
5. Recommended policies (including cloud security basics and compliance)
6. Conclusion

Appendix A. Other weaknesses noted on the host

Appendix B. References

Appendix C. Glossary

<!-- pagebreak -->

## 1. Executive summary

**What we looked at.** HanTech asked for a security review of a server that was found running inside its network. The server is Metasploitable 2, a system that was built on purpose to be insecure so that people can practise security testing. It was never meant to run on a business network, and nobody at HanTech appears to have approved, recorded or monitored it.

**Overall security posture: Critical.** Anyone who can reach this server over the network can take full control of it, without a password, using tools that are freely available online. Because it sits inside HanTech's network, a person who takes it over could use it as a stepping stone to reach other systems, client data and HanTech's cloud accounts.

**Key findings.** We selected the five most serious weaknesses for this report:

| # | Finding, in plain terms | Risk |
|---|---|---|
| 1 | The file transfer service (FTP) contains a hidden backdoor planted in the software before it was installed | Critical |
| 2 | Default, blank and easily guessed passwords on remote access and database services, sent across the network unencrypted | Critical |
| 3 | The file-sharing service (Samba) can be tricked into running an attacker's commands with full administrator rights | Critical |
| 4 | An unapproved chat server (IRC) contains a hidden backdoor | Critical |
| 5 | A software-build service (distcc) accepts and runs commands from any computer on the network | High |

**Highest-risk vulnerabilities.** The backdoored FTP service and the default passwords are the most urgent, followed by Samba and the IRC backdoor. Each gives an outsider complete control of the server. The likely business consequences are theft of client or company data, ransomware spreading to other systems, service outages, fines and mandatory breach reporting under data protection laws such as the GDPR and Nigeria's NDPA, and loss of client trust.

**The root cause is a governance gap, not a single bad setting.** An unmanaged, out-of-date system was able to join the network with no owner, no patching and no monitoring. Fixing this one server without closing that gap would leave HanTech exposed to the next one.

**Recommended controls.**

* **Within 24 hours:** disconnect the server from the network, check whether it has been used to reach other systems, and reset any passwords that may have been used on it.
* **Within 30 days:** remove the server permanently (or rebuild it in a sealed training lab), start a complete inventory of every system HanTech runs, block unneeded network services, and turn on multi-factor authentication (MFA) for all remote and cloud administrator access.
* **Within 90 days:** run regular vulnerability scans, patch on a fixed timetable, and collect security logs centrally so that problems are spotted quickly.

**Recommended policies.** Asset Management, Acceptable Use, Access Control, Password and Authentication, Patch Management, Vulnerability Management, and Secure Configuration and Network Security. Together they make sure every system has an owner, is kept up to date, is locked down by default, and is checked regularly.

**Decisions requested from leadership:** approve removal of the server, name an owner for the asset inventory and vulnerability management programme, and fund a vulnerability scanning tool and MFA for all staff with administrative access.

<!-- pagebreak -->

## 2. Vulnerability findings

### 2.1 Scope, method and limitations

**Scope.** One host: a Metasploitable 2 virtual machine (Ubuntu 8.04 base) discovered inside the HanTech environment. Cloud infrastructure was not tested directly, but the findings, controls and policies are applied to HanTech's cloud environment where relevant (Section 5.3).

**Method.** This is a defensive desk review. The findings are based on the publicly documented build of Metasploitable 2 and the services it exposes by default. Each vulnerability was checked against the U.S. National Vulnerability Database (NVD) for its CVE record, CVSS base score and weakness type (CWE), and against the CISA Known Exploited Vulnerabilities (KEV) catalogue. No exploitation was carried out and this report contains no exploit instructions.

**Limitations.** No live scan of the HanTech copy of the host was performed for this report. If the host was modified after it was deployed, some details may differ. A credentialed vulnerability scan of the actual host should confirm the findings before it is removed, and a compromise assessment should establish whether it has already been misused (see Section 4.2).

**Selection.** Metasploitable 2 has dozens of weaknesses. The five below were chosen because together they cover the main causes of real-world breaches: a tampered software supply chain (findings 1 and 4), unpatched software (finding 3), weak and default credentials (finding 2), and insecure configuration of an exposed service (finding 5). Other weaknesses are listed in Appendix A.

### 2.2 Summary of findings

| ID | Vulnerability name | Affected service (port) | CVE | NVD CVSS base score |
|---|---|---|---|---|
| V1 | vsftpd 2.3.4 backdoor command execution | FTP, vsftpd 2.3.4 (21/tcp) | CVE-2011-2523 | 9.8 Critical (v3.1); 10.0 High (v2) |
| V2 | Weak, default and blank credentials over cleartext protocols | Telnet (23), rlogin/rsh (512 to 514), VNC (5900), MySQL (3306), PostgreSQL (5432), Tomcat Manager (8180), SSH (22) | CVE-1999-0502 (generic) | 7.5 High (v2) |
| V3 | Samba "username map script" command execution | SMB, Samba 3.0.20 (139/tcp, 445/tcp) | CVE-2007-2447 | 6.0 Medium (v2) |
| V4 | UnrealIRCd 3.2.8.1 backdoor command execution | IRC, UnrealIRCd 3.2.8.1 (6667/tcp) | CVE-2010-2075 | 7.5 High (v2) |
| V5 | distcc daemon unrestricted command execution | distccd v1 (3632/tcp) | CVE-2004-2687 | 9.3 High (v2) |

NVD only gives a CVSS v3.1 score for CVE-2011-2523. The other CVEs pre-date CVSS v3, so their CVSS v2 scores are shown. None of the five appears in the CISA KEV catalogue at the time of writing, but public exploit code for all five has been available for many years.

### 2.3 Finding V1: vsftpd 2.3.4 backdoor

| Requirement | Detail |
|---|---|
| Vulnerability name | vsftpd 2.3.4 backdoor command execution (CVE-2011-2523, CWE-78 OS command injection) |
| Affected service | FTP service on 21/tcp, running vsftpd version 2.3.4. The service also allows anonymous login. |
| Brief description | The copy of vsftpd 2.3.4 on this host was built from a source archive that was tampered with on the project's download site between 30 June and 3 July 2011. The tampering added a hidden backdoor: a specially formed login attempt makes the server open a command shell with root (full administrator) privileges on a second port, 6200/tcp. No valid account is needed. This is a software supply chain compromise: the software was malicious before it was installed, so no amount of careful configuration would have made it safe. |
| Potential attacker goal | Full remote control of the host as root without credentials; theft or deletion of data on the host; installing persistent malware or ransomware; using the host as a foothold to move to other internal systems and to cloud resources reachable from it. |

### 2.4 Finding V2: weak, default and blank credentials over cleartext protocols

| Requirement | Detail |
|---|---|
| Vulnerability name | Weak, default and blank credentials, sent over cleartext protocols (CVE-1999-0502; CWE-1392 use of default credentials; CWE-521 weak password requirements; CWE-319 cleartext transmission of sensitive information) |
| Affected service | Telnet (23/tcp), rlogin, rsh and rexec (512 to 514/tcp), VNC remote desktop (5900/tcp), MySQL 5.0 (3306/tcp), PostgreSQL 8.3 (5432/tcp), Apache Tomcat Manager (8180/tcp) and SSH (22/tcp) |
| Brief description | Several services on the host accept factory-default, blank or trivially guessable passwords. They include the default operating system administrator account, which has unrestricted sudo (administrator) rights, a database administrator account with no password at all, and remote desktop and web application management accounts with widely published default passwords. The credentials are publicly documented, so guessing them takes seconds. On top of that, Telnet, the r-services, FTP and VNC send usernames and passwords across the network unencrypted, so anyone who can observe network traffic can capture valid credentials. |
| Potential attacker goal | Log in as a legitimate user, which is harder to detect than an exploit; gain root through the administrator account; read, change or delete database contents; deploy malicious web applications through the Tomcat Manager; capture passwords that staff may reuse on other systems, including email and cloud consoles. |

### 2.5 Finding V3: Samba "username map script" command execution

| Requirement | Detail |
|---|---|
| Vulnerability name | Samba "username map script" remote command execution (CVE-2007-2447) |
| Affected service | SMB file-sharing service on 139/tcp and 445/tcp, running Samba 3.0.20-Debian |
| Brief description | Samba versions 3.0.0 to 3.0.25rc3 pass a user-supplied name to the system shell without filtering it when the "username map script" option is enabled, as it is on this host. Shell control characters placed in a username therefore cause the server to run operating system commands. The Samba service runs as root, so those commands run with full administrator rights. NVD's CVSS v2 vector lists single authentication (Au:S), which keeps the base score at 6.0, but published advisories and testing show the flaw is reachable on this configuration before any successful login. The real-world risk on this host is therefore much higher than the base score suggests (see Section 3). |
| Potential attacker goal | Root command execution on the host; reading and changing files on shared folders; harvesting stored data and credentials; encrypting shares for ransom; using the host to attack other machines over SMB. |

### 2.6 Finding V4: UnrealIRCd 3.2.8.1 backdoor

| Requirement | Detail |
|---|---|
| Vulnerability name | UnrealIRCd 3.2.8.1 backdoor command execution (CVE-2010-2075, CWE-20 improper input validation) |
| Affected service | IRC chat server on 6667/tcp, running UnrealIRCd 3.2.8.1 |
| Brief description | Copies of UnrealIRCd 3.2.8.1 distributed through some download mirrors between November 2009 and June 2010 contained a trojan hidden in a debugging macro. Data sent to the service in a particular form is executed as an operating system command, with no authentication. On a default Metasploitable 2 build the daemon runs with root privileges. Like V1, this is a supply chain compromise. Separately, an IRC server has no business purpose at HanTech: its presence is itself unapproved software, and IRC is a channel commonly used to control botnets. |
| Potential attacker goal | Root command execution; turning the host into a command-and-control relay for malware on other machines; data theft and pivoting into the wider network. |

### 2.7 Finding V5: distcc daemon unrestricted command execution

| Requirement | Detail |
|---|---|
| Vulnerability name | distcc daemon remote command execution through unrestricted access (CVE-2004-2687, CWE-16 configuration) |
| Affected service | distccd v1, the distributed C/C++ compiler service, on 3632/tcp |
| Brief description | distcc speeds up software builds by sending compile jobs to other machines. It is designed to be used only by trusted build hosts, and relies on an "allow" list and firewall rules for protection. On this host the daemon accepts jobs from any network address, so any remote user can make it run arbitrary commands. The commands run as a low-privileged service account rather than root, which limits the immediate damage. However, the host's out-of-date operating system also contains local privilege escalation flaws, for example in udev (CVE-2009-1185, CVSS v2 7.2), so in practice this foothold can be turned into full control. |
| Potential attacker goal | Gain an initial foothold on the host, then escalate to root; tamper with any software built through the service, which would be a supply chain risk to HanTech's own products; use the host for further attacks. |

<!-- pagebreak -->

## 3. Risk assessment

### 3.1 Rating method

Risk is rated as **Likelihood x Impact** on a four-point scale. CVSS base scores from NVD are an input, not the final answer: CVSS describes a vulnerability in general, while risk depends on HanTech's context (who can reach the service, what privileges it runs with, what data and systems sit behind it, and whether any compensating controls exist). No compensating controls such as network segmentation, intrusion detection or monitoring were found protecting this host.

**Likelihood** considers the CVSS exploitability metrics (attack vector, attack complexity, authentication or privileges required), whether public exploit code exists, and how exposed the service is.

| Level | Score | Meaning |
|---|---|---|
| Low | 1 | Requires local access or rare conditions; no public exploit |
| Medium | 2 | Requires valid credentials or uncommon conditions; exploit details public |
| High | 3 | Network reachable, little or no authentication, public exploit, some conditions apply |
| Critical | 4 | Network reachable, no authentication, trivial to perform with freely available tools |

**Impact** considers effect on confidentiality, integrity and availability, the privileges gained, the sensitivity of reachable data, the potential to move to other systems including the cloud, and legal or regulatory consequences.

| Level | Score | Meaning |
|---|---|---|
| Low | 1 | Minor information disclosure; no privileged access |
| Medium | 2 | Limited access to non-sensitive data or a single unprivileged account |
| High | 3 | Command execution as an unprivileged user; sensitive data at risk |
| Critical | 4 | Full administrator (root) control; complete loss of confidentiality, integrity and availability; likely breach notification |

**Risk rating** = Likelihood score x Impact score: 1 to 3 is Low, 4 to 6 is Medium, 8 to 9 is High, 12 to 16 is Critical.

### 3.2 Risk register

| ID | Vulnerability | CVE and CVSS | Likelihood | Impact | Risk rating |
|---|---|---|---|---|---|
| V1 | vsftpd 2.3.4 backdoor | CVE-2011-2523, 9.8 (v3.1) | Critical (4) | Critical (4) | Critical (16) |
| V2 | Weak, default and blank credentials over cleartext protocols | CVE-1999-0502, 7.5 (v2) | Critical (4) | Critical (4) | Critical (16) |
| V3 | Samba "username map script" command execution | CVE-2007-2447, 6.0 (v2) | High (3) | Critical (4) | Critical (12) |
| V4 | UnrealIRCd 3.2.8.1 backdoor | CVE-2010-2075, 7.5 (v2) | High (3) | Critical (4) | Critical (12) |
| V5 | distcc unrestricted command execution | CVE-2004-2687, 9.3 (v2) | High (3) | High (3) | High (9) |

### 3.3 Risk matrix

| Likelihood / Impact | Low (1) | Medium (2) | High (3) | Critical (4) |
|---|---|---|---|---|
| Critical (4) | | | | V1, V2 |
| High (3) | | | V5 | V3, V4 |
| Medium (2) | | | | |
| Low (1) | | | | |

### 3.4 Justification of ratings

**V1, vsftpd backdoor: Critical.**

*Likelihood Critical.* The CVSS v3.1 vector (AV:N/AC:L/PR:N/UI:N) means it is reachable over the network, low in complexity and needs no credentials or user action. FTP on port 21 is one of the first services any scan finds, and ready-made tools detect and trigger the backdoor automatically.

*Impact Critical.* The backdoor gives a root shell: complete loss of confidentiality, integrity and availability (C:H/I:H/A:H) and a launch point into the rest of the network.

**V2, weak and default credentials: Critical.**

*Likelihood Critical.* The default passwords are published, password guessing is fully automated, and several services have no lockout or rate limiting. Cleartext protocols add a second, passive route: credentials can be captured from network traffic. Weak and stolen credentials are consistently among the most common causes of breaches reported in industry studies.

*Impact Critical.* The default administrator account has unrestricted sudo rights, and the database administrator account has no password, so a successful login gives full control of the host and its data. Logins with valid credentials also look like normal activity, which delays detection. CVE-1999-0502's generic CVSS v2 score of 7.5 understates the impact here because of the administrator rights involved.

**V3, Samba command execution: Critical.**

*Likelihood High.* NVD scores attack complexity as medium and lists single authentication, giving a base score of only 6.0. In this configuration the flaw is reachable before login and public tools exploit it reliably, so the likelihood is higher than the base score implies. It is rated High rather than Critical because it depends on a specific non-default option being enabled. That option is enabled here, but the condition would not hold on every Samba server.

*Impact Critical.* The service runs as root, so commands run with full control of the host and of every file share on it. This finding shows why a CVSS base score must not be used as the risk rating without context.

**V4, UnrealIRCd backdoor: Critical.**

*Likelihood High.* No authentication is needed (AV:N/AC:L/Au:N) and public tools exist. It is rated High rather than Critical only because port 6667 is a less common service and is not always included in quick scans. A full port scan finds it immediately.

*Impact Critical.* The daemon runs as root on this build, so the backdoor gives complete control. An IRC service also gives attackers a ready-made channel to command other infected machines.

**V5, distcc command execution: High.**

*Likelihood High.* The service accepts jobs from any address without authentication (AV:N/Au:N, CVSS v2 9.3), and public tools exist. Its attack complexity is rated medium.

*Impact High.* Commands run as an unprivileged service account, not root, which limits the immediate damage. The rating is High rather than Critical for that reason. It would rise to Critical in a risk register that treated the local privilege escalation flaws on the host (for example CVE-2009-1185) as part of the same attack chain, and those flaws should be fixed for that reason.

### 3.5 Business risk by finding

HanTech management named five concerns: unauthorised access, data breaches, service disruption, regulatory compliance violations and damage to reputation. The table shows how each finding creates them. "Direct" means the finding causes the outcome by itself; "Indirect" means it enables a follow-on attack that does.

| ID | Unauthorised access | Data breach | Service disruption | Compliance violation | Reputation damage |
|---|---|---|---|---|---|
| V1 | Direct: root access with no password | Direct: all data on the host, and data reachable from it | Direct: host can be wiped or encrypted | Direct: unpatched, tampered software fails GDPR Art. 32 and PCI DSS Req. 6 | Direct: a breach through a known, 15-year-old backdoor would be hard to defend to clients |
| V2 | Direct: logins with published passwords | Direct: databases readable and changeable | Direct: data and services can be deleted | Direct: default passwords breach PCI DSS Req. 2.2.2; cleartext logins breach encryption duties | Direct: weak passwords are seen as basic negligence |
| V3 | Direct: root command execution | Direct: file shares exposed | Direct: ransomware on file shares | Direct: unpatched software and missing access control | Direct |
| V4 | Direct: root command execution | Indirect: through pivoting to other systems | Indirect: host used to attack others | Direct: unapproved software outside any control framework | Direct: HanTech infrastructure used as a botnet relay |
| V5 | Direct: foothold as a service account | Indirect: after privilege escalation | Indirect | Direct: insecure configuration of an exposed service | Indirect: tampered builds would harm clients |

### 3.6 Remediation priority

Remediate in this order: V1 and V2 first (Critical 16), then V3 and V4 (Critical 12), then V5 (High 9). In practice, the containment step in Section 4.2 (isolating the host) lowers the likelihood of all five at once and should be done before anything else.

<!-- pagebreak -->

## 4. Recommended controls

Controls are described by type: **preventive** (stops the attack), **detective** (spots it) and **corrective** (limits damage and restores service). For each control the report explains whether it reduces risk by lowering **likelihood**, lowering **impact**, or both. Control references are to NIST SP 800-53 Rev. 5, ISO/IEC 27001:2022 Annex A and CIS Controls v8.1.

### 4.1 Summary of recommended controls

| Vulnerability | Recommended control |
|---|---|
| V1 vsftpd backdoor (outdated, tampered software) | Patch management process; software integrity verification; replace FTP with SFTP |
| V2 Weak, default and blank passwords | MFA and password policy; remove default accounts; replace cleartext protocols with SSH and TLS |
| V3 Samba command execution (outdated software) | Patch management process; secure configuration baseline; network segmentation |
| V4 UnrealIRCd backdoor (unapproved software) | Remove the service; software inventory and application allowlisting |
| V5 distcc open to any host (insecure configuration) | Remove or restrict the service with allow lists and firewall rules; host hardening |

### 4.2 First control for every finding: contain and decommission the host

Metasploitable 2 is deliberately insecure. The correct long-term control is to **remove it from the HanTech network**, not to patch it.

| Step | Action | How it reduces risk |
|---|---|---|
| 1. Contain (within 24 hours) | Disconnect the host from the network, or move it to an isolated quarantine network with no route to production systems, the internet or cloud environments. Preserve a copy of the disk and memory for investigation before shutting it down. | Removes network reachability, which lowers the likelihood of all five findings to near zero at once. Preserving evidence supports the investigation and any legal duties. |
| 2. Investigate | Carry out a compromise assessment: review firewall, DNS and authentication logs for connections to and from the host, check other systems for logins from it, and identify who deployed it and why. | Detective and corrective. Establishes whether a breach has already happened, which decides whether breach notification duties apply (Section 5.3.7). |
| 3. Reset credentials | Reset any password or key that was used on, stored on, or typed into the host. | Corrective. Stops captured credentials (V2) from being reused elsewhere. |
| 4. Decommission | Wipe and retire the host. If HanTech needs it for staff training, rebuild it inside a sealed lab network with no connection to production or cloud environments. | Removes the risk entirely. A lab copy keeps its training value without exposing the business. |

The controls below address each finding individually. They apply to any production system HanTech runs that shares these weaknesses, and they prevent the same problems from appearing on the next unmanaged system.

### 4.3 Controls for V1, vsftpd backdoor

| Recommended control | Type | How it reduces the risk |
|---|---|---|
| Patch management: remove vsftpd 2.3.4 and replace FTP with SFTP (file transfer over SSH) from a supported, vendor-maintained package | Preventive | Removes the vulnerable code, so the likelihood falls to Low. SFTP also encrypts credentials and data in transit, which helps V2. |
| Software integrity verification: install software only from trusted, signed repositories and check published checksums or digital signatures before deployment | Preventive | Stops tampered software, the root cause of V1 and V4, from being installed in the first place. (NIST SI-7; ISO 8.19) |
| Disable anonymous FTP | Preventive | Removes unauthenticated access to files on the host. |
| Host and network firewall rules that allow only approved ports, plus egress filtering | Preventive | Limits who can reach port 21 and blocks unexpected ports such as the backdoor's 6200/tcp, lowering both likelihood and impact. (NIST SC-7; ISO 8.20; CIS 4, 12) |
| Intrusion detection signatures and alerts for connections on unexpected ports | Detective | Spots attempts quickly, which shortens the time an attacker has on the host. (NIST SI-4; CIS 13) |

### 4.4 Controls for V2, weak, default and blank credentials

| Recommended control | Type | How it reduces the risk |
|---|---|---|
| MFA and password policy: require MFA for all remote and administrative access; set strong passwords using length (at least 15 characters where a password is the only factor), screening against known-breached passwords, and no factory defaults | Preventive | Makes guessed or captured passwords useless on their own, so the likelihood of V2 drops from Critical to Low. (NIST IA-2(1), IA-5; ISO 5.17, 8.5; NIST SP 800-63B) |
| Change or disable every default account before a system goes live, and check for defaults in every vulnerability scan | Preventive and detective | Removes the published passwords that make V2 trivial. (PCI DSS v4.0.1 Req. 2.2.2; CIS 4.7) |
| Replace Telnet, rlogin/rsh and unencrypted VNC with SSH using key-based authentication; require TLS for database and web management connections | Preventive | Encrypts credentials in transit, removing the passive capture route. (NIST SC-8; ISO 8.24) |
| Least privilege and privileged access management: remove unrestricted sudo from day-to-day accounts, use named individual accounts, and grant administrator rights only when needed | Preventive | Even if an account is compromised, the attacker does not automatically gain root, which lowers impact. (NIST AC-6; ISO 8.2) |
| Bind MySQL and PostgreSQL to the local host or a private database network; restrict Tomcat Manager to an administration network | Preventive | Takes the database and management services off the general network, lowering likelihood. |
| Account lockout or rate limiting, plus alerting on repeated failed logins | Preventive and detective | Slows password guessing and gives early warning of an attack. (NIST AC-7; CIS 8) |
| Store application and service passwords in a secrets manager, not in configuration files | Preventive | Prevents one compromised host from revealing passwords for other systems. |

### 4.5 Controls for V3, Samba command execution

| Recommended control | Type | How it reduces the risk |
|---|---|---|
| Patch management: upgrade Samba to a currently supported release from the operating system vendor | Preventive | Removes the vulnerable code, so the likelihood falls to Low. (NIST SI-2; ISO 8.8; CIS 7) |
| Secure configuration baseline: disable the "username map script" option and any other options without a documented business need; disable SMBv1 | Preventive | Removes the condition the flaw depends on, even before patching. (NIST CM-6, CM-7; ISO 8.9; CIS 4) |
| Network segmentation: block SMB (139/tcp, 445/tcp) at the internet edge and between network zones; allow it only from approved client subnets | Preventive | Reduces who can reach the service (likelihood) and stops SMB being used to spread to other systems (impact). (NIST SC-7; ISO 8.22) |
| Monitoring of SMB logs and file-share activity, with alerts on unusual access or mass file changes | Detective | Spots exploitation or ransomware behaviour early. |
| Tested, offline or immutable backups of file shares | Corrective | Allows recovery without paying a ransom, lowering impact. (NIST CP-9; ISO 8.13) |

### 4.6 Controls for V4, UnrealIRCd backdoor

| Recommended control | Type | How it reduces the risk |
|---|---|---|
| Least functionality: remove the IRC server, since there is no business need for it | Preventive | Removes the service and the risk entirely. (NIST CM-7; CIS 2) |
| Software inventory and application allowlisting: only approved software may be installed on servers | Preventive and detective | Prevents unapproved services like this one from being installed, and flags them if they appear. (NIST CM-8, CM-11; ISO 5.9, 8.19; CIS 2) |
| Software integrity verification (as for V1) | Preventive | Stops trojaned downloads from reaching servers. |
| Egress filtering and network monitoring for IRC and other command-and-control traffic | Detective and preventive | Stops an infected host from receiving commands and helps detect compromised machines. (CIS 13) |

### 4.7 Controls for V5, distcc command execution

| Recommended control | Type | How it reduces the risk |
|---|---|---|
| Least functionality: remove distcc from any host that is not a build server | Preventive | Removes the service and the risk. |
| Where distcc is needed: restrict it with the allow list to named build hosts, bind it to a private build network, and block 3632/tcp everywhere else | Preventive | Only trusted machines can submit jobs, so the likelihood falls to Low. (NIST SC-7, AC-3) |
| Patch the operating system and kernel, and harden the host against a recognised baseline such as the relevant CIS Benchmark | Preventive | Removes local privilege escalation routes (for example CVE-2009-1185), so a foothold cannot become root. This lowers impact. |
| Run build services in isolated, disposable build environments | Preventive and corrective | Limits damage and protects the integrity of software HanTech builds. |

### 4.8 Cross-cutting controls

These controls address the governance gap that allowed the host to exist at all.

| Control | How it reduces the risk |
|---|---|
| Asset inventory and regular network discovery scanning | Finds unknown and unmanaged systems such as this one before an attacker does. (CIS 1; ISO 5.9) |
| Network access control (for example 802.1X) on wired and wireless networks | Stops unapproved devices and virtual machines from joining the corporate network. |
| Vulnerability scanning on a fixed schedule, with tracked remediation | Finds V1 to V5 and similar problems on other systems, and measures progress. (NIST RA-5; CIS 7) |
| Centralised logging and a security information and event management (SIEM) tool | Gives the visibility needed to detect attacks and to investigate incidents. (NIST AU-6; ISO 8.15, 8.16) |
| Incident response plan, tested at least once a year | Ensures HanTech can contain an incident quickly and meet breach notification deadlines. (ISO 5.24 to 5.28) |

### 4.9 Residual risk after controls

| ID | Current risk | Expected risk after controls | Main remaining concern |
|---|---|---|---|
| V1 | Critical | Low | Future supply chain compromise of other software, reduced by integrity checks |
| V2 | Critical | Low to Medium | Phishing of MFA codes; reduce further with phishing-resistant MFA for administrators |
| V3 | Critical | Low | New Samba flaws; managed through patching and segmentation |
| V4 | Critical | Low (service removed) | Unapproved software appearing elsewhere; managed through allowlisting |
| V5 | High | Low | Build environments that are not isolated |

<!-- pagebreak -->

## 5. Recommended policies

Technical controls only last if policy requires them, assigns responsibility for them and checks that they are followed. The policies below would have prevented this host from reaching the network, or ensured it was found and fixed quickly. Each policy should have a named owner, be approved by senior management, be reviewed at least once a year, and define how exceptions are requested, risk-accepted and recorded.

### 5.1 Policy summary

| Policy | Purpose | Findings mitigated |
|---|---|---|
| Asset Management Policy | Ensures every system, physical, virtual or cloud, is recorded, has an owner and is approved before it connects to the network. | All (root cause) |
| Acceptable Use Policy | Defines acceptable user behaviour and system usage, including a ban on installing unapproved software or servers. | V1, V4, V5 and the presence of the host itself |
| Access Control Policy | Defines how users and services are granted, reviewed and removed from access, based on least privilege. | V2, V3, V4, V5 |
| Password and Authentication Policy | Sets password strength, bans default credentials and requires MFA. | V2 |
| Patch Management Policy | Ensures systems receive security updates within set timeframes and that unsupported software is replaced. | V1, V3, V4, V5 |
| Vulnerability Management Policy | Defines how vulnerabilities are identified, assessed, tracked and remediated. | All |
| Secure Configuration and Network Security Policy | Sets hardened baselines, least functionality, segmentation and encryption in transit. | V1, V2, V3, V4, V5 |

### 5.2 Policy details

**5.2.1 Asset Management Policy**

*(a) Purpose.* Nobody at HanTech knew this host existed, which is why it was never patched, monitored or removed. HanTech cannot protect systems it does not know about. The policy requires a single inventory of all hardware, virtual machines, cloud resources and software, each with a named business owner, a data classification and a support end date. Nothing may connect to the network or be deployed in a cloud account until it is recorded and approved, and cloud resources must carry ownership tags.

*(b) Mitigates.* All five findings, because it removes the root cause: an unmanaged system. (ISO 5.9; CIS 1, 2; NIST CM-8)

**5.2.2 Acceptable Use Policy**

*(a) Purpose.* Someone deployed an intentionally vulnerable machine and an IRC server onto a business network, whether for testing, training or curiosity. HanTech needs clear rules on what staff may and may not do with company systems, so that well-meaning shadow IT does not create serious risk. The policy forbids installing unapproved software, servers or virtual machines on company networks or cloud accounts, requires security testing tools to be used only in approved isolated labs, and sets out the consequences of breaches of the policy. Staff must read and accept it every year.

*(b) Mitigates.* V4 (unapproved IRC server), V1 and V5 (unneeded services), and the presence of the Metasploitable 2 host itself. (ISO 5.10)

**5.2.3 Access Control Policy**

*(a) Purpose.* HanTech must ensure that people and services can only reach what they need for their job. The policy requires access to be granted on the principle of least privilege and on a role basis, approved by the system owner, reviewed every quarter for privileged accounts, and removed promptly when people change roles or leave. It requires named individual accounts instead of shared ones, services that run without root rights wherever possible, and network access to management interfaces only from administration networks.

*(b) Mitigates.* V2 (unrestricted sudo, shared default accounts), V3 and V4 (services running as root), V5 (a service open to any address). (ISO 5.15, 5.18, 8.2; NIST AC-2, AC-6)

**5.2.4 Password and Authentication Policy**

*(a) Purpose.* Weak and default credentials are one of the most common causes of breaches. The policy requires all vendor default passwords to be changed before a system goes live, minimum password length (at least 15 characters where a password is the only factor) with screening against breached-password lists, and MFA for all remote access, administrator access, email and cloud consoles. In line with current NIST SP 800-63B guidance, it favours length and breach screening over forced periodic changes, and requires a change when compromise is suspected. Passwords must never be sent over unencrypted protocols.

*(b) Mitigates.* V2 directly, and limits the follow-on damage from credentials stolen through any other finding. (ISO 5.17, 8.5; NIST IA-2, IA-5)

**5.2.5 Patch Management Policy**

*(a) Purpose.* This host runs software and an operating system that stopped receiving security updates more than a decade ago. HanTech needs a fixed timetable for applying updates and a rule for replacing unsupported software. The policy sets remediation deadlines by severity: actively exploited vulnerabilities (for example those in the CISA KEV catalogue) within 72 hours, Critical within 7 days, High within 30 days, Medium within 60 days and Low within 90 days. It requires patches to be tested and applied through change management, and it bans end-of-life operating systems and software from production unless a time-limited, risk-accepted exception is signed by the system owner.

*(b) Mitigates.* V3 (outdated Samba), V5 (outdated distcc and the local privilege escalation flaws), and V1 and V4, whose vulnerable versions would have been replaced. (ISO 8.8; NIST SI-2; PCI DSS v4.0.1 Req. 6.3.3)

**5.2.6 Vulnerability Management Policy**

*(a) Purpose.* Patching only fixes problems HanTech knows about. This policy defines how vulnerabilities are found, rated, tracked and closed. It requires authenticated internal scans at least monthly and external scans at least quarterly (and after significant changes), an annual penetration test, risk rating that combines CVSS with business context as in Section 3 of this report, a tracked register with owners and due dates, and monthly reporting of open Critical and High findings to management.

*(b) Mitigates.* All five findings: any of them would have been detected by a routine scan. (ISO 8.8; NIST RA-5; CIS 7; PCI DSS v4.0.1 Req. 11.3)

**5.2.7 Secure Configuration and Network Security Policy**

*(a) Purpose.* Most of this host's weaknesses come from services that are switched on, open to everyone and configured insecurely. The policy requires every system to be built from an approved hardened baseline (for example CIS Benchmarks), with all unneeded services disabled, the network divided into zones with default-deny firewall rules between them, management ports reachable only from administration networks, and encryption for all data in transit (no Telnet, FTP, rlogin or unencrypted VNC). Configuration drift must be checked automatically.

*(b) Mitigates.* V1 and V4 (unneeded services), V2 (cleartext protocols, exposed databases), V3 (insecure Samba option), V5 (distcc open to all). (ISO 8.9, 8.20, 8.22, 8.24; NIST CM-2, CM-6, CM-7, SC-7, SC-8)

### 5.3 Cloud security basics

HanTech hosts client workloads and data in the cloud. Every finding in this report could appear just as easily on a cloud virtual machine, and the cloud adds its own risks. This section summarises the fundamentals and applies them to HanTech.

**5.3.1 Shared responsibility.** In the cloud, security is split between the provider and the customer. The provider secures the cloud itself: data centres, physical hardware, the hypervisor and the core network. HanTech secures what it puts in the cloud: its data, user identities and permissions, network rules, and, for virtual machines, the operating system and every application on it. The split moves with the service model:

| Layer | IaaS (virtual machines) | PaaS (managed databases, app platforms) | SaaS (finished applications) |
|---|---|---|---|
| Physical facilities, hardware, hypervisor | Provider | Provider | Provider |
| Operating system patching | HanTech | Provider | Provider |
| Application and its configuration | HanTech | HanTech (provider runs the platform) | Provider (HanTech sets options) |
| Network rules (security groups, firewalls) | HanTech | Shared | Provider |
| Identities, access and MFA | HanTech | HanTech | HanTech |
| Data and its classification and encryption settings | HanTech | HanTech | HanTech |

Applied to this report: if a Metasploitable-style image were launched as a cloud virtual machine, all five findings would be HanTech's responsibility, not the provider's. The provider would not patch vsftpd or change default passwords. Identities and data are always HanTech's responsibility, whatever the service model.

**5.3.2 Identity and access management (IAM).** IAM controls who can do what in HanTech's cloud accounts. It has three parts:
* *Authentication* (proving who you are): all staff sign in through one central identity provider with single sign-on and MFA. No shared accounts. Long-lived access keys are replaced with short-lived credentials, and the cloud root or global administrator account is locked away and used only in emergencies.
* *Authorisation* (deciding what you may do): permissions are granted through roles and groups, not to individuals, and are scoped to specific accounts, projects and resources. Production and development are kept in separate accounts or subscriptions.
* *Auditing* (recording what you did): cloud audit logs (for example AWS CloudTrail, Azure Activity Log or Google Cloud Audit Logs) are enabled in every account and region, kept in tamper-resistant storage, sent to the SIEM, and alerting is set up for high-risk events such as root account use, new administrator grants or logging being switched off.

**5.3.3 Multi-factor authentication (MFA).** MFA requires a second proof of identity in addition to a password, such as an authenticator app, a hardware security key or a passkey. It matters because passwords are guessed, reused and stolen (finding V2): with MFA, a stolen password alone is not enough. HanTech should enforce MFA for every cloud console user, with phishing-resistant methods (FIDO2 security keys or passkeys) for administrators and the root account, and also for VPN and remote access, email, source code repositories and the CI/CD pipeline, and any administrative interface.

**5.3.4 Least privilege.** Every user, application and service gets only the permissions it needs, for only as long as it needs them. On the assessed host the opposite was true: services ran as root and the default account had unrestricted administrator rights, so every flaw led to total control. HanTech should apply least privilege by using role-based access with permission boundaries, granting administrator rights just-in-time with approval and automatic expiry, giving each application or workload its own narrowly scoped identity instead of an administrator key, removing unused permissions found by the provider's access analysis tools, and reviewing privileged access every quarter.

**5.3.5 Top cloud security threats relevant to HanTech.**

| Threat | Relevance to HanTech | Link to this assessment |
|---|---|---|
| Misconfiguration | High. The most common cause of cloud breaches: storage buckets left public, firewall rules open to the whole internet, logging switched off. | V3 and V5 are configuration failures; an unmanaged host is the extreme case. |
| Weak credentials | High. Stolen or guessed passwords and leaked access keys give direct entry to cloud consoles and APIs. | V2 |
| Excessive permissions | High. Over-privileged users and service roles turn a small compromise into a total one. | Services running as root (V3, V4); unrestricted sudo (V2) |
| Unencrypted data | High. Client data stored or transmitted without encryption is exposed if intercepted or copied. | Cleartext protocols (V2) |
| Insecure APIs | High. Cloud platforms are managed entirely through APIs; unauthenticated or poorly protected management APIs give attackers control. | distcc (V5) and Tomcat Manager (V2) are unauthenticated or weakly protected management interfaces. |
| Insider threats | Medium. Staff with access, whether careless or malicious, can expose data or deploy risky systems. | The host itself appears to have been deployed without approval. |
| Distributed denial of service (DDoS) | Medium. Client-facing platforms can be made unavailable, breaching service agreements. | Not a direct finding, but a compromised host could be used to launch attacks on others. |

**5.3.6 Cloud security best practices for HanTech.**
* Build on a secure landing zone: separate accounts or subscriptions for production, development and security tooling, with organisation-wide guardrail policies that block risky settings (for example public storage).
* Use a cloud security posture management (CSPM) tool to check continuously against the provider's CIS Foundations Benchmark and alert on misconfiguration.
* Define infrastructure as code, scan the templates for security issues before deployment, and build virtual machines and containers from hardened, regularly patched "golden" images.
* Never expose management ports (SSH, RDP, database ports) to the internet; use a bastion host, the provider's session manager or just-in-time access instead.
* Encrypt all data at rest with keys managed in the provider's key management service, and require TLS 1.2 or higher in transit.
* Keep secrets in a secrets manager; scan code repositories for leaked keys.
* Enable audit logging in every account and region and forward it to the SIEM.
* Scan cloud workloads and container images for vulnerabilities and feed results into the vulnerability management process.
* Take backups that are immutable, stored in a separate account, and restored in regular tests.
* Tag every resource with an owner and data classification, so the cloud is covered by the Asset Management Policy.

**5.3.7 Compliance.** Which laws and standards apply depends on what data HanTech holds and where its clients and their customers are. HanTech should complete a data inventory and classification exercise and confirm its obligations with legal counsel. The most likely to apply are:

| Law or framework | When it applies to HanTech | Requirements most relevant to this report |
|---|---|---|
| GDPR (EU Regulation 2016/679) | HanTech processes personal data of people in the EU or EEA, either directly or as a processor for clients | Art. 32 appropriate security of processing (patching, access control, encryption); Art. 33 notify the supervisory authority within 72 hours of becoming aware of a personal data breach; Art. 28 processor duties to clients |
| Nigeria Data Protection Act 2023 (NDPA) and NDPR 2019 | HanTech processes personal data of individuals in Nigeria, or is established there | Appropriate technical and organisational security measures; notify the Nigeria Data Protection Commission of breaches within 72 hours; registration as a data controller or processor of major importance where thresholds are met; annual data protection compliance audits under the NDPR framework |
| PCI DSS v4.0.1 | HanTech stores, processes or transmits payment card data, or can affect the security of systems that do | Req. 2.2.2 manage vendor default accounts; Req. 6.3.3 install critical patches within one month; Req. 8.4 MFA; Req. 11.3 quarterly internal and external vulnerability scans |
| HIPAA Security Rule (45 CFR Part 164, Subpart C) | HanTech handles U.S. protected health information for healthcare clients, as a business associate | Risk analysis and risk management; access control; audit controls; transmission security; business associate agreements |
| ISO/IEC 27001:2022, ISO/IEC 27017 and 27018, SOC 2 | Frameworks and attestations that clients often require from technology service providers | A certified information security management system; cloud-specific controls; protection of personal data in public clouds |
| Data protection laws of other countries | HanTech's clients operate in, or hold data about residents of, other jurisdictions | Varies; many follow the GDPR model of security duties and breach notification |

A compromise of the assessed host could trigger breach notification duties under several of these at once if personal or client data was reachable from it. That is why the investigation step in Section 4.2 matters.

<!-- pagebreak -->

## 6. Conclusion

The Metasploitable 2 host gives HanTech a clear picture of what an unmanaged system means in practice. Five independent weaknesses each allow an outsider to take control of it, four of them with full administrator rights and without any password. The overall security posture of the host is **Critical**.

The individual flaws are old and well understood: tampered software, unpatched services, default passwords, cleartext protocols and services left open to everyone. What made them dangerous is that nothing in HanTech's processes caught them. The host had no owner, no patching, no scanning and no monitoring. The most important outcome of this engagement is therefore not the removal of one server, but the governance that prevents the next one.

**Roadmap**

| Timeframe | Actions | Owner (to be assigned) |
|---|---|---|
| 0 to 24 hours | Isolate the host, preserve evidence, reset exposed credentials | IT operations, security lead |
| 0 to 30 days | Complete the compromise assessment; decommission the host or move it to a sealed lab; begin the asset inventory; enforce MFA for remote, administrator and cloud console access; block unneeded services at the firewall | Security lead, IT operations, cloud team |
| 30 to 90 days | Approve and publish the seven policies; deploy vulnerability scanning and the patching timetable; centralise logs in a SIEM; enable CSPM and audit logging across all cloud accounts | CISO or IT director, policy owners |
| Ongoing | Monthly scans and reporting, quarterly access reviews, annual policy review, penetration test and incident response exercise, staff awareness training | Policy owners, management |

**Measures of success.** Leadership can track progress with a small set of indicators: the percentage of systems recorded in the asset inventory, MFA coverage for privileged and cloud accounts, average time to fix Critical and High vulnerabilities against the policy deadlines, the number of default or unapproved services found in each scan, and the percentage of cloud accounts passing the CIS Foundations Benchmark.

With these controls and policies in place, the risk from the five findings falls from Critical to Low, and HanTech will be in a far stronger position to meet the security and breach notification duties of the GDPR, the NDPA, PCI DSS and the other frameworks its clients expect.

<!-- pagebreak -->

## Appendix A. Other weaknesses noted on the host

These are publicly documented weaknesses of the Metasploitable 2 build that were not selected for detailed rating. All of them are removed by decommissioning the host, and all are covered by the controls and policies above.

| Weakness | Service | Reference | Covered by |
|---|---|---|---|
| PHP-CGI query string argument injection | Apache with PHP 5.2 as CGI (80/tcp) | CVE-2012-1823, CVSS v3.1 9.8; listed in the CISA KEV catalogue since 25 March 2022 | Patch Management |
| Root shell listening without authentication | "ingreslock" (1524/tcp) | No CVE; deliberate backdoor | Secure Configuration, Vulnerability Management |
| Root file system exported to any host over NFS | NFS (2049/tcp) | Insecure configuration | Secure Configuration |
| Host-based trust for r-services | rlogin and rsh (512 to 514/tcp) | Insecure configuration | Secure Configuration, Password and Authentication |
| Java RMI registry with insecure default configuration | Java RMI (1099/tcp) | Insecure configuration | Secure Configuration |
| Deliberately vulnerable web applications (for example DVWA and Mutillidae) | Web server (80/tcp) | Training applications | Acceptable Use, Asset Management |
| End-of-life operating system (Ubuntu 8.04 LTS, server support ended May 2013) | Whole host | Vendor end of life | Patch Management |

## Appendix B. References

* NIST National Vulnerability Database records: CVE-2011-2523, CVE-1999-0502, CVE-2007-2447, CVE-2010-2075, CVE-2004-2687, CVE-2009-1185, CVE-2012-1823. https://nvd.nist.gov/vuln/detail/ followed by the CVE identifier. Scores checked on 20 November 2026.
* CISA Known Exploited Vulnerabilities Catalog. https://www.cisa.gov/known-exploited-vulnerabilities-catalog
* FIRST, Common Vulnerability Scoring System v3.1 and v2 specifications. https://www.first.org/cvss/
* MITRE, Common Weakness Enumeration (CWE-16, CWE-20, CWE-78, CWE-319, CWE-521, CWE-1392). https://cwe.mitre.org/
* Rapid7, Metasploitable 2 documentation.
* NIST SP 800-53 Rev. 5, Security and Privacy Controls for Information Systems and Organizations.
* NIST SP 800-63B, Digital Identity Guidelines: Authentication and Lifecycle Management.
* NIST Cybersecurity Framework 2.0.
* ISO/IEC 27001:2022, Information security management systems: Requirements (Annex A controls).
* ISO/IEC 27017:2015 and ISO/IEC 27018:2019, cloud security and protection of personal data in public clouds.
* Center for Internet Security, CIS Critical Security Controls v8.1 and CIS Benchmarks.
* Cloud Security Alliance, Top Threats to Cloud Computing.
* Regulation (EU) 2016/679, General Data Protection Regulation.
* Nigeria Data Protection Act 2023 and Nigeria Data Protection Regulation 2019.
* PCI Security Standards Council, PCI DSS v4.0.1.
* U.S. Department of Health and Human Services, HIPAA Security Rule, 45 CFR Part 164 Subpart C.

## Appendix C. Glossary

| Term | Meaning |
|---|---|
| Backdoor | A hidden way into a system that bypasses normal login. |
| CVE | Common Vulnerabilities and Exposures: a public identifier for a specific known vulnerability. |
| CVSS | Common Vulnerability Scoring System: a 0 to 10 score of a vulnerability's general severity. |
| CWE | Common Weakness Enumeration: a category of software weakness, such as command injection. |
| Cleartext | Data sent without encryption, readable by anyone who can see the network traffic. |
| GRC | Governance, risk management and compliance. |
| Least privilege | Giving each user or service only the access it needs, and no more. |
| MFA | Multi-factor authentication: proving identity with more than just a password. |
| Root | The all-powerful administrator account on Linux and Unix systems. |
| Segmentation | Dividing a network into zones so that a problem in one zone cannot easily spread. |
| SIEM | Security information and event management: a system that collects and analyses security logs. |
| Supply chain compromise | An attack in which software is tampered with before it reaches the customer. |
