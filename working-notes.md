# Working notes: HanTech capstone

These notes record how the report was put together. They are not part of the deliverable.

## Files

* `HanTech_Security_Assessment_Report.md`, `.docx` and `.pdf`: the same report in three formats. Submit one of them, normally the PDF.
* The title page carries Fonyuy Berka Dzekem Jr., Group 25.
* The script that produced the DOCX and PDF was removed after the final build. If the Markdown changes again, edit the DOCX to match.

## CVE data checked against the NVD API (20 November 2026)

| CVE | Finding | NVD score | CWE | In CISA KEV |
|---|---|---|---|---|
| CVE-2011-2523 | V1 vsftpd 2.3.4 backdoor | v3.1 9.8 Critical; v2 10.0 | CWE-78 | No |
| CVE-1999-0502 | V2 default, null or blank passwords (generic) | v2 7.5 | Other | No |
| CVE-2007-2447 | V3 Samba username map script | v2 6.0 (AV:N/AC:M/Au:S) | Other | No |
| CVE-2010-2075 | V4 UnrealIRCd 3.2.8.1 backdoor | v2 7.5 | CWE-20 | No |
| CVE-2004-2687 | V5 distcc | v2 9.3 | CWE-16 | No |
| CVE-2009-1185 | udev local privilege escalation (V5 chain) | v2 7.2 | CWE-346 | No |
| CVE-2012-1823 | PHP-CGI argument injection (Appendix A) | v3.1 9.8 | CWE-77 | Yes, added 25 March 2022 |

KEV status was read from the NVD record's CISA fields. Only CVE-2012-1823 carries them.

## Decisions

* Five findings were chosen to cover distinct root causes: supply chain tampering (V1, V4), unpatched software (V3), credentials (V2) and insecure configuration (V5).
* Risk = Likelihood x Impact on a 1 to 4 scale. CVSS is an input, adjusted for context. Samba (V3) is the worked example: base 6.0, rated Critical because smbd runs as root and the flaw is reachable before login on this configuration.
* The report names no default passwords and gives no exploit steps. It stays defensive, as the brief requires.
* The first control for every finding is to isolate and decommission the host, because Metasploitable 2 is insecure by design.
* No live scan was run. The report states this as a limitation and recommends a credentialed scan and compromise assessment.

## Not done

* No git repository was created and nothing was committed or pushed, as the brief requires.
