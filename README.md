# KORTNIT GROUP-OSINT Driven Threat Intelligence Assessment
**Analyst:** John Doe
**Date:** 8/9/25
**Company in Focus:** Kortnit Financial Services (kortnit.com)
**Industry:** Financial Services

## 1. Introduction
Kortnit Financial Services is one of the three largest credit reporting agencies in the United States. It is responsible for storing and managing the personal and financial data of millions of people and businesses. Because of the nature of its business, Kortnit is considered a high-value target for malicious actors who are seeking financial gain, personal data, or reputational disruption.
The 2017 Kortnit Financial Services breach - one of the largest in history, has compromised the sensitive data of 147 million people. This incident demonstrates the catastrophic consequences of a single unpatched vulnerability of a public system.
My report provides a passive open-source intelligence (OSINT) assessment of Kortnit Financial Services’ digital footprint. Using tools such as Google Dorks, DNSDumpster, TheHarvester, Shodan and Maltego, I assess and identify exposures and potential risks that could be exploited by malicious actors.

## 2. Executive Summary
This report highlights publicly available information about Kortnit Financial Services that can be discovered through OSINT techniques. The objective is to identify elements of Kortnit Financial Services' digital footprint that may present risks, including subdomains, email address patterns, service banners, and infrastructure mappings.
**The findings show that:**

•	Public subdomains expand the attack surface.
•	Exposed employee email formats enable targeted phishing campaigns.
•	Banner information from Shodan reveals services that could be exploited if unpatched.
•	Maltego visualizations show infrastructure relationships that can guide threat actors.
•	Past failures, such as the Apache Struts vulnerability exploited in 2017, emphasize the importance of timely patch management.
The potential threats include phishing, exploitation of outdated systems, and data exfiltration. Threat actors such as APT10 and FIN6 pose significant risks to Kortnit Financial Services and the financial services sector. Recommendations include strong patch management, proactive monitoring, segmentation of critical assets, and employee awareness training. This assessment was conducted passively and ethically, with no attempts to intrude or exploit systems.

## 3. Scope and Methodology
**•	Scope**
This project focused only on Kortnit Financial Service's main website domain (kortnit.com) and whatever public information could be found connected to it. The work stayed within the rules of passive research, meaning no hacking, no password guessing, and no scanning that would directly touch their servers. The point was to see what an attacker could find just by using the open internet.

To carry out the assessment, several well-known OSINT tools were used:
**•	Google Dorks** - By using Google search operators, I looked for files, login pages, or other information that might be sitting out in the open.
**•	DNSDumpster** - This tool maps out DNS records and subdomains. It’s handy for spotting parts of a company’s online presence that aren’t always obvious, like older or forgotten web services.
**•	TheHarvester** - A tool that gathers emails, names, and subdomains from public sources. This shows what information about employees or systems could be used in phishing or social engineering.
**•	Shodan** - A search engine for internet-connected devices. It reveals what services and ports are exposed, and sometimes even what software is running, which can be risky if it’s outdated.
**•	Maltego** - Maltego is a visualization tool that creates maps of how domains, IP addresses, emails, and other elements connect. It’s useful for spotting relationships in the company’s online footprint that might not be obvious otherwise.

## 4. Findings and Analysis
**4.1 Google Dorks**
**Query 1 – Public Documents**
Using advanced Google search operators (often called Google Dorks), publicly accessible documents and portals related to Kortnit Financial Services were identified. For instance, the query: site:kortnit.com filetype:pdf returned multiple Kortnit-hosted PDFs, primarily investor reports and financial statements. While no sensitive files (such as credentials or configuration data) were exposed, the visibility of login portals, password reset pages, and financial documents demonstrates how corporate information can be indexed by public search engines.

**Screenshot 1:**
 Google search results for the query site:kortnit.com filetype:pdf, showing publicly available Kortnit PDF documents.
 
 <img width="838" height="660" alt="image" src="https://github.com/user-attachments/assets/703acb51-a1c7-489f-82ca-6d851ff1d3ad" />



**Query 2 – Login and Password Pages**
**-	site:kortnit.com inurl:login**
**-	site:kortnit.com inurl:password**
•	Revealed employee/customer login portals and password reset interfaces.
•	While not directly vulnerable, their visibility makes them attractive for phishing or credential stuffing.

**Screenshot 2:**
 Search results highlighting Kortnit Financial Services’ login and password-related portals.

<img width="939" height="742" alt="image" src="https://github.com/user-attachments/assets/8d835ef7-45e8-4b38-bb11-0064e6fbf62e" />

 

 <img width="939" height="744" alt="image" src="https://github.com/user-attachments/assets/a802ccda-609e-4116-b729-31fc025fe0b3" />

**Query 3 - Cached Content**
-	cache:kortnit.com
•	Displayed cached versions of Kortnit Financial Services pages.
•	Cached content can sometimes reveal older structures or outdated information is not visible on the live site.

**Screenshot 3:**
 Google’s cached snapshot of Kortnit Financial Services page, illustrating the persistence of data even after site changes.
 
<img width="939" height="780" alt="image" src="https://github.com/user-attachments/assets/9de0007c-7678-48eb-8ffa-150fadb16995" />


**Query 4 – Potentially Sensitive File Types**
**-	site:kortnit.com filetype:xls**
**-	filetype:csv**
-	Returned limited results but showed that structured data files (like CSV/Excel) can sometimes be indexed.
-	Such files may expose metadata or internal formatting if not properly controlled.
  
**Screenshot 4:**
 Google search results for site:kortnit.com filetype:xls and filetype:csv, checking for exposed spreadsheets or data files.
 
<img width="939" height="789" alt="image" src="https://github.com/user-attachments/assets/43d083bb-b880-498d-8005-a849e60078ef" />


<img width="939" height="741" alt="image" src="https://github.com/user-attachments/assets/3ada4143-de39-4554-ba95-47b3a375ff5d" />

## Implications
Even without exposed credentials, these searches demonstrate how Kortnit Financial Services’ external-facing content can be mapped and monitored by anyone. Such visibility allows attackers to craft more convincing phishing campaigns or prepare targeted attacks.

# 4.2 DNSDumpster
•	Returned **837 DNS records** (free view limited).
•	Examples: uat.ai.kortnit.com, secure.api.kortnit.com, api-breach-services.kortnit.com.
•	Hosting confirmed across Google Cloud, Akamai, and Kortnit’s own secure services.
**Implication:** Staging and test subdomains may be less monitored and therefore vulnerable. Attackers often prioritize API endpoints or forgotten services as weak points.

<img width="939" height="506" alt="image" src="https://github.com/user-attachments/assets/654a493b-b876-490e-b59a-3e5d430374e9" />


 “Visualization of Kortnit’s map of subdomain and DNS records, including uat.ai.kortnit.com and airlock-sftp.kortnit.com. The network graph highlights infrastructure spread across Akamai and Google Cloud.”

<img width="939" height="494" alt="image" src="https://github.com/user-attachments/assets/33414810-c0a3-472e-a100-5060a77925e1" />
 
**Query 2 – Infrastructure Mapping (Network Graph)**
•	DNSDumpster provides a visualization of how domains and subdomains connect to hosting providers.
•	Kortnit infrastructure was confirmed across **Google Cloud, Akamai,** and Kortnit-owned secure services.

**Screenshot 2:**
 Network map highlighting Kortnit’s distribution across Google Cloud and Akamai.

<img width="939" height="453" alt="image" src="https://github.com/user-attachments/assets/b5a54c3c-487b-45a3-9c74-ef6cfd8acf90" />
 
 

**Query 3 – MX and TXT Records**
•	DNSDumpster also reveals MX (mail exchange) records and TXT entries.
•	Example: SPF (Sender Policy Framework) records showing which mail servers are authorized.
•	Such records can help attackers craft targeted phishing campaigns.

**Screenshot 3:**
 DNSDumpster results displaying MX and TXT records associated with Kortnit Financial Services’ mail servers.
 
<img width="939" height="575" alt="image" src="https://github.com/user-attachments/assets/2f495a93-2b14-47a1-939f-3bb2d0e2188f" />
 

**Query 4 – Service Fingerprinting**
•	The scan identified backend services like **BigIP load balancers, Google-Edge-Cache,** and **nginx servers.**
•	These indicate a mix of enterprise-grade infrastructure with third-party dependencies.

**Screenshot 4:**
 Service details from DNSDumpster results, showing backend technologies in use.

 <img width="939" height="522" alt="image" src="https://github.com/user-attachments/assets/1cf0bf35-1129-4fca-ad3f-95d2bb4aa2a2" />

 
## Implications
Staging and test subdomains (such as uat.*) and exposed API endpoints expand Kortnit Financial Services’ attack surface. Even if these services return error messages today, their presence signals potential entry points for attackers, particularly if monitoring or patching is inconsistent.

# 4.3 TheHarvester
TheHarvester is a reconnaissance tool designed to collect subdomains, IP addresses, and related infrastructure from open sources. It provides analysts with a clear view of a company’s external footprint without requiring intrusive scans.
For Kortnit Financial Services, TheHarvester was executed against multiple free sources (DuckDuckGo, crt.sh, RapidDNS, Qwant, ThreatCrowd, HackerTarget, Omnisint). The query returned **thousands of hostnames and subdomains**, many of which correspond to both production services and testing environments.
•	Examples of discovered hosts include:
**o	aa.econsumer.....com**
**o	academy.....com**
**o	uat-ui.ext.....com**
**o	secure.evvssc2.....com**
•	The JSON output (Figure X) displayed these results in structured arrays, while the XML output (Figure Y) showed hostnames alongside IP addresses.

## Screenshot X – JSON Results
 TheHarvester JSON output showing discovered Kortnit subdomains, including both production (e.g., academy.kortnit.com) and test environments (e.g., achq-uat.us.kortnit.com).

<img width="939" height="877" alt="image" src="https://github.com/user-attachments/assets/c6ee2bb9-1730-48ac-a1e4-9959413c772a" />

**Screenshot Y – XML Results**
 TheHarvester XML export pairing hostnames with IP addresses, such as uat-ui.ext.kortnit.com and auth2.mum.kortnit.com.
 
<img width="939" height="916" alt="image" src="https://github.com/user-attachments/assets/606698c8-044c-4cd5-84f6-e76d0acb06b3" />
 
## Implications
The results reveal the scale of Kortnit Financial Services’ online presence. Even without employee emails, the large number of hostnames provides valuable intelligence for adversaries. Test and staging subdomains (uat.*, qa.*) are often less hardened than production, making them attractive entry points. These findings, when combined with DNSDumpster results, confirm a broad and diverse attack surface.



# 4.4 Shodan
Shodan is a search engine that indexes internet-connected devices, exposing information about open ports, SSL certificates, and the software services running on those systems. By searching for Kortnit-related assets, it is possible to gain insights into the organization’s global infrastructure.
Several targeted queries were executed:

**•	Query 1: ssl.cert.subject.cn:kortnit.com**
Returned over **1,200** hosts linked to Kortnit SSL certificates. This confirms wide certificate reuse across multiple regions.

**Screenshot 1 – SSL Certificates**
 Shodan results for ssl.cert.subject.cn:kortnit.com, showing hosts associated with Kortnit-issued certificates.

<img width="939" height="603" alt="image" src="https://github.com/user-attachments/assets/6f716624-fabc-4e93-a81d-b767a291d005" />

 
**•	Query 2: org:"Kortnit"**
Displayed more than **4 million results** tied to Kortnit Financial Services infrastructure worldwide. Results were concentrated in the United States, with additional presence in Europe, India, and Asia-Pacific.
**Screenshot 2 – Organization Search**
 Global Shodan search results for org:"Kortnit", highlighting the scale and distribution of Kortnit infrastructure.

<img width="939" height="647" alt="image" src="https://github.com/user-attachments/assets/d07764e0-1707-43a7-a2c7-35bb28c683c7" />

 
**•	Query 3: hostname:kortnit.com**
Focused on assets directly under the kortnit.com domain, yielding 33,000+ hosts. These results reveal a broad footprint across production, staging, and international subdomains.

**Screenshot 3 – Hostname Search**
 Shodan results for hostname:kortnit.com, listing tens of thousands of hosts associated with Kortnit.

<img width="939" height="613" alt="image" src="https://github.com/user-attachments/assets/47a2d720-0880-46c3-83d2-569695546fac" />
 
 
**•	Query 4:**

**Host Detail View**
 By opening individual host records, service banners confirmed widespread use of HTTPS (port 443) alongside integrations with Akamai, Salesforce, and DigiCert.

**Screenshot 4 – Host Services**
 Detail view of an Kortnit host, showing exposed ports and service banners (HTTPS 443, CDN integrations, and certificate details).

<img width="939" height="411" alt="image" src="https://github.com/user-attachments/assets/cff83b93-c2f8-44aa-8f98-75f8614d4d16" />
 

## Implications
Shodan results demonstrate the global scale of Kortnit Financial Services’ infrastructure and its reliance on third-party providers. For attackers, this visibility can highlight less-monitored regions or services to target. For defenders, it underlines the importance of continuous monitoring, strict patching, and reviewing cloud/CDN dependencies.

# 4.8 Maltego
## DNS Mapping and Infrastructure Validation (Maltego)
To validate DNS exposure and uncover potential infrastructure links, Maltego was used to run a series of transforms against the entity “Kortnit.” These included schema-based DNS name discovery, mail server resolution (MX/NS), and website associations via SecurityTrails. The transforms revealed standard services and filtered ports, suggesting firewall or IDS restrictions. Attempts to retrieve zone transfer data returned no records, indicating hardened DNS configurations. The visual graph mapped relationships between domains, subdomains, and associated IPs, providing a clear view of Kortnit’s public-facing infrastructure. This approach complements passive reconnaissance tools like Shodan by confirming exposure through active OSINT techniques.
 
<img width="1015" height="578" alt="image" src="https://github.com/user-attachments/assets/071fa133-4a05-43ea-8696-48c4cd694b77" />

# Findings
During the passive reconnaissance and analysis phase, several OSINT and scanning tools were used to assess the publicly available information on the target organization. The combined findings from each tool are summarized below. Screenshots are included as supporting evidence.

## 1. Google Dorks
•	Multiple Google Dork queries were tested.
•	Results highlighted indexed subdomains, documents, and cached files associated with the target.
•	No sensitive information (such as login pages or config files) was directly exposed, but the searches confirmed that some Kortnit-related subdomains are visible through open search indexing.

## 2. DNSDumpster
•	DNSDumpster queries returned **837 records**, with the first 50 subdomains visible in the dataset.
•	Several subdomains were mapped to **Google Cloud Platform, EFXSecure, and Akamai networks**.
•	Services identified included **BigIP load balancers, Google-Edge-Cache**, and **nginx servers**.
•	The mapping confirmed global distribution of infrastructure across the US, Australia, Netherlands, and Chile.

## 3. theHarvester
•	theHarvester was executed against equifax.com using multiple engines (DuckDuckGo, crt.sh, RapidDNS).
•	Total of **4,567 hosts discovered**.
•	No emails or employee names were returned in this scan, but the host results confirmed a large attack surface with multiple subdomains and IP mappings.

## 4. Shodan
•	Shodan searches were performed using queries like:
o	ssl.cert.subject.cn:kortnit.com
o	org:"Kortnit"
o	hostname:kortnit.com
•	Results showed:
o	Over 4 million results tied to Equifax infrastructure, primarily located in the United States.
o	Open port 443 (HTTPS) was the most common, with some additional services detected in smaller ranges.
o	SSL certificates confirmed ties to Salesforce, Akamai, and DigiCert, indicating third-party integrations and cloud dependencies.

## 5. Maltego
•	Multiple transforms successfully resolved DNS names, including common subdomains and mail servers (MX/NS), indicating active infrastructure components.
•	Website associations were confirmed via quick lookup, validating public-facing services.
•	Attempts to retrieve zone transfer data returned no results, suggesting hardened DNS configurations.
•	Some DNS records were not found, implying restricted visibility or intentional obfuscation.
•	Credit consumption confirms active querying, with no anomalies in transform execution.
These findings support the conclusion that Kortnit’s infrastructure is selectively exposed, with defensive measures in place to limit reconnaissance.

# Analysis & Conclusion
The reconnaissance phase revealed a wide range of publicly available information on Kortnit Financial Services’ digital infrastructure. While no direct vulnerabilities or sensitive data were exposed during passive scanning, the findings provide valuable insight into the organization’s attack surface and risk posture.

## Key Observations
**•	Large attack surface:** TheHarvester alone showed >4,500 subdomains, confirming the distributed and complex nature of Kortnit’s systems.
**•	Third-party reliance:** DNSDumpster and Shodan data revealed reliance on Google Cloud, Akamai, Salesforce, and DigiCert. This expands the trust boundary beyond Kortnit’s direct control.
**•	Exposure visibility:** SSL certificates and hostnames are easily indexed online, providing attackers with infrastructure maps before they ever launch an exploit.

# Threat Actor Profile: Chinese PLA (54th Research Institute)

## Overview
In 2017, **Kortnit Financial Services** suffered a breach later attributed to four members of the People’s Liberation Army (PLA), 54th Research Institute. Unlike profit-driven cybercriminal groups, this was a state-sponsored Advanced Persistent Threat (APT) operation. The attackers exploited a known but unpatched Apache Struts vulnerability (CVE-2017-5638) and operated inside Kortnit’s systems for months, extracting sensitive personal and financial records of approximately 147 million individuals.

## Motivations
**•	Strategic intelligence gathering:** No evidence suggests monetization on underground markets. Instead, the data was absorbed into a long-term intelligence collection campaign.
**•	The “shadow census”:** Kortnit’s dataset, when combined with other landmark breaches-OPM (2015, security clearance files), Anthem (2015, health insurance data), and Marriott (2018, travel records)-enabled the creation of a de facto shadow census of U.S. citizens. This census contained identity, biometrics, medical, financial, and travel data at population scale.
**•	Operational leverage:** Such a dataset enhances counterintelligence (detecting covert U.S. personnel abroad), recruitment targeting (identifying financially vulnerable individuals), and strategic forecasting (modeling population behavior, economic stress, or mobility trends).

## Behavior and Tactics

## Initial Access
•	Exploited CVE-2017-5638 (Apache Struts remote code execution).
•	Used passive reconnaissance to identify Kortnit’s distributed subdomains and mapped infrastructure.

## Establishing Foothold
•	Deployed custom web shells for persistent access.
•	Harvested internal credentials using standard credential-dumping techniques.
•	Established redundant footholds to ensure continuity even if partial remediation occurred.

## Lateral Movement
•	Pivoted across network segments toward databases storing PII and credit histories.
•	Used stolen administrative credentials to impersonate legitimate accounts.
•	Maintained low operational noise to avoid triggering automated detection.

## Data Collection & Exfiltration
•	Queried and staged records in structured batches to avoid detection.
•	Compressed and encrypted datasets before exfiltration.
•	Used multi-hop routes and compromised intermediary servers to obfuscate exfiltration paths.

## Indicators of Compromise (IOCs)
Activity associated with this intrusion included:
•	Exploitation attempts of Apache Struts (CVE-2017-5638).
•	Outbound data transfers to external IP ranges not aligned with business activity.
•	Large-volume, structured database queries inconsistent with normal business logic.
•	Web shell traffic patterns (HTTP POST anomalies on Struts-hosted endpoints).

## Relevance to Kortnit Financial Services
The Kortnit breach demonstrates that **state-backed APTs target financial institutions not for profit, but for population-scale intelligence**. For Kortnit, and for similar organizations, the risks extend far beyond immediate financial loss:
**•	Infrastructure exposure:** A single unpatched framework can compromise even a mature security program.
**•	Subdomain sprawl:** Large, distributed infrastructures create discovery opportunities for adversaries. Forgotten or misconfigured endpoints can be exploited.
**•	Third-party trust:** Reliance on cloud, CDN, or SaaS providers extends the attack surface beyond direct oversight.
**•	Data risk:** If compromised, customer records may not simply be monetized but could be integrated into larger intelligence campaigns like the “shadow census.”

## Risk Implications
**•	Forgotten assets = open doors:** Any misconfigured or legacy subdomain can provide a stealthy entry point.
**•	Vendor risk inheritance:** A breach in any third-party provider effectively becomes a breach of the organization.
**•	Weaponized metadata:** SSL certs, DNS entries, and employee patterns are sufficient for attackers to develop precise phishing or exploit attempts.
**•	Strategic exploitation:** Unlike criminals seeking fast monetization, APTs may sit quietly for months, harvesting data for integration into long-term projects like the “shadow census.”

# Executive Takeaway
The 2017 incident involving **Kortnit Financial Services** was not a routine data breach driven by profit-motivated cybercrime. It was part of a **state-sponsored intelligence campaign** carried out by members of China’s People’s Liberation Army. Attackers exploited a single unpatched web framework, maintained stealthy access for months, and exfiltrated the personal and financial records of ~147 million individuals.

Critically, this data was not sold on underground markets. Instead, it was integrated into a **“shadow census”**-a vast intelligence dataset built by combining Kortnit’s financial records with data from other landmark breaches (OPM, Anthem, Marriott). The result was a near-complete profile of U.S. citizens at scale, including identity, health, travel, and financial dimensions.

For organizations like Kortnit, this incident illustrates that **the threat landscape extends beyond financial loss into geopolitical risk**. Even seemingly routine technical exposures-forgotten subdomains, unpatched services, or third-party dependencies—can become entry points for adversaries operating with patience, stealth, and strategic intent.

# Recommendations
Based on the reconnaissance findings, the following steps are recommended to further strengthen Kortnit Financial Services’ security posture:
## 1.	Subdomain and Host Monitoring
a.	Regularly scan for forgotten or outdated subdomains.
b.	Decommission unused hosts to reduce the attack surface.
## 2.	Third-Party Dependency Review:
a.	Audit contracts and security guarantees with providers such as Google Cloud, Akamai, and Salesforce.
b.	Implement vendor risk management to ensure compliance with Equifax’s security standards.
## 3.	Encryption Upgrades:
a.	While TLSv1.2 is secure, migration to **TLSv1.3** is encouraged to adopt stronger, more modern encryption.
## 4.	Continuous OSINT Monitoring:
a.	Automate Google Dorks and Harvester queries on a scheduled basis to detect potential credential leaks or misconfigurations early.
## 5.	Proactive Threat Hunting:
a.	Utilize Shodan and similar tools periodically to identify exposed services or misconfigured systems before attackers do.
## 6.	Employee Awareness & Training:
a.	Educate staff on social engineering threats, as reconnaissance data can be leveraged in phishing or targeted attacks.

# Conclusion
Kortnit Financial Services has implemented strong **encryption (HTTPS)** and relies on **security-focused partners** (Akamai, Salesforce). However, **its scale and complexity** inherently broaden the attack surface. This reinforces the need for:
•	Continuous monitoring of subdomains and hosts.
•	Vendor risk assessments and third-party audits.
•	Automated OSINT monitoring to detect exposures early.
•	Employee phishing awareness training.
Kortnit Financial Services remains a **high-value target**. Preventing a repeat of 2017 requires a proactive stance on visibility, patching, and early detection.

# End of Report


