# HELLCAT Practical Initial Access Guide for Red Teams
This guide is a modified version of an original playbook exclusively used by the HELLCAT ransomware group. The original material was written from an offensive, threat actor perspective, detailing real-world attack methodologies.

This version has been restructured for ethical red team education, with all techniques presented strictly for security research purposes. It covers the full attack lifecycle: reconnaissance, exploitation, C2 infrastructure, lateral movement, persistence, evasion techniques, and includes real-world case studies (including walkthroughs of the Pinger.com and Indonesian government breaches).

Important: All content is provided for educational use only. Unauthorized penetration testing is illegal.

## Table of Contents  
1. Resources  
2. Walkthroughs (Including the Pinger.com Breach)  
3. Case Study: Indonesian Government Ransomware Attack 
4. C2 Infrastructure Setup  
5. Persistence Techniques  
6. Targeted Attack Methodologies  
7. Network Pivoting Fundamentals  
8. Operational Security: Reducing Footprint  
9. Command Cheat Sheet 

## 1. Resources

### CVE Databases:
- MITRE CVE Database  
- National Vulnerability Database (NVD)  
- Exploit Database (Exploit-DB)  

### Security News Platforms:
- Search LinkedIn for 'rce cve'  
- Follow sites like:  
  - BleepingComputer  
  - ThreatPost  
  - The Hacker News  
- Newsletters:  
  - Cybersecurity Insiders  
  - DarkReading  

### Vendor Security Advisories:
- Monitor advisories from:  
  - Microsoft  
  - Cisco  
  - Adobe  
  - Other major vendors  

### Tools:
#### Find New CVEs:
- LinkedIn  
- YouTube ("CVE")  
- Google ("rce cve")  

#### Find Vulnerable Hosts:
- en.fofa.info (3000 free credits per new account - use new Tor circuit)  
- leakix.net  
- shodan.io  
- censys.io  

#### Find Exploit Scripts:
- github.com  
- sploitus.com  
- 0day.today  

### Researching Proof-of-Concept (PoC) Exploits:
#### Platforms:
- GitHub repositories (search "PoC CVE-xxxx-xxxx")  
- Exploit-DB (use advanced search)  
- Packet Storm Security  

#### Evaluating PoCs:
- **Authenticity**: Verify through trusted platforms/community feedback  
- **Replicability**: Test in controlled, isolated environment  
- **Complexity**: Analyze prerequisites (privileges/configurations)  

#### Key Tools:
- Metasploit Framework (exploit testing)  
- Python/scripting knowledge (for PoC modification)  
