# ASPHelpParser(AHP)

Burp Suite Extension for Parsing request from asp.net `/Help` page.

AHP automates the tedious task of extracting API endpoint details from the default ASP.NET Web API Help Page (/Help) and converting them into usable requests directly within Burp Suite.

# 📦 Installation

1. Download Burp Suite
    - Get the latest version from: [PortSwigger Burp Suite](http://portswigger.net/burp/download.html)
2. Download Jython Standalone JAR
    - Obtain the Jython standalone JAR from: [Jython Downloads](http://www.jython.org/download.html)
3. Configure Python Environment in Burp
    - Go to Extender → Options → Python Environment.
    - Select the downloaded Jython standalone JAR.
4. Clone Tripwire
```bash
git clone https://github.com/7imbitz/AHP.git
```
5. Load Extension
    - In Burp, navigate to Extender → Extensions → Add.
    - Choose the extension.py file from the ASPHelpParser(AHP) source code.
6. Verify Installation
    - A new AHP tab should appear in Burp Suite.

# 🛠 User Guide

1. Initial State
- Upon installation, the AHP tab will appear in Burp Suite.
- The tab will be empty by default until a relevant request is parsed.

2. Locate API Help Page
- Navigate to Proxy → HTTP History.
- Identify the target ASP.NET Web API help page request (commonly ending with /Help).

3. Send Request to Extension
- Right-click the identified request (either in the request viewer or HTTP history log).
- Select Extensions → ASPHelpParser → Send to AHP.

4. Parsed Output
- The parsed request details will be displayed in the AHP tab for review.

5. Further Actions
- Within the AHP tab, you can right-click on a parsed log entry and choose "Send Crafted Request to Repeater",
or use the configured keyboard shortcut to forward the crafted request directly to Burp Repeater.