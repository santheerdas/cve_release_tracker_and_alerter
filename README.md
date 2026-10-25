# NVD CVE Telegram Alerter

**Overview**
An automated Python script that polls the National Vulnerability Database (NVD) API for newly published, high-severity vulnerabilities (CVSS > 7.5) and delivers real-time formatted alerts directly to a Telegram chat.

**How It Works**
1. **Time-Window Polling:** The script calculates a 48-hour rolling window using timezone-aware UTC datetime objects and queries the NVD API for recent publications.
2. **State Management:** Fetched CVE IDs are cross-referenced against a local JSON state file (`processed_cves.json`). Only new, unprocessed vulnerabilities proceed to the next step, preventing duplicate notifications across multiple daily runs.
3. **Severity Filtering:** The API response is parsed to evaluate CVSS v3.0/v3.1 base scores. Any vulnerability scoring 7.5 or below is safely ignored.
4. **Smart Product Extraction:** To identify the affected software reliably, the script uses a three-tier cascading extraction logic:
    * **CPE Matching:** Attempts to parse the exact product name from NIST's official Common Platform Enumeration (CPE) configurations.
    * **CNA Fallback:** Checks the `affected` array provided early by the CVE Numbering Authority (CNA).
    * **Regex Extraction:** If the CVE is newly published and pending manual NIST analysis, the script cleans the description string (removing leading articles) and uses Regular Expressions to capture the primary software name, explicitly tagging it as Unverified alongside the CNA source domain.
5. **Notification & Logging:** A Markdown-formatted payload is pushed to the Telegram Bot API. The CVE ID is then appended to the local state file, which automatically rotates to keep only the 1,000 most recent records to optimize file size and performance.

**Prerequisites**
* Python 3.12+ (Handles deprecated naive datetime objects)
* Telegram Bot Token and Target Chat ID

**Configuration**
Create a `.env` file in the project directory:
```env
TELEGRAM_BOT_TOKEN=your_bot_token_here
TELEGRAM_CHAT_ID=your_chat_id_here
STATE_FILE=processed_cves.json

**Execution**
The script includes dynamic dependency resolution and will automatically install required packages (like requests and python-dotenv) from requirements.txt if they are missing.

Execute directly via Python or schedule using cron/Kubernetes:

#python3 cve_alerter.py
