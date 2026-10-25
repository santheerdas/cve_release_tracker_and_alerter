import sys
import subprocess
import os
import json
import datetime
import re

# Verify and install dependencies dynamically
try:
    import requests
    from dotenv import load_dotenv
except ImportError:
    print("Required packages missing. Installing from requirements.txt...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
    import requests
    from dotenv import load_dotenv

# Load variables from the .env file
load_dotenv()

TELEGRAM_BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')
TELEGRAM_CHAT_ID = os.getenv('TELEGRAM_CHAT_ID')
STATE_FILE = os.getenv('STATE_FILE', 'processed_cves.json')

def load_processed_cves():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, 'r') as f:
            return json.load(f)
    return []

def save_processed_cve(cve_id, processed_list):
    processed_list.append(cve_id)
    with open(STATE_FILE, 'w') as f:
        json.dump(processed_list[-1000:], f)

def get_affected_product(cve, description):
    # 1. Try to get the product from NIST's analyzed CPE configurations
    configurations = cve.get('configurations', [])
    for config in configurations:
        for node in config.get('nodes', []):
            for match in node.get('cpeMatch', []):
                criteria = match.get('criteria', '')
                if criteria.startswith('cpe:2.3:') and len(criteria.split(':')) >= 5:
                    return criteria.split(':')[4].capitalize()
                        
    # 2. If no CPEs exist, try to check the CNA's 'affected' data if provided
    for affected_item in cve.get('affected', []):
        product = affected_item.get('product')
        if product and product.lower() not in ["n/a", "unknown"]:
            return product.capitalize()
            
    # 3. Regex Fallback: Extract the first word from the description
    if description and description != "No description available.":
        # Remove leading "The " or "A " for cleaner extraction
        clean_desc = re.sub(r'^(The|A|An)\s+', '', description, flags=re.IGNORECASE)
        # Capture the first sequence of letters, numbers, or hyphens
        match = re.match(r'^([a-zA-Z0-9\-]+)', clean_desc)
        if match:
            extracted_word = match.group(1)
            source = cve.get('sourceIdentifier', 'CNA').split('@')[-1]
            return f"{extracted_word.capitalize()} (Unverified / {source})"
            
    # 4. Final Fallback
    source_identifier = cve.get('sourceIdentifier', 'Unknown CNA')
    return f"Pending Analysis (CNA: {source_identifier})"

def send_telegram_alert(cve_id, product, description, score):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    message = f"🚨 *High Severity Vulnerability: {cve_id}*\n*Product:* {product}\n*Score:* {score}\n\n*Details:*\n{description}"
    payload = {'chat_id': TELEGRAM_CHAT_ID, 'text': message, 'parse_mode': 'Markdown'}
    requests.post(url, data=payload)

def fetch_recent_cves():
    now = datetime.datetime.now(datetime.timezone.utc)
    
    start_date = (now - datetime.timedelta(days=2)).isoformat(timespec='milliseconds').replace('+00:00', 'Z')
    end_date = now.isoformat(timespec='milliseconds').replace('+00:00', 'Z')
    
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate={start_date}&pubEndDate={end_date}"
    response = requests.get(url)
    
    if response.status_code != 200:
        print(f"API Request failed with status code {response.status_code}")
        return
        
    data = response.json()
    processed_cves = load_processed_cves()
    
    for item in data.get('vulnerabilities', []):
        cve = item.get('cve', {})
        cve_id = cve.get('id')
        
        if cve_id in processed_cves:
            continue
            
        metrics = cve.get('metrics', {})
        cvss = metrics.get('cvssMetricV31', metrics.get('cvssMetricV30', []))
        
        if cvss:
            score = cvss[0].get('cvssData', {}).get('baseScore', 0)
            if score > 7.5:
                descriptions = cve.get('descriptions', [])
                english_desc = next((d['value'] for d in descriptions if d['lang'] == 'en'), "No description available.")
                
                # Pass the description to the updated function
                product_name = get_affected_product(cve, english_desc)
                
                send_telegram_alert(cve_id, product_name, english_desc, score)
                save_processed_cve(cve_id, processed_cves)

if __name__ == "__main__":
    fetch_recent_cves()
