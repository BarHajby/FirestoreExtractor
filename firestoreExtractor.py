import os
import json
import requests
import random
import string
from tabulate import tabulate
from colorama import init, Fore, Style

# Initialize colorama
init()

# ASCII Art and Banner
def show_banner():
    banner = f"""
{Fore.RED}
#    _____ _               _                 _____      _                  _             
#   |  ___(_)_ __ ___  ___| |_ ___  _ __ ___| ____|_  _| |_ _ __ __ _  ___| |_ ___  _ __ 
#   | |_  | | '__/ _ \/ __| __/ _ \| '__/ _ \  _| \ \/ / __| '__/ _` |/ __| __/ _ \| '__|
#   |  _| | | | |  __/\__ \ || (_) | | |  __/ |___ >  <| |_| | | (_| | (__| || (_) | |   
#   |_|   |_|_|  \___||___/\__\___/|_|  \___|_____/_/\_\\__|_|  \__,_|\___|\__\___/|_|   
{Style.RESET_ALL}
{Fore.CYAN}FirestoreExtractor - Firestore Pentesting Tool - Use with permission to do so, and caution!{Style.RESET_ALL}
{Fore.YELLOW}Version 1.0 | By Bar Hajby{Style.RESET_ALL}
"""
    print(banner)

# Constants
COMMON_COLLECTIONS = [
    "users", "accounts", "profiles", "admins", "admin", "staff",
    "messages", "notifications", "posts", "orders", "transactions", "sessions",
    "products", "items", "inventory", "cart", "carts", "payments", "logs",
    "feedback", "reviews", "tickets", "comments", "products", "chats", "inbox",
    "config", "settings", "clients", "leads", "documents", "reports", "forms"
]

SENSITIVE_KEYWORDS = [
    'api', 'key', 'secret', 'token', 'auth', 'password', 'credential',
    'private', 'cert', 'ssh', 'gpg', 'jwt', 'oauth', 'bearer', 'access',
    'refresh', 'session', 'cookie', 'database', 'connection', 'url',
    'endpoint', 'config', 'setting', 'certificate', 'pem', 'rsa', 'dsa',
    'keystore', 'truststore', 'jks', 'pkcs', 'p12', 'pfx', 'pem', 'der',
    'conf', 'cfg', 'cred', 'login', 'pass', 'pwd', 'account', 'user'
]

SENSITIVE_FILE_EXTENSIONS = [
    '.pdf', '.csv', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.pem', '.key', '.cer', '.crt', '.der', '.p12', '.pfx', '.jks',
    '.json', '.xml', '.yml', '.yaml', '.conf', '.cfg', '.env', '.sh',
    '.bash', '.zsh', '.history', '.log', '.bak', '.backup', '.dump'
]

# Helper Functions
def ask_input(prompt_text, default=None):
    if default:
        return default
    user_input = input(f"{Fore.WHITE}{Style.BRIGHT}{prompt_text}{Style.RESET_ALL} ")
    return user_input.strip()

def build_headers(token=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers

def get_proxies(use_proxy):
    return {
        "http": "http://127.0.0.1:8080",
        "https": "http://127.0.0.1:8080"
    } if use_proxy else {}

def icon(val):
    if "accessible" in val or "successful" in val:
        return f"{Fore.GREEN}✅{Style.RESET_ALL}"
    elif "not tested" in val:
        return f"{Fore.YELLOW}➖{Style.RESET_ALL}"
    else:
        return f"{Fore.RED}❌{Style.RESET_ALL}"

# Core Functions
def get_config():
    print(f"\n{Fore.BLUE}[*] FirestoreDumper Setup{Style.RESET_ALL}\n")
    config = {}
    config['project_id'] = ask_input("Enter Firebase project ID or full Firestore URL (e.g. project-id or https://project-id.firebaseio.com):")
    config['auth_token'] = ask_input("Enter Firebase Auth token (press enter if unauthenticated):")
    hardcoded = ask_input("Enter comma-separated collection names to try (optional):")
    config['collections'] = [x.strip() for x in hardcoded.split(",")] if hardcoded else []
    wordlist_path = ask_input("Path to wordlist for brute-forcing collections (optional):")
    config['wordlist_path'] = wordlist_path if os.path.exists(wordlist_path) else None
    use_burp = ask_input("Route all traffic through BurpSuite at http://127.0.0.1:8080? (y/N):").lower()
    config['use_proxy'] = use_burp == 'y'
    print(f"\n{Fore.BLUE}[*] Summary of provided configuration:{Style.RESET_ALL}")
    print(json.dumps(config, indent=2))
    return config

def build_collection_list(hardcoded, wordlist_path):
    collections = set(COMMON_COLLECTIONS)
    collections.update(hardcoded)
    if wordlist_path:
        try:
            with open(wordlist_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        collections.add(line)
        except Exception as e:
            print(f"{Fore.RED}[!] Error reading wordlist: {e}{Style.RESET_ALL}")
    return list(collections)

def random_doc_name():
    return "__pentest__doc_" + ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))

def test_read(project_id, collection, token=None, use_proxy=False):
    url = f"https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/documents/{collection}"
    try:
        r = requests.get(url, headers=build_headers(token), proxies=get_proxies(use_proxy), verify=False)
        if r.status_code == 200:
            return "accessible", r.json()
        elif r.status_code == 403:
            return "access denied", None
        elif r.status_code == 404:
            return "not found", None
        else:
            return f"HTTP {r.status_code}", None
    except requests.exceptions.RequestException as e:
        return f"Request failed: {e}", None

def test_write(project_id, collection, token=None, use_proxy=False):
    url = f"https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/documents/{collection}"
    doc_id = random_doc_name()
    payload = {
        "fields": {
            "pentest": {"stringValue": "test"},
            "created": {"stringValue": "yes"}
        }
    }
    try:
        r = requests.post(url, headers=build_headers(token), proxies=get_proxies(use_proxy), verify=False, json=payload)
        if r.status_code == 200:
            doc_name = r.json().get("name")
            delete_success = test_delete(doc_name, token, use_proxy)
            return "write successful", doc_name if delete_success else "created (not deleted)"
        elif r.status_code == 403:
            return "access denied", None
        elif r.status_code == 404:
            return "not found", None
        else:
            return f"HTTP {r.status_code}", None
    except requests.exceptions.RequestException as e:
        return f"Request failed: {e}", None

def test_delete(doc_url, token=None, use_proxy=False):
    try:
        r = requests.delete(f"https://firestore.googleapis.com/v1/{doc_url}", headers=build_headers(token), proxies=get_proxies(use_proxy), verify=False)
        return r.status_code in [200, 204]
    except:
        return False

def detect_sensitive_data(collection_data):
    """Scan collection data for potential sensitive information"""
    findings = {
        'sensitive_fields': [],
        'possible_files': [],
        'high_entropy_values': []
    }

    if not collection_data or 'documents' not in collection_data:
        return findings

    for doc in collection_data['documents']:
        if 'fields' not in doc:
            continue

        # Check field names for sensitive keywords
        for field_name in doc['fields'].keys():
            lower_field = field_name.lower()
            for keyword in SENSITIVE_KEYWORDS:
                if keyword in lower_field:
                    findings['sensitive_fields'].append({
                        'document': doc.get('name', 'unknown'),
                        'field': field_name,
                        'value': str(doc['fields'][field_name])[:100] + '...'  # Truncate long values
                    })
                    break

        # Check for potential file references
        for field_name, field_value in doc['fields'].items():
            if 'stringValue' in field_value:
                value = field_value['stringValue']
                for ext in SENSITIVE_FILE_EXTENSIONS:
                    if ext in value.lower():
                        findings['possible_files'].append({
                            'document': doc.get('name', 'unknown'),
                            'field': field_name,
                            'value': value[:200]  # Truncate long values
                        })
                        break

    return findings

def print_summary_table(results):
    table = []
    headers = [f"{Fore.CYAN}Collection{Style.RESET_ALL}", 
               f"{Fore.CYAN}Unauth Read{Style.RESET_ALL}", 
               f"{Fore.CYAN}Unauth Write{Style.RESET_ALL}", 
               f"{Fore.CYAN}Auth Read{Style.RESET_ALL}", 
               f"{Fore.CYAN}Auth Write{Style.RESET_ALL}"]
    for entry in results:
        row = [
            entry["collection"],
            icon(entry.get("unauthenticated_read", "not tested")),
            icon(entry.get("unauthenticated_write", "not tested")),
            icon(entry.get("authenticated_read", "not tested")),
            icon(entry.get("authenticated_write", "not tested")),
        ]
        table.append(row)
    print(f"\n{Fore.BLUE}📊 Collection Access Summary:{Style.RESET_ALL}\n")
    print(tabulate(table, headers=headers, tablefmt="grid"))

def prompt_and_dump_accessible_data(results, config):
    available = [r['collection'] for r in results if r.get('unauthenticated_read') == 'accessible' or r.get('authenticated_read') == 'accessible']
    if not available:
        print(f"\n{Fore.YELLOW}[!] No readable collections found to dump.{Style.RESET_ALL}")
        return

    print(f"\n{Fore.BLUE}[?] The following collections are readable:{Style.RESET_ALL}")
    for name in available:
        print(f" - {name}")

    selected = ask_input("Enter comma-separated names of collections to dump (or 'all'): ")
    to_dump = available if selected.strip().lower() == 'all' else [x.strip() for x in selected.split(',') if x.strip() in available]

    for collection in to_dump:
        token = config.get('auth_token') if any(r for r in results if r['collection'] == collection and r.get('authenticated_read') == 'accessible') else None
        status, data = test_read(config['project_id'], collection, token, config['use_proxy'])
        
        if data:
            # Save raw data
            with open(f"{collection}.json", "w") as f:
                json.dump(data, f, indent=2)
            print(f"{Fore.GREEN}[+] Dumped {collection} to {collection}.json{Style.RESET_ALL}")
            
            # Scan for sensitive data
            findings = detect_sensitive_data(data)
            
            # Report findings
            if findings['sensitive_fields'] or findings['possible_files']:
                print(f"\n{Fore.RED}🔐 Sensitive Data Findings in {collection}:{Style.RESET_ALL}")
                
                if findings['sensitive_fields']:
                    print(f"\n{Fore.YELLOW}[!] Potential Credential Fields:{Style.RESET_ALL}")
                    for item in findings['sensitive_fields']:
                        print(f" - Document: {item['document'].split('/')[-1]}")
                        print(f"   Field: {Fore.RED}{item['field']}{Style.RESET_ALL}")
                        print(f"   Value: {item['value']}\n")
                
                if findings['possible_files']:
                    print(f"\n{Fore.YELLOW}[!] Potential File References:{Style.RESET_ALL}")
                    for item in findings['possible_files']:
                        print(f" - Document: {item['document'].split('/')[-1]}")
                        print(f"   Field: {item['field']}")
                        print(f"   Value: {Fore.BLUE}{item['value']}{Style.RESET_ALL}\n")
                
                # Save findings to separate file
                with open(f"{collection}_findings.json", "w") as f:
                    json.dump(findings, f, indent=2)
                print(f"{Fore.GREEN}[+] Findings saved to {collection}_findings.json{Style.RESET_ALL}")
            else:
                print(f"{Fore.GREEN}[+] No obvious sensitive data found in {collection}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[-] Could not dump data from {collection}{Style.RESET_ALL}")

def brute_force_collections(config):
    print(f"\n{Fore.BLUE}[*] Starting collection brute-force...{Style.RESET_ALL}\n")
    results = []
    escalation_collections = []
    all_collections = build_collection_list(config['collections'], config['wordlist_path'])
    for collection in all_collections:
        print(f"{Fore.WHITE}[*] Checking collection: {collection}{Style.RESET_ALL}")
        result = {"collection": collection}
        for mode in ["unauthenticated", "authenticated"]:
            token = None if mode == "unauthenticated" else config.get("auth_token")
            if mode == "authenticated" and not token:
                result[f"{mode}_read"] = "not tested"
                result[f"{mode}_write"] = "not tested"
                continue
            read_status, _ = test_read(config['project_id'], collection, token, config['use_proxy'])
            write_status, doc_url = test_write(config['project_id'], collection, token, config['use_proxy'])
            print(f"    [{mode}] Read : {read_status}")
            print(f"    [{mode}] Write: {write_status}")
            result[f"{mode}_read"] = read_status
            result[f"{mode}_write"] = write_status
            result[f"{mode}_sample_doc"] = doc_url if "http" in str(doc_url) else None
            if collection.lower() == "users" and "write successful" in write_status:
                escalation_collections.append(mode)
        results.append(result)
    print_summary_table(results)
    return results, escalation_collections

if __name__ == "__main__":
    show_banner()
    requests.packages.urllib3.disable_warnings()
    config = get_config()
    brute_force_results, escalation_hits = brute_force_collections(config)
    with open("discovered_collections.json", "w") as f:
        json.dump(brute_force_results, f, indent=2)
    print(f"\n{Fore.BLUE}[*] Brute-force complete. Results saved to discovered_collections.json{Style.RESET_ALL}")
    if escalation_hits:
        print(f"\n{Fore.RED}[!] 🔥 Potential Privilege Escalation Detected!{Style.RESET_ALL}")
        print("    'users' collection is writable in the following contexts:")
        for mode in escalation_hits:
            print(f"    - {mode}")
        print("    ➤ Try modifying roles, permissions, or elevating access via a crafted user document.")

    prompt_and_dump_accessible_data(brute_force_results, config)
