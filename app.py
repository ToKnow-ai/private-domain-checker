from flask import Flask, request, send_from_directory
import dns.resolver
import socket
import requests
from urllib.parse import urlparse
import dns.resolver
import socket
import platform
import subprocess
from shutil import which

app = Flask(__name__)
unsupported_TLDs = [
    {
        "tld": '.ly',
        "try": "https://reg.ly/ly-domain/"
    }
]

@app.route('/')
def index():
    """Route handler for the home page"""
    try:
        return send_from_directory('.', 'index.html')
    except Exception as e:
        return str(e)

@app.route('/check/<domain>', methods=['POST'])
def check_domain(domain: str):
    """Check domain availability"""
    try:
        domain = domain.lower().strip('/').strip()
        if '://' in domain:
            domain = urlparse(domain).netloc

        for unsupported_TLD in unsupported_TLDs:
            if domain.endswith(unsupported_TLD.get('tld', '')):
                return { 
                    'domain': domain, 
                    "available": False, 
                    "method": f"Unsupported TLD, try at {unsupported_TLD.get('try')}"
                }

        result = check_domain_availability(domain)
        if result:
            return { 
                "domain": domain,
                "method": f"Checked via {result['method']}",
                "available": result['available'] 
            }
    except:
        pass
    return { 
        'domain': domain, 
        "available": False, 
        "method": "Cannot confirm if doimain is available"
    }

def check_domain_availability(domain):
    """Check domain availability using multiple methods."""
    # First try DNS resolution
    is_available, availability_method, _continue = dns_is_available(domain)
    if not _continue:
        return { "available": is_available, "method": f"DNS:{availability_method}" }
    
    # Try RDAP
    is_available, availability_method, _continue = rdap_is_available(domain)
    if not _continue:
        return { "available": is_available, "method": f"RDAP:{availability_method}" }

    # Fall back to WHOIS
    is_available, availability_method, _continue = whois_is_available(domain)
    if not _continue:
        return {"available": is_available, "method": f"WHOIS:{availability_method}"}

def dns_is_available(domain):
    """Check if domain exists in DNS by looking for common record types."""
    # Check NS records first as they're required for valid domains
    for record_type in ['NS', 'A', 'AAAA', 'MX', 'CNAME']:
        try:
            dns.resolver.resolve(domain, record_type)
            return False, record_type, False
        except:
            continue
    return True, None, True

def rdap_is_available(domain):
    try:
        bootstrap_url = "https://data.iana.org/rdap/dns.json"
        bootstrap_data = requests.get(bootstrap_url, timeout=5).json()
        tld = domain.split('.')[-1]
        services: list[tuple[list[str], list[str]]] = bootstrap_data['services']
        for [tlds, rdap_base_urls] in services:
            if tld in tlds:
                for rdap_base_url in rdap_base_urls:
                    response = requests.get(
                        f"{rdap_base_url.lstrip('/')}/domain/{domain}", timeout=5)
                    if response.status_code == 404:
                        return True, rdap_base_url, False
                    elif response.status_code == 200:
                        return False, rdap_base_url, False
    except:
        pass
    return False, None, True

def whois_is_available(domain) -> bool:
    try:
        available_patterns = [
            'no match',
            'not found',
            'no entries found',
            'no data found',
            'not registered',
            'available',
            'status: free',
            'domain not found'
        ]
        is_available_callback = lambda output: any(pattern in output for pattern in available_patterns)
        is_available, availability_method = socket_whois_is_available(domain, is_available_callback)
        if is_available:
            return True, availability_method, False
        is_available, availability_method = terminal_whois_is_available(domain, is_available_callback)
        if is_available:
            return True, availability_method, False
    except:
        pass
    return False, None, True

def socket_whois_is_available(domain, is_available_callback):
    try:
        whois_server = get_whois_server(domain)
        whois_server = "whois.reg.ly"

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((whois_server, 43))
        sock.send(f"{domain}\r\n".encode())
        response = sock.recv(4096).decode(errors='ignore')
        sock.close()
        
        response_lower = response.lower()
        return is_available_callback(response_lower), whois_server
    except:
        pass
    return False, None

def terminal_whois_is_available(domain, is_available_callback):
    try:
        # Check if OS is Linux
        if platform.system().lower() == 'linux':
            if which('whois') is not None:
                # Run whois command with timeout
                process = subprocess.Popen(
                    ['whois', domain], 
                    stdout=subprocess.PIPE, 
                    stderr=subprocess.PIPE)
                try:
                    stdout, _ = process.communicate(timeout=60)
                    output = stdout.decode('utf-8', errors='ignore').lower()
                    return is_available_callback(output), "system whois"
                except subprocess.TimeoutExpired:
                    process.kill()
    except:
        pass
    return False, None

def get_whois_server(domain):
    """Get WHOIS server from IANA root zone database."""
    try:
        response = requests.get(f'https://www.iana.org/whois?q={domain}')
        if 'whois:' in response.text.lower():
            for line in response.text.split('\n'):
                if 'whois:' in line.lower():
                    return line.split(':')[1].strip()
    except:
        pass
    return None