import random
from typing import Callable
from flask import Flask, send_from_directory
from urllib.parse import urlparse
import dns.resolver
import socket
import requests
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
    logs: list[str] = []
    try:
        domain = domain.lower().strip('/').strip()
        if '://' in domain:
            domain = urlparse(domain).netloc

        for unsupported_TLD in unsupported_TLDs:
            if domain.endswith(unsupported_TLD.get('tld', '')):
                return { 
                    'domain': domain, 
                    "available": False, 
                    "method": f"Unsupported TLD, try at {unsupported_TLD.get('try')}",
                    "logs": logs
                }

        result = check_domain_availability(domain, logs.append)
        if result:
            return { 
                "domain": domain,
                "method": f"Checked via {result['method']}",
                "available": result['available'],
                "logs": logs
            }
        logs.append(f"{check_domain.__name__}:result == None")
    except Exception as e:
        logs.append(f"{check_domain.__name__}:Exception:{str(e)}")
    return { 
        'domain': domain, 
        "available": False, 
        "method": "Cannot confirm if doimain is available",
        "logs": logs
    }

def check_domain_availability(domain, logs_append: Callable[[str], None]):
    """Check domain availability using multiple methods."""
    # First try DNS resolution
    is_available, availability_method, _continue = dns_is_available(domain, logs_append)
    if not _continue:
        return { "available": is_available, "method": f"DNS:{availability_method}" }
    
    # Try RDAP
    is_available, availability_method, _continue = rdap_is_available(domain, logs_append)
    if not _continue:
        return { "available": is_available, "method": f"RDAP:{availability_method}" }

    # Fall back to WHOIS
    is_available, availability_method, _continue = whois_is_available(domain, logs_append)
    if not _continue:
        return {"available": is_available, "method": f"WHOIS:{availability_method}"}

def dns_is_available(domain, logs_append: Callable[[str], None]):
    """Check if domain exists in DNS by looking for common record types."""
    # Check NS records first as they're required for valid domains
    try:
        resolver = get_dns_resolver()
        resolver_nameservers = resolver.nameservers
        for record_type in ['NS', 'A', 'AAAA', 'MX', 'CNAME']:
            resolver_nameservers = []
            try:
                resolver.resolve(domain, record_type)
                return False, record_type, False
            except Exception as e:
                logs_append(f"{dns_is_available.__name__}:{record_type}:Exception:{'|'.join(resolver_nameservers)}:{str(e)}")
    except Exception as e:
        logs_append(f"{dns_is_available.__name__}:Exception:{'|'.join(resolver_nameservers)}:{str(e)}")
    return True, None, True

def get_dns_resolver():
    # list of major DNS resolvers
    resolver = dns.resolver.Resolver()
    def myshuffle(ls):
        random.shuffle(ls)
        return ls
    namesevers = { 
        'cloudflare': myshuffle(['1.1.1.1', '1.0.0.1']),
        'google': myshuffle(['8.8.8.8', '8.8.4.4']),
        'quad9': myshuffle(['9.9.9.9', '149.112.112.112']),
        'opendns': myshuffle(['208.67.222.222', '208.67.220.220']),
        'adguard': myshuffle(['94.140.14.14', '94.140.15.15']),
        'nextdns': myshuffle(['45.90.28.167', '45.90.30.167']),
        'default': myshuffle(resolver.nameservers)
    }
    resolver.nameservers = random.choice(list(namesevers.values()))
    return resolver

def rdap_is_available(domain, logs_append: Callable[[str], None]):
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
        logs_append(f"{get_whois_server.__name__}:no RDAP")
    except Exception as e:
        logs_append(f"{rdap_is_available.__name__}:Exception:{str(e)}")
    return False, None, True

def whois_is_available(domain, logs_append: Callable[[str], None]) -> bool:
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
        is_available, availability_method = socket_whois_is_available(domain, is_available_callback, logs_append)
        if is_available:
            return True, availability_method, False
        is_available, availability_method = terminal_whois_is_available(domain, is_available_callback, logs_append)
        if is_available:
            return True, availability_method, False
    except Exception as e:
        logs_append(f"{whois_is_available.__name__}:Exception:{str(e)}")
    return False, None, True

def socket_whois_is_available(domain, is_available_callback: Callable[[str], bool], logs_append: Callable[[str], None]):
    try:
        whois_server = get_whois_server(domain, logs_append)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(4)
        sock.connect((whois_server, 43))
        sock.send(f"{domain}\r\n".encode())
        response = sock.recv(4096).decode(errors='ignore')
        sock.close()
        
        response_lower = response.lower()
        return is_available_callback(response_lower), whois_server
    except Exception as e:
        logs_append(f"{socket_whois_is_available.__name__}:whois_server:{whois_server}")
        logs_append(f"{socket_whois_is_available.__name__}:Exception:{str(e)}")
    return False, None

def terminal_whois_is_available(domain, is_available_callback: Callable[[str], bool], logs_append: Callable[[str], None]):
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
                    stdout, stderr = process.communicate(timeout=10)
                    output = stdout.decode('utf-8', errors='ignore').lower()
                    logs_append(f"{terminal_whois_is_available.__name__}:stderr:{str(stderr.decode(encoding='utf-8'))}")
                    return is_available_callback(output), "system whois"
                except subprocess.TimeoutExpired as timeout_e:
                    logs_append(f"{terminal_whois_is_available.__name__}:TimeoutExpired:{str(timeout_e)}")
                    process.kill()
            else:
                logs_append(f"{terminal_whois_is_available.__name__}:Exception:WHOIS not installed. Install with: sudo apt-get install whois")
        else:
            logs_append(f"{terminal_whois_is_available.__name__}:Exception:System WHOIS check only available on Linux")
    except Exception as e:
        logs_append(f"{terminal_whois_is_available.__name__}:Exception:{str(e)}")
    return False, None

def get_whois_server(domain, logs_append: Callable[[str], None]):
    """Get WHOIS server from IANA root zone database."""
    try:
        response = requests.get(f'https://www.iana.org/whois?q={domain}')
        if 'whois:' in response.text.lower():
            for line in response.text.split('\n'):
                if 'whois:' in line.lower():
                    return line.split(':')[1].strip()
    except Exception as e:
        logs_append(f"{get_whois_server.__name__}:Exception:{str(e)}")
    return None