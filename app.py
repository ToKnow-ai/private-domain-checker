from flask import Flask, request, send_from_directory
import dns.resolver
import socket
import requests
from urllib.parse import urlparse
import dns.resolver
import socket

app = Flask(__name__)

@app.route('/')
def index():
    """Route handler for the home page"""
    try:
        return send_from_directory('.', 'index.html')
    except Exception as e:
        return str(e)

@app.route('/check', methods=['POST'])
def check_domain():
    """Check domain availability"""
    try:
        domain = request.json.get('domain', '').strip().lower().strip('/')
        if '://' in domain:
            domain = urlparse(domain).netloc
        result = check_domain_availability(domain) or {}
        return {
            "domain": domain,
            "available": result.get("available"),
            "method": result.get("method", None),
            "error": result.get("error", None)
        }
    except Exception as e:
        return { "domain": domain, "error": str(e) }

def check_domain_availability(domain):
    """Check domain availability using multiple methods."""
    # First try DNS resolution
    dns_exists, record_type = check_dns_records(domain)
    if dns_exists:
        return { "available": False, "method": f"DNS:{record_type}" }
    
    # Try RDAP
    rdap_status_code, rdap_base_url = check_rdap_records(domain)
    if rdap_status_code == 404:
        return { "available": True, "method": f"RDAP:{rdap_base_url}" }
    elif rdap_status_code == 200:
        return { "available": False, "method": f"RDAP:{rdap_base_url}" }

    # Fall back to WHOIS
    whois_server = get_whois_server(domain)
    if whois_server and no_whois_records(domain, whois_server):
        return {"available": True, "method": f"WHOIS:{whois_server}"}
    
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

def check_dns_records(domain):
    """Check if domain exists in DNS by looking for common record types."""
    # Check NS records first as they're required for valid domains
    for record_type in ['NS', 'A', 'AAAA', 'MX', 'CNAME']:
        try:
            dns.resolver.resolve(domain, record_type)
            return True, record_type
        except:
            continue
    return False, None

def check_rdap_records(domain):
    try:
        bootstrap_url = "https://data.iana.org/rdap/dns.json"
        bootstrap_data = requests.get(bootstrap_url, timeout=5).json()
        
        tld = domain.split('.')[-1]
        rdap_base_url = None
        
        for service in bootstrap_data['services']:
            if tld in service[0]:
                rdap_base_url = service[1][0].strip('/')
                break
        
        if rdap_base_url:
            rdap_url = f"{rdap_base_url}/domain/{domain}"
            response = requests.get(rdap_url, timeout=5)
            return response.status_code, rdap_base_url
    except:
        pass
    return None, None

def no_whois_records(domain, whois_server) -> bool:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((whois_server, 43))
        sock.send(f"{domain}\r\n".encode())
        response = sock.recv(4096).decode(errors='ignore')
        sock.close()
        
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
        
        response_lower = response.lower()
        for pattern in available_patterns:
            if pattern in response_lower:
                return True
    except:
        pass
    return False