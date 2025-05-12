import os
import sys
import threading
import socket
import ssl
import datetime
import traceback
import subprocess
import socketserver
from http.server import BaseHTTPRequestHandler
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import re
import json
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog, Listbox, Scrollbar, END
import requests
from requests.adapters import HTTPAdapter, Retry
from requests.cookies import RequestsCookieJar
from cryptography.x509 import load_pem_x509_certificate
from urllib.parse import urlparse, parse_qs # Added for URL parsing

# --- Configuration ---
CA_CERT_PATH = "ca.crt"
CA_KEY_PATH = "ca.key"
CERTS_DIR = "certs"
os.makedirs(CERTS_DIR, exist_ok=True)
DEFAULT_CERT_TTL_DAYS = 7
PROXY_HOST = '127.0.0.1'
PROXY_PORT = 8888

# --- Analysis Configuration ---
# Define a basic API pattern.
API_PATTERN = re.compile(
    r'/api/|/v[1-9][0-9]*/|/[a-zA-Z0-9_.-]+\.(json|xml|yaml)(\?.*)?$|service|endpoint|soap|rest'
)
# Keywords to look for indicating potential vulnerabilities or sensitive data
ANALYSIS_KEYWORDS = [
    "password", "token", "api_key", "secret", "auth", "credential",
    "error", "exception", "stack trace", "debug", "admin", "private",
    "jwt", "cookie", "session" # Added common terms
]

# Sensitive paths often requiring HTTPS
SENSITIVE_PATHS_PATTERN = re.compile(r'/login|/register|/signup|/account|/profile|/checkout|/payment|/admin', re.IGNORECASE)


# --- CA & Cert Management (Same as before - include your full functions here) ---
# ... (create_or_load_ca, open_ca_cert, is_cert_expired, generate_cert, get_cert_for_host, check_revocation_status)

# Assuming these functions are present from the previous code block:
def is_cert_expired(cert_path):
    try:
        with open(cert_path, 'rb') as f:
            cert_data = f.read()
            if not cert_data:
                return True
            cert = load_pem_x509_certificate(cert_data)
            return cert.not_valid_after < datetime.datetime.utcnow() + datetime.timedelta(days=1)
    except FileNotFoundError:
        return True
    except ValueError as e:
        print(f"[!] Error loading certificate {cert_path} for expiry check: {e}")
        return True

def create_or_load_ca():
    # ... (implementation from previous code)
    if os.path.exists(CA_CERT_PATH) and os.path.exists(CA_KEY_PATH):
        try:
            with open(CA_CERT_PATH, "rb") as f: ca_cert_data = f.read()
            if not ca_cert_data: raise ValueError("CA certificate file is empty.")
            loaded_ca_cert = x509.load_pem_x509_certificate(ca_cert_data)
            with open(CA_KEY_PATH, "rb") as f: ca_key_data = f.read()
            if not ca_key_data: raise ValueError("CA key file is empty.")
            loaded_ca_key = serialization.load_pem_private_key(ca_key_data, password=None)
            if loaded_ca_cert.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo) != loaded_ca_key.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo):
                 raise ValueError("CA certificate and key do not match.")
            if loaded_ca_cert.not_valid_after < datetime.datetime.utcnow():
                print("[!] Existing CA certificate has expired. Please delete ca.crt and ca.key to regenerate.")
                messagebox.showerror("CA Error", "Existing CA certificate has expired. Please delete ca.crt and ca.key and restart the application to regenerate the CA.")
                sys.exit(1)
            print("Loaded existing CA.")
            return loaded_ca_cert, loaded_ca_key
        except Exception as e:
            print(f"[!] Error loading existing CA: {e}. Will attempt to generate a new one after removing old files if they exist.")
            messagebox.showwarning("CA Load Error", f"Could not load existing CA files (ca.crt, ca.key): {e}. If they exist, they might be corrupted. Will try to regenerate.")
            try:
                if os.path.exists(CA_CERT_PATH): os.remove(CA_CERT_PATH)
                if os.path.exists(CA_KEY_PATH): os.remove(CA_KEY_PATH)
            except OSError as ose:
                print(f"[!] Error removing old CA files: {ose}")
                messagebox.showerror("CA Error", f"Error removing old CA files: {ose}. Please manually remove them and restart.")
                sys.exit(1)
    print("Generating new CA...")
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "MyProxy MITM CA")])
    ca_cert_builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(ca_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1)).not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650)).add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).add_extension(x509.KeyUsage(key_cert_sign=True, crl_sign=True, digital_signature=False, content_commitment=False, key_encipherment=False, data_encipherment=False, key_agreement=False, encipher_only=False, decipher_only=False), critical=True))
    new_ca_cert = ca_cert_builder.sign(ca_key, hashes.SHA256())
    with open(CA_CERT_PATH, "wb") as f: f.write(new_ca_cert.public_bytes(serialization.Encoding.PEM))
    with open(CA_KEY_PATH, "wb") as f: f.write(ca_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()))
    print("New CA generated.")
    messagebox.showinfo("CA Generated", "A new Certificate Authority (ca.crt) has been generated. You MUST install and trust this certificate in your browser/system to intercept HTTPS traffic.")
    return new_ca_cert, ca_key

ca_cert, ca_private_key = create_or_load_ca() # Ensure CA is loaded/created on startup

def open_ca_cert():
    ca_path = os.path.abspath(CA_CERT_PATH)
    if not os.path.exists(ca_path):
        messagebox.showerror("Error", f"CA certificate not found at {ca_path}. Try restarting the application to generate it.")
        return
    if sys.platform.startswith("win"):
        os.startfile(ca_path)
    elif sys.platform.startswith("darwin"):
        subprocess.run(["open", ca_path])
    elif sys.platform.startswith("linux"):
        subprocess.run(["xdg-open", ca_path])
    else:
        messagebox.showinfo("Trust CA", f"Please open and trust the CA certificate located at:\n{ca_path}\n\nRefer to your operating system and browser documentation for instructions on how to install and trust a root CA certificate.")
    show_trust_instructions(ca_path)

def generate_cert(hostname, ttl_days_param):
    print(f"[*] Generating certificate for {hostname} with TTL {ttl_days_param} days")
    not_before = datetime.datetime.utcnow() - datetime.timedelta(days=1)
    not_after = datetime.datetime.utcnow() + datetime.timedelta(days=int(ttl_days_param))

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject_name_attributes = [x509.NameAttribute(NameOID.COMMON_NAME, hostname)]
    try:
        encoded_hostname = hostname.encode('idna').decode('ascii')
        dns_name = x509.DNSName(encoded_hostname)
    except (UnicodeError, Exception) as e:
        print(f"[!] Warning: Could not IDNA encode hostname {hostname}: {e}. Using raw hostname.")
        dns_name = x509.DNSName(hostname)

    subject = x509.Name(subject_name_attributes)

    builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(ca_cert.subject).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(not_before).not_valid_after(not_after).add_extension(x509.SubjectAlternativeName([dns_name]), critical=False).add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=True, content_commitment=False, data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False), critical=True).add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False).add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False).add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()), critical=False))

    new_cert = builder.sign(ca_private_key, hashes.SHA256())

    cert_path = os.path.join(CERTS_DIR, f"{hostname}.pem")
    key_path = os.path.join(CERTS_DIR, f"{hostname}_key.pem")

    with open(cert_path, "wb") as f: f.write(new_cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as f: f.write(key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()))
    return cert_path, key_path

def get_cert_for_host(hostname, ttl_days_param):
    cert_path = os.path.join(CERTS_DIR, f"{hostname}.pem")
    key_path = os.path.join(CERTS_DIR, f"{hostname}_key.pem")

    if os.path.exists(cert_path) and os.path.exists(key_path):
        if not is_cert_expired(cert_path):
            return cert_path, key_path
        else:
            print(f"[*] Existing certificate for {hostname} is expired or nearing expiry. Regenerating.")
            try:
                os.remove(cert_path)
                os.remove(key_path)
            except OSError as e:
                 print(f"[!] Error removing old certificate files for {hostname}: {e}")
            return generate_cert(hostname, ttl_days_param)
    else:
        print(f"[*] No existing certificate for {hostname}. Generating new one.")
        return generate_cert(hostname, ttl_days_param)

def check_revocation_status(cert_obj):
    # Placeholder for OCSP/CRL checks
    pass

# --- Analysis Logic ---

def analyze_traffic_entry(entry):
    """
    Performs basic analysis on a single traffic entry, including potential
    vulnerability indicators.
    Flags potential API calls and adds findings to the entry.
    """
    entry['is_api'] = False
    entry['analysis_findings'] = []

    method = entry.get('method', '')
    path = entry.get('path', '')
    request_headers = entry.get('request_headers', {})
    response_status = entry.get('response_status')
    response_headers = entry.get('response_headers', {})
    url = entry.get('url', '') # Capture the full URL if available from forward_request

    # --- API Detection ---
    if path and API_PATTERN.search(path):
        entry['is_api'] = True
        entry['analysis_findings'].append("Matches API path pattern.")

    # Simple check for common API request/response headers
    content_type_req = request_headers.get('Content-Type', '').lower()
    accept_resp = response_headers.get('Content-Type', '').lower() # Check response content type too

    if 'json' in content_type_req or 'xml' in content_type_req or 'yaml' in content_type_req:
         entry['analysis_findings'].append(f"Request Content-Type indicates API: {request_headers.get('Content-Type', 'N/A')}")
         entry['is_api'] = True

    if 'json' in accept_resp or 'xml' in accept_resp or 'yaml' in accept_resp:
         entry['analysis_findings'].append(f"Response Content-Type indicates API: {response_headers.get('Content-Type', 'N/A')}")
         entry['is_api'] = True

    # --- Vulnerability Checks ---

    # 1. Insecure/Missing Response Headers
    security_headers = {
        'Strict-Transport-Security': False, # HSTS
        'Content-Security-Policy': False,   # CSP
        'X-Content-Type-Options': False,    # MIME-sniffing
        'X-Frame-Options': False,         # Clickjacking
        'Referrer-Policy': False,         # Referrer leakage
        'Permissions-Policy': False,      # Browser features access
        'X-XSS-Protection': False         # Basic XSS protection (partially deprecated by CSP)
    }
    for header, present in security_headers.items():
        if header in response_headers:
            security_headers[header] = True
        else:
            entry['analysis_findings'].append(f"Missing security header: {header}")

    if security_headers.get('Strict-Transport-Security') and url.startswith('http://'):
         entry['analysis_findings'].append("HSTS header sent over HTTP (ineffective).")

    # 2. Information Disclosure Headers
    info_disclosure_headers = ['Server', 'X-Powered-By', 'Via', 'X-AspNet-Version', 'X-AspNetMvc-Version']
    for header in info_disclosure_headers:
        if header in request_headers:
             entry['analysis_findings'].append(f"Information disclosure in request header: {header} = {request_headers[header][:50]}...")
        if header in response_headers:
            entry['analysis_findings'].append(f"Information disclosure in response header: {header} = {response_headers[header][:50]}...")

    # 3. Insecure Cookie Flags
    set_cookie_headers = response_headers.get('Set-Cookie', None)
    if set_cookie_headers:
        # 'Set-Cookie' can be a list or a single string depending on requests version/handling
        if isinstance(set_cookie_headers, str):
             set_cookie_headers = [set_cookie_headers]
        elif not isinstance(set_cookie_headers, list): # Handle other potential types
             set_cookie_headers = []

        for cookie_string in set_cookie_headers:
            # Basic parsing - just look for flags
            cookie_string_lower = cookie_string.lower()
            if 'httponly' not in cookie_string_lower:
                entry['analysis_findings'].append(f"Missing 'HttpOnly' flag in Set-Cookie: {cookie_string[:80]}...")
            if url.startswith('https://') and 'secure' not in cookie_string_lower:
                entry['analysis_findings'].append(f"Missing 'Secure' flag in Set-Cookie over HTTPS: {cookie_string[:80]}...")
            if 'samesite' not in cookie_string_lower:
                 # Note: Browsers default to Lax now, but explicit flag is better
                entry['analysis_findings'].append(f"Missing 'SameSite' flag in Set-Cookie: {cookie_string[:80]}...")

    # 4. Sensitive Data in URL (Path or Query String)
    if url: # Check the full URL
        parsed_url = urlparse(url)
        # Check path segments
        for segment in parsed_url.path.split('/'):
             if any(keyword in segment.lower() for keyword in ANALYSIS_KEYWORDS):
                  entry['analysis_findings'].append(f"Potential sensitive info in URL path segment: /{segment[:50]}...")

        # Check query parameters
        query_params = parse_qs(parsed_url.query)
        for param_name, param_values in query_params.items():
             param_name_lower = param_name.lower()
             if any(keyword in param_name_lower for keyword in ANALYSIS_KEYWORDS):
                  entry['analysis_findings'].append(f"Potential sensitive info in URL query parameter name: {param_name[:50]}...")
             for value in param_values:
                  if any(keyword in value.lower() for keyword in ANALYSIS_KEYWORDS):
                       entry['analysis_findings'].append(f"Potential sensitive info in URL query parameter value '{param_name[:50]}': {value[:50]}...")


    # 6. HTTP Usage for Sensitive Paths
    # This check is most relevant if the proxy is receiving direct HTTP requests
    # (not CONNECT tunnels, where the scheme is inferred later by requests)
    # Need to be careful how `url` is determined for HTTP requests
    # For requests received by the proxy over plain HTTP:
    # url starts with http://host + path
    # For requests received over an HTTPS tunnel (after CONNECT):
    # url is constructed by requests based on the request read from the TLS socket.
    # We'll perform this check if the inferred scheme is http and path matches sensitive pattern.
    inferred_scheme = 'https' if entry.get('method') == 'CONNECT' or url.startswith('https://') else 'http'

    if inferred_scheme == 'http' and SENSITIVE_PATHS_PATTERN.search(path):
         entry['analysis_findings'].append(f"Potential sensitive path accessed over HTTP: {path[:80]}...")


    # Add findings from the body analysis (called separately)
    # We won't call perform_body_analysis here in real-time for performance,
    # but findings from on-demand body analysis will be added to this list
    # if the user performs that action in the viewer.


    # Remove duplicate findings
    entry['analysis_findings'] = list(set(entry['analysis_findings']))


def perform_body_analysis(body_content, content_type=''):
    """
    Performs analysis on a specific request or response body.
    Can be called on-demand from the viewer.
    Returns a list of findings.
    """
    findings = []
    if not body_content:
        return findings

    # Try to decode body if it's bytes
    decoded_body = None
    if isinstance(body_content, bytes):
        try:
            # Attempt decoding based on content_type or common encodings
            charset_match = re.search(r'charset=([\w-]+)', content_type.lower())
            encoding = charset_match.group(1) if charset_match else 'utf-8'
            decoded_body = body_content.decode(encoding, errors='replace')
            # findings.append(f"Attempted decoding body with '{encoding}'.") # Too verbose
        except Exception as e:
             # findings.append(f"Failed to decode body: {e}") # Too verbose
             pass # Continue with potential raw byte checks or skip text analysis

    elif isinstance(body_content, str):
        decoded_body = body_content
        # findings.append("Body is already text.") # Too verbose

    if decoded_body:
        # Check for keywords in body (case-insensitive)
        body_lower = decoded_body.lower()
        for keyword in ANALYSIS_KEYWORDS:
            if keyword in body_lower:
                findings.append(f"Keyword '{keyword}' found in body text.")

        # Check for common error/stack trace patterns
        if re.search(r'(traceback|stack trace|exception|fatal error)', body_lower):
             findings.append("Body appears to contain an error message or stack trace.")

        # Check if body looks like JSON or XML and attempt parsing (basic)
        if 'json' in content_type.lower() or (decoded_body.strip().startswith('{') or decoded_body.strip().startswith('[')):
            try:
                json_data = json.loads(decoded_body)
                # findings.append("Body appears to be valid JSON.") # Too verbose
                # Look for keywords in JSON keys and string values
                def search_json(obj):
                    json_findings = []
                    if isinstance(obj, dict):
                        for key, value in obj.items():
                            if any(keyword in key.lower() for keyword in ANALYSIS_KEYWORDS):
                                json_findings.append(f"Potential sensitive key name '{key[:50]}...' in JSON.")
                            json_findings.extend(search_json(value)) # Recurse into value
                    elif isinstance(obj, list):
                        for item in obj:
                            json_findings.extend(search_json(item)) # Recurse into list items
                    elif isinstance(obj, str):
                         value_lower = obj.lower()
                         if any(keyword in value_lower for keyword in ANALYSIS_KEYWORDS):
                              json_findings.append(f"Keyword found in JSON string value: '{obj[:50]}...'")
                    return json_findings

                json_findings = search_json(json_data)
                findings.extend(json_findings)


            except json.JSONDecodeError:
                findings.append("Body looks like JSON but failed to parse.")
            except Exception as e:
                 findings.append(f"Error analyzing JSON body: {e}")

        elif 'xml' in content_type.lower() or (decoded_body.strip().startswith('<') and decoded_body.strip().endswith('>')):
             try:
                 # Basic check for XML structure and keywords
                 if "<" in decoded_body and ">" in decoded_body:
                      # findings.append("Body appears to be XML.") # Too verbose
                      xml_lower = decoded_body.lower()
                      for keyword in ANALYSIS_KEYWORDS:
                           if keyword in xml_lower:
                                findings.append(f"Keyword '{keyword}' found in XML body text.")
             except Exception as e:
                 findings.append(f"Error analyzing XML body: {e}")
        # Add other format checks (e.g., URL-encoded, multipart) as needed

    elif isinstance(body_content, bytes) and b"BINARY_DATA" in body_content:
        findings.append("Body contains binary data (not logged/analyzed).")
    elif isinstance(body_content, bytes):
         findings.append("Body is raw bytes (attempted decoding failed or skipped).")
         # You could add analysis for raw bytes here if applicable


    return list(set(findings)) # Remove duplicates from body findings

def run_batch_analysis():
    """
    Placeholder function to run analysis on all captured traffic.
    Currently, real-time analysis is done, but this could re-analyze or
    perform different checks.
    """
    global proxy_server
    if not proxy_server or not hasattr(proxy_server, 'traffic'):
        messagebox.showinfo("Analysis", "No traffic data captured yet.")
        return

    print("\n[*] Running batch analysis on all captured traffic...")
    analysis_summary = {
        'total_entries': len(proxy_server.traffic),
        'potential_api_calls': 0,
        'total_findings': 0
    }
    # Re-analyze all entries (optional, real-time is active)
    # for entry in proxy_server.traffic:
    #    analyze_traffic_entry(entry) # Re-run analysis

    # Collect summary info
    for entry in proxy_server.traffic:
        if entry.get('is_api'):
            analysis_summary['potential_api_calls'] += 1
        analysis_summary['total_findings'] += len(entry.get('analysis_findings', []))

    print("[*] Batch analysis finished.")
    print(f"    Total Entries: {analysis_summary['total_entries']}")
    print(f"    Potential API Calls: {analysis_summary['potential_api_calls']}")
    print(f"    Total Findings: {analysis_summary['total_findings']}")

    # Update GUI or show a summary report
    messagebox.showinfo("Analysis Summary",
                        f"Batch analysis complete.\n"
                        f"Total Entries: {analysis_summary['total_entries']}\n"
                        f"Potential API Calls: {analysis_summary['potential_api_calls']}\n"
                        f"Total Findings: {analysis_summary['total_findings']}")


# =================== Proxy Server with Traffic Tracking ===================
class TrafficLoggingServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    def __init__(self, server_address, RequestHandlerClass):
        super().__init__(server_address, RequestHandlerClass)
        self.traffic = []

# =================== Proxy Handler ===================
class ProxyHandler(BaseHTTPRequestHandler):
    def sanitize_headers(self, headers):
        sanitized = {}
        hop_by_hop_headers = [
            'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
            'te', 'trailers', 'transfer-encoding', 'upgrade', 'proxy-connection',
            'content-length',
            'expect',
        ]
        for key, value in headers.items():
            if key.lower() not in hop_by_hop_headers:
                sanitized[key] = value
        return sanitized

    def forward_request(self):
        # Ensure urlparse works correctly by having a scheme+host for self.path
        # BaseHTTPRequestHandler gives us the path component.
        # For HTTP, it's the full URL. For HTTPS tunnel, it's just the path component.
        # We reconstruct the URL for requests using the Host header.
        host = self.headers.get('Host', None)
        scheme = 'http' # Default for non-CONNECT requests received directly

        if self.path.startswith(('http://', 'https://')):
             url = self.path
             # Try to infer scheme for later analysis if path is absolute
             scheme = urlparse(url).scheme
        elif host:
             # For HTTPS CONNECT, self.path is host:port, this method isn't called.
             # This method is called for HTTP requests received directly by the proxy,
             # or for requests OVER an HTTPS tunnel AFTER the TLS wrapping.
             # If over an HTTPS tunnel, the original connection was HTTPS.
             # Need a way to track if this request came over an HTTPS tunnel.
             # A simple check could be if self.connection is an SSL socket, but
             # BaseHTTPRequestHandler abstracts that after replacing rfile/wfile.
             # A more robust way might pass a flag during the CONNECT handling.
             # For now, let's infer based on the original connection type (handled in do_CONNECT)
             # and assume this method is called for requests over that connection.
             # This is a simplification; accurately tracking the *original* scheme
             # for requests over a tunnel handled internally by BaseHTTPRequestHandler is complex.
             # A safer approach for analysis is to check if the current self.connection
             # is an SSLSocket (after wrapping), but this bypasses the BaseHTTPRequestHandler abstraction.
             # Let's add the 'url' field and try to populate it best effort.
             # For requests *after* CONNECT, the path will be relative, Host header present.
             # Requests library will handle the scheme/host based on the Session's internal state
             # established by the CONNECT call, but self.path remains relative.
             # Reconstructing the URL for logging/analysis needs the original scheme+host.

             # A possible workaround: In do_CONNECT, store the target host and port.
             # Access it here via self.server (if stored there).
             # Let's simplify for now: if it's a non-absolute path, assume the scheme
             # is http unless the originating connection context implies https (hard within BHRH).
             # We'll improve this URL/Scheme tracking for analysis.

             # *Correction*: For requests *over* a tunnel, the handler reads the full HTTP request line
             # from the wrapped socket. The path *is* the path component (e.g., `/index.html`).
             # The `Host` header is present. We need the original scheme (https) and host from CONNECT.
             # Let's add 'original_host' and 'original_scheme' to the handler instance during CONNECT.
             # Then use those here.

             # Temporarily adding placeholders based on self.server attributes set in do_CONNECT
             original_scheme = getattr(self, 'original_scheme', 'http') # Default to http
             original_host = getattr(self, 'original_host', host) # Use Host header if original_host not set
             original_port = getattr(self, 'original_port', (80 if original_scheme=='http' else 443)) # Use default port

             if original_host:
                 # Construct the URL using the original scheme, host, and the path
                 url = f"{original_scheme}://{original_host}:{original_port}{self.path}"
                 # Clean up default port if present
                 if (original_scheme == 'http' and original_port == 80) or (original_scheme == 'https' and original_port == 443):
                      url = f"{original_scheme}://{original_host}{self.path}"
             else:
                  print(f"[!] Could not determine original host for path {self.path}. URL construction may be inaccurate.")
                  url = self.path # Fallback, likely incomplete


        else:
             # No absolute path or Host header? Bad request.
            print(f"[!] Missing Host header or absolute path for request path: {self.path}")
            self.send_error(400, "Bad Request: Missing Host header or Invalid Path")
            request_info = {
                'timestamp': datetime.datetime.now().isoformat(),
                'method': self.command,
                'path': self.path,
                'request_headers': dict(self.headers),
                'url': self.path, # Log path as URL if reconstruction failed
                'response_status': 400,
                'error': "Missing Host header or Invalid Path",
                'is_api': False,
                'analysis_findings': ["Failed to parse URL due to missing Host or invalid path."]
            }
            if hasattr(self.server, 'traffic'): self.server.traffic.append(request_info)
            if root: root.event_generate("<<NewTrafficLog>>", when="tail")
            return


        request_info = {
            'timestamp': datetime.datetime.now().isoformat(),
            'method': self.command,
            'path': self.path, # Keep original path component
            'url': url, # Add reconstructed full URL
            'request_headers': dict(self.headers),
            'request_body': None,
            'response_status': None,
            'response_headers': None,
            'response_body': None,
            'error': None,
            'is_api': False,
            'analysis_findings': []
        }
        start_time = datetime.datetime.now()

        try:
            # Read request body
            if self.command in ('POST', 'PUT', 'PATCH', 'DELETE'):
                length = int(self.headers.get('Content-Length', 0))
                if length > 0:
                    # Limit request body capture size for logging/analysis
                    max_req_body_size = 1024 * 1024 # 1MB
                    if length > max_req_body_size:
                         print(f"[*] Request body too large ({length} bytes). Truncating capture for {url}")
                         request_info['request_body'] = self.rfile.read(max_req_body_size) + b"... (truncated)"
                    else:
                         request_info['request_body'] = self.rfile.read(length)
                else:
                    request_info['request_body'] = b''
        except Exception as e:
            print(f"[!] Error reading request body for {url}: {e}\n{traceback.format_exc()}")
            request_info['error'] = f"Error reading request body: {e}"


        forwarded_headers = self.sanitize_headers(self.headers)

        try:
            # Use the global session for requests
            resp = session.request(
                self.command, url, # Use the reconstructed full URL
                headers=forwarded_headers,
                data=request_info['request_body'] if isinstance(request_info['request_body'], bytes) else None, # Ensure bytes for data
                stream=True,
                timeout=30,
                verify=True # Verify target server certs
            )
            request_info['response_status'] = resp.status_code
            request_info['response_headers'] = dict(resp.headers)

            self.send_response(resp.status_code)
            response_content_type = resp.headers.get('Content-Type', '').lower()

            resp_hop_by_hop_headers = [
                 'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
                 'te', 'trailers', 'transfer-encoding', 'upgrade', 'content-length'
            ]
            for k, v in resp.headers.items():
                if k.lower() not in resp_hop_by_hop_headers:
                    self.send_header(k, v)

            self.send_header('X-Proxied-By', 'MyProxy/1.1')
            self.end_headers()

            # Determine if response body is likely binary for logging/analysis
            is_binary_response = any(keyword in response_content_type for keyword in
                                     ['application/octet-stream', 'image/', 'video/', 'audio/', 'application/zip', 'application/pdf']) or \
                                 'gzip' in resp.headers.get('Content-Encoding','').lower() # Gzip is encoding

            # --- Response Body Consumption and Logging ---
            response_body_chunks = []
            max_resp_body_capture_size = 2 * 1024 * 1024 # Limit response body capture size (e.g., 2MB)
            response_truncated_for_log = False

            try:
                for chunk in resp.iter_content(8192):
                    if chunk:
                        self.wfile.write(chunk) # Send chunk to client
                        # Only append to chunks if not considered binary and below size limit
                        if not is_binary_response and (len(b''.join(response_body_chunks)) + len(chunk)) < max_resp_body_capture_size:
                             response_body_chunks.append(chunk)
                        elif not is_binary_response and (len(b''.join(response_body_chunks) + len(chunk)) >= max_resp_body_capture_size):
                             if not response_truncated_for_log: # Append truncation marker only once
                                 response_body_chunks.append(b"... (truncated)")
                                 response_truncated_for_log = True
                             # Stop adding further chunks to the logging list
                             pass

            except Exception as e_stream:
                 print(f"[!] Error streaming response body for {url}: {e_stream}")
                 request_info['error'] = (request_info['error'] or "") + f" | Stream Error: {e_stream}"


            # Attempt to decode response body for logging if it's not binary
            if not is_binary_response:
                try:
                    full_response_body = b''.join(response_body_chunks)
                    content_type_header = resp.headers.get('Content-Type', '')
                    charset_match = re.search(r'charset=([\w-]+)', content_type_header)
                    encoding = charset_match.group(1) if charset_match else 'utf-8'
                    try:
                        request_info['response_body'] = full_response_body.decode(encoding)
                    except UnicodeDecodeError:
                        print(f"[!] UnicodeDecodeError logging response body for {url} with encoding {encoding}. Storing as lossy string.")
                        request_info['response_body'] = full_response_body.decode(encoding, errors='replace')
                except Exception as e_decode:
                    print(f"[!] Error decoding response body for logging {url}: {e_decode}")
                    request_info['response_body'] = b"DECODING_ERROR_FOR_LOG (original was text)"
            elif request_info.get('response_body') is None: # Ensure it's marked if it was binary/truncated
                 if response_truncated_for_log:
                     request_info['response_body'] = b"TEXT_DATA_TRUNCATED_FOR_LOGGING (not logged)"
                 else:
                     request_info['response_body'] = b"BINARY_DATA (not logged)"


        except requests.exceptions.Timeout:
            print(f"[!] Timeout connecting to {url}")
            self.send_error(504, "Gateway Timeout")
            request_info['error'] = f"Timeout connecting to {url}"
            request_info['response_status'] = 504
        except requests.exceptions.RequestException as e:
            print(f"[!] Error forwarding request to {url}: {e}\n{traceback.format_exc()}")
            self.send_error(502, "Proxy Error (Bad Gateway)")
            request_info['error'] = f"Error forwarding request: {e}"
            request_info['response_status'] = 502
        except Exception as e:
            print(f"[!] Unhandled error in forward_request for {url}: {e}\n{traceback.format_exc()}")
            self.send_error(500, "Internal Proxy Error")
            request_info['error'] = f"Internal proxy error: {e}"
            request_info['response_status'] = 500
        finally:
            end_time = datetime.datetime.now()
            request_info['duration_ms'] = (end_time - start_time).total_seconds() * 1000

            # --- Perform Real-time Analysis ---
            analyze_traffic_entry(request_info)

            # Append the completed traffic entry to the log
            if hasattr(self.server, 'traffic'):
                self.server.traffic.append(request_info)
                # Ensure GUI is updated from the main thread
                if proxy_server and root:
                    root.event_generate("<<NewTrafficLog>>", when="tail")

    def log_message(self, format_str, *args):
        # Suppress default BaseHTTPRequestHandler logging
        return

    def do_CONNECT(self):
        hostname, port_str = self.path.split(':', 1)
        port = int(port_str)

        # Store original target details for later use in forward_request
        # (This is a workaround; ideally BaseHTTPRequestHandler would provide this)
        self.original_host = hostname
        self.original_port = port
        self.original_scheme = 'https' # CONNECT is always for HTTPS

        # We won't log the CONNECT itself as a full traffic entry normally,
        # as it's just the tunnel setup. Errors during setup will be logged.
        connect_log_entry = {
             'timestamp': datetime.datetime.now().isoformat(),
             'method': 'CONNECT',
             'path': self.path,
             'url': f"https://{hostname}:{port}", # Log target URL for CONNECT
             'request_headers': dict(self.headers),
             'response_status': None,
             'error': None,
             'is_api': False,
             'analysis_findings': []
        }
        start_time = datetime.datetime.now()


        print(f"[*] HTTPS CONNECT to {hostname}:{port}")

        try:
            certfile, keyfile = get_cert_for_host(hostname, cert_ttl_days)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certfile=certfile, keyfile=keyfile)
        except Exception as e:
            print(f"[!] Error setting up SSL context for {hostname}: {e}\n{traceback.format_exc()}")
            self.send_error(500, "SSL Context Error")
            connect_log_entry['error'] = f"SSL Context Setup Error: {e}"
            connect_log_entry['response_status'] = 500
            # Log error entry
            if hasattr(self.server, 'traffic'): self.server.traffic.append(connect_log_entry)
            if root: root.event_generate("<<NewTrafficLog>>", when="tail")
            return

        self.send_response(200, 'Connection Established')
        self.end_headers()

        try:
            # Wrap client socket with our server-side TLS context
            tls_client_socket = context.wrap_socket(self.connection, server_side=True)

            # Replace handler's streams with the wrapped socket's streams
            self.rfile = tls_client_socket.makefile('rb', -1)
            self.wfile = tls_client_socket.makefile('wb', 0)

            # Process the first decrypted HTTP request from the client
            # The handler's loop will handle subsequent requests on this tunnel
            print(f"[*] Successfully wrapped client socket for {hostname}. Processing tunneled request(s)...")
            # BaseHTTPRequestHandler's handle_one_request reads one full request,
            # and its internal handle loop keeps processing if the connection is persistent.
            # No explicit loop needed here after the initial call.
            self.handle_one_request()

        except ssl.SSLError as e:
            print(f"[!] TLS wrap error with client for {hostname}: {e}")
            connect_log_entry['error'] = f"TLS Wrap Error (Client-Side): {e}"
            connect_log_entry['response_status'] = 500
            if hasattr(self.server, 'traffic'): self.server.traffic.append(connect_log_entry)
            if root: root.event_generate("<<NewTrafficLog>>", when="tail")
            try: self.connection.close()
            except: pass
        except socket.timeout:
             print(f"[!] Socket timeout during CONNECT or initial TLS wrap for {hostname}.")
             # Error likely handled within handle_one_request or forward_request
             try: self.connection.close()
             except: pass
        except Exception as e:
            print(f"[!] Unexpected error during CONNECT handling for {hostname}: {e}\n{traceback.format_exc()}")
            connect_log_entry['error'] = f"Unexpected Error during CONNECT handling: {e}"
            connect_log_entry['response_status'] = 500
            if hasattr(self.server, 'traffic'): self.server.traffic.append(connect_log_entry)
            if root: root.event_generate("<<NewTrafficLog>>", when="tail")
            try: self.connection.close()
            except: pass

# =================== GUI & Proxy Control ===================
proxy_server = None
cert_ttl_days = DEFAULT_CERT_TTL_DAYS

session = requests.Session()
session.cookies = RequestsCookieJar()
retry_strategy = Retry(
    total=3,
    backoff_factor=1,
    status_forcelist=[429, 500, 502, 503, 504],
)
adapter = HTTPAdapter(max_retries=retry_strategy)
session.mount('http://', adapter)
session.mount('https://', adapter)

proxy_host_var = tk.StringVar(value=PROXY_HOST)
proxy_port_var = tk.StringVar(value=str(PROXY_PORT))
last_results = None

traffic_listbox = None
root = None

def handle_new_traffic_log_event(event):
    update_live_traffic_display()

def update_live_traffic_display():
    global traffic_listbox, proxy_server
    if not traffic_listbox or not proxy_server or not hasattr(proxy_server, 'traffic'):
        return

    selected_index = None
    selected_log_text = None
    try:
        current_selection = traffic_listbox.curselection()
        if current_selection:
            selected_index = current_selection[0]
            selected_log_text = traffic_listbox.get(selected_index)
    except Exception:
        selected_index = None

    traffic_listbox.delete(0, END)

    max_entries_display = 200
    start_index = max(0, len(proxy_server.traffic) - max_entries_display)

    for i, entry in enumerate(proxy_server.traffic[start_index:]):
        method = entry.get('method', 'N/A')
        # Display the full URL if available, fallback to path
        display_url = entry.get('url', entry.get('path', 'N/A'))
        status = entry.get('response_status', 'N/A')
        error = entry.get('error')
        is_api = entry.get('is_api', False)
        findings_count = len(entry.get('analysis_findings', []))

        # Truncate long URLs for display
        display_url_truncated = display_url[:80] + '...' if len(display_url) > 80 else display_url

        # Add indicators for API and findings
        api_indicator = "[API] " if is_api else ""
        findings_indicator = f"({findings_count} finding{'s' if findings_count != 1 else ''})" if findings_count > 0 else ""

        log_line = f"[{start_index + i + 1}] {api_indicator}{method} {display_url_truncated} -> {status} {findings_indicator}"
        if error:
            log_line += f" (Error: {str(error)[:30]}...)"

        traffic_listbox.insert(END, log_line)

    if selected_index is not None and selected_log_text:
         try:
             items = traffic_listbox.get(0, END)
             if selected_log_text in items:
                 new_index = items.index(selected_log_text)
                 traffic_listbox.selection_set(new_index)
                 traffic_listbox.activate(new_index)
                 # Don't auto-scroll if re-selecting, user is likely inspecting
                 # traffic_listbox.yview(new_index)
             else:
                  # If the previously selected item is no longer in the visible range,
                  # we might want to scroll to the bottom or a relevant position.
                  # For simplicity, just don't re-select if not found.
                  pass
         except Exception:
             pass

    # Auto-scroll to the bottom only if nothing was selected before
    if selected_index is None:
         traffic_listbox.yview(END)


def set_buttons_state(is_running_analysis=False, is_proxy_running=False):
    run_batch_analysis_button.config(state=tk.DISABLED if is_running_analysis or is_proxy_running else tk.NORMAL)
    start_button.config(state=tk.DISABLED if is_proxy_running else tk.NORMAL)
    stop_button.config(state=tk.NORMAL if is_proxy_running else tk.DISABLED)


def start_proxy():
    global proxy_server
    if proxy_server:
        messagebox.showinfo("Info", "Proxy is already running.")
        return

    host = proxy_host_var.get()
    port = int(proxy_port_var.get())

    try:
        # Clear previous traffic logs before starting new session
        if proxy_server and hasattr(proxy_server, 'traffic'):
             proxy_server.traffic = []
        elif not proxy_server:
             # Create a dummy server instance just to hold the traffic list before real server starts
             # This is a bit of a hack, better to restructure global state
             class DummyServer: pass
             proxy_server = DummyServer()
             proxy_server.traffic = []


        proxy_server_instance = TrafficLoggingServer((host, port), ProxyHandler)
        # Replace the dummy/previous server instance with the real one
        proxy_server = proxy_server_instance

        proxy_thread = threading.Thread(target=proxy_server.serve_forever, name="ProxyServerThread", daemon=True)
        proxy_thread.start()
        print(f"[*] Proxy started on {host}:{port}")
        messagebox.showinfo("Info", f"Proxy started on {host}:{port}")
        set_buttons_state(is_proxy_running=True)
        update_live_traffic_display() # Refresh display

    except Exception as e:
        print(f"[!] Failed to start proxy: {e}\n{traceback.format_exc()}")
        messagebox.showerror("Error", f"Failed to start proxy:\n{e}")
        proxy_server = None # Ensure server is None if startup failed
        set_buttons_state(is_proxy_running=False)


def stop_proxy():
    global proxy_server
    if proxy_server and isinstance(proxy_server, socketserver.ThreadingTCPServer): # Check if it's the real server
        print("[*] Stopping proxy...")
        proxy_server.shutdown()
        proxy_server.server_close()
        proxy_server = None # Clear the server instance
        print("[*] Proxy stopped.")
        messagebox.showinfo("Info", "Proxy stopped.")
        set_buttons_state(is_proxy_running=False)
    elif proxy_server and hasattr(proxy_server, 'traffic'): # If it was a dummy server instance
         proxy_server = None
         messagebox.showinfo("Info", "Proxy state reset (server was not running).")
         set_buttons_state(is_proxy_running=False)
    else:
        messagebox.showinfo("Info", "Proxy is not running.")
        set_buttons_state(is_proxy_running=False)


def on_closing():
    if messagebox.askokcancel("Quit", "Do you want to quit?"):
        stop_proxy()
        root.destroy()


def show_trust_instructions(ca_path=None):
     instructions = (
         "To intercept HTTPS traffic, you must install and trust the Certificate Authority (CA) certificate.\n\n"
         f"The CA certificate is located at:\n{ca_path if ca_path else os.path.abspath(CA_CERT_PATH)}\n\n"
         "**General Steps:**\n"
         "1. Open your browser's security settings or your operating system's certificate manager.\n"
         "2. Find the option to import or add a new trusted root certificate.\n"
         "3. Select the 'ca.crt' file.\n"
         "4. Ensure you explicitly trust it for identifying websites/authorities.\n\n"
         "Consult your browser's or OS's documentation for specific steps."
     )
     messagebox.showinfo("Trust CA Instructions", instructions)

def export_traffic():
    global proxy_server
    if not proxy_server or not hasattr(proxy_server, 'traffic') or not proxy_server.traffic:
        messagebox.showinfo("Info", "No traffic data to export.")
        return

    file_path = filedialog.asksaveasfilename(
        defaultextextension=".json",
        filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        title="Save Traffic Log"
    )

    if file_path:
        try:
            # Prepare data for serialization: convert bytes to strings, handle truncation markers
            serializable_traffic = []
            for entry in proxy_server.traffic:
                serializable_entry = entry.copy()

                def prepare_body_for_json(body):
                    if body is None:
                        return None
                    elif isinstance(body, bytes):
                         # Handle truncation markers specially, otherwise attempt decode
                         if b"... (truncated)" in body: # Checks for truncation in both req/resp capture
                              return "BODY_TRUNCATED_FOR_LOGGING"
                         elif b"BINARY_DATA" in body:
                              return "BINARY_DATA (not logged)"
                         elif b"DECODING_ERROR_FOR_LOG" in body:
                              return "DECODING_ERROR_FOR_LOG (original was text, not saved)"
                         else:
                            try:
                                return body.decode('utf-8', errors='replace')
                            except Exception:
                                return str(body) # Fallback
                    else: # Assume string
                        return body

                serializable_entry['request_body'] = prepare_body_for_json(serializable_entry.get('request_body'))
                serializable_entry['response_body'] = prepare_body_for_json(serializable_entry.get('response_body'))

                serializable_traffic.append(serializable_entry)

            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(serializable_traffic, f, indent=4)
            messagebox.showinfo("Export Complete", f"Traffic log saved to {file_path}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to save traffic log:\n{e}")


# --- Traffic Viewer Dialog ---
class TrafficViewerDialog(tk.Toplevel):
    def __init__(self, parent, entry_index, entry_data):
        super().__init__(parent)
        self.entry_index = entry_index
        self.entry_data = entry_data
        # Display full URL in title if available, fallback to path
        display_url = entry_data.get('url', entry_data.get('path', f"Entry {entry_index}"))
        self.title(f"Traffic Entry {entry_index}: {display_url[:80]}...") # Truncate title
        self.geometry("900x700") # Increased size
        self.transient(parent)
        self.grab_set()

        self.create_widgets()
        self.populate_data()

    def create_widgets(self):
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)

        # Request Tab
        request_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(request_frame, text='Request')
        self.request_text = tk.Text(request_frame, wrap=tk.WORD, state=tk.DISABLED)
        self.request_text.pack(fill=tk.BOTH, expand=True)

        # Response Tab
        response_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(response_frame, text='Response')
        self.response_text = tk.Text(response_frame, wrap=tk.WORD, state=tk.DISABLED)
        self.response_text.pack(fill=tk.BOTH, expand=True)

        # Analysis Tab
        analysis_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(analysis_frame, text='Analysis')

        ttk.Label(analysis_frame, text="Real-time Analysis Findings:").pack(pady=(0, 5), anchor=tk.W)
        self.analysis_text = tk.Text(analysis_frame, wrap=tk.WORD, state=tk.DISABLED, height=8) # Increased height
        self.analysis_text.pack(fill=tk.X, expand=False, pady=(0, 5))

        ttk.Label(analysis_frame, text="On-Demand Body Analysis Results:").pack(pady=(5, 0), anchor=tk.W)
        body_analysis_frame = ttk.Frame(analysis_frame)
        body_analysis_frame.pack(fill=tk.BOTH, expand=True)

        body_analysis_scrollbar = Scrollbar(body_analysis_frame)
        body_analysis_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.body_analysis_text = tk.Text(body_analysis_frame, wrap=tk.WORD, state=tk.DISABLED, yscrollcommand=body_analysis_scrollbar.set)
        self.body_analysis_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        body_analysis_scrollbar.config(command=self.body_analysis_text.yview)

        # Buttons for body analysis
        analysis_buttons_frame = ttk.Frame(analysis_frame)
        analysis_buttons_frame.pack(fill=tk.X, expand=False, pady=(5,0))

        ttk.Button(analysis_buttons_frame, text="Analyze Request Body", command=self.analyze_request_body).pack(side=tk.LEFT, padx=5)
        ttk.Button(analysis_buttons_frame, text="Analyze Response Body", command=self.analyze_response_body).pack(side=tk.LEFT, padx=5)


    def populate_data(self):
        entry = self.entry_data

        # Request Data
        request_info_str = f"Method: {entry.get('method', 'N/A')}\n"
        request_info_str += f"URL: {entry.get('url', 'N/A')}\n" # Display full URL
        request_info_str += f"Timestamp: {entry.get('timestamp', 'N/A')}\n"
        request_info_str += f"Duration: {entry.get('duration_ms', 'N/A')} ms\n\n"
        request_info_str += "Request Headers:\n"
        for k, v in entry.get('request_headers', {}).items():
            request_info_str += f"  {k}: {v}\n"
        request_info_str += "\nRequest Body:\n"
        body = entry.get('request_body')
        if body is None:
             request_info_str += "  (No body)"
        elif isinstance(body, bytes):
             # Attempt to decode bytes for display, handle truncation/binary markers
             if b"... (truncated)" in body:
                  request_info_str += body.decode('utf-8', errors='replace') + "\n  (Body truncated in log)"
             elif b"BINARY_DATA" in body:
                  request_info_str += "  (BINARY_DATA - Not logged/displayed)"
             elif b"DECODING_ERROR_FOR_LOG" in body:
                   request_info_str += "  (DECODING_ERROR_FOR_LOG - Original was text, could not decode for log)"
             else:
                 try:
                     request_info_str += body.decode('utf-8', errors='replace')
                 except Exception:
                     request_info_str += str(body) # Fallback
        else: # Already string
            request_info_str += str(body)


        self.request_text.config(state=tk.NORMAL)
        self.request_text.delete('1.0', tk.END)
        self.request_text.insert(tk.END, request_info_str)
        self.request_text.config(state=tk.DISABLED)

        # Response Data
        response_info_str = f"Status: {entry.get('response_status', 'N/A')}\n\n"
        response_info_str += "Response Headers:\n"
        for k, v in entry.get('response_headers', {}).items():
            response_info_str += f"  {k}: {v}\n"
        response_info_str += "\nResponse Body:\n"
        body = entry.get('response_body')
        if body is None:
             response_info_str += "  (No body)"
        elif isinstance(body, bytes):
            # Attempt to decode bytes for display, handle truncation/binary markers
             if b"... (truncated)" in body:
                  response_info_str += body.decode('utf-8', errors='replace') + "\n  (Body truncated in log)"
             elif b"BINARY_DATA" in body:
                  response_info_str += "  (BINARY_DATA - Not logged/displayed)"
             elif b"DECODING_ERROR_FOR_LOG" in body:
                  response_info_str += "  (DECODING_ERROR_FOR_LOG - Original was text, could not decode for log)"
             else:
                 try:
                     response_info_str += body.decode('utf-8', errors='replace')
                 except Exception:
                     response_info_str += str(body) # Fallback
        else: # Already string
            response_info_str += str(body)


        self.response_text.config(state=tk.NORMAL)
        self.response_text.delete('1.0', tk.END)
        self.response_text.insert(tk.END, response_info_str)
        self.response_text.config(state=tk.DISABLED)

        # Analysis Data
        analysis_info_str = f"Potential API Call: {'Yes' if entry.get('is_api') else 'No'}\n\n"
        analysis_info_str += "Real-time Findings:\n"
        findings = entry.get('analysis_findings', [])
        if findings:
            for finding in findings:
                analysis_info_str += f"- {finding}\n"
        else:
            analysis_info_str += "  (No real-time findings)\n"

        self.analysis_text.config(state=tk.NORMAL)
        self.analysis_text.delete('1.0', tk.END)
        self.analysis_text.insert(tk.END, analysis_info_str)
        self.analysis_text.config(state=tk.DISABLED)

        # Clear previous body analysis results
        self.body_analysis_text.config(state=tk.NORMAL)
        self.body_analysis_text.delete('1.0', tk.END)
        self.body_analysis_text.config(state=tk.DISABLED)


    def analyze_request_body(self):
         body = self.entry_data.get('request_body')
         content_type = self.entry_data.get('request_headers', {}).get('Content-Type', '')
         findings = perform_body_analysis(body, content_type)
         self.display_body_analysis_findings(findings)
         # Optional: Add body findings back to the main entry's analysis_findings if desired
         # self.entry_data['analysis_findings'].extend(findings)
         # self.entry_data['analysis_findings'] = list(set(self.entry_data['analysis_findings']))
         # update_live_traffic_display() # Trigger GUI update if changing the main list

    def analyze_response_body(self):
         body = self.entry_data.get('response_body')
         content_type = self.entry_data.get('response_headers', {}).get('Content-Type', '')
         findings = perform_body_analysis(body, content_type)
         self.display_body_analysis_findings(findings)
         # Optional: Add body findings back to the main entry's analysis_findings if desired
         # self.entry_data['analysis_findings'].extend(findings)
         # self.entry_data['analysis_findings'] = list(set(self.entry_data['analysis_findings']))
         # update_live_traffic_display() # Trigger GUI update if changing the main list


    def display_body_analysis_findings(self, findings):
         self.body_analysis_text.config(state=tk.NORMAL)
         self.body_analysis_text.delete('1.0', tk.END)
         if findings:
              self.body_analysis_text.insert(tk.END, "On-Demand Body Analysis Findings:\n")
              for finding in findings:
                   self.body_analysis_text.insert(tk.END, f"- {finding}\n")
         else:
              self.body_analysis_text.insert(tk.END, "No specific findings from body analysis.")
         self.body_analysis_text.config(state=tk.DISABLED)


# --- GUI Setup ---
def create_gui():
    global root, traffic_listbox, start_button, stop_button, run_batch_analysis_button

    root = tk.Tk()
    root.title("MyProxy MITM with Analysis")
    root.geometry("1000x700") # Increased default size

    root.protocol("WM_DELETE_WINDOW", on_closing)

    # --- Controls Frame ---
    controls_frame = ttk.Frame(root, padding="10")
    controls_frame.pack(fill=tk.X)

    ttk.Label(controls_frame, text="Host:").pack(side=tk.LEFT, padx=5)
    host_entry = ttk.Entry(controls_frame, textvariable=proxy_host_var, width=15)
    host_entry.pack(side=tk.LEFT, padx=5)

    ttk.Label(controls_frame, text="Port:").pack(side=tk.LEFT, padx=5)
    port_entry = ttk.Entry(controls_frame, textvariable=proxy_port_var, width=8)
    port_entry.pack(side=tk.LEFT, padx=5)

    start_button = ttk.Button(controls_frame, text="Start Proxy", command=start_proxy)
    start_button.pack(side=tk.LEFT, padx=10)

    stop_button = ttk.Button(controls_frame, text="Stop Proxy", command=stop_proxy, state=tk.DISABLED)
    stop_button.pack(side=tk.LEFT, padx=5)

    ttk.Button(controls_frame, text="View CA Cert", command=open_ca_cert).pack(side=tk.LEFT, padx=5)
    ttk.Button(controls_frame, text="Trust CA Info", command=show_trust_instructions).pack(side=tk.LEFT, padx=5)

    # --- Analysis & Export Controls Frame ---
    analysis_controls_frame = ttk.Frame(root, padding="10")
    analysis_controls_frame.pack(fill=tk.X)

    run_batch_analysis_button = ttk.Button(analysis_controls_frame, text="Run Batch Analysis", command=run_batch_analysis)
    run_batch_analysis_button.pack(side=tk.LEFT, padx=5)

    ttk.Button(analysis_controls_frame, text="Export Traffic", command=export_traffic).pack(side=tk.LEFT, padx=5)
    ttk.Button(analysis_controls_frame, text="Clear Traffic", command=clear_traffic_logs).pack(side=tk.LEFT, padx=5) # Added Clear Logs button

    # --- Traffic Display Frame ---
    traffic_frame = ttk.Frame(root, padding="10")
    traffic_frame.pack(fill=tk.BOTH, expand=True)

    traffic_scrollbar = Scrollbar(traffic_frame)
    traffic_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    traffic_listbox = Listbox(traffic_frame, yscrollcommand=traffic_scrollbar.set, width=100)
    traffic_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    traffic_scrollbar.config(command=traffic_listbox.yview)

    traffic_listbox.bind('<Double-1>', on_traffic_double_click)
    root.bind("<<NewTrafficLog>>", handle_new_traffic_log_event)

    set_buttons_state(is_proxy_running=False)

    root.mainloop()

def clear_traffic_logs():
    """Clears the captured traffic logs."""
    global proxy_server
    if messagebox.askokcancel("Clear Logs", "Are you sure you want to clear all captured traffic logs? This cannot be undone."):
        if proxy_server and hasattr(proxy_server, 'traffic'):
            proxy_server.traffic = []
            update_live_traffic_display()
            print("[*] Traffic logs cleared.")
        else:
            messagebox.showinfo("Info", "No traffic logs to clear.")


def on_traffic_double_click(event):
    global proxy_server
    if not proxy_server or not hasattr(proxy_server, 'traffic'):
        return

    try:
        selection = traffic_listbox.curselection()
        if not selection:
            return

        listbox_index = selection[0]

        # Find the corresponding index in the *full* traffic list
        # Need to re-calculate start_index based on current traffic size and display limit
        max_entries_display = 200 # Must match the value in update_live_traffic_display
        current_traffic_size = len(proxy_server.traffic)
        start_index_full_list = max(0, current_traffic_size - max_entries_display)
        full_list_index = start_index_full_list + listbox_index

        if 0 <= full_list_index < current_traffic_size:
            entry_data = proxy_server.traffic[full_list_index]
            TrafficViewerDialog(root, full_list_index + 1, entry_data)
    except Exception as e:
        print(f"[!] Error opening traffic viewer: {e}\n{traceback.format_exc()}")
        messagebox.showerror("Error", f"Failed to open traffic viewer:\n{e}")


# --- Main execution ---
if __name__ == "__main__":
    # Ensure CA is created/loaded on startup
    # ca_cert, ca_private_key = create_or_load_ca() # Already called globally

    # Initialize proxy_server.traffic list even if not running immediately
    class DummyServer: pass
    proxy_server = DummyServer()
    proxy_server.traffic = []

    create_gui()
