from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, session, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import socket
import ssl
import ipaddress
import json
import csv
import io
from concurrent.futures import ThreadPoolExecutor, as_completed
import subprocess
import re
import time
import ping3
import urllib.request
import urllib.parse
from datetime import datetime, timedelta
import sqlite3
import os
import platform
import sys
import uuid
import hashlib
import hmac
import base64
import random
from cryptography.fernet import Fernet
import bcrypt

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'your-secret-key-change-in-production')

# Setup Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'

# Database setup
DATABASE = 'network_diagnostics.db'

# User class for authentication
class User(UserMixin):
    def __init__(self, id, username, password_hash):
        self.id = id
        self.username = username
        self.password_hash = password_hash

@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('SELECT id, username, password_hash FROM users WHERE id = ?', (user_id,))
    user_data = cursor.fetchone()
    conn.close()
    
    if user_data:
        return User(user_data[0], user_data[1], user_data[2])
    return None

def init_database():
    """Initialize the SQLite database for storing test results"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT,
            role TEXT DEFAULT 'user',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_login DATETIME
        )
    ''')
    
    # Create test results table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS test_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            ip_address TEXT,
            test_type TEXT NOT NULL,
            status TEXT NOT NULL,
            response_time_ms REAL,
            timestamp DATETIME NOT NULL,
            details TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create working hosts table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS working_hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL UNIQUE,
            ip_address TEXT,
            last_seen DATETIME NOT NULL,
            first_seen DATETIME NOT NULL,
            total_tests INTEGER DEFAULT 0,
            avg_response_time_ms REAL DEFAULT 0,
            status TEXT DEFAULT 'unknown',
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create secure IP storage table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS secure_ip_storage (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL,
            domain TEXT,
            hostname TEXT,
            test_results TEXT,
            ssl_info TEXT,
            dns_info TEXT,
            ping_info TEXT,
            http_info TEXT,
            last_tested DATETIME,
            test_count INTEGER DEFAULT 1,
            status TEXT DEFAULT 'active',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(ip_address)
        )
    ''')
    
    # Create access log table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS access_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            resource TEXT,
            ip_address TEXT,
            user_agent TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_timestamp ON test_results(timestamp)
    ''')
    
    cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_working_domain ON working_hosts(domain)
    ''')
    
    conn.commit()
    conn.close()

def save_test_result(domain, test_type, status, response_time_ms, details=None, ip_address=None):
    """Save test result to database"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT INTO test_results (domain, ip_address, test_type, status, response_time_ms, timestamp, details)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (domain, ip_address, test_type, status, response_time_ms, datetime.utcnow(), json.dumps(details) if details else None))
    
    conn.commit()
    conn.close()

def update_working_host(domain, ip_address, response_time_ms, status):
    """Update working host statistics"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Check if host exists
    cursor.execute('SELECT id, total_tests, avg_response_time_ms FROM working_hosts WHERE domain = ?', (domain,))
    result = cursor.fetchone()
    
    if result:
        host_id, total_tests, avg_response_time = result
        
        # Update existing record
        new_total_tests = total_tests + 1
        new_avg_response_time = (avg_response_time * total_tests + response_time_ms) / new_total_tests
        
        cursor.execute('''
            UPDATE working_hosts 
            SET ip_address = ?, last_seen = ?, total_tests = ?, avg_response_time_ms = ?, status = ?, updated_at = ?
            WHERE id = ?
        ''', (ip_address, datetime.utcnow(), new_total_tests, new_avg_response_time, status, datetime.utcnow(), host_id))
    else:
        # Insert new record
        cursor.execute('''
            INSERT INTO working_hosts (domain, ip_address, last_seen, first_seen, total_tests, avg_response_time_ms, status)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (domain, ip_address, datetime.utcnow(), datetime.utcnow(), 1, response_time_ms, status))
    
    conn.commit()
    conn.close()

def get_working_hosts(limit=50):
    """Get list of working hosts with their statistics"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT domain, ip_address, last_seen, first_seen, total_tests, success_rate, avg_response_time_ms, status
        FROM working_hosts 
        WHERE status = 'working'
        ORDER BY last_seen DESC 
        LIMIT ?
    ''', (limit,))
    
    results = cursor.fetchall()
    conn.close()
    
    return [
        {
            'domain': row[0],
            'ip_address': row[1],
            'last_seen': row[2],
            'first_seen': row[3],
            'total_tests': row[4],
            'success_rate': row[5],
            'avg_response_time_ms': row[6],
            'status': row[7]
        }
        for row in results
    ]

def get_host_history(domain, limit=20):
    """Get test history for a specific host"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT test_type, status, response_time_ms, timestamp, details
        FROM test_results 
        WHERE domain = ?
        ORDER BY timestamp DESC 
        LIMIT ?
    ''', (domain, limit))
    
    results = cursor.fetchall()
    conn.close()
    
    return [
        {
            'test_type': row[0],
            'status': row[1],
            'response_time_ms': row[2],
            'timestamp': row[3],
            'details': json.loads(row[4]) if row[4] else None
        }
        for row in results
    ]

# Initialize database on startup
init_database()

# Zimbabwean ISP IP ranges
ZIMBABWE_ISPS = {
    "Econet": [
        "41.78.112.0/20",
        "41.78.128.0/20", 
        "41.85.0.0/16",
        "41.86.0.0/16",
        "41.87.0.0/16",
        "41.88.0.0/16",
        "41.89.0.0/16",
        "41.220.0.0/16",
        "196.4.78.0/24",
        "196.4.79.0/24",
        "196.4.80.0/24",
        "196.4.81.0/24",
        "196.4.82.0/24",
        "196.4.83.0/24",
        "196.4.84.0/24",
        "196.4.85.0/24",
        "196.4.86.0/24",
        "196.4.87.0/24",
        "196.4.88.0/24",
        "196.4.89.0/24",
        "196.4.90.0/24",
        "196.4.91.0/24",
        "196.4.92.0/24",
        "196.4.93.0/24",
        "196.4.94.0/24",
        "196.4.95.0/24",
        "197.221.128.0/17",
        "197.221.192.0/18",
        "197.221.224.0/19",
        "197.221.240.0/20",
        "197.221.248.0/21",
        "197.221.252.0/22",
        "197.221.254.0/23",
        "197.221.255.0/24"
    ],
    "NetOne": [
        "41.72.0.0/16",
        "41.73.0.0/16", 
        "41.74.0.0/16",
        "41.75.0.0/16",
        "41.76.0.0/16",
        "41.77.0.0/16",
        "41.78.0.0/16",
        "41.79.0.0/16",
        "41.80.0.0/16",
        "41.81.0.0/16",
        "41.82.0.0/16",
        "41.83.0.0/16",
        "41.84.0.0/16",
        "41.85.0.0/16",
        "41.86.0.0/16",
        "41.87.0.0/16",
        "41.88.0.0/16",
        "41.89.0.0/16",
        "41.90.0.0/16",
        "41.91.0.0/16",
        "41.92.0.0/16",
        "41.93.0.0/16",
        "41.94.0.0/16",
        "41.95.0.0/16",
        "41.96.0.0/16",
        "41.97.0.0/16",
        "41.98.0.0/16",
        "41.99.0.0/16",
        "41.100.0.0/16",
        "41.101.0.0/16",
        "41.102.0.0/16",
        "41.103.0.0/16",
        "41.104.0.0/16",
        "41.105.0.0/16",
        "41.106.0.0/16",
        "41.107.0.0/16",
        "41.108.0.0/16",
        "41.109.0.0/16",
        "41.110.0.0/16",
        "41.111.0.0/16",
        "41.112.0.0/16",
        "41.113.0.0/16",
        "41.114.0.0/16",
        "41.115.0.0/16",
        "41.116.0.0/16",
        "41.117.0.0/16",
        "41.118.0.0/16",
        "41.119.0.0/16",
        "41.120.0.0/16",
        "41.121.0.0/16",
        "41.122.0.0/16",
        "41.123.0.0/16",
        "41.124.0.0/16",
        "41.125.0.0/16",
        "41.126.0.0/16",
        "41.127.0.0/16",
        "196.43.192.0/19",
        "196.43.224.0/20",
        "196.43.240.0/21",
        "196.43.248.0/22",
        "196.43.252.0/23",
        "196.43.254.0/24",
        "196.43.255.0/24"
    ]
}

def expand_cidr(cidr):
    """Expand CIDR notation to list of IP addresses"""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return [str(ip) for ip in network.hosts()]
    except Exception as e:
        return []

def reverse_dns_lookup(ip):
    """Perform reverse DNS lookup using system nslookup"""
    try:
        # Use system nslookup command for faster and more reliable results
        result = subprocess.run(['nslookup', ip], capture_output=True, text=True, timeout=5)
        output = result.stdout
        
        # Parse nslookup output to find domain names
        domains = []
        lines = output.split('\n')
        for line in lines:
            line = line.strip()
            if 'name =' in line.lower() or 'name = ' in line.lower():
                # Extract domain name from lines like "name = example.com"
                match = re.search(r'name\s*=\s*([^\s]+)', line, re.IGNORECASE)
                if match:
                    domain = match.group(1).rstrip('.')
                    if domain and domain != ip:
                        domains.append(domain)
            elif line.endswith('.in-addr.arpa.'):
                # Extract domain from PTR records
                parts = line.split()
                if len(parts) >= 4:
                    domain = parts[3].rstrip('.')
                    if domain and domain != ip:
                        domains.append(domain)
        
        return list(set(domains))  # Remove duplicates
    except Exception:
        return []

def test_ssl_certificate(hostname, port=443, timeout=10):
    """Test SSL certificate"""
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        start_time = time.time()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                handshake_time = time.time() - start_time
                
                # Parse subject and issuer for better display
                subject_dict = {}
                issuer_dict = {}
                
                for item in cert.get('subject', []):
                    subject_dict[item[0][0]] = item[0][1]
                
                for item in cert.get('issuer', []):
                    issuer_dict[item[0][0]] = item[0][1]
                
                # Format subject line
                subject_parts = []
                if 'commonName' in subject_dict:
                    subject_parts.append(f"CN = {subject_dict['commonName']}")
                if 'organizationName' in subject_dict:
                    subject_parts.append(f"O = {subject_dict['organizationName']}")
                if 'countryName' in subject_dict:
                    subject_parts.append(f"C = {subject_dict['countryName']}")
                
                subject_line = ", ".join(subject_parts) if subject_parts else subject_dict.get('commonName', 'Unknown')
                
                # Format issuer line
                issuer_parts = []
                if 'countryName' in issuer_dict:
                    issuer_parts.append(f"C = {issuer_dict['countryName']}")
                if 'organizationName' in issuer_dict:
                    issuer_parts.append(f"O = {issuer_dict['organizationName']}")
                if 'commonName' in issuer_dict:
                    issuer_parts.append(f"CN = {issuer_dict['commonName']}")
                
                issuer_line = ", ".join(issuer_parts) if issuer_parts else issuer_dict.get('commonName', 'Unknown')
                
                # Calculate days until expiration
                not_after = cert.get('notAfter', '')
                days_until_expiry = 0
                is_expired = False
                is_expiring_soon = False
                
                if not_after:
                    from datetime import datetime
                    expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (expiry_date - datetime.utcnow()).days
                    is_expired = days_until_expiry < 0
                    is_expiring_soon = 0 <= days_until_expiry <= 30
                
                return {
                    'valid': True,
                    'handshake_time_ms': round(handshake_time * 1000, 2),
                    'subject': subject_dict,
                    'issuer': issuer_dict,
                    'subject_line': subject_line,
                    'issuer_line': issuer_line,
                    'not_before': cert.get('notBefore', ''),
                    'not_after': cert.get('notAfter', ''),
                    'days_until_expiry': days_until_expiry,
                    'is_expired': is_expired,
                    'is_expiring_soon': is_expiring_soon,
                    'serial_number': cert.get('serialNumber', ''),
                    'cert_chain_length': len(ssock.get_peer_cert_chain()),
                    'subject_alt_names': cert.get('subjectAltName', []),
                    'protocol_version': ssock.version(),
                    'cipher': ssock.cipher()
                }
    except Exception as e:
        return {
            'valid': False,
            'error': str(e),
            'handshake_time_ms': 0
        }

def test_sni_support(hostname, port=443, timeout=10):
    """Advanced SNI testing with certificate comparison and host name checking"""
    try:
        # Get IP address first
        ip = socket.gethostbyname(hostname)
        
        # Test 1: With SNI (proper hostname)
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        start_time = time.time()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_with_sni = ssock.getpeercert()
                sni_handshake_time = time.time() - start_time
        
        # Test 2: Without SNI (using IP address)
        context2 = ssl.create_default_context()
        context2.check_hostname = False
        context2.verify_mode = ssl.CERT_NONE
        
        start_time2 = time.time()
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with context2.wrap_socket(sock, server_hostname=None) as ssock:
                cert_without_sni = ssock.getpeercert()
                no_sni_handshake_time = time.time() - start_time2
        
        # Test 3: With wrong SNI (invalid hostname)
        context3 = ssl.create_default_context()
        context3.check_hostname = False
        context3.verify_mode = ssl.CERT_NONE
        
        start_time3 = time.time()
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with context3.wrap_socket(sock, server_hostname='invalid.test.invalid') as ssock:
                cert_with_wrong_sni = ssock.getpeercert()
                wrong_sni_handshake_time = time.time() - start_time3
        
        # Extract certificate details for comparison
        subject_with_sni = dict(x[0] for x in cert_with_sni['subject']) if cert_with_sni else {}
        subject_without_sni = dict(x[0] for x in cert_without_sni['subject']) if cert_without_sni else {}
        subject_with_wrong_sni = dict(x[0] for x in cert_with_wrong_sni['subject']) if cert_with_wrong_sni else {}
        
        # Get certificate subjects for comparison
        cert_with_sni_subject = subject_with_sni.get('commonName', '')
        cert_without_sni_subject = subject_without_sni.get('commonName', '')
        cert_with_wrong_sni_subject = subject_with_wrong_sni.get('commonName', '')
        
        # Check if certificate matches the hostname
        hostname_matches = cert_with_sni_subject == hostname or \
                        hostname in [alt[1] for alt in cert_with_sni.get('subjectAltName', [])] or \
                        cert_with_sni_subject == f'www.{hostname}'
        
        # Check if SNI is working correctly
        sni_working = hostname_matches and cert_with_sni_subject == hostname
        
        # Check if wrong SNI fails (security)
        wrong_sni_fails = cert_with_wrong_sni_subject == 'invalid.test.invalid'
        
        return {
            'sni_supported': True,
            'cert_matches': cert_with_sni == cert_without_sni,
            'sni_handshake_time_ms': round(sni_handshake_time * 1000, 2),
            'no_sni_handshake_time_ms': round(no_sni_handshake_time * 1000, 2),
            'wrong_sni_handshake_time_ms': round(wrong_sni_handshake_time * 1000, 2),
            'subject_with_sni': subject_with_sni,
            'subject_without_sni': subject_without_sni,
            'subject_with_wrong_sni': subject_with_wrong_sni,
            'cert_with_sni': cert_with_sni,
            'cert_without_sni': cert_without_sni,
            'cert_with_wrong_sni': cert_with_wrong_sni,
            'ip_address': ip,
            'hostname_matches': hostname_matches,
            'sni_working': sni_working,
            'wrong_sni_fails': wrong_sni_fails,
            'certificate_subject': cert_with_sni_subject,
            'sni_security_check': 'passed' if sni_working and wrong_sni_fails else 'failed'
        }
    except Exception as e:
        return {'sni_supported': False, 'error': str(e)}

def test_dns_resolution(hostname):
    """DNS resolution test with timing"""
    try:
        start_time = time.time()
        ip = socket.gethostbyname(hostname)
        resolve_time = time.time() - start_time
        
        return {
            'resolves': True,
            'ip_address': ip,
            'resolve_time_ms': round(resolve_time * 1000, 2),
            'dns_server': 'system'
        }
    except socket.gaierror as e:
        return {
            'resolves': False,
            'error': str(e),
            'resolve_time_ms': 0
        }

def test_http_response(hostname, port=80, timeout=10):
    """HTTP response test"""
    try:
        url = f"http://{hostname}:{port}"
        start_time = time.time()
        
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=timeout) as response:
            response_time = time.time() - start_time
            status_code = response.getcode()
            
            return {
                'responds': True,
                'status_code': status_code,
                'response_time_ms': round(response_time * 1000, 2),
                'server': response.headers.get('Server', 'Unknown'),
                'content_length': response.headers.get('Content-Length', 'Unknown'),
                'headers': dict(response.headers)
            }
    except Exception as e:
        return {
            'responds': False,
            'error': str(e),
            'response_time_ms': 0
        }

def test_ping(hostname, count=3, timeout=5):
    """Comprehensive ping test with statistics"""
    try:
        ping_times = []
        packet_loss = 0
        total_time = 0
        
        for i in range(count):
            try:
                start_time = time.time()
                response = ping3.ping(hostname, timeout=timeout)
                ping_time = time.time() - start_time
                total_time += ping_time
                
                if response:
                    ping_times.append(round(response * 1000, 2))
                else:
                    packet_loss += 1
            except:
                packet_loss += 1
        
        if ping_times:
            # Calculate standard deviation (mdev)
            avg = sum(ping_times) / len(ping_times)
            variance = sum((x - avg) ** 2 for x in ping_times) / len(ping_times)
            mdev = round(variance ** 0.5, 3)
            
            return {
                'pingable': True,
                'hostname': hostname,
                'latency_ms': {
                    'min': min(ping_times),
                    'max': max(ping_times),
                    'avg': round(avg, 2),
                    'mdev': mdev,
                    'individual': ping_times
                },
                'packet_loss': round((packet_loss / count) * 100, 1),
                'packets_sent': count,
                'packets_received': len(ping_times),
                'ttl': '64',  # Default TTL for most systems
                'total_time': round(total_time * 1000)
            }
        else:
            return {
                'pingable': False,
                'hostname': hostname,
                'latency_ms': 0,
                'packet_loss': 100,
                'packets_sent': count,
                'packets_received': 0,
                'error': 'Host unreachable'
            }
    except Exception as e:
        return {
            'pingable': False,
            'hostname': hostname,
            'error': str(e),
            'latency_ms': 0,
            'packet_loss': 100
        }

def test_dns_lookup(hostname):
    """Comprehensive DNS lookup with all record types"""
    try:
        import dns.resolver
        import dns.exception
        
        results = {
            'resolves': True,
            'records': {}
        }
        
        # A records (IPv4)
        try:
            a_records = dns.resolver.resolve(hostname, 'A')
            results['records']['A'] = [str(record) for record in a_records]
        except:
            results['records']['A'] = []
        
        # AAAA records (IPv6)
        try:
            aaaa_records = dns.resolver.resolve(hostname, 'AAAA')
            results['records']['AAAA'] = [str(record) for record in aaaa_records]
        except:
            results['records']['AAAA'] = []
        
        # MX records (Mail)
        try:
            mx_records = dns.resolver.resolve(hostname, 'MX')
            results['records']['MX'] = [{'preference': record.preference, 'exchange': str(record.exchange)} for record in mx_records]
        except:
            results['records']['MX'] = []
        
        # NS records (Name Servers)
        try:
            ns_records = dns.resolver.resolve(hostname, 'NS')
            results['records']['NS'] = [str(record) for record in ns_records]
        except:
            results['records']['NS'] = []
        
        # TXT records
        try:
            txt_records = dns.resolver.resolve(hostname, 'TXT')
            results['records']['TXT'] = [str(record).strip('"') for record in txt_records]
        except:
            results['records']['TXT'] = []
        
        # CNAME records
        try:
            cname_records = dns.resolver.resolve(hostname, 'CNAME')
            results['records']['CNAME'] = [str(record) for record in cname_records]
        except:
            results['records']['CNAME'] = []
        
        # SOA records
        try:
            soa_records = dns.resolver.resolve(hostname, 'SOA')
            results['records']['SOA'] = [str(record) for record in soa_records]
        except:
            results['records']['SOA'] = []
        
        return results
        
    except ImportError:
        # Fallback to basic DNS resolution
        try:
            ip = socket.gethostbyname(hostname)
            return {
                'resolves': True,
                'records': {
                    'A': [ip],
                    'AAAA': [],
                    'MX': [],
                    'NS': [],
                    'TXT': [],
                    'CNAME': [],
                    'SOA': []
                }
            }
        except:
            return {
                'resolves': False,
                'error': 'DNS resolution failed',
                'records': {}
            }
    except Exception as e:
        return {
            'resolves': False,
            'error': str(e),
            'records': {}
        }

def test_traceroute(hostname, max_hops=30):
    """Traceroute implementation showing path to destination"""
    try:
        system = platform.system().lower()
        
        if system == 'windows':
            cmd = ['tracert', hostname]
        else:
            cmd = ['traceroute', hostname]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            hops = []
            
            for line in lines:
                if line.strip() and not line.startswith('Tracing route') and not line.startswith('traceroute'):
                    # Parse hop information
                    parts = line.split()
                    if parts and parts[0].isdigit():
                        hop_num = parts[0]
                        if len(parts) >= 3:
                            # Extract IP and latency
                            ip_address = parts[-1]
                            latencies = []
                            
                            for part in parts[1:]:
                                try:
                                    if part.endswith('ms'):
                                        latencies.append(part)
                                except:
                                    pass
                            
                            hops.append({
                                'hop': hop_num,
                                'ip': ip_address,
                                'latencies': latencies,
                                'status': 'reachable'
                            })
                        else:
                            hops.append({
                                'hop': hop_num,
                                'ip': '*',
                                'latencies': [],
                                'status': 'timeout'
                            })
            
            return {
                'success': True,
                'hops': hops,
                'total_hops': len(hops),
                'destination': hostname
            }
        else:
            return {
                'success': False,
                'error': result.stderr,
                'hops': []
            }
            
    except subprocess.TimeoutExpired:
        return {
            'success': False,
            'error': 'Traceroute timeout',
            'hops': []
        }
    except Exception as e:
        return {
            'success': False,
            'error': str(e),
            'hops': []
        }

# USSD Balance Checking Functions

class USSDBalanceChecker:
    def __init__(self):
        self.session_tokens = {}
        self.api_keys = {
            'econet': os.getenv('ECONET_USSD_API_KEY', 'demo_key_econet'),
            'netone': os.getenv('NETONE_USSD_API_KEY', 'demo_key_netone')
        }
        self.gateway_endpoints = {
            'econet': os.getenv('ECONET_USSD_ENDPOINT', 'https://api.econet.co.zw/ussd'),
            'netone': os.getenv('NETONE_USSD_ENDPOINT', 'https://api.netone.co.zw/ussd')
        }
        
    def generate_session_token(self, phone_number, network):
        """Generate a secure session token for USSD session"""
        timestamp = str(int(time.time()))
        random_str = str(random.randint(1000, 9999))
        token_data = f"{phone_number}:{network}:{timestamp}:{random_str}"
        
        # Create HMAC signature
        signature = hmac.new(
            self.api_keys[network].encode(),
            token_data.encode(),
            hashlib.sha256
        ).hexdigest()
        
        session_token = base64.b64encode(f"{token_data}:{signature}".encode()).decode()
        self.session_tokens[phone_number] = session_token
        return session_token
    
    def validate_session_token(self, phone_number, token, network):
        """Validate USSD session token"""
        stored_token = self.session_tokens.get(phone_number)
        if not stored_token or stored_token != token:
            return False
        
        try:
            decoded = base64.b64decode(stored_token.encode()).decode()
            token_data, signature = decoded.rsplit(':', 1)
            
            expected_signature = hmac.new(
                self.api_keys[network].encode(),
                token_data.encode(),
                hashlib.sha256
            ).hexdigest()
            
            return hmac.compare_digest(signature, expected_signature)
        except:
            return False
    
    def simulate_ussd_session(self, phone_number, network, ussd_code):
        """Simulate USSD session (for demo purposes)"""
        # This is a simulation - in production, you'd integrate with actual USSD gateway
        
        session_token = self.generate_session_token(phone_number, network)
        
        # Simulate different responses based on network and USSD code
        if network == 'econet':
            if '125' in ussd_code:  # Airtime balance
                return {
                    'success': True,
                    'session_id': session_token[:16],
                    'network': network,
                    'phone_number': phone_number,
                    'ussd_code': ussd_code,
                    'balance': {
                        'airtime': f'${random.uniform(1.50, 50.00):.2f}',
                        'currency': 'USD',
                        'expiry': f'{random.randint(1, 30)} days'
                    },
                    'response': f'Your Econet airtime balance is ${random.uniform(1.50, 50.00):.2f}. Valid for {random.randint(1, 30)} days.',
                    'timestamp': datetime.utcnow().isoformat()
                }
            elif '143' in ussd_code:  # Bundle balance
                return {
                    'success': True,
                    'session_id': session_token[:16],
                    'network': network,
                    'phone_number': phone_number,
                    'ussd_code': ussd_code,
                    'balance': {
                        'data': f'{random.uniform(100, 10000):.0f} MB',
                        'voice': f'{random.randint(50, 500)} minutes',
                        'sms': f'{random.randint(10, 100)} SMS',
                        'expiry': f'{random.randint(1, 30)} days'
                    },
                    'response': f'Data: {random.uniform(100, 10000):.0f}MB, Voice: {random.randint(50, 500)}min, SMS: {random.randint(10, 100)}',
                    'timestamp': datetime.utcnow().isoformat()
                }
        
        elif network == 'netone':
            if '134' in ussd_code:  # Airtime balance
                return {
                    'success': True,
                    'session_id': session_token[:16],
                    'network': network,
                    'phone_number': phone_number,
                    'ussd_code': ussd_code,
                    'balance': {
                        'airtime': f'${random.uniform(0.50, 30.00):.2f}',
                        'currency': 'USD',
                        'expiry': f'{random.randint(1, 60)} days'
                    },
                    'response': f'Your NetOne airtime balance is ${random.uniform(0.50, 30.00):.2f}. Valid for {random.randint(1, 60)} days.',
                    'timestamp': datetime.utcnow().isoformat()
                }
            elif '400' in ussd_code:  # OneFusion balance
                return {
                    'success': True,
                    'session_id': session_token[:16],
                    'network': network,
                    'phone_number': phone_number,
                    'ussd_code': ussd_code,
                    'balance': {
                        'data': f'{random.uniform(50, 5000):.0f} MB',
                        'voice': f'{random.randint(100, 1000)} minutes',
                        'sms': f'{random.randint(20, 200)} SMS',
                        'expiry': f'{random.randint(1, 30)} days'
                    },
                    'response': f'OneFusion: Data: {random.uniform(50, 5000):.0f}MB, Voice: {random.randint(100, 1000)}min, SMS: {random.randint(20, 200)}',
                    'timestamp': datetime.utcnow().isoformat()
                }
        
        # Default response
        return {
            'success': False,
            'error': 'USSD code not recognized',
            'session_id': session_token[:16],
            'network': network,
            'phone_number': phone_number,
            'ussd_code': ussd_code,
            'timestamp': datetime.utcnow().isoformat()
        }
    
    def check_balance(self, phone_number, network, balance_type='airtime'):
        """Check balance for specified network and type"""
        ussd_codes = {
            'econet': {
                'airtime': '*125#',
                'bundle': '*143#'
            },
            'netone': {
                'airtime': '*134#',
                'bundle': '*400#'
            }
        }
        
        ussd_code = ussd_codes.get(network, {}).get(balance_type, '*125#')
        
        # Validate phone number (Zimbabwe format)
        if not re.match(r'^263[78]\d{8}$', phone_number):
            return {
                'success': False,
                'error': 'Invalid Zimbabwe phone number format. Must start with 2637 or 2638 and be 12 digits.'
            }
        
        return self.simulate_ussd_session(phone_number, network, ussd_code)

def test_whois(domain):
    """WHOIS lookup for domain registration information"""
    try:
        # Check if it's an IP address - WHOIS doesn't work on IPs
        import re
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(ip_pattern, domain):
            return {
                'success': False,
                'error': 'WHOIS lookup requires a domain name, not an IP address',
                'data': {
                    'domain_name': domain,
                    'registrar': 'N/A (IP Address)',
                    'creation_date': 'N/A',
                    'expiration_date': 'N/A',
                    'updated_date': 'N/A',
                    'name_servers': [],
                    'status': 'IP Address',
                    'registrant': 'N/A',
                    'admin_email': 'N/A',
                    'tech_email': 'N/A'
                }
            }
        
        system = platform.system().lower()
        
        if system == 'windows':
            # Use online WHOIS API for Windows
            try:
                import urllib.request
                import urllib.parse
                import json
                
                # Using whoisjson.com API (free)
                url = f"https://whoisjson.com/api/v1/whois"
                data = urllib.parse.urlencode({'domain': domain}).encode('utf-8')
                
                req = urllib.request.Request(url, data=data, headers={
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'User-Agent': 'Mozilla/5.0'
                })
                
                with urllib.request.urlopen(req, timeout=30) as response:
                    result = json.loads(response.read().decode('utf-8'))
                
                if result.get('success') and result.get('whois'):
                    whois_data = result['whois']
                    
                    # Parse online WHOIS data
                    parsed_data = {
                        'domain_name': domain,
                        'registrar': whois_data.get('registrar', {}).get('name', ''),
                        'creation_date': whois_data.get('created_date', ''),
                        'expiration_date': whois_data.get('expires_date', ''),
                        'updated_date': whois_data.get('updated_date', ''),
                        'name_servers': [ns.get('name', '') for ns in whois_data.get('name_servers', [])],
                        'status': ', '.join([s.get('name', '') for s in whois_data.get('status', [])]),
                        'registrant': whois_data.get('registrant', {}).get('name', ''),
                        'admin_email': whois_data.get('admin_email', ''),
                        'tech_email': whois_data.get('tech_email', '')
                    }
                    
                    return {
                        'success': True,
                        'data': parsed_data,
                        'raw': str(whois_data)
                    }
                else:
                    return {
                        'success': False,
                        'error': result.get('error', 'WHOIS lookup failed'),
                        'data': {}
                    }
                    
            except Exception as api_error:
                # Fallback to basic domain validation
                return {
                    'success': False,
                    'error': f'WHOIS service unavailable: {str(api_error)}',
                    'data': {
                        'domain_name': domain,
                        'registrar': 'Unknown',
                        'creation_date': 'Unknown',
                        'expiration_date': 'Unknown',
                        'updated_date': 'Unknown',
                        'name_servers': [],
                        'status': 'Unknown',
                        'registrant': 'Unknown',
                        'admin_email': 'Unknown',
                        'tech_email': 'Unknown'
                    }
                }
        
        # For non-Windows systems, try system whois
        result = subprocess.run(['whois', domain], capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            whois_data = result.stdout
            
            # Parse key WHOIS information
            parsed_data = {
                'domain_name': domain,
                'registrar': '',
                'creation_date': '',
                'expiration_date': '',
                'updated_date': '',
                'name_servers': [],
                'status': '',
                'registrant': '',
                'admin_email': '',
                'tech_email': ''
            }
            
            # Extract common fields
            lines = whois_data.split('\n')
            for line in lines:
                line = line.strip()
                if ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip().lower()
                    value = value.strip()
                    
                    if 'registrar' in key and not parsed_data['registrar']:
                        parsed_data['registrar'] = value
                    elif 'creation date' in key or 'created' in key:
                        parsed_data['creation_date'] = value
                    elif 'expiration date' in key or 'expires' in key:
                        parsed_data['expiration_date'] = value
                    elif 'updated date' in key or 'updated' in key:
                        parsed_data['updated_date'] = value
                    elif 'name server' in key or 'nserver' in key:
                        parsed_data['name_servers'].append(value)
                    elif 'status' in key:
                        parsed_data['status'] = value
                    elif 'registrant' in key and 'email' not in key.lower():
                        parsed_data['registrant'] = value
                    elif 'admin' in key and 'email' in key.lower():
                        parsed_data['admin_email'] = value
                    elif 'tech' in key and 'email' in key.lower():
                        parsed_data['tech_email'] = value
            
            return {
                'success': True,
                'data': parsed_data,
                'raw': whois_data
            }
        else:
            return {
                'success': False,
                'error': result.stderr,
                'data': {}
            }
            
    except subprocess.TimeoutExpired:
        return {
            'success': False,
            'error': 'WHOIS timeout',
            'data': {}
        }
    except Exception as e:
        return {
            'success': False,
            'error': str(e),
            'data': {}
        }

def scan_ip_range(ip_range, max_threads=10):
    """Fast IP range scanning using system tools"""
    results = []
    ips = expand_cidr(ip_range)
    
    # Limit IP range to prevent excessive scanning
    if len(ips) > 500:
        ips = ips[:500]  # Limit to first 500 IPs for faster scanning
    
    def scan_single_ip(ip):
        try:
            domains = reverse_dns_lookup(ip)
            if domains:
                result = {
                    'ip': ip,
                    'domains': domains,
                    'ssl_info': {},
                    'sni_info': {},
                    'status': 'active'
                }
                # Store IP data securely
                store_secure_ip_data(
                    ip, domains[0] if domains else '', domains[0] if domains else '',  # hostname
                    {'domains': domains},  # test_results
                    {},  # ssl_info
                    {'domains': domains},  # dns_info
                    {},  # ping_info
                    {}   # http_info
                )
                return result
        except Exception:
            pass
        return None
    
    # Use smaller thread pool for faster results
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        future_to_ip = {executor.submit(scan_single_ip, ip): ip for ip in ips}
        for future in as_completed(future_to_ip):
            result = future.result()
            if result:
                results.append(result)
    
    return results

# Authentication routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Please enter both username and password', 'error')
            return render_template('login.html')
        
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('SELECT id, username, password_hash FROM users WHERE username = ?', (username,))
        user_data = cursor.fetchone()
        conn.close()
        
        if user_data and bcrypt.checkpw(password.encode('utf-8'), user_data[2].encode('utf-8')):
            user = User(user_data[0], user_data[1], user_data[2])
            login_user(user)
            
            # Log access
            log_access(user.id, 'login', 'authentication', request.remote_addr, request.user_agent.string)
            
            # Update last login
            conn = sqlite3.connect(DATABASE)
            cursor = conn.cursor()
            cursor.execute('UPDATE users SET last_login = ? WHERE id = ?', (datetime.utcnow(), user.id))
            conn.commit()
            conn.close()
            
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    log_access(current_user.id, 'logout', 'authentication', request.remote_addr, request.user_agent.string)
    logout_user()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')
        
        if not username or not password:
            flash('Please enter both username and password', 'error')
            return render_template('register.html')
        
        if len(password) < 6:
            flash('Password must be at least 6 characters long', 'error')
            return render_template('register.html')
        
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Check if username already exists
        cursor.execute('SELECT COUNT(*) FROM users WHERE username = ?', (username,))
        if cursor.fetchone()[0] > 0:
            flash('Username already exists', 'error')
            conn.close()
            return render_template('register.html')
        
        # Create new user
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        cursor.execute('''
            INSERT INTO users (username, password_hash, email, role)
            VALUES (?, ?, ?, ?)
        ''', (username, password_hash.decode('utf-8'), email, 'user'))
        
        conn.commit()
        conn.close()
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/')
def index():
    # If user is not logged in, redirect to login
    try:
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
        return render_template('index.html', isps=ZIMBABWE_ISPS)
    except AttributeError:
        # current_user not available, redirect to login
        return redirect(url_for('login'))

# Secure IP storage functions
def store_secure_ip_data(ip_address, domain, hostname, test_results, ssl_info, dns_info, ping_info, http_info):
    """Store IP test data securely in database"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT OR REPLACE INTO secure_ip_storage 
        (ip_address, domain, hostname, test_results, ssl_info, dns_info, ping_info, http_info, last_tested, test_count, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, COALESCE((SELECT test_count FROM secure_ip_storage WHERE ip_address = ?), 0) + 1, ?)
    ''', (
        ip_address, domain, hostname,
        json.dumps(test_results) if test_results else None,
        json.dumps(ssl_info) if ssl_info else None,
        json.dumps(dns_info) if dns_info else None,
        json.dumps(ping_info) if ping_info else None,
        json.dumps(http_info) if http_info else None,
        datetime.utcnow(), ip_address, datetime.utcnow()
    ))
    
    conn.commit()
    conn.close()

def get_secure_ip_data(ip_address=None, limit=100):
    """Get stored IP data (requires authentication)"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    if ip_address:
        cursor.execute('''
            SELECT ip_address, domain, hostname, test_results, ssl_info, dns_info, ping_info, http_info, 
                   last_tested, test_count, status, created_at, updated_at
            FROM secure_ip_storage 
            WHERE ip_address = ?
        ''', (ip_address,))
    else:
        cursor.execute('''
            SELECT ip_address, domain, hostname, test_results, ssl_info, dns_info, ping_info, http_info, 
                   last_tested, test_count, status, created_at, updated_at
            FROM secure_ip_storage 
            ORDER BY last_tested DESC
            LIMIT ?
        ''', (limit,))
    
    results = []
    for row in cursor.fetchall():
        results.append({
            'ip_address': row[0],
            'domain': row[1],
            'hostname': row[2],
            'test_results': json.loads(row[3]) if row[3] else {},
            'ssl_info': json.loads(row[4]) if row[4] else {},
            'dns_info': json.loads(row[5]) if row[5] else {},
            'ping_info': json.loads(row[6]) if row[6] else {},
            'http_info': json.loads(row[7]) if row[7] else {},
            'last_tested': row[8],
            'test_count': row[9],
            'status': row[10],
            'created_at': row[11],
            'updated_at': row[12]
        })
    
    conn.close()
    return results

def log_access(user_id, action, resource, ip_address, user_agent):
    """Log user access for security auditing"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT INTO access_logs (user_id, action, resource, ip_address, user_agent)
        VALUES (?, ?, ?, ?, ?)
    ''', (user_id, action, resource, ip_address, user_agent))
    
    conn.commit()
    conn.close()

@app.route('/scan', methods=['POST'])
def scan():
    data = request.get_json()
    ip_range = data.get('ip_range', '')
    isp = data.get('isp', '')
    ip_list = data.get('ip_list', '')
    
    if ip_list:
        # Scan specific IP list from file
        print(f"Scanning {len(ip_list)} IP addresses from list")
        results = []
        for i, ip in enumerate(ip_list):
            print(f"Scanning IP {i+1}/{len(ip_list)}: {ip}")
            domains = reverse_dns_lookup(ip)
            if domains:
                result = {'ip': ip, 'domains': domains}
                results.append(result)
                # Store IP data securely
                store_secure_ip_data(
                    ip, domains[0] if domains else '', domains[0] if domains else '',  # hostname
                    {'domains': domains},  # test_results
                    {},  # ssl_info
                    {'domains': domains},  # dns_info
                    {},  # ping_info
                    {}   # http_info
                )
                print(f"Found {len(domains)} domains for {ip}")
        
        print(f"IP list scan completed: {len(results)} IPs with domains found")
        return jsonify({'results': results, 'total_ips_scanned': len(results)})
    elif isp and isp in ZIMBABWE_ISPS:
        # Scan only first 10 ranges for faster results
        all_results = []
        ranges_to_scan = ZIMBABWE_ISPS[isp][:10]  # Limit to first 10 ranges
        total_ranges = len(ranges_to_scan)
        
        print(f"Scanning first {total_ranges} {isp} ranges (limited for speed)")
        
        for i, cidr in enumerate(ranges_to_scan):
            print(f"Scanning {isp} range {i+1}/{total_ranges}: {cidr}")
            results = scan_ip_range(cidr)
            all_results.extend(results)
            print(f"Found {len(results)} IPs with domains in {cidr}")
        
        print(f"Total {isp} scan completed: {len(all_results)} IPs with domains found")
        return jsonify({'results': all_results, 'total_ips_scanned': len(all_results)})
    elif ip_range:
        # Scan specific IP range
        print(f"Scanning IP range: {ip_range}")
        results = scan_ip_range(ip_range)
        print(f"Manual scan completed: {len(results)} IPs with domains found")
        return jsonify({'results': results, 'total_ips_scanned': len(results)})
    else:
        return jsonify({'error': 'Please provide an IP range, IP list, or select an ISP'}), 400

@app.route('/api/ssl-test', methods=['POST'])
def api_ssl_test():
    """API endpoint for SSL/TLS testing"""
    data = request.get_json()
    domain = data.get('domain', '')
    port = data.get('port', 443)
    
    if not domain:
        return jsonify({'error': 'No domain provided'}), 400
    
    try:
        ssl_result = test_ssl_certificate(domain, port)
        return jsonify({
            'domain': domain,
            'port': port,
            'timestamp': datetime.utcnow().isoformat(),
            'ssl_test': ssl_result
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/sni-test', methods=['POST'])
def api_sni_test():
    """API endpoint for SNI testing"""
    data = request.get_json()
    domain = data.get('domain', '')
    port = data.get('port', 443)
    
    if not domain:
        return jsonify({'error': 'No domain provided'}), 400
    
    try:
        sni_result = test_sni_support(domain, port)
        return jsonify({
            'domain': domain,
            'port': port,
            'timestamp': datetime.utcnow().isoformat(),
            'sni_test': sni_result
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/dns-test', methods=['POST'])
def api_dns_test():
    """API endpoint for DNS testing"""
    data = request.get_json()
    domain = data.get('domain', '')
    
    if not domain:
        return jsonify({'error': 'No domain provided'}), 400
    
    try:
        dns_result = test_dns_resolution(domain)
        return jsonify({
            'domain': domain,
            'timestamp': datetime.utcnow().isoformat(),
            'dns_test': dns_result
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/http-test', methods=['POST'])
def api_http_test():
    """API endpoint for HTTP testing"""
    data = request.get_json()
    hostname = data.get('hostname', '')
    port = data.get('port', 80)
    
    if not hostname:
        return jsonify({'error': 'No hostname provided'}), 400
    
    try:
        http_result = test_http_response(hostname, port)
        return jsonify({
            'hostname': hostname,
            'port': port,
            'timestamp': datetime.utcnow().isoformat(),
            'http_test': http_result
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/comprehensive-test', methods=['POST'])
def api_comprehensive_test():
    """Comprehensive network diagnostic test with database tracking"""
    data = request.get_json()
    domain = data.get('domain', '')
    isp = data.get('isp', 'global')
    
    if not domain:
        return jsonify({'error': 'No domain provided'}), 400
    
    try:
        # Run all tests
        results = {
            'domain': domain,
            'isp': isp,
            'timestamp': datetime.utcnow().isoformat(),
            'tests': {}
        }
        
        # DNS Test
        dns_result = test_dns_resolution(domain)
        results['tests']['dns'] = dns_result
        
        if dns_result['resolves']:
            ip_address = dns_result['ip_address']
            
            # Ping Test
            ping_result = test_ping(domain)
            results['tests']['ping'] = ping_result
            
            # HTTP Test
            http_result = test_http_response(domain)
            results['tests']['http'] = http_result
            
            # SSL Test
            ssl_result = test_ssl_certificate(domain)
            results['tests']['ssl'] = ssl_result
            
            # SNI Test
            sni_result = test_sni_support(domain)
            results['tests']['sni'] = sni_result
        
        # Overall status
        results['overall_status'] = {
            'passed': sum(1 for test in results['tests'].values() if test.get('resolves') or test.get('valid') or test.get('pingable') or test.get('responds')),
            'total': len(results['tests']),
            'success_rate': 0
        }
        
        if results['overall_status']['total'] > 0:
            results['overall_status']['success_rate'] = round(
                (results['overall_status']['passed'] / results['overall_status']['total']) * 100, 1
            )
        
        return jsonify(results)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/working-hosts', methods=['GET'])
def api_working_hosts():
    """Get list of working hosts with their statistics"""
    try:
        limit = request.args.get('limit')
        if limit is None:
            limit = 50
        else:
            limit = int(limit)
        
        hosts = get_working_hosts(limit)
        return jsonify({
            'hosts': hosts,
            'total': len(hosts),
            'timestamp': datetime.utcnow().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/ping-test', methods=['POST'])
def api_ping_test():
    """Enhanced ping test with statistics"""
    try:
        data = request.get_json()
        hostname = data.get('hostname', '')
        count = data.get('count')
        
        # Convert count to int safely
        if count is None:
            count = 3
        else:
            count = int(count)
        
        if not hostname:
            return jsonify({'error': 'No hostname provided'}), 400
        
        ping_result = test_ping(hostname, count)
        return jsonify({
            'hostname': hostname,
            'timestamp': datetime.utcnow().isoformat(),
            'ping_test': ping_result
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/dns-lookup', methods=['POST'])
def api_dns_lookup():
    """Comprehensive DNS lookup"""
    data = request.get_json()
    hostname = data.get('hostname', '')
    
    if not hostname:
        return jsonify({'error': 'No hostname provided'}), 400
    
    try:
        dns_result = test_dns_lookup(hostname)
        return jsonify({
            'hostname': hostname,
            'timestamp': datetime.utcnow().isoformat(),
            'dns_lookup': dns_result
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/traceroute', methods=['POST'])
def api_traceroute():
    """Traceroute test"""
    try:
        data = request.get_json()
        hostname = data.get('hostname', '')
        max_hops = data.get('max_hops')
        
        # Convert max_hops to int safely
        if max_hops is None:
            max_hops = 30
        else:
            max_hops = int(max_hops)
        
        if not hostname:
            return jsonify({'error': 'No hostname provided'}), 400
        
        traceroute_result = test_traceroute(hostname, max_hops)
        return jsonify({
            'hostname': hostname,
            'timestamp': datetime.utcnow().isoformat(),
            'traceroute': traceroute_result
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/ssl-checker', methods=['POST'])
def api_ssl_checker():
    """SSL certificate checker"""
    try:
        data = request.get_json()
        hostname = data.get('hostname', '')
        port = data.get('port')
        
        # Convert port to int safely
        if port is None:
            port = 443
        else:
            port = int(port)
        
        if not hostname:
            return jsonify({'error': 'No hostname provided'}), 400
        
        ssl_result = test_ssl_certificate(hostname, port)
        return jsonify({
            'hostname': hostname,
            'port': port,
            'timestamp': datetime.utcnow().isoformat(),
            'ssl_certificate': ssl_result
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/whois', methods=['POST'])
def api_whois():
    """WHOIS lookup"""
    try:
        data = request.get_json()
        domain = data.get('domain', '')
        
        if not domain:
            return jsonify({'error': 'No domain provided'}), 400
        
        whois_result = test_whois(domain)
        return jsonify({
            'domain': domain,
            'timestamp': datetime.utcnow().isoformat(),
            'whois': whois_result
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/host-history', methods=['POST'])
def api_host_history():
    """Get test history for a specific host"""
    try:
        data = request.get_json()
        domain = data.get('domain', '')
        limit = data.get('limit')
        if limit is None:
            limit = 20
        else:
            limit = int(limit)
        
        if not domain:
            return jsonify({'error': 'No domain provided'}), 400
        
        history = get_host_history(domain, limit)
        return jsonify({
            'domain': domain,
            'history': history,
            'total': len(history),
            'timestamp': datetime.utcnow().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/balance-check', methods=['POST'])
def api_balance_check():
    """Check mobile balance via USSD"""
    try:
        data = request.get_json()
        phone_number = data.get('phone_number', '')
        network = data.get('network', '').lower()
        balance_type = data.get('balance_type', 'airtime')
        
        if not phone_number:
            return jsonify({'error': 'Phone number is required'}), 400
        
        if network not in ['econet', 'netone']:
            return jsonify({'error': 'Network must be "econet" or "netone"'}), 400
        
        if balance_type not in ['airtime', 'bundle']:
            return jsonify({'error': 'Balance type must be "airtime" or "bundle"'}), 400
        
        # Initialize USSD checker
        ussd_checker = USSDBalanceChecker()
        result = ussd_checker.check_balance(phone_number, network, balance_type)
        
        # Save balance check result to database
        save_balance_check(phone_number, network, balance_type, result)
        
        return jsonify({
            'phone_number': phone_number,
            'network': network,
            'balance_type': balance_type,
            'timestamp': datetime.utcnow().isoformat(),
            'result': result
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/balance-history', methods=['GET'])
def api_balance_history():
    """Get balance check history"""
    try:
        limit = request.args.get('limit')
        if limit is None:
            limit = 50
        else:
            limit = int(limit)
        
        history = get_balance_history(limit)
        return jsonify({
            'history': history,
            'total': len(history),
            'timestamp': datetime.utcnow().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/ussd-codes', methods=['GET'])
def api_ussd_codes():
    """Get available USSD codes for networks"""
    try:
        ussd_codes = {
            'econet': {
                'airtime': '*125#',
                'bundle': '*143#',
                'data_bundles': '*140#',
                'social_bundles': '*152#',
                'international': '*152*1#'
            },
            'netone': {
                'airtime': '*134#',
                'bundle': '*400#',
                'data_bundles': '*410#',
                'social_bundles': '*420#',
                'international': '*123*1#'
            }
        }
        
        return jsonify({
            'ussd_codes': ussd_codes,
            'description': 'Available USSD codes for balance checking',
            'note': 'In production, these would connect to actual USSD gateways'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Secure IP access endpoints
@app.route('/api/secure-ips', methods=['GET'])
@login_required
def api_secure_ips():
    """Get stored IP data (requires authentication)"""
    try:
        limit = request.args.get('limit')
        if limit is None:
            limit = 100
        else:
            limit = int(limit)
        
        ip_address = request.args.get('ip_address')
        
        # Log access
        log_access(current_user.id, 'access', 'secure_ips', request.remote_addr, request.user_agent.string)
        
        results = get_secure_ip_data(ip_address, limit)
        
        return jsonify({
            'results': results,
            'total': len(results),
            'user': current_user.username,
            'timestamp': datetime.utcnow().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/store-ip', methods=['POST'])
@login_required
def api_store_ip():
    """Store IP test data securely (requires authentication)"""
    try:
        data = request.get_json()
        ip_address = data.get('ip_address', '')
        domain = data.get('domain', '')
        hostname = data.get('hostname', '')
        test_results = data.get('test_results', {})
        ssl_info = data.get('ssl_info', {})
        dns_info = data.get('dns_info', {})
        ping_info = data.get('ping_info', {})
        http_info = data.get('http_info', {})
        
        if not ip_address:
            return jsonify({'error': 'IP address is required'}), 400
        
        # Store data securely
        store_secure_ip_data(ip_address, domain, hostname, test_results, ssl_info, dns_info, ping_info, http_info)
        
        # Log access
        log_access(current_user.id, 'store', f'ip:{ip_address}', request.remote_addr, request.user_agent.string)
        
        return jsonify({
            'success': True,
            'message': 'IP data stored successfully',
            'ip_address': ip_address,
            'user': current_user.username,
            'timestamp': datetime.utcnow().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/access-logs', methods=['GET'])
@login_required
def api_access_logs():
    """Get access logs (admin only)"""
    try:
        if current_user.username != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        
        limit = request.args.get('limit')
        if limit is None:
            limit = 100
        else:
            limit = int(limit)
        
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT u.username, al.action, al.resource, al.ip_address, al.user_agent, al.timestamp
            FROM access_logs al
            JOIN users u ON al.user_id = u.id
            ORDER BY al.timestamp DESC
            LIMIT ?
        ''', (limit,))
        
        results = []
        for row in cursor.fetchall():
            results.append({
                'username': row[0],
                'action': row[1],
                'resource': row[2],
                'ip_address': row[3],
                'user_agent': row[4],
                'timestamp': row[5]
            })
        
        conn.close()
        
        return jsonify({
            'logs': results,
            'total': len(results),
            'timestamp': datetime.utcnow().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def save_balance_check(phone_number, network, balance_type, result):
    """Save balance check result to database"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Create balance_checks table if it doesn't exist
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS balance_checks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                phone_number TEXT NOT NULL,
                network TEXT NOT NULL,
                balance_type TEXT NOT NULL,
                success INTEGER NOT NULL,
                balance_data TEXT,
                response_message TEXT,
                session_id TEXT,
                timestamp DATETIME NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Insert balance check result
        cursor.execute('''
            INSERT INTO balance_checks 
            (phone_number, network, balance_type, success, balance_data, response_message, session_id, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            phone_number,
            network,
            balance_type,
            1 if result.get('success') else 0,
            json.dumps(result.get('balance', {})),
            result.get('response', ''),
            result.get('session_id', ''),
            result.get('timestamp', datetime.utcnow().isoformat())
        ))
        
        conn.commit()
        conn.close()
        
    except Exception as e:
        print(f"Error saving balance check: {e}")

def get_balance_history(limit=50):
    """Get balance check history from database"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT phone_number, network, balance_type, success, balance_data, response_message, timestamp
            FROM balance_checks
            ORDER BY timestamp DESC
            LIMIT ?
        ''', (limit,))
        
        results = []
        for row in cursor.fetchall():
            results.append({
                'phone_number': row[0],
                'network': row[1],
                'balance_type': row[2],
                'success': bool(row[3]),
                'balance_data': json.loads(row[4]) if row[4] else {},
                'response_message': row[5],
                'timestamp': row[6]
            })
        
        conn.close()
        return results
        
    except Exception as e:
        print(f"Error getting balance history: {e}")
        return []

@app.route('/test-domain', methods=['POST'])
def test_domain():
    data = request.get_json()
    domain = data.get('domain', '')
    
    if not domain:
        return jsonify({'error': 'No domain provided'}), 400
    
    try:
        # Validate domain format
        if not domain or len(domain) < 3:
            return jsonify({
                'resolves': False,
                'error': 'Invalid domain format'
            })
        
        # Test domain resolution
        ip = socket.gethostbyname(domain)
        
        # Test reverse DNS
        domains = reverse_dns_lookup(ip)
        
        # Test SSL certificate (with timeout)
        try:
            ssl_info = test_ssl_certificate(domain)
        except Exception as ssl_error:
            ssl_info = {'valid': False, 'error': str(ssl_error)}
        
        return jsonify({
            'resolves': True,
            'ip': ip,
            'domains': domains,
            'ssl': ssl_info
        })
        
    except socket.gaierror as e:
        return jsonify({
            'resolves': False,
            'error': f'Domain does not resolve: {str(e)}'
        })
    except Exception as e:
        return jsonify({
            'resolves': False,
            'error': f'Connection error: {str(e)}'
        })

@app.route('/export', methods=['POST'])
def export_results():
    data = request.get_json()
    results = data.get('results', [])
    format_type = data.get('format', 'csv')
    
    if format_type == 'csv':
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Check if these are domain results or IP results
        if results and 'domain' in results[0]:
            # Domain results
            writer.writerow(['Domain', 'Resolves', 'IP Address', 'SSL Valid', 'SSL Issuer', 'SSL Expires'])
            
            for result in results:
                ssl_info = result.get('ssl', {})
                writer.writerow([
                    result.get('domain', 'N/A'),
                    result.get('resolves', 'N/A'),
                    result.get('ip', 'N/A'),
                    ssl_info.get('valid', 'N/A'),
                    ssl_info.get('issuer', {}).get('commonName', 'N/A') if ssl_info.get('valid') else 'N/A',
                    ssl_info.get('not_after', 'N/A') if ssl_info.get('valid') else 'N/A'
                ])
        else:
            # IP results
            writer.writerow(['IP Address', 'Domain', 'SSL Valid', 'SSL Subject', 'SSL Expires', 'SNI Supported'])
            
            for result in results:
                ip = result['ip']
                for domain in result['domains']:
                    ssl_info = result['ssl_info'].get(domain, {})
                    sni_info = result['sni_info'].get(domain, {})
                    
                    writer.writerow([
                        ip,
                        domain,
                        ssl_info.get('valid', 'N/A'),
                        ssl_info.get('subject', {}).get('commonName', 'N/A') if ssl_info.get('valid') else 'N/A',
                        ssl_info.get('not_after', 'N/A') if ssl_info.get('valid') else 'N/A',
                        sni_info.get('sni_supported', 'N/A')
                    ])
        
        output.seek(0)
        return send_file(
            io.BytesIO(output.getvalue().encode()),
            mimetype='text/csv',
            as_attachment=True,
            download_name=f'scan_results_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
        )
    
    elif format_type == 'json':
        json_data = json.dumps(results, indent=2)
        return send_file(
            io.BytesIO(json_data.encode()),
            mimetype='application/json',
            as_attachment=True,
            download_name=f'scan_results_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        )
    
    return jsonify({'error': 'Invalid format'}), 400

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)
