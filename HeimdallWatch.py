import requests
import dns.resolver
import argparse
from datetime import datetime
import json
import numpy as np
from sklearn.ensemble import RandomForestClassifier
import colorama
from colorama import Fore, Back, Style
import threading
import time
import socket
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress
import whois
import ssl
import certifi
import random
import tldextract
from urllib.parse import urlparse
import subprocess
import os


colorama.init(autoreset=True)
def print_banner():
    print(f"""
{Fore.RED}[x] {Fore.WHITE}OPERATOR: {Fore.LIGHTBLACK_EX}[NoneR00tk1t]
{Fore.RED}[x] {Fore.WHITE}TEAM: {Fore.LIGHTBLACK_EX}[Valhala]
{Fore.LIGHTMAGENTA_EX}
                               █                                                                                                                           
                              ██                                                   █████████                                     █                          
                          ███  █                 ████████                         █  ██████████                                 ████                        
                         █     █               █     █████                             ██████  ██                              █                            
                        █  █  █               ██   ██                                        █████                             ████ █                       
                       ██  ███               ██  ████                                       █ █  █                             █ ██ █                       
                           █                 █  ████████ ███  █                          █ ███ ██                █  █           ██ █                        
                        █   ██                  █      █   ██  █                      ██ ███ ███              ███████████       ████                        
                    █     ██   █            ██ ██    ███   █    ██                     ██ ███                ███████  ██████    ██                          
               ██       ██  █    █           █ ██    █    █   █                     █ █ █ █████              █ ██     █ █ ███ ████ ███   ██ ██              
              █    ██     ██ █   █           █  ██   █   █     █                     ███ █ ███████████       ████ █      ███  ██ ███████████████            
            ██   ██   ██        ██            █   ███        ██████████               ████████████ █████       █████████    █ █ ███ ████  ███████           
            ██  █        ██   ███              ██    ████████           ██                       ███ ████       ████ ██ ██ █████  ██         ████           
            ██  █     ███ ███████ █                ██     █     █   ██   █           ██████████    ███ ███         ███████  █  █            █ ███           
             ██  ████   █   █ █ █  █               █████ █    █      █    █       ██     █   ██ █████  ██       ██       █  █             █   ██            
              █████ ████ █    ██████          ███████████  ████████  █   █       █    ████ ██ ██████████              █ █     █  █ ██ ██     ██             
                 ███      █████   █        ███  ███ ███████████████     █           █           ███ █        █   ██       ██  █  █          █               
                 █   █ █ █     ███        ██   █  █████ ██         █ ██         █  ██████████                 █  █             ███ ███████                  
                █  ██                     █   ██        ██ ███ █ █ █ ████        █  ███████████                  ███       █ ███████████████                
                ██ ███  █  █               █    ██      █ █   ███████    █         ███   ██████                █  ██████████ ██ █       █████               
                 ██    █ ██    █            █      █ █     █ ███      █   █            ███████                   ███  █████  █ █ █  █   █████               
                    ███  ████   █              ██       ████████ █████  ██            █████                           █ ███████████████████                 
                      ███ █ ██   █                ██ ██████████       ███            ████                           ████████  ██ █                          
                   █ ██   █  ██  █                █     ███                           ███████                      ████  █  █  ███                          
                  █  █     █    █                ██ █ █   ██ █                            █ ██                    ██ █  ██ ██████                           
                   █  ██      █                   ██ ██████  █                           ████                      ██ ██ ██ █                               
                     ████████                       ██ ██████                           █ █                          ███  █ ███████                         
                         █ █                             █   ██                            █                                      ██                        
                         ██                                    █                         █                                        █                         
                         █                                █████                          █                                      █                           
                         █                              █                                █                                     █                            
                          █                                                              █                                    █   
                                                              by NoneR00tk1t
{Style.RESET_ALL}
""")

CLOUDFLARE_IP_RANGES = [
    "https://www.cloudflare.com/ips-v4",
    "https://www.cloudflare.com/ips-v6"
]

common_subdomains = [
    'www', 'mail', 'ftp', 'webmail', 'smtp', 'pop', 'ns1', 'ns2', 'ns3',
    'dev', 'test', 'staging', 'api', 'blog', 'shop', 'forum', 'admin',
    'secure', 'vpn', 'portal', 'cdn', 'assets', 'static', 'media',
    'app', 'apps', 'beta', 'alpha', 'demo', 'docs', 'support', 'help',
    'shop', 'store', 'payment', 'billing', 'account', 'login', 'signin',
    'api2', 'api3', 'internal', 'external', 'proxy', 'cache', 'img',
    'images', 'video', 'download', 'upload', 'files', 'db', 'database',
    'backup', 'monitor', 'status', 'stats', 'analytics', 'tracking'
]

KNOWN_SERVICE_IPS = {
    'aws': ['3.0.0.0/8', '13.0.0.0/8', '18.0.0.0/8', '23.20.0.0/14', '34.0.0.0/8'],
    'gcp': ['8.8.8.8/32', '8.8.4.4/32', '35.0.0.0/8', '104.154.0.0/15'],
    'azure': ['13.64.0.0/11', '40.74.0.0/15', '52.0.0.0/10', '104.40.0.0/13'],
    'digitalocean': ['104.131.0.0/16', '104.236.0.0/16', '159.203.0.0/16'],
    'linode': ['45.33.0.0/16', '45.56.0.0/16', '50.116.0.0/16']
}

class AdvancedIPClassifier:
    def __init__(self):
        self.model = RandomForestClassifier(n_estimators=200, random_state=42, max_depth=10)
        self.trained = False
        self.feature_importances_ = None

    def extract_features(self, ip):
        try:
            ip_obj = ipaddress.ip_address(ip)
            octets = list(map(int, ip.split('.'))) if '.' in ip else [0, 0, 0, 0]
            
            is_private = 1 if ip_obj.is_private else 0
            is_multicast = 1 if ip_obj.is_multicast else 0
            is_global = 1 if ip_obj.is_global else 0
            
            is_known_service = 0
            for service, ranges in KNOWN_SERVICE_IPS.items():
                for range_ip in ranges:
                    if ip_obj in ipaddress.ip_network(range_ip):
                        is_known_service = 1
                        break
            
            entropy = len(set(ip)) / len(ip) if len(ip) > 0 else 0
            digit_ratio = sum(1 for c in ip if c.isdigit()) / len(ip) if len(ip) > 0 else 0
            
            is_cloudflare = 1 if ip in known_cloudflare_ips else 0
            
            first_octet = octets[0] if len(octets) > 0 else 0
            second_octet = octets[1] if len(octets) > 1 else 0
            
            return [
                first_octet, second_octet, octets[2] if len(octets) > 2 else 0, octets[3] if len(octets) > 3 else 0,
                is_private, is_multicast, is_global, is_known_service,
                entropy, digit_ratio, is_cloudflare
            ]
        except ValueError:
            return [0] * 11

    def train(self):
        training_data = [
            ('104.16.0.0', 0), ('172.67.0.0', 0), ('108.162.0.0', 0),
            ('173.245.48.0', 0), ('141.101.64.0', 0), ('190.93.240.0', 0),
            
            ('192.168.1.1', 1), ('10.0.0.1', 1), ('172.16.0.1', 1),
            ('203.0.113.1', 1), ('198.51.100.1', 1), ('8.8.8.8', 1),
            ('1.1.1.1', 1), ('45.33.23.1', 1), ('104.131.0.1', 1),
            ('159.203.0.1', 1), ('34.120.0.1', 1), ('52.0.0.1', 1),
            
            ('127.0.0.1', 1), ('0.0.0.0', 1), ('255.255.255.255', 1)
        ]
        
        features = [self.extract_features(ip) for ip, _ in training_data]
        labels = [label for _, label in training_data]
        
        self.model.fit(features, labels)
        self.feature_importances_ = self.model.feature_importances_
        self.trained = True

    def predict(self, ip):
        if not self.trained:
            self.train()
        features = self.extract_features(ip)
        return self.model.predict_proba([features])[0][1]

def update_database():
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Updating Cloudflare IP database...")
    
    global known_cloudflare_ips
    known_cloudflare_ips = set()
    
    for url in CLOUDFLARE_IP_RANGES:
        try:
            response = requests.get(url, timeout=15, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })
            if response.status_code == 200:
                ip_ranges = response.text.strip().split('\n')
                for ip_range in ip_ranges:
                    if ip_range and not ip_range.startswith('#'):
                        try:
                            network = ipaddress.ip_network(ip_range)
                            known_cloudflare_ips.update(str(ip) for ip in network)
                        except ValueError:
                            continue
        except Exception as e:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Error updating from {url}: {e}")
    
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Database updated with {len(known_cloudflare_ips)} Cloudflare IPs")

def scan_dns(target):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Scanning DNS for {target}...")
    
    ips = set()
    targets = [target] + [f"{sub}.{target}" for sub in common_subdomains]
    
    record_types = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS']
    
    def resolve_target(target_domain, record_type):
        try:
            answers = dns.resolver.resolve(target_domain, record_type, lifetime=8)
            results = set()
            for rdata in answers:
                if record_type == 'A':
                    results.add(str(rdata.address))
                elif record_type == 'AAAA':
                    results.add(str(rdata.address))
                elif record_type == 'CNAME':
                    try:
                        cname_answers = dns.resolver.resolve(str(rdata.target), 'A', lifetime=5)
                        for cname_rdata in cname_answers:
                            results.add(str(cname_rdata.address))
                    except:
                        pass
            return results
        except:
            return set()
    
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = []
        for target_domain in targets:
            for record_type in record_types:
                futures.append(executor.submit(resolve_target, target_domain, record_type))
        
        for future in as_completed(futures):
            try:
                ips.update(future.result())
            except:
                pass
    
    return ips

def verify_ip(ip):
    try:
        socket.inet_pton(socket.AF_INET, ip)
        return True
    except socket.error:
        try:
            socket.inet_pton(socket.AF_INET6, ip)
            return True
        except socket.error:
            return False

def check_ssl_certificate(ip, domain):
    try:
        context = ssl.create_default_context(cafile=certifi.where())
        with socket.create_connection((ip, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                subject = dict(x[0] for x in cert['subject'])
                common_name = subject.get('commonName', '')
                return common_name.endswith(domain)
    except:
        return False

def perform_http_scan(ip, domain):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Connection': 'close'
    }
    
    try:
        response = requests.get(f"http://{ip}", headers=headers, timeout=8, 
                              allow_redirects=False, verify=False)
        server_header = response.headers.get('Server', '').lower()
        
        origin_indicators = ['apache', 'nginx', 'iis', 'lightspeed', 'openresty']
        is_origin_server = any(indicator in server_header for indicator in origin_indicators)
        
        return {
            'status_code': response.status_code,
            'server': server_header,
            'is_origin_server': is_origin_server,
            'content_length': len(response.content)
        }
    except:
        return None

def main(target):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Initializing CloudAIReveal - Date: {datetime.now().strftime('%m/%d/%Y')}")
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Target: {target}")
    
    extracted = tldextract.extract(target)
    if not extracted.domain or not extracted.suffix:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Invalid domain format, exiting...")
        return
    
    update_database()
    
    classifier = AdvancedIPClassifier()
    
    potential_ips = scan_dns(target)
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Found {len(potential_ips)} potential IP addresses")
    
    real_ips = []
    
    for ip in potential_ips:
        if not verify_ip(ip):
            continue
        
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Analyzing {ip}...")
        
        if ip in known_cloudflare_ips:
            continue
        
        probability = classifier.predict(ip)
        
        ssl_match = check_ssl_certificate(ip, target)
        http_info = perform_http_scan(ip, target)
        
        confidence = probability
        if ssl_match:
            confidence += 0.15
        if http_info and http_info.get('is_origin_server'):
            confidence += 0.10
        
        confidence = min(confidence, 1.0)  
        
        if confidence > 0.65:  
            real_ips.append({
                "ip": ip,
                "confidence": round(confidence, 3),
                "ssl_match": ssl_match,
                "http_info": http_info,
                "ml_score": round(probability, 3)
            })
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Real IP found: {ip} (Confidence: {confidence:.3f})")
    
    result = {
        "target": target,
        "scan_date": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "real_ips": real_ips,
        "total_ips_scanned": len(potential_ips),
        "cloudflare_ips_detected": len([ip for ip in potential_ips if ip in known_cloudflare_ips]),
        "classifier_accuracy": "Trained on real-world IP patterns",
        "scan_duration": f"{time.time() - start_time:.2f} seconds"
    }
    
    print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Scan complete. Results:")
    print(json.dumps(result, indent=2))
    
    filename = f"scan_results_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, 'w') as f:
        json.dump(result, f, indent=2)
    
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Results saved to {filename}")

if __name__ == "__main__":
    print_banner()
    start_time = time.time()
    
    parser = argparse.ArgumentParser(description="CloudAIReveal - Advanced Cloudflare IP Detection")
    parser.add_argument("-t", "--target", required=True, help="Target domain (e.g., example.com)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    try:
        main(args.target)
    except KeyboardInterrupt:
        print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Scan interrupted by user")
    except Exception as e:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Error: {e}")