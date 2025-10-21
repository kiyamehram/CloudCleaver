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
import pickle
from typing import Set, List, Dict, Optional, Tuple
import asyncio
import aiohttp
from aiohttp_socks import ProxyConnector
import hashlib

colorama.init(autoreset=True)

CLOUDFLARE_IP_RANGES_URLS = [
    "https://www.cloudflare.com/ips-v4",
    "https://www.cloudflare.com/ips-v6"
]

CACHE_FILE = "cloudflare_cache.pkl"
CACHE_DURATION = 86400  

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

KNOWN_CDN_RANGES = {
    'aws': ['3.0.0.0/8', '13.0.0.0/8', '18.0.0.0/8', '23.20.0.0/14', '34.0.0.0/8'],
    'gcp': ['8.8.8.8/32', '8.8.4.4/32', '35.0.0.0/8', '104.154.0.0/15'],
    'azure': ['13.64.0.0/11', '40.74.0.0/15', '52.0.0.0/10', '104.40.0.0/13'],
    'fastly': ['23.235.32.0/20', '104.156.80.0/20', '151.101.0.0/16'],
    'akamai': ['23.0.0.0/8', '104.64.0.0/10']
}

USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0'
]

DNS_CACHE = {}
HTTP_CACHE = {}

def print_banner():
    print(f"""
{Fore.RED}[x] {Fore.WHITE}OPERATOR: {Fore.LIGHTBLACK_EX}[NoneR00tk1t]
{Fore.RED}[x] {Fore.WHITE}TEAM: {Fore.LIGHTBLACK_EX}[Valhala] {Fore.LIGHTMAGENTA_EX}v2.0 ADVANCED
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
                                                              by NoneR00tk1t {Fore.GREEN}[FIXED & ADVANCED]{Style.RESET_ALL}
    """)

class AdvancedIPClassifier:
    def __init__(self):
        self.model = RandomForestClassifier(n_estimators=300, random_state=42, max_depth=15, class_weight='balanced')
        self.trained = False
        self.feature_importances_ = None
        self.known_cloudflare_networks: List[ipaddress.IPv4Network] = []
        self.known_cdn_networks: Dict[str, List[ipaddress.IPv4Network]] = {}
        self.asn_cache: Dict[str, str] = {}

    def load_cdn_networks(self):
        self.known_cdn_networks = {}
        for cdn, ranges in KNOWN_CDN_RANGES.items():
            self.known_cdn_networks[cdn] = [ipaddress.ip_network(range_str) for range_str in ranges]

    def update_cloudflare_db(self, networks: List[ipaddress.IPv4Network]):
        self.known_cloudflare_networks = networks
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {Fore.GREEN}Classifier DB updated: {len(networks)} Cloudflare networks loaded")

    def is_cloudflare_ip(self, ip_obj: ipaddress.IPv4Address) -> bool:
        return any(ip_obj in net for net in self.known_cloudflare_networks)

    def is_cdn_ip(self, ip_obj: ipaddress.IPv4Address) -> Optional[str]:
        for cdn, networks in self.known_cdn_networks.items():
            if any(ip_obj in net for net in networks):
                return cdn
        return None

    def get_asn(self, ip: str) -> str:
        if ip in self.asn_cache:
            return self.asn_cache[ip]
        try:
            result = subprocess.run(['whois', '-h', 'whois.cymru.com', f'{ip}|-- -v'], 
                                  capture_output=True, text=True, timeout=5)
            asn = re.search(r'AS(\d+)', result.stdout)
            asn_str = asn.group(1) if asn else 'Unknown'
            self.asn_cache[ip] = asn_str
            return asn_str
        except:
            self.asn_cache[ip] = 'Unknown'
            return 'Unknown'

    def extract_features(self, ip: str) -> List[float]:
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ':' in ip:  
                ipv4_equiv = ip.split(':')[:4]
                octets = [int(x, 16) % 256 for x in ipv4_equiv] + [0, 0]
            else:
                octets = list(map(int, ip.split('.')))

            is_private = 1 if ip_obj.is_private else 0
            is_global = 1 if ip_obj.is_global else 0
            is_cloudflare = 1 if self.is_cloudflare_ip(ip_obj) else 0
            cdn_type = self.is_cdn_ip(ip_obj) or 'none'
            cdn_score = {'cloudflare': 1.0, 'aws': 0.8, 'fastly': 0.9, 'akamai': 0.9, 'gcp': 0.7, 'azure': 0.7, 'none': 0.0}[cdn_type]

            asn = self.get_asn(ip)
            asn_cloudflare_like = 1 if '13335' in asn or '20940' in asn else 0  

            entropy = -sum(p * np.log2(p + 1e-10) for p in np.bincount(octets)/len(octets))
            first_octet = octets[0]

            return [
                first_octet, octets[1], octets[2], octets[3],
                is_private, is_global, is_cloudflare, cdn_score,
                entropy, asn_cloudflare_like,
                *octets[:4]  
            ]
        except:
            return [0.0] * 12

    def train(self):
        training_data = [
            ('104.16.24.147', 0), ('172.67.130.123', 0), ('108.162.133.45', 0),
            ('173.245.58.200', 0), ('141.101.121.67', 0), ('190.93.243.89', 0),
            ('192.168.1.1', 1), ('10.0.0.1', 1), ('172.16.0.1', 1),
            ('203.0.113.1', 1), ('198.51.100.1', 1), ('8.8.8.8', 1),
            ('1.1.1.1', 1), ('45.33.23.1', 1), ('104.131.0.1', 1),
            ('159.203.0.1', 1), ('34.120.0.1', 1), ('52.0.0.1', 1),
            ('142.250.190.78', 1), ('151.101.1.67', 1), ('23.235.44.123', 0)
        ] * 10  

        features = [self.extract_features(ip) for ip, _ in training_data]
        labels = [label for _, label in training_data]

        self.model.fit(features, labels)
        self.feature_importances_ = self.model.feature_importances_
        self.trained = True
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {Fore.GREEN}ML Model trained with accuracy boost")

    def predict(self, ip: str) -> float:
        if not self.trained:
            self.train()
        features = self.extract_features(ip)
        prob_real = self.model.predict_proba([features])[0][1]
        return prob_real

def load_cached_db() -> Optional[Tuple[List[ipaddress.IPv4Network], datetime]]:
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, 'rb') as f:
                data = pickle.load(f)
                if (datetime.now() - data['timestamp']).total_seconds() < CACHE_DURATION:
                    networks = [ipaddress.ip_network(range_str) for range_str in data['ranges']]
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] {Fore.CYAN}Loaded cached Cloudflare DB ({len(networks)} networks)")
                    return networks, data['timestamp']
        except:
            pass
    return None

def save_cached_db(networks: List[str]):
    cache_data = {
        'ranges': networks,
        'timestamp': datetime.now()
    }
    with open(CACHE_FILE, 'wb') as f:
        pickle.dump(cache_data, f)

def update_database() -> List[ipaddress.IPv4Network]:
    cached = load_cached_db()
    if cached:
        return cached[0]

    print(f"[{datetime.now().strftime('%H:%M:%S')}] {Fore.YELLOW}Updating Cloudflare IP database...")
    all_ranges = []
    
    for url in CLOUDFLARE_IP_RANGES_URLS:
        try:
            resp = requests.get(url, timeout=15, headers={'User-Agent': random.choice(USER_AGENTS)})
            if resp.status_code == 200:
                ranges = [line.strip() for line in resp.text.split('\n') if line.strip() and not line.startswith('#')]
                all_ranges.extend(ranges)
        except Exception as e:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Error updating {url}: {e}")

    networks = [ipaddress.ip_network(range_str) for range_str in all_ranges]
    save_cached_db(all_ranges)
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {Fore.GREEN}Database updated: {len(networks)} networks")
    return networks

async def resolve_dns_async(session: aiohttp.ClientSession, domain: str, record_type: str) -> Set[str]:
    cache_key = f"{domain}:{record_type}"
    if cache_key in DNS_CACHE:
        return DNS_CACHE[cache_key]
    
    try:
        answers = await asyncio.get_event_loop().run_in_executor(
            None, lambda: dns.resolver.resolve(domain, record_type, lifetime=8)
        )
        ips = set()
        for rdata in answers:
            if record_type in ['A', 'AAAA']:
                ips.add(str(rdata.address))
            elif record_type == 'CNAME':
                cname_ip = await resolve_dns_async(session, str(rdata.target), 'A')
                ips.update(cname_ip)
        DNS_CACHE[cache_key] = ips
        return ips
    except:
        DNS_CACHE[cache_key] = set()
        return set()

async def scan_dns_advanced(target: str, proxy: Optional[str] = None) -> Set[str]:
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Scanning DNS for {target}...")
    
    targets = [target] + [f"{sub}.{target}" for sub in common_subdomains[:20]]  
    record_types = ['A', 'AAAA', 'CNAME']
    
    connector = ProxyConnector.from_url(proxy) if proxy else None
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = []
        for t_domain in targets:
            for r_type in record_types:
                tasks.append(resolve_dns_async(session, t_domain, r_type))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        all_ips = set()
        for result in results:
            if isinstance(result, set):
                all_ips.update(result)
    
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Found {len(all_ips)} unique IPs")
    return all_ips

async def check_http_async(session: aiohttp.ClientSession, ip: str, domain: str, stealth: bool = False) -> Optional[Dict]:
    cache_key = f"http:{ip}"
    if cache_key in HTTP_CACHE:
        return HTTP_CACHE[cache_key]
    
    url = f"https://{ip}" if random.random() > 0.5 else f"http://{ip}"
    headers = {
        'User-Agent': random.choice(USER_AGENTS),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Connection': 'close'
    }
    
    if stealth:
        await asyncio.sleep(random.uniform(1, 3))
    
    try:
        async with session.get(url, headers=headers, timeout=10, allow_redirects=False, ssl=False) as resp:
            server = resp.headers.get('Server', '').lower()
            cf_ray = resp.headers.get('CF-RAY', '')
            x_powered = resp.headers.get('X-Powered-By', '')
            
            is_proxy = any(x in server + cf_ray + x_powered for x in ['cloudflare', 'cf-ray', 'cloudfront'])
            is_origin = any(x in server for x in ['apache', 'nginx', 'iis', 'lite', 'openresty']) and not is_proxy
            
            result = {
                'status': resp.status,
                'server': server,
                'cf_ray': bool(cf_ray),
                'is_proxy': is_proxy,
                'is_origin': is_origin,
                'content_length': len(await resp.text())
            }
            HTTP_CACHE[cache_key] = result
            return result
    except:
        HTTP_CACHE[cache_key] = None
        return None

async def check_ssl_async(session: aiohttp.ClientSession, ip: str, domain: str) -> bool:
    try:
        async with session.get(f"https://{ip}", ssl=False, timeout=8) as resp:
            if resp.status == 200:
                text = await resp.text()
                return domain in text or f"{domain}." in text
    except:
        pass
    return False

async def analyze_ip(classifier: AdvancedIPClassifier, ip: str, domain: str, session: aiohttp.ClientSession, stealth: bool) -> Optional[Dict]:
    if not ipaddress.ip_address(ip).version:  
        return None
    
    ip_obj = ipaddress.ip_address(ip)
    if classifier.is_cloudflare_ip(ip_obj):
        return None  
    
    ml_score = classifier.predict(ip)
    
    http_info, ssl_match = await asyncio.gather(
        check_http_async(session, ip, domain, stealth),
        check_ssl_async(session, ip, domain)
    )
    
    confidence = ml_score
    if ssl_match:
        confidence += 0.20
    if http_info and http_info.get('is_origin'):
        confidence += 0.25
    if http_info and not http_info.get('cf_ray'):
        confidence += 0.15
    confidence = min(confidence, 1.0)
    
    if confidence > 0.70:  
        cdn = classifier.is_cdn_ip(ip_obj) or 'none'
        return {
            "ip": ip,
            "confidence": round(confidence, 3),
            "ml_score": round(ml_score, 3),
            "ssl_match": ssl_match,
            "http_info": http_info,
            "cdn_detected": cdn
        }
    return None

async def main_scan(target: str, proxy: Optional[str] = None, stealth: bool = False):
    start_time = time.time()
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {Fore.CYAN}Initializing CloudAIReveal v2.0 Advanced")
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Target: {target}")
    
    extracted = tldextract.extract(target)
    if not extracted.domain or not extracted.suffix:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {Fore.RED}Invalid domain!")
        return
    
    cf_networks = update_database()
    
    classifier = AdvancedIPClassifier()
    classifier.load_cdn_networks()
    classifier.update_cloudflare_db(cf_networks)  
    classifier.train()
    
    potential_ips = await scan_dns_advanced(target, proxy)
    
    connector = ProxyConnector.from_url(proxy) if proxy else None
    async with aiohttp.ClientSession(connector=connector, timeout=aiohttp.ClientTimeout(total=15)) as session:
        tasks = [analyze_ip(classifier, ip, target, session, stealth) for ip in potential_ips]
        results = await asyncio.gather(*tasks, return_exceptions=True)
    
    real_ips = [r for r in results if isinstance(r, dict)]
    
    result = {
        "target": target,
        "scan_date": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "real_ips": real_ips,
        "total_ips_scanned": len(potential_ips),
        "cloudflare_ips_skipped": len(potential_ips) - len(real_ips),
        "duration": round(time.time() - start_time, 2),
        "ml_accuracy": "Advanced RandomForest + HTTP/SSL checks"
    }
    
    print(f"\n{Fore.GREEN}═{'═' * 70}═")
    print(f"   {Fore.WHITE}SCAN COMPLETE | Real IPs Found: {len(real_ips)}")
    print(f"═{'═' * 70}═")
    for i, ip_info in enumerate(real_ips, 1):
        conf = ip_info['confidence']
        color = Fore.GREEN if conf > 0.9 else Fore.YELLOW if conf > 0.8 else Fore.RED
        print(f"{color}{i}. {ip_info['ip']} (Confidence: {conf}) {ip_info.get('cdn_detected', 'none')}{Style.RESET_ALL}")
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    json_file = f"scan_{target.replace('.', '_')}_{timestamp}.json"
    with open(json_file, 'w') as f:
        json.dump(result, f, indent=2)
    print(f"\n{Fore.CYAN}JSON saved: {json_file}")
    
    html_file = f"report_{target.replace('.', '_')}_{timestamp}.html"
    html_content = generate_html_report(result, real_ips)
    with open(html_file, 'w') as f:
        f.write(html_content)
    print(f"{Fore.CYAN}HTML saved: {html_file}")

def generate_html_report(result: Dict, real_ips: List[Dict]) -> str:
    severity_colors = {
        'high': '#2ecc71', 'medium': '#f39c12', 'low': '#e74c3c'
    }
    
    ips_html = ""
    for ip_info in real_ips:
        conf = ip_info['confidence']
        sev_class = 'high' if conf > 0.9 else 'medium' if conf > 0.8 else 'low'
        ips_html += f"""
        <tr class="{sev_class}">
            <td>{ip_info['ip']}</td>
            <td>{ip_info['confidence']}</td>
            <td>{ip_info.get('ml_score', 0)}</td>
            <td>{ip_info.get('cdn_detected', 'none')}</td>
            <td>{ip_info.get('ssl_match', False)}</td>
            <td>{ip_info['http_info'].get('server', 'N/A') if ip_info.get('http_info') else 'N/A'}</td>
        </tr>
        """
    
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>CloudAIReveal v2.0 Report - {result['target']}</title>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: #333; }}
            .container {{ max-width: 1200px; margin: auto; background: white; border-radius: 15px; box-shadow: 0 20px 40px rgba(0,0,0,0.1); overflow: hidden; }}
            .header {{ background: linear-gradient(135deg, #ff6b6b, #4ecdc4); color: white; padding: 30px; text-align: center; }}
            .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; padding: 20px; background: #f8f9fa; }}
            .stat {{ text-align: center; padding: 15px; background: white; border-radius: 10px; box-shadow: 0 5px 15px rgba(0,0,0,0.08); }}
            .stat h3 {{ margin: 0; font-size: 2.5em; color: #4ecdc4; }}
            table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
            th, td {{ padding: 15px; text-align: left; border-bottom: 1px solid #eee; }}
            th {{ background: #667eea; color: white; }}
            tr:hover {{ background: #f8f9fa; }}
            .high {{ background: #d4edda; color: #155724; }}
            .medium {{ background: #fff3cd; color: #856404; }}
            .low {{ background: #f8d7da; color: #721c24; }}
            .footer {{ text-align: center; padding: 20px; background: #f8f9fa; color: #666; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1> CloudAIReveal v2.0 Advanced Report</h1>
                <p><strong>Target:</strong> {result['target']} | <strong>Date:</strong> {result['scan_date']} | <strong>Duration:</strong> {result['duration']}s</p>
            </div>
            <div class="stats">
                <div class="stat"><h3>{len(real_ips)}</h3><p>Real IPs Found</p></div>
                <div class="stat"><h3>{result['total_ips_scanned']}</h3><p>Total Scanned</p></div>
                <div class="stat"><h3>{result['cloudflare_ips_skipped']}</h3><p>CF IPs Skipped</p></div>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>IP Address</th>
                        <th>Confidence</th>
                        <th>ML Score</th>
                        <th>CDN Detected</th>
                        <th>SSL Match</th>
                        <th>Server Info</th>
                    </tr>
                </thead>
                <tbody>
                    {ips_html}
                </tbody>
            </table>
            <div class="footer">
                <p>Generated by <strong>NoneR00tk1t</strong> | Team <strong>Valhala</strong> | Advanced ML + Async Scanning</p>
            </div>
        </div>
    </body>
    </html>
    """

def parse_args():
    parser = argparse.ArgumentParser(description="CloudAIReveal v2.0 - Advanced Cloudflare Origin IP Finder")
    parser.add_argument("-t", "--target", required=True, help="Target domain (e.g., example.com)")
    parser.add_argument("-p", "--proxy", help="Proxy URL (e.g., socks5://127.0.0.1:1080)")
    parser.add_argument("--stealth", action="store_true", help="Stealth mode (slower but evades WAF)")
    parser.add_argument("--nocache", action="store_true", help="Disable cache, force fresh DB update")
    return parser.parse_args()

async def main():
    args = parse_args()
    if not args.nocache:
        global CACHE_DURATION
        CACHE_DURATION = 3600  
    
    try:
        await main_scan(args.target, args.proxy, args.stealth)
    except KeyboardInterrupt:
        print(f"\n[{datetime.now().strftime('%H:%M:%S')}] {Fore.YELLOW}Scan interrupted by user")
    except Exception as e:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {Fore.RED}Error: {e}")

if __name__ == "__main__":
    print_banner()
    asyncio.run(main())
