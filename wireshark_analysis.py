
#!/usr/bin/env python3
"""
Wireshark PCAP Analysis Tool
B205 Computer Networks - Task 2
Network Traffic Analysis and Firewall Rule Generation

This tool analyzes PCAP files to:
- Extract network traffic patterns
- Identify potential security threats
- Generate firewall rules
- Provide network topology insights

Requirements:
pip install scapy matplotlib seaborn pandas plotly
"""

import os
import sys
import json
import logging
from datetime import datetime
from collections import defaultdict, Counter
from typing import Dict, List, Set, Tuple, Any
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.http import HTTPRequest, HTTPResponse
    from scapy.layers.dns import DNS, DNSQR
except ImportError:
    print("Error: Please install scapy: pip install scapy")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('wireshark_analysis.log'),
        logging.StreamHandler()
    ]
)

class NetworkTrafficAnalyzer:
    """Comprehensive network traffic analyzer for PCAP files"""
    
    def __init__(self, pcap_file: str):
        self.pcap_file = pcap_file
        self.packets = []
        self.analysis_results = {}
        self.security_threats = []
        self.firewall_rules = []
        
        # Traffic statistics
        self.protocol_stats = Counter()
        self.ip_stats = Counter()
        self.port_stats = Counter()
        self.connection_pairs = Counter()
        self.dns_queries = []
        self.http_requests = []
        
        # Security analysis
        self.suspicious_ips = set()
        self.port_scans = defaultdict(set)
        self.ddos_suspects = defaultdict(int)
        self.unusual_traffic = []
        
    def load_pcap(self) -> bool:
        """Load and parse PCAP file"""
        try:
            logging.info(f"Loading PCAP file: {self.pcap_file}")
            self.packets = rdpcap(self.pcap_file)
            logging.info(f"Loaded {len(self.packets)} packets")
            return True
        except Exception as e:
            logging.error(f"Error loading PCAP file: {e}")
            return False
    
    def analyze_basic_statistics(self):
        """Analyze basic network statistics"""
        logging.info("Analyzing basic network statistics...")
        
        total_packets = len(self.packets)
        total_size = sum(len(pkt) for pkt in self.packets)
        
        # Time analysis
        if self.packets:
            start_time = float(self.packets[0].time)
            end_time = float(self.packets[-1].time)
            duration = end_time - start_time
        else:
            start_time = end_time = duration = 0.0
        
        # Protocol analysis
        for pkt in self.packets:
            if IP in pkt:
                self.protocol_stats[pkt[IP].proto] += 1
                self.ip_stats[pkt[IP].src] += 1
                self.ip_stats[pkt[IP].dst] += 1
                
                # TCP/UDP port analysis
                if TCP in pkt:
                    self.port_stats[pkt[TCP].dport] += 1
                    self.port_stats[pkt[TCP].sport] += 1
                    self.connection_pairs[(pkt[IP].src, pkt[IP].dst, pkt[TCP].dport)] += 1
                elif UDP in pkt:
                    self.port_stats[pkt[UDP].dport] += 1
                    self.port_stats[pkt[UDP].sport] += 1
                    self.connection_pairs[(pkt[IP].src, pkt[IP].dst, pkt[UDP].dport)] += 1
        
        self.analysis_results['basic_stats'] = {
            'total_packets': total_packets,
            'total_size_bytes': total_size,
            'duration_seconds': duration,
            'packets_per_second': total_packets / duration if duration > 0 else 0,
            'start_time': datetime.fromtimestamp(start_time).isoformat() if start_time else None,
            'end_time': datetime.fromtimestamp(end_time).isoformat() if end_time else None
        }
    
    def analyze_protocols(self):
        """Analyze protocol distribution"""
        logging.info("Analyzing protocol distribution...")
        
        protocol_names = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
        protocol_distribution = {}
        
        for proto_num, count in self.protocol_stats.items():
            proto_name = protocol_names.get(proto_num, f'Protocol_{proto_num}')
            protocol_distribution[proto_name] = count
        
        self.analysis_results['protocols'] = protocol_distribution
    
    def analyze_top_talkers(self, top_n: int = 10):
        """Identify top talking IP addresses"""
        logging.info("Analyzing top talkers...")
        
        top_ips = self.ip_stats.most_common(top_n)
        self.analysis_results['top_talkers'] = [
            {'ip': ip, 'packet_count': count} for ip, count in top_ips
        ]
    
    def analyze_port_activity(self, top_n: int = 20):
        """Analyze port activity and identify common services"""
        logging.info("Analyzing port activity...")
        
        # Common port mappings
        well_known_ports = {
            80: 'HTTP', 443: 'HTTPS', 53: 'DNS', 22: 'SSH',
            21: 'FTP', 25: 'SMTP', 110: 'POP3', 143: 'IMAP',
            993: 'IMAPS', 995: 'POP3S', 587: 'SMTP Submission',
            3389: 'RDP', 23: 'Telnet', 161: 'SNMP', 445: 'SMB'
        }
        
        top_ports = self.port_stats.most_common(top_n)
        port_analysis = []
        
        for port, count in top_ports:
            service = well_known_ports.get(port, 'Unknown')
            port_analysis.append({
                'port': port,
                'service': service,
                'packet_count': count
            })
        
        self.analysis_results['port_activity'] = port_analysis
    
    def analyze_dns_traffic(self):
        """Analyze DNS queries and responses"""
        logging.info("Analyzing DNS traffic...")
        
        dns_queries = []
        for pkt in self.packets:
            if DNS in pkt and pkt[DNS].qr == 0:  # DNS query
                if DNSQR in pkt:
                    query_name = pkt[DNSQR].qname.decode('utf-8').rstrip('.')
                    dns_queries.append({
                        'timestamp': datetime.fromtimestamp(pkt.time).isoformat(),
                        'source_ip': pkt[IP].src,
                        'query': query_name,
                        'query_type': pkt[DNSQR].qtype
                    })
        
        # Analyze DNS query patterns
        domain_counter = Counter([q['query'] for q in dns_queries])
        
        self.analysis_results['dns_analysis'] = {
            'total_queries': len(dns_queries),
            'unique_domains': len(domain_counter),
            'top_queried_domains': domain_counter.most_common(10),
            'recent_queries': dns_queries[-20:] if dns_queries else []
        }
        
        self.dns_queries = dns_queries
    
    def analyze_http_traffic(self):
        """Analyze HTTP traffic"""
        logging.info("Analyzing HTTP traffic...")
        
        http_requests = []
        for pkt in self.packets:
            if HTTPRequest in pkt:
                http_requests.append({
                    'timestamp': datetime.fromtimestamp(pkt.time).isoformat(),
                    'source_ip': pkt[IP].src,
                    'destination_ip': pkt[IP].dst,
                    'host': pkt[HTTPRequest].Host.decode() if pkt[HTTPRequest].Host else 'Unknown',
                    'path': pkt[HTTPRequest].Path.decode() if pkt[HTTPRequest].Path else '/',
                    'method': pkt[HTTPRequest].Method.decode() if pkt[HTTPRequest].Method else 'Unknown'
                })
        
        self.analysis_results['http_analysis'] = {
            'total_requests': len(http_requests),
            'recent_requests': http_requests[-20:] if http_requests else []
        }
        
        self.http_requests = http_requests
    
    def detect_security_threats(self):
        """Detect potential security threats"""
        logging.info("Detecting security threats...")
        
        threats = []
        
        # 1. Port scanning detection
        for src_ip in self.ip_stats:
            contacted_ports = set()
            for (s_ip, d_ip, port), count in self.connection_pairs.items():
                if s_ip == src_ip:
                    contacted_ports.add(port)
            
            if len(contacted_ports) > 20:  # Threshold for port scanning
                threats.append({
                    'type': 'Port Scan',
                    'source_ip': src_ip,
                    'severity': 'High',
                    'description': f'IP {src_ip} contacted {len(contacted_ports)} different ports',
                    'details': f'Ports contacted: {sorted(list(contacted_ports))[:20]}...'
                })
                self.suspicious_ips.add(src_ip)
        
        # 2. DDoS detection (high packet rate from single source)
        for ip, count in self.ip_stats.items():
            if count > 1000:  # Threshold for potential DDoS
                threats.append({
                    'type': 'Potential DDoS',
                    'source_ip': ip,
                    'severity': 'Critical',
                    'description': f'IP {ip} sent {count} packets',
                    'details': 'Abnormally high packet count from single source'
                })
                self.suspicious_ips.add(ip)
        
        # 3. Unusual protocol usage
        total_packets = sum(self.protocol_stats.values())
        for proto, count in self.protocol_stats.items():
            percentage = (count / total_packets) * 100
            if proto not in [1, 6, 17] and percentage > 5:  # Non-standard protocols
                threats.append({
                    'type': 'Unusual Protocol',
                    'protocol': proto,
                    'severity': 'Medium',
                    'description': f'Protocol {proto} accounts for {percentage:.2f}% of traffic',
                    'details': f'{count} packets using uncommon protocol'
                })
        
        # 4. Suspicious DNS queries
        suspicious_domains = ['malware', 'phishing', 'botnet', 'suspicious']
        for query in self.dns_queries:
            for suspicious_term in suspicious_domains:
                if suspicious_term in query['query'].lower():
                    threats.append({
                        'type': 'Suspicious DNS Query',
                        'source_ip': query['source_ip'],
                        'severity': 'High',
                        'description': f'DNS query for suspicious domain: {query["query"]}',
                        'details': f'Timestamp: {query["timestamp"]}'
                    })
                    self.suspicious_ips.add(query['source_ip'])
        
        self.security_threats = threats
        self.analysis_results['security_threats'] = threats
    
    def generate_firewall_rules(self):
        """Generate firewall rules based on analysis"""
        logging.info("Generating firewall rules...")
        
        rules = []
        rule_id = 1
        
        # 1. Block suspicious IPs
        for ip in self.suspicious_ips:
            rules.append({
                'id': rule_id,
                'action': 'DROP',
                'direction': 'INPUT',
                'source': ip,
                'destination': 'ANY',
                'protocol': 'ANY',
                'port': 'ANY',
                'description': f'Block suspicious IP {ip} identified through traffic analysis'
            })
            rule_id += 1
        
        # 2. Rate limiting rules for high-traffic sources
        for ip, count in self.ip_stats.most_common(5):
            if count > 500:  # High traffic threshold
                rules.append({
                    'id': rule_id,
                    'action': 'LIMIT',
                    'direction': 'INPUT',
                    'source': ip,
                    'destination': 'ANY',
                    'protocol': 'ANY',
                    'port': 'ANY',
                    'limit': '100/minute',
                    'description': f'Rate limit IP {ip} due to high traffic volume ({count} packets)'
                })
                rule_id += 1
        
        # 3. Block uncommon ports if they show suspicious activity
        suspicious_ports = [port for port, count in self.port_stats.items() 
                        if port > 1024 and port not in [8080, 8443, 3389, 5432, 3306] and count > 100]
        
        for port in suspicious_ports[:10]:  # Limit to top 10
            rules.append({
                'id': rule_id,
                'action': 'DROP',
                'direction': 'INPUT',
                'source': 'ANY',
                'destination': 'ANY',
                'protocol': 'TCP',
                'port': port,
                'description': f'Block potentially malicious traffic on port {port}'
            })
            rule_id += 1
        
        # 4. Allow essential services
        essential_services = [
            (80, 'TCP', 'HTTP web traffic'),
            (443, 'TCP', 'HTTPS secure web traffic'),
            (53, 'UDP', 'DNS queries'),
            (22, 'TCP', 'SSH administration'),
            (25, 'TCP', 'SMTP email'),
            (993, 'TCP', 'IMAPS secure email'),
            (995, 'TCP', 'POP3S secure email')
        ]
        
        for port, protocol, description in essential_services:
            rules.append({
                'id': rule_id,
                'action': 'ACCEPT',
                'direction': 'INPUT',
                'source': 'ANY',
                'destination': 'ANY',
                'protocol': protocol,
                'port': port,
                'description': f'Allow {description}'
            })
            rule_id += 1
        
        # 5. Default deny rule
        rules.append({
            'id': rule_id,
            'action': 'DROP',
            'direction': 'INPUT',
            'source': 'ANY',
            'destination': 'ANY',
            'protocol': 'ANY',
            'port': 'ANY',
            'description': 'Default deny all other traffic'
        })
        
        self.firewall_rules = rules
        self.analysis_results['firewall_rules'] = rules
    
    def generate_network_topology(self):
        """Generate network topology information"""
        logging.info("Analyzing network topology...")
        
        internal_networks = ['192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.',
                            '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.',
                            '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.']
        
        internal_ips = set()
        external_ips = set()
        
        for ip in self.ip_stats:
            is_internal = any(ip.startswith(network) for network in internal_networks)
            if is_internal:
                internal_ips.add(ip)
            else:
                external_ips.add(ip)
        
        # Network communication patterns
        internal_to_external = 0
        external_to_internal = 0
        internal_to_internal = 0
        
        for (src, dst, port), count in self.connection_pairs.items():
            src_internal = any(src.startswith(network) for network in internal_networks)
            dst_internal = any(dst.startswith(network) for network in internal_networks)
            
            if src_internal and not dst_internal:
                internal_to_external += count
            elif not src_internal and dst_internal:
                external_to_internal += count
            elif src_internal and dst_internal:
                internal_to_internal += count
        
        self.analysis_results['network_topology'] = {
            'internal_ips': list(internal_ips),
            'external_ips': list(external_ips)[:50],  # Limit for readability
            'total_internal': len(internal_ips),
            'total_external': len(external_ips),
            'traffic_patterns': {
                'internal_to_external': internal_to_external,
                'external_to_internal': external_to_internal,
                'internal_to_internal': internal_to_internal
            }
        }
    
    def create_visualizations(self):
        """Create traffic visualization charts"""
        logging.info("Creating visualizations...")
        
        # Set up the plotting style
        plt.style.use('seaborn-v0_8')
        fig, axes = plt.subplots(2, 2, figsize=(15, 12))
        fig.suptitle('Network Traffic Analysis', fontsize=16, fontweight='bold')
        
        # 1. Protocol distribution pie chart
        protocols = self.analysis_results.get('protocols', {})
        if protocols:
            axes[0, 0].pie(protocols.values(), labels=protocols.keys(), autopct='%1.1f%%')
            axes[0, 0].set_title('Protocol Distribution')
        
        # 2. Top talkers bar chart
        top_talkers = self.analysis_results.get('top_talkers', [])[:10]
        if top_talkers:
            ips = [t['ip'] for t in top_talkers]
            counts = [t['packet_count'] for t in top_talkers]
            axes[0, 1].bar(range(len(ips)), counts)
            axes[0, 1].set_xticks(range(len(ips)))
            axes[0, 1].set_xticklabels(ips, rotation=45, ha='right')
            axes[0, 1].set_title('Top Talkers')
            axes[0, 1].set_ylabel('Packet Count')
        
        # 3. Port activity
        port_activity = self.analysis_results.get('port_activity', [])[:15]
        if port_activity:
            ports = [f"{p['port']}\n({p['service']})" for p in port_activity]
            counts = [p['packet_count'] for p in port_activity]
            axes[1, 0].bar(range(len(ports)), counts)
            axes[1, 0].set_xticks(range(len(ports)))
            axes[1, 0].set_xticklabels(ports, rotation=45, ha='right')
            axes[1, 0].set_title('Top Port Activity')
            axes[1, 0].set_ylabel('Packet Count')
        
        # 4. Security threats summary
        threats = self.analysis_results.get('security_threats', [])
        threat_types = Counter([t['type'] for t in threats])
        if threat_types:
            axes[1, 1].bar(threat_types.keys(), threat_types.values())
            axes[1, 1].set_title('Security Threats by Type')
            axes[1, 1].set_ylabel('Count')
            axes[1, 1].tick_params(axis='x', rotation=45)
        
        plt.tight_layout()
        plt.savefig('network_traffic_analysis.png', dpi=300, bbox_inches='tight')
        logging.info("Visualizations saved to 'network_traffic_analysis.png'")
    
    def run_full_analysis(self):
        """Run complete network traffic analysis"""
        logging.info("Starting comprehensive network analysis...")
        
        if not self.load_pcap():
            return False
        
        # Run all analysis components
        self.analyze_basic_statistics()
        self.analyze_protocols()
        self.analyze_top_talkers()
        self.analyze_port_activity()
        self.analyze_dns_traffic()
        self.analyze_http_traffic()
        self.generate_network_topology()
        self.detect_security_threats()
        self.generate_firewall_rules()
        
        # Create visualizations
        try:
            self.create_visualizations()
        except Exception as e:
            logging.warning(f"Could not create visualizations: {e}")
        
        logging.info("Analysis complete!")
        return True
    
    def generate_report(self, output_file: str = 'network_analysis_report.json'):
        """Generate comprehensive analysis report"""
        logging.info(f"Generating report: {output_file}")
        
        report = {
            'analysis_metadata': {
                'pcap_file': self.pcap_file,
                'analysis_time': datetime.now().isoformat(),
                'analyzer_version': '1.0'
            },
            'analysis_results': self.analysis_results
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        logging.info(f"Report saved to {output_file}")
    
    def print_summary(self):
        """Print analysis summary to console"""
        print("\n" + "="*60)
        print("NETWORK TRAFFIC ANALYSIS SUMMARY")
        print("="*60)
        
        # Basic statistics
        basic_stats = self.analysis_results.get('basic_stats', {})
        print(f"\n📊 BASIC STATISTICS:")
        print(f"  Total Packets: {basic_stats.get('total_packets', 0):,}")
        print(f"  Total Size: {basic_stats.get('total_size_bytes', 0):,} bytes")
        print(f"  Duration: {basic_stats.get('duration_seconds', 0):.2f} seconds")
        print(f"  Packets/Second: {basic_stats.get('packets_per_second', 0):.2f}")
        
        # Protocol distribution
        protocols = self.analysis_results.get('protocols', {})
        print(f"\n🌐 PROTOCOL DISTRIBUTION:")
        for proto, count in protocols.items():
            percentage = (count / basic_stats.get('total_packets', 1)) * 100
            print(f"  {proto}: {count:,} packets ({percentage:.1f}%)")
        
        # Top talkers
        top_talkers = self.analysis_results.get('top_talkers', [])[:5]
        print(f"\n💬 TOP 5 TALKERS:")
        for talker in top_talkers:
            print(f"  {talker['ip']}: {talker['packet_count']:,} packets")
        
        # Security threats
        threats = self.analysis_results.get('security_threats', [])
        print(f"\n🚨 SECURITY THREATS: {len(threats)} detected")
        threat_summary = Counter([t['type'] for t in threats])
        for threat_type, count in threat_summary.items():
            print(f"  {threat_type}: {count}")
        
        # Firewall rules
        rules = self.analysis_results.get('firewall_rules', [])
        print(f"\n🔥 FIREWALL RULES: {len(rules)} generated")
        drop_rules = sum(1 for rule in rules if rule['action'] == 'DROP')
        accept_rules = sum(1 for rule in rules if rule['action'] == 'ACCEPT')
        print(f"  DROP rules: {drop_rules}")
        print(f"  ACCEPT rules: {accept_rules}")
        
        print("\n" + "="*60)


def main():
    """Main function to run the analyzer"""
    if len(sys.argv) != 2:
        print("Usage: python wireshark_analyzer.py <pcap_file>")
        print("Example: python wireshark_analyzer.py network_dump.pcap")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    
    if not os.path.exists(pcap_file):
        print(f"Error: PCAP file '{pcap_file}' not found!")
        sys.exit(1)
    
    # Initialize analyzer
    analyzer = NetworkTrafficAnalyzer(pcap_file)
    
    # Run analysis
    if analyzer.run_full_analysis():
        # Print summary
        analyzer.print_summary()
        
        # Generate detailed report
        analyzer.generate_report()
        
        print(f"\n✅ Analysis complete!")
        print(f"📄 Detailed report: network_analysis_report.json")
        print(f"📊 Visualizations: network_traffic_analysis.png")
        print(f"📝 Log file: wireshark_analysis.log")
    else:
        print("❌ Analysis failed!")
        sys.exit(1)


if __name__ == "__main__":
    main()
