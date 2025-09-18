#!/usr/bin/env python3
"""
GhostMap v0.2 - Network Reconnaissance Tool
A refined network discovery and scanning utility with improved error handling and security practices.
"""

import scapy.all as scapy
import nmap
import netifaces
import os
import sys
import random
import time
import logging
import argparse
from typing import List, Optional, Dict, Any
from dataclasses import dataclass
from colorama import Fore, Style, init

# Initialize colorama for colored CLI output
init(autoreset=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('ghostmap.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


@dataclass
class DiscoveredHost:
    """Data class to represent a discovered host."""
    ip: str
    mac: str
    hostname: Optional[str] = None
    ports: Optional[Dict[int, Dict[str, str]]] = None
    os_info: Optional[str] = None


class NetworkInterface:
    """Handle network interface operations."""
    
    @staticmethod
    def get_active_interface() -> Optional[str]:
        """Dynamically detect active network interface with better validation."""
        interfaces = netifaces.interfaces()
        
        for iface in interfaces:
            # Skip loopback and virtual interfaces
            if iface in ['lo', 'localhost'] or any(
                iface.startswith(prefix) for prefix in ['vmnet', 'vbox', 'docker', 'br-']
            ):
                continue
                
            try:
                addresses = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addresses:
                    # Check if interface has a valid IP address
                    ip_info = addresses[netifaces.AF_INET][0]
                    if ip_info.get('addr') and ip_info['addr'] != '127.0.0.1':
                        logger.info(f"Found active interface: {iface} ({ip_info['addr']})")
                        return iface
            except (KeyError, IndexError, OSError) as e:
                logger.debug(f"Error checking interface {iface}: {e}")
                continue
                
        return None
    
    @staticmethod
    def generate_random_mac() -> str:
        """Generate a random MAC address with proper vendor prefix."""
        # Use locally administered MAC address (second bit of first octet set)
        first_octet = 0x02 | (random.randint(0, 63) << 2)
        mac_parts = [f"{first_octet:02x}"]
        mac_parts.extend([f"{random.randint(0, 255):02x}" for _ in range(5)])
        return ":".join(mac_parts)
    
    @staticmethod
    def spoof_mac(interface: str, new_mac: Optional[str] = None) -> bool:
        """Spoof MAC address with improved error handling."""
        if not new_mac:
            new_mac = NetworkInterface.generate_random_mac()
            
        print(f"{Fore.YELLOW}[*] Changing MAC address of {interface} to {new_mac}")
        
        try:
            # Check if running as root
            if os.geteuid() != 0:
                print(f"{Fore.RED}[-] Root privileges required for MAC spoofing")
                return False
            
            # Bring interface down
            if os.system(f"ip link set {interface} down") != 0:
                raise OSError("Failed to bring interface down")
            
            # Change MAC address
            if os.system(f"ip link set {interface} address {new_mac}") != 0:
                raise OSError("Failed to change MAC address")
            
            # Bring interface up
            if os.system(f"ip link set {interface} up") != 0:
                raise OSError("Failed to bring interface up")
            
            print(f"{Fore.GREEN}[+] MAC address changed successfully!")
            logger.info(f"MAC address of {interface} changed to {new_mac}")
            return True
            
        except OSError as e:
            print(f"{Fore.RED}[-] Error changing MAC address: {e}")
            logger.error(f"MAC spoofing failed: {e}")
            return False


class NetworkScanner:
    """Handle network scanning operations."""
    
    def __init__(self, timeout: int = 3, verbose: bool = False):
        self.timeout = timeout
        self.verbose = verbose
        self.discovered_hosts: List[DiscoveredHost] = []
    
    def arp_scan(self, ip_range: str) -> List[DiscoveredHost]:
        """Perform ARP scan with improved error handling and validation."""
        print(f"{Fore.YELLOW}[*] Starting ARP scan on {ip_range}...")
        logger.info(f"Starting ARP scan on {ip_range}")
        
        discovered = []
        
        try:
            # Validate IP range format
            if '/' not in ip_range:
                raise ValueError("IP range must be in CIDR notation (e.g., 192.168.1.0/24)")
            
            # Create ARP request
            arp_request = scapy.ARP(pdst=ip_range)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            
            # Send packets and receive responses
            answered_list = scapy.srp(
                arp_request_broadcast, 
                timeout=self.timeout, 
                verbose=self.verbose,
                retry=2
            )[0]
            
            for element in answered_list:
                ip = element[1].psrc
                mac = element[1].hwsrc
                
                # Try to resolve hostname
                hostname = None
                try:
                    import socket
                    hostname = socket.gethostbyaddr(ip)[0]
                except:
                    pass
                
                host = DiscoveredHost(ip=ip, mac=mac, hostname=hostname)
                discovered.append(host)
                
                hostname_str = f" ({hostname})" if hostname else ""
                print(f"{Fore.GREEN}[+] Discovered: {ip}{hostname_str} (MAC: {mac})")
                
            logger.info(f"ARP scan completed. Found {len(discovered)} hosts")
            
        except ValueError as e:
            print(f"{Fore.RED}[-] Invalid input: {e}")
            logger.error(f"ARP scan input error: {e}")
        except Exception as e:
            print(f"{Fore.RED}[-] Error during ARP scan: {e}")
            logger.error(f"ARP scan error: {e}")
        
        self.discovered_hosts.extend(discovered)
        return discovered
    
    def passive_sniff(self, interface: str, packet_count: int = 10, duration: int = 30) -> None:
        """Enhanced passive packet sniffing with filtering."""
        print(f"{Fore.YELLOW}[*] Starting passive sniffing on {interface}")
        print(f"[*] Capturing up to {packet_count} packets for {duration} seconds...")
        
        try:
            # Define packet filter for interesting traffic
            filter_str = "not arp and not icmp6 and (tcp or udp)"
            
            packets = scapy.sniff(
                iface=interface,
                count=packet_count,
                timeout=duration,
                filter=filter_str,
                store=True
            )
            
            unique_connections = set()
            
            for pkt in packets:
                if pkt.haslayer(scapy.IP):
                    src_ip = pkt[scapy.IP].src
                    dst_ip = pkt[scapy.IP].dst
                    
                    # Get protocol and port information
                    proto = "Unknown"
                    port_info = ""
                    
                    if pkt.haslayer(scapy.TCP):
                        proto = "TCP"
                        port_info = f":{pkt[scapy.TCP].dport}"
                    elif pkt.haslayer(scapy.UDP):
                        proto = "UDP"
                        port_info = f":{pkt[scapy.UDP].dport}"
                    
                    connection = f"{src_ip} -> {dst_ip}{port_info} ({proto})"
                    
                    if connection not in unique_connections:
                        unique_connections.add(connection)
                        print(f"{Fore.CYAN}[*] Traffic: {connection}")
            
            logger.info(f"Passive sniffing completed. Captured {len(packets)} packets")
            
        except Exception as e:
            print(f"{Fore.RED}[-] Error during packet sniffing: {e}")
            logger.error(f"Sniffing error: {e}")
    
    def nmap_scan(self, target_ip: str, scan_type: str = "fast") -> Optional[DiscoveredHost]:
        """Enhanced Nmap scanning with different scan types."""
        print(f"{Fore.YELLOW}[*] Starting Nmap {scan_type} scan on {target_ip}...")
        
        nm = nmap.PortScanner()
        
        # Define scan arguments based on scan type
        scan_args = {
            "fast": "-F -sV --version-intensity 1",  # Fast scan with service detection
            "comprehensive": "-sS -sV -O -A --top-ports 1000",  # Comprehensive scan
            "stealth": "-sS -f --scan-delay 1s"  # Stealth scan
        }
        
        args = scan_args.get(scan_type, scan_args["fast"])
        
        try:
            # Perform the scan with timeout
            nm.scan(target_ip, arguments=args, timeout=300)
            
            if target_ip not in nm.all_hosts():
                print(f"{Fore.RED}[-] No results for {target_ip}")
                return None
            
            host_info = nm[target_ip]
            print(f"{Fore.GREEN}[+] Scan results for {target_ip}:")
            
            # Extract OS information
            os_info = None
            if 'osclass' in host_info and host_info['osclass']:
                osclass = host_info['osclass'][0]
                os_info = f"{osclass.get('osfamily', 'Unknown')} ({osclass.get('vendor', 'Unknown')})"
                accuracy = osclass.get('accuracy', 0)
                print(f"{Fore.CYAN}  OS: {os_info} (Accuracy: {accuracy}%)")
            
            # Extract port information
            ports_info = {}
            for proto in host_info.all_protocols():
                ports = host_info[proto].keys()
                for port in sorted(ports):
                    port_info = host_info[proto][port]
                    state = port_info['state']
                    service = port_info.get('name', 'unknown')
                    version = port_info.get('version', '')
                    
                    ports_info[port] = {
                        'protocol': proto,
                        'state': state,
                        'service': service,
                        'version': version
                    }
                    
                    version_str = f" ({version})" if version else ""
                    color = Fore.GREEN if state == 'open' else Fore.YELLOW
                    print(f"{color}  Port {port}/{proto}: {state} - {service}{version_str}")
            
            # Find existing host or create new one
            discovered_host = None
            for host in self.discovered_hosts:
                if host.ip == target_ip:
                    discovered_host = host
                    break
            
            if not discovered_host:
                discovered_host = DiscoveredHost(ip=target_ip, mac="unknown")
                self.discovered_hosts.append(discovered_host)
            
            discovered_host.ports = ports_info
            discovered_host.os_info = os_info
            
            logger.info(f"Nmap scan of {target_ip} completed successfully")
            return discovered_host
            
        except Exception as e:
            print(f"{Fore.RED}[-] Error during Nmap scan of {target_ip}: {e}")
            logger.error(f"Nmap scan error for {target_ip}: {e}")
            return None


def print_banner():
    """Print application banner."""
    banner = f"""
{Fore.CYAN}{Style.BRIGHT}
 ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗███╗   ███╗ █████╗ ██████╗ 
██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝████╗ ████║██╔══██╗██╔══██╗
██║  ███╗███████║██║   ██║███████╗   ██║   ██╔████╔██║███████║██████╔╝
██║   ██║██╔══██║██║   ██║╚════██║   ██║   ██║╚██╔╝██║██╔══██║██╔═══╝ 
╚██████╔╝██║  ██║╚██████╔╝███████║   ██║   ██║ ╚═╝ ██║██║  ██║██║     
 ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     

{Fore.YELLOW}GhostMap v0.2 - Enhanced Network Reconnaissance Tool
{Fore.RED}⚠️  For educational and authorized testing purposes only!{Style.RESET_ALL}
"""
    print(banner)


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="GhostMap - Network Reconnaissance Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        "-r", "--range",
        help="IP range to scan in CIDR notation (e.g., 192.168.1.0/24)",
        required=False
    )
    
    parser.add_argument(
        "-i", "--interface",
        help="Network interface to use",
        required=False
    )
    
    parser.add_argument(
        "--no-mac-spoof",
        action="store_true",
        help="Skip MAC address spoofing"
    )
    
    parser.add_argument(
        "--scan-type",
        choices=["fast", "comprehensive", "stealth"],
        default="fast",
        help="Nmap scan type (default: fast)"
    )
    
    parser.add_argument(
        "--max-hosts",
        type=int,
        default=5,
        help="Maximum number of hosts to scan with Nmap (default: 5)"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    
    return parser.parse_args()


def main():
    """Main execution function."""
    print_banner()
    
    # Parse command line arguments
    args = parse_arguments()
    
    try:
        # Step 1: Detect or use specified interface
        if args.interface:
            interface = args.interface
            print(f"{Fore.GREEN}[+] Using specified interface: {interface}")
        else:
            interface = NetworkInterface.get_active_interface()
            if not interface:
                print(f"{Fore.RED}[-] No active network interface found. Exiting...")
                return 1
            print(f"{Fore.GREEN}[+] Auto-detected interface: {interface}")
        
        # Step 2: MAC spoofing (optional)
        if not args.no_mac_spoof:
            success = NetworkInterface.spoof_mac(interface)
            if success:
                time.sleep(3)  # Wait for interface to stabilize
            else:
                print(f"{Fore.YELLOW}[!] Continuing without MAC spoofing...")
        else:
            print(f"{Fore.YELLOW}[!] Skipping MAC spoofing as requested")
        
        # Initialize scanner
        scanner = NetworkScanner(verbose=args.verbose)
        
        # Step 3: Get IP range and perform ARP scan
        if args.range:
            ip_range = args.range
        else:
            ip_range = input(f"{Fore.YELLOW}[?] Enter IP range to scan (e.g., 192.168.1.0/24): {Fore.RESET}")
        
        if not ip_range:
            print(f"{Fore.RED}[-] No IP range specified. Exiting...")
            return 1
        
        discovered_hosts = scanner.arp_scan(ip_range)
        
        if not discovered_hosts:
            print(f"{Fore.RED}[-] No hosts discovered. Exiting...")
            return 1
        
        # Step 4: Passive sniffing
        print(f"\n{Fore.YELLOW}[*] Starting passive network sniffing...")
        scanner.passive_sniff(interface, packet_count=15, duration=20)
        
        # Step 5: Nmap scanning on discovered hosts
        if discovered_hosts:
            print(f"\n{Fore.YELLOW}[*] Starting detailed scans on discovered hosts...")
            hosts_to_scan = discovered_hosts[:args.max_hosts]
            
            for i, host in enumerate(hosts_to_scan, 1):
                print(f"\n{Fore.CYAN}[*] Scanning host {i}/{len(hosts_to_scan)}: {host.ip}")
                scanner.nmap_scan(host.ip, scan_type=args.scan_type)
                
                # Small delay between scans to be less aggressive
                if i < len(hosts_to_scan):
                    time.sleep(2)
        
        # Summary
        print(f"\n{Fore.BLUE}{'='*60}")
        print(f"{Fore.BLUE}SCAN SUMMARY")
        print(f"{Fore.BLUE}{'='*60}")
        print(f"{Fore.GREEN}[+] Total hosts discovered: {len(scanner.discovered_hosts)}")
        print(f"{Fore.GREEN}[+] Results saved to: ghostmap.log")
        print(f"{Fore.YELLOW}[*] Scan completed successfully!")
        
        return 0
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user")
        return 1
    except Exception as e:
        print(f"{Fore.RED}[-] Unexpected error: {e}")
        logger.error(f"Unexpected error in main: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
