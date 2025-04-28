import scapy.all as scapy
import nmap
import netifaces
import os
import random
import time
from colorama import Fore, init

# Initialize colorama for colored CLI output
init()

def get_active_interface():
    """Dynamically detect active network interface."""
    interfaces = netifaces.interfaces()
    for iface in interfaces:
        if iface == 'lo' or iface.startswith('vmnet'):
            continue
        try:
            if netifaces.ifaddresses(iface).get(netifaces.AF_INET):
                return iface
        except:
            pass
    return None

def spoof_mac(interface):
    """Spoof MAC address for the given interface."""
    new_mac = f"00:{random.randint(0, 99):02x}:{random.randint(0, 99):02x}:{random.randint(0, 99):02x}:{random.randint(0, 99):02x}:{random.randint(0, 99):02x}"
    print(f"{Fore.YELLOW}[*] Changing MAC address of {interface} to {new_mac}{Fore.RESET}")
    try:
        os.system(f"sudo ifconfig {interface} down")
        os.system(f"sudo ifconfig {interface} hw ether {new_mac}")
        os.system(f"sudo ifconfig {interface} up")
        print(f"{Fore.GREEN}[+] MAC address changed successfully!{Fore.RESET}")
    except Exception as e:
        print(f"{Fore.RED}[-] Error changing MAC address: {e}{Fore.RESET}")

def arp_scan(ip_range):
    """Perform a stealth ARP scan to discover live hosts."""
    print(f"{Fore.YELLOW}[*] Starting ARP scan on {ip_range}...{Fore.RESET}")
    alive_ips = []
    try:
        arp_request = scapy.ARP(pdst=ip_range)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]
        
        for element in answered_list:
            ip = element[1].psrc
            mac = element[1].hwsrc
            print(f"{Fore.GREEN}[+] Alive: {ip} (MAC: {mac}){Fore.RESET}")
            alive_ips.append(ip)
    except Exception as e:
        print(f"{Fore.RED}[-] Error during ARP scan: {e}{Fore.RESET}")
    return alive_ips

def passive_sniff(interface, packet_count=5):
    """Passively sniff packets on the network."""
    print(f"{Fore.YELLOW}[*] Starting passive sniffing on {interface} (capturing {packet_count} packets)...{Fore.RESET}")
    try:
        packets = scapy.sniff(iface=interface, count=packet_count)
        for pkt in packets:
            if pkt.haslayer(scapy.IP):
                src_ip = pkt[scapy.IP].src
                dst_ip = pkt[scapy.IP].dst
                print(f"{Fore.CYAN}[*] Packet: {src_ip} -> {dst_ip}{Fore.RESET}")
    except Exception as e:
        print(f"{Fore.RED}[-] Error during sniffing: {e}{Fore.RESET}")

def nmap_scan(ip):
    """Perform Nmap scan (top 100 ports + OS detection)."""
    print(f"{Fore.YELLOW}[*] Starting Nmap scan on {ip}...{Fore.RESET}")
    nm = nmap.PortScanner()
    try:
        nm.scan(ip, arguments='-F -O')  # -F for top 100 ports, -O for OS detection
        for host in nm.all_hosts():
            print(f"{Fore.GREEN}[+] Host: {host}{Fore.RESET}")
            if 'osclass' in nm[host]:
                for osclass in nm[host]['osclass']:
                    print(f"{Fore.CYAN}  OS: {osclass['osfamily']} ({osclass['vendor']}), Accuracy: {osclass['accuracy']}%{Fore.RESET}")
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    state = nm[host][proto][port]['state']
                    service = nm[host][proto][port]['name']
                    print(f"{Fore.CYAN}  Port {port}/{proto}: {state} ({service}){Fore.RESET}")
    except Exception as e:
        print(f"{Fore.RED}[-] Error during Nmap scan: {e}{Fore.RESET}")

def main():
    print(f"{Fore.BLUE}=== GhostMap v0.1 - Network Recon Tool ==={Fore.RESET}")
    
    # Step 1: Detect active interface
    interface = get_active_interface()
    if not interface:
        print(f"{Fore.RED}[-] No active network interface found. Exiting...{Fore.RESET}")
        return
    print(f"{Fore.GREEN}[+] Active interface: {interface}{Fore.RESET}")

    # Step 2: Spoof MAC address
    spoof_mac(interface)
    time.sleep(2)  # Wait for interface to stabilize

    # Step 3: ARP scan
    ip_range = input(f"{Fore.YELLOW}[?] Enter IP range to scan (e.g., 192.168.1.0/24): {Fore.RESET}")
    alive_ips = arp_scan(ip_range)

    # Step 4: Passive sniffing
    passive_sniff(interface, packet_count=5)

    # Step 5: Nmap scan on alive IPs
    if alive_ips:
        print(f"{Fore.YELLOW}[*] Scanning alive IPs with Nmap...{Fore.RESET}")
        for ip in alive_ips[:2]:  # Limit to 2 IPs for demo
            nmap_scan(ip)
    else:
        print(f"{Fore.RED}[-] No alive IPs found for Nmap scanning.{Fore.RESET}")

if __name__ == "__main__":
    main()
