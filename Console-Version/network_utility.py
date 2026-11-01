# EN
# Network Utility Tool
# Developed by: Marwan Al Khateeb
# Copyright (c) 2026 Marwan Al Khateeb
# GitHub: https://github.com/07X0

# Unauthorized redistribution or commercial use
# is not permitted without the author's permission.

# DE
# Netzwerk-Dienstprogramm
# Entwickelt von: Marwan Al Khateeb
# Copyright (c) 2026 Marwan Al Khateeb
# GitHub: https://github.com/07X0

# Eine unbefugte Weiterverbreitung oder kommerzielle Nutzung
# ist ohne die Genehmigung des Autors nicht gestattet.

import socket
import ipaddress
import concurrent.futures
from scapy.all import (
    ARP,
    Ether,
    srp,
    sniff,
    conf,
    get_if_hwaddr,
    get_if_addr,
    get_if_list
)

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"

def print_banner():
    print(f"""{CYAN}
╔══════════════════════════════════════════╗
║          NETWORK UTILITY TOOL            ║
║                                          ║
║          Developed by Marwan Al Khateeb  ║
║          Python Networking Tool          ║
╚══════════════════════════════════════════╝
{RESET}""")

def get_website_ip():
    try:
        user_input = input(f"{YELLOW}[?] Enter full domain name (e.g. google.com): {RESET}").strip()
        if not user_input:
            print(f"{RED}[!] Domain cannot be empty.{RESET}")
            return
            
        ip = socket.gethostbyname(user_input)
        print(f"{GREEN}[+] Target: {user_input}")
        print(f"[+] IP Address (IPv4): {ip}{RESET}")
        
    except socket.gaierror:
        print(f"{RED}[!] Error: Hostname could not be resolved (Invalid domain).{RESET}")
    except Exception as e:
        print(f"{RED}[!] Unexpected Error: {e}{RESET}")

def get_website_name():
    try:
        user_input = input(f"{YELLOW}[?] Enter any website IPv4 address (Reverse DNS Lookup): {RESET}").strip()
        if not user_input:
            print(f"{RED}[!] IP cannot be empty.{RESET}")
            return
            
        try:
            ipaddress.ip_address(user_input)
        except ValueError:
            print(f"{RED}[!] Error: Invalid IP address format.{RESET}")
            return
            
        name = socket.gethostbyaddr(user_input)
        print(f"{GREEN}[+] Hostname: {name[0]}")
        print(f"[+] Aliases: {name[1]}")
        print(f"[+] IP(s): {name[2]}{RESET}")
        
    except socket.herror:
        print(f"{RED}[!] Error: Host not found for this IP (No PTR record).{RESET}")
    except Exception as e:
        print(f"{RED}[!] Unexpected Error: {e}{RESET}")

def get_port_service():
    try:
        user_input = input(f"{YELLOW}[?] Enter any port service name (e.g., http, ftp): {RESET}").strip()
        if not user_input:
            print(f"{RED}[!] Service name cannot be empty.{RESET}")
            return
            
        port_service = socket.getservbyname(user_input, 'tcp')
        print(f"{GREEN}[+] Port Number (TCP): {port_service}{RESET}")
        
    except OSError:
        print(f"{RED}[!] Error: Unknown service name.{RESET}")
    except Exception as e:
        print(f"{RED}[!] Unexpected Error: {e}{RESET}")

def get_service_name():
    try:
        user_input = int(input(f"{YELLOW}[?] Enter any port number (1-65535): {RESET}"))
        if not (1 <= user_input <= 65535):
            print(f"{RED}[!] Error: Port must be between 1 and 65535.{RESET}")
            return
            
        service_port = socket.getservbyport(user_input, 'tcp')
        print(f"{GREEN}[+] Service Name (TCP): {service_port}{RESET}")
        
    except ValueError:
        print(f"{RED}[!] Error: Please enter a valid integer for the port.{RESET}")
    except OSError:
        print(f"{RED}[!] Error: No service found for this port number.{RESET}")
    except Exception as e:
        print(f"{RED}[!] Unexpected Error: {e}{RESET}")

def scan_single_port(target_ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as serversocket:
            serversocket.settimeout(0.3)
            result = serversocket.connect_ex((target_ip, port))
            if result == 0:
                try:
                    service_name = socket.getservbyport(port, 'tcp')
                except OSError:
                    service_name = "Unknown Service"
                return port, service_name
    except (socket.timeout, ConnectionRefusedError, OSError):
        pass
    return None

def port_scan():
    try:
        user_input = input(f"{YELLOW}[?] Enter target IP to scan: {RESET}").strip()
        if not user_input:
            print(f"{RED}[!] IP cannot be empty.{RESET}")
            return

        try:
            target_ip = str(ipaddress.ip_address(user_input))
        except ValueError:
            print(f"{RED}[!] Error: Invalid IP address format.{RESET}")
            return

        port_input = input(f"{YELLOW}[?] Enter a port (e.g., 80), range (1-100), or Enter for full scan: {RESET}").strip()
        
        if port_input == "":
            ports_to_scan = range(1, 65536)
            print(f"{CYAN}[-] Scanning all ports (1 - 65535) using Threading... Please wait.{RESET}")
            
        elif "-" in port_input:
            parts = port_input.split("-")
            if len(parts) != 2:
                print(f"{RED}[!] Invalid range format. Use start-end (e.g., 1-100).{RESET}")
                return
            start_port, end_port = map(int, parts)
            
            if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535):
                print(f"{RED}[!] Error: Ports must be between 1 and 65535.{RESET}")
                return
            if start_port > end_port:
                print(f"{RED}[!] Error: Start port cannot be greater than end port.{RESET}")
                return
                
            ports_to_scan = range(start_port, end_port + 1)
            print(f"{CYAN}[-] Scanning range ({start_port} - {end_port})...{RESET}")
            
        else:
            single_port = int(port_input)
            if not (1 <= single_port <= 65535):
                print(f"{RED}[!] Error: Port must be between 1 and 65535.{RESET}")
                return
            ports_to_scan = [single_port]
            print(f"{CYAN}[-] Scanning port {single_port}...{RESET}")

        open_ports = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            futures = {executor.submit(scan_single_port, target_ip, port): port for port in ports_to_scan}
            for future in concurrent.futures.as_completed(futures):
                res = future.result()
                if res:
                    port, service_name = res
                    open_ports.append((port, service_name))
                    print(f"{GREEN}[+] Port {port} is OPEN | Service: {service_name}{RESET}")

        print(f"\n{CYAN}[*] Port scan completed! Total open ports found: {len(open_ports)}{RESET}")

    except ValueError:
        print(f"{RED}[!] Error: Invalid port number format.{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error: {e}{RESET}")

def get_local_info():
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        print(f"{GREEN}[+] Local Hostname: {hostname}")
        print(f"[+] Local IP Address: {local_ip}{RESET}")
        
        try:
            default_iface = conf.iface
            local_mac = get_if_hwaddr(default_iface)
            iface_ip = get_if_addr(default_iface)
            print(f"{GREEN}[+] Default Interface: {default_iface}")
            print(f"[+] Interface IP Address: {iface_ip}")
            print(f"[+] Local MAC Address: {local_mac}{RESET}")
        except Exception:
            print(f"{YELLOW}[!] Could not retrieve interface details automatically.{RESET}")

    except socket.gaierror:
        print(f"{RED}[!] Error: Could not retrieve local host information.{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error: {e}{RESET}")

def scan_network_host(ip, target_port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as serversocket:
            serversocket.settimeout(0.2)
            result = serversocket.connect_ex((str(ip), target_port))
            if result == 0:
                return str(ip)
    except (socket.timeout, ConnectionRefusedError, OSError):
        pass
    return None

def scan_all_ips_ports_network():
    try:
        network_input = input(f"{YELLOW}[?] Enter network range with CIDR (e.g., 192.168.1.0/24): {RESET}").strip()
        if not network_input:
            print(f"{RED}[!] Network input cannot be empty.{RESET}")
            return
            
        try:
            net = ipaddress.ip_network(network_input, strict=False)
        except ValueError:
            print(f"{RED}[!] Error: Invalid network CIDR format.{RESET}")
            return
            
        target_port_input = input(f"{YELLOW}[?] Enter port to check across network (default 80): {RESET}").strip()
        target_port = int(target_port_input) if target_port_input else 80
        
        if not (1 <= target_port <= 65535):
            print(f"{RED}[!] Error: Port must be between 1 and 65535.{RESET}")
            return

        print(f"{CYAN}[-] Scanning network {net} on port {target_port} using Threading...{RESET}")

        active_hosts = []
        hosts_to_scan = list(net.hosts())

        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(scan_network_host, ip, target_port): ip for ip in hosts_to_scan}
            for future in concurrent.futures.as_completed(futures):
                active_ip = future.result()
                if active_ip:
                    active_hosts.append(active_ip)
                    print(f"{GREEN}[+] Active Host Found: {active_ip} (Port {target_port} is OPEN){RESET}")

        print(f"\n{CYAN}[*] Network Scan completed! Total active hosts: {len(active_hosts)}{RESET}")
        
    except ValueError:
        print(f"{RED}[!] Error: Invalid port number.{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error: {e}{RESET}")

def network_packet_sniffer():
    try:
        print(f"{YELLOW}[-] Note: Make sure to run this script as Administrator / Root!{RESET}")
        
        user_input_iface = input("Enter your Network Interface (or press Enter for default): ").strip()
        if not user_input_iface:
            user_input_iface = None 
            
        user_input_filter = input("Enter your filter (e.g., tcp, arp, icmp, or leave blank): ").strip()
        if not user_input_filter:
            user_input_filter = None
            
        count_input = input("Enter packet count to sniff (e.g., 5): ").strip()
        user_input_count = int(count_input) if count_input else 5
        if user_input_count <= 0:
            print(f"{RED}[!] Packet count must be greater than 0.{RESET}")
            return
        
        print(f"\n{CYAN}[-] Sniffing packets... Please wait.{RESET}")
        
        capture = sniff(iface=user_input_iface, filter=user_input_filter, count=user_input_count)

        print(f"\n{GREEN}[+] Sniffing Completed Successfully! Total Packets: {len(capture)}{RESET}\n")
        print("=" * 50)

        for index, pkt in enumerate(capture, start=1):
            print(f"Packet #{index}")
            
            if pkt.haslayer('IP'):
                src_ip = pkt['IP'].src
                dst_ip = pkt['IP'].dst
                print(f"  ├── Source IP      : {src_ip}")
                print(f"  └── Destination IP : {dst_ip}")
                
                if pkt.haslayer('TCP'):
                    print(f"      Protocol       : TCP")
                    print(f"      Source Port    : {pkt['TCP'].sport}")
                    print(f"      Dest Port      : {pkt['TCP'].dport}")
                elif pkt.haslayer('UDP'):
                    print(f"      Protocol       : UDP")
                    print(f"      Source Port    : {pkt['UDP'].sport}")
                    print(f"      Dest Port      : {pkt['UDP'].dport}")
            else:
                print(f"  └── Layer 2 / Other: {pkt.summary()}")
                
            print("-" * 50)

    except PermissionError:
        print(f"{RED}[!] Error: You need Administrator or Root privileges to capture network packets!{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error: {e}{RESET}")

def my_network_interface():
    try:
        print(f"{CYAN}[-] Listing all available network interfaces (conf.ifaces):{RESET}")
        print(conf.ifaces)
        
        print(f"\n{CYAN}[-] Simple list of interface names (get_if_list):{RESET}")
        interfaces = get_if_list()
        print(interfaces)
        
    except Exception as e:
        print(f"{RED}[!] Error: {e}{RESET}")

def check_routing_table():
    try:
        print(f"{CYAN}[-] Displaying Scapy Routing Table:{RESET}")
        print(conf.route)
        
        target = "8.8.8.8"
        route_info = conf.route.route(target)
        print(f"\n{CYAN}[-] Route info to reach {target}:{RESET}")
        print(f"    Interface: {route_info[0]}")
        print(f"    Gateway IP: {route_info[1]}")
        print(f"    Source IP: {route_info[2]}")
        
    except Exception as e:
        print(f"{RED}[!] Error: {e}{RESET}")

def scapy_arp_scan():
    try:
        target_ip = input(f"{YELLOW}[?] Enter network range with CIDR (e.g., 192.168.1.0/24): {RESET}").strip()
        if not target_ip:
            print(f"{RED}[!] Range cannot be empty.{RESET}")
            return
            
        try:
            ipaddress.ip_network(target_ip, strict=False)
        except ValueError:
            print(f"{RED}[!] Error: Invalid network CIDR format.{RESET}")
            return
            
        print(f"{CYAN}[-] Scanning network {target_ip} using ARP... Please wait.{RESET}")
        
        arp_request = ARP(pdst=target_ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        
        answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]
        
        print(f"\n{GREEN}[+] Active Devices Found: {len(answered_list)}{RESET}\n")
        print(f"{'IP Address':<20} | {'MAC Address'}")
        print("-" * 45)
        
        for element in answered_list:
            ip = element[1].psrc
            mac = element[1].hwsrc
            print(f"{ip:<20} | {mac}")
            
    except PermissionError:
        print(f"{RED}[!] Error: Administrator or Root privileges are required for ARP scanning!{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error: {e}{RESET}")


#############################################################################################


def main():
    while True:
        try:
            print_banner()
            print(f"{YELLOW}[1]{RESET} Get Website IP (DNS Lookup)")
            print(f"{YELLOW}[2]{RESET} Reverse DNS Lookup (IP to Website)")
            print(f"{YELLOW}[3]{RESET} Get Port Number by Service Name")
            print(f"{YELLOW}[4]{RESET} Get Service Name by Port Number")
            print(f"{YELLOW}[5]{RESET} Port Scanner (Single, Range, Full)")
            print(f"{YELLOW}[6]{RESET} Local Network Host Scan (TCP)")
            print(f"{YELLOW}[7]{RESET} Local System Information")
            print(f"{YELLOW}[8]{RESET} Network Packet Sniffer (Scapy)")
            print(f"{YELLOW}[9]{RESET} List Network Interfaces (conf.ifaces & get_if_list)")
            print(f"{YELLOW}[10]{RESET} Check Scapy Routing Table")
            print(f"{YELLOW}[11]{RESET} ARP Network Scanner (Scapy)")
            print(f"{YELLOW}[0]{RESET} Exit")
            
            choice = input(f"\n{YELLOW}[?] Select an option (0-11): {RESET}").strip()
            print("-" * 50)
            
            if choice == '1':
                get_website_ip()
            elif choice == '2':
                get_website_name()
            elif choice == '3':
                get_port_service()
            elif choice == '4':
                get_service_name()
            elif choice == '5':
                port_scan()
            elif choice == '6':
                scan_all_ips_ports_network()
            elif choice == '7':
                get_local_info()
            elif choice == '8':
                network_packet_sniffer()
            elif choice == '9':
                my_network_interface()
            elif choice == '10':
                check_routing_table()
            elif choice == '11':
                scapy_arp_scan()
            elif choice == '0':
                print(f"{GREEN}[+] Thank you for using Network Utility Tool. Goodbye!{RESET}")
                break
            else:
                print(f"{RED}[!] Invalid option. Please choose a number between 0 and 11.{RESET}")
                
            input(f"\n{CYAN}Press Enter to continue...{RESET}")
            
        except KeyboardInterrupt:
            print(f"\n\n{YELLOW}[!] Program interrupted by user. Exiting safely...{RESET}")
            break

if __name__ == "__main__":
    main()
