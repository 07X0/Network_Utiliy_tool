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
import threading
import customtkinter as ctk

# Scapy-Imports
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


ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")


class NetworkToolGUI(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Network Utility Tool - Developed by Marwan Al Khateeb")
        self.geometry("950x650")
        self.minsize(850, 550)

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # ------------------ SIDEBAR ------------------
        self.sidebar_frame = ctk.CTkFrame(self, width=220, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(12, weight=1)

        self.logo_label = ctk.CTkLabel(
            self.sidebar_frame, 
            text="NETWORK UTILITY", 
            font=ctk.CTkFont(size=18, weight="bold")
        )
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))

        # Navigation Buttons
        tools = [
            ("DNS Lookup", self.show_dns_lookup),
            ("Reverse DNS", self.show_reverse_dns),
            ("Port / Service Lookup", self.show_port_service_lookup),
            ("Port Scanner", self.show_port_scanner),
            ("Host Scan (TCP)", self.show_host_scan),
            ("System Info", self.show_sys_info),
            ("Packet Sniffer", self.show_sniffer),
            ("Interfaces & Routes", self.show_interfaces_routes),
            ("ARP Scanner", self.show_arp_scan)
        ]

        for i, (name, command) in enumerate(tools, start=1):
            btn = ctk.CTkButton(
                self.sidebar_frame, 
                text=name, 
                command=command, 
                anchor="w"
            )
            btn.grid(row=i, column=0, padx=15, pady=5, sticky="ew")

        # ------------------ MAIN CONTAINER ------------------
        self.main_frame = ctk.CTkFrame(self, corner_radius=10)
        self.main_frame.grid(row=0, column=1, padx=15, pady=15, sticky="nsew")
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(2, weight=1)

        # Dynamic Title
        self.title_label = ctk.CTkLabel(
            self.main_frame, 
            text="Willkommen zum Network Utility Tool", 
            font=ctk.CTkFont(size=20, weight="bold")
        )
        self.title_label.grid(row=0, column=0, padx=20, pady=(15, 5), sticky="w")

        # Input & Controls Frame
        self.input_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.input_frame.grid(row=1, column=0, padx=20, pady=10, sticky="ew")

        # Output / Log Area
        self.output_box = ctk.CTkTextbox(
            self.main_frame, 
            font=ctk.CTkFont(family="Consolas", size=13)
        )
        self.output_box.grid(row=2, column=0, padx=20, pady=(10, 20), sticky="nsew")

        # Initialize Default View
        self.show_dns_lookup()

    # ------------------ HELPER FUNCTIONS ------------------
    def log(self, text):
        """Fügt Text in das Ausgabefeld ein."""
        self.output_box.insert("end", text + "\n")
        self.output_box.see("end")

    def clear_output(self):
        """Leert das Ausgabefeld."""
        self.output_box.delete("1.0", "end")

    def clear_inputs(self):
        """Entfernt Steuerelemente im Eingabebereich."""
        for widget in self.input_frame.winfo_children():
            widget.destroy()

    def run_thread(self, target_function, *args):
        """Führt rechen- oder netzwerkintensive Funktionen in einem eigenen Thread aus."""
        threading.Thread(target=target_function, args=args, daemon=True).start()

    # ------------------ TOOL VIEWS ------------------

    # 1. DNS Lookup
    def show_dns_lookup(self):
        self.clear_inputs()
        self.title_label.configure(text="DNS Lookup (Domain zu IP)")

        entry = ctk.CTkEntry(self.input_frame, placeholder_text="z. B. google.com", width=300)
        entry.pack(side="left", padx=(0, 10))

        def execute():
            domain = entry.get().strip()
            if not domain:
                self.log("[!] Domain darf nicht leer sein.")
                return
            self.clear_output()
            self.log(f"[-] Suche IP für Domain: {domain}...")
            try:
                ip = socket.gethostbyname(domain)
                self.log(f"[+] Ziel: {domain}")
                self.log(f"[+] IPv4-Adresse: {ip}")
            except socket.gaierror:
                self.log("[!] Fehler: Hostname konnte nicht aufgelöst werden.")
            except Exception as e:
                self.log(f"[!] Unerwarteter Fehler: {e}")

        btn = ctk.CTkButton(self.input_frame, text="Abfragen", command=execute)
        btn.pack(side="left")

    # 2. Reverse DNS
    def show_reverse_dns(self):
        self.clear_inputs()
        self.title_label.configure(text="Reverse DNS Lookup (IP zu Hostname)")

        entry = ctk.CTkEntry(self.input_frame, placeholder_text="z. B. 8.8.8.8", width=300)
        entry.pack(side="left", padx=(0, 10))

        def execute():
            ip_str = entry.get().strip()
            if not ip_str:
                self.log("[!] IP darf nicht leer sein.")
                return
            self.clear_output()
            try:
                ipaddress.ip_address(ip_str)
            except ValueError:
                self.log("[!] Fehler: Ungültiges IP-Format.")
                return

            self.log(f"[-] Suche Hostname für IP: {ip_str}...")
            try:
                name = socket.gethostbyaddr(ip_str)
                self.log(f"[+] Hostname: {name[0]}")
                self.log(f"[+] Aliases: {name[1]}")
                self.log(f"[+] IP(s): {name[2]}")
            except socket.herror:
                self.log("[!] Fehler: kein PTR-Record für diese IP gefunden.")
            except Exception as e:
                self.log(f"[!] Unerwarteter Fehler: {e}")

        btn = ctk.CTkButton(self.input_frame, text="Abfragen", command=execute)
        btn.pack(side="left")

    # 3. Port / Service Lookup
    def show_port_service_lookup(self):
        self.clear_inputs()
        self.title_label.configure(text="Port / Dienst Lookup")

        entry_service = ctk.CTkEntry(self.input_frame, placeholder_text="Dienstname (z.B. http)", width=200)
        entry_service.pack(side="left", padx=(0, 10))

        def lookup_service():
            svc = entry_service.get().strip()
            if not svc:
                self.log("[!] Dienstname darf nicht leer sein.")
                return
            try:
                port = socket.getservbyname(svc, 'tcp')
                self.log(f"[+] TCP-Port für '{svc}': {port}")
            except OSError:
                self.log(f"[!] Fehler: Unbekannter Dienst '{svc}'.")

        btn1 = ctk.CTkButton(self.input_frame, text="Nach Dienst suchen", command=lookup_service)
        btn1.pack(side="left", padx=(0, 20))

        entry_port = ctk.CTkEntry(self.input_frame, placeholder_text="Port (z.B. 80)", width=150)
        entry_port.pack(side="left", padx=(0, 10))

        def lookup_port():
            try:
                p = int(entry_port.get().strip())
                svc = socket.getservbyport(p, 'tcp')
                self.log(f"[+] Dienst für TCP-Port {p}: {svc}")
            except ValueError:
                self.log("[!] Fehler: Bitte eine gültige Ganzzahl eingeben.")
            except OSError:
                self.log(f"[!] Fehler: Kein Dienst für Port {p} gefunden.")

        btn2 = ctk.CTkButton(self.input_frame, text="Nach Port suchen", command=lookup_port)
        btn2.pack(side="left")

    # 4. Port Scanner
    def show_port_scanner(self):
        self.clear_inputs()
        self.title_label.configure(text="Port Scanner")

        entry_ip = ctk.CTkEntry(self.input_frame, placeholder_text="Ziel-IP", width=180)
        entry_ip.pack(side="left", padx=(0, 10))

        entry_ports = ctk.CTkEntry(self.input_frame, placeholder_text="Port (80), Bereich (1-100) oder Leer", width=220)
        entry_ports.pack(side="left", padx=(0, 10))

        def worker(target_ip, ports_to_scan):
            open_ports = []
            
            def scan_single(port):
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(0.3)
                        if s.connect_ex((target_ip, port)) == 0:
                            try:
                                svc = socket.getservbyport(port, 'tcp')
                            except OSError:
                                svc = "Unbekannter Dienst"
                            return port, svc
                except Exception:
                    pass
                return None

            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
                futures = {executor.submit(scan_single, p): p for p in ports_to_scan}
                for future in concurrent.futures.as_completed(futures):
                    res = future.result()
                    if res:
                        port, svc = res
                        open_ports.append(res)
                        self.log(f"[+] Port {port} ist OFFEN | Dienst: {svc}")

            self.log(f"\n[*] Portscan beendet! Offene Ports: {len(open_ports)}")

        def start_scan():
            target = entry_ip.get().strip()
            port_val = entry_ports.get().strip()
            self.clear_output()

            try:
                target_ip = str(ipaddress.ip_address(target))
            except ValueError:
                self.log("[!] Fehler: Ungültiges IP-Format.")
                return

            if port_val == "":
                ports = range(1, 65536)
                self.log(f"[-] Scanne alle Ports (1-65535) für {target_ip}...")
            elif "-" in port_val:
                try:
                    p_start, p_end = map(int, port_val.split("-"))
                    if not (1 <= p_start <= 65535 and 1 <= p_end <= 65535) or p_start > p_end:
                        raise ValueError()
                    ports = range(p_start, p_end + 1)
                    self.log(f"[-] Scanne Bereich {p_start}-{p_end} für {target_ip}...")
                except ValueError:
                    self.log("[!] Fehler: Ungültiges Bereichsformat (z.B. 1-100).")
                    return
            else:
                try:
                    p = int(port_val)
                    if not (1 <= p <= 65535):
                        raise ValueError()
                    ports = [p]
                    self.log(f"[-] Scanne Port {p} für {target_ip}...")
                except ValueError:
                    self.log("[!] Fehler: Port muss zwischen 1 und 65535 liegen.")
                    return

            self.run_thread(worker, target_ip, ports)

        btn = ctk.CTkButton(self.input_frame, text="Scan starten", command=start_scan)
        btn.pack(side="left")

    # 5. Host Scan (TCP)
    def show_host_scan(self):
        self.clear_inputs()
        self.title_label.configure(text="Netzwerk Host-Scan (TCP)")

        entry_net = ctk.CTkEntry(self.input_frame, placeholder_text="CIDR (z.B. 192.168.1.0/24)", width=220)
        entry_net.pack(side="left", padx=(0, 10))

        entry_port = ctk.CTkEntry(self.input_frame, placeholder_text="Port (Standard: 80)", width=150)
        entry_port.pack(side="left", padx=(0, 10))

        def worker(net, target_port):
            active_hosts = []
            hosts_to_scan = list(net.hosts())

            def scan_host(ip):
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(0.3)
                        if s.connect_ex((str(ip), target_port)) == 0:
                            return str(ip)
                except Exception:
                    pass
                return None

            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
                futures = {executor.submit(scan_host, ip): ip for ip in hosts_to_scan}
                for future in concurrent.futures.as_completed(futures):
                    ip_res = future.result()
                    if ip_res:
                        active_hosts.append(ip_res)
                        self.log(f"[+] Aktiver Host gefunden: {ip_res} (Port {target_port} OFFEN)")

            self.log(f"\n[*] Netzwerk-Scan abgeschlossen! Aktive Hosts: {len(active_hosts)}")

        def start_scan():
            net_str = entry_net.get().strip()
            port_str = entry_port.get().strip()
            self.clear_output()

            try:
                net = ipaddress.ip_network(net_str, strict=False)
            except ValueError:
                self.log("[!] Fehler: Ungültiges CIDR-Format.")
                return

            target_port = int(port_str) if port_str else 80
            if not (1 <= target_port <= 65535):
                self.log("[!] Fehler: Port muss zwischen 1 und 65535 liegen.")
                return

            self.log(f"[-] Scanne Netzwerk {net} auf Port {target_port}...")
            self.run_thread(worker, net, target_port)

        btn = ctk.CTkButton(self.input_frame, text="Netzwerk Scannen", command=start_scan)
        btn.pack(side="left")

    # 6. Local System Info
    def show_sys_info(self):
        self.clear_inputs()
        self.title_label.configure(text="Lokale Systeminformationen")

        def execute():
            self.clear_output()
            try:
                hostname = socket.gethostname()
                local_ip = socket.gethostbyname(hostname)
                self.log(f"[+] Lokaler Hostname: {hostname}")
                self.log(f"[+] Lokale IP-Adresse: {local_ip}")

                try:
                    default_iface = conf.iface
                    local_mac = get_if_hwaddr(default_iface)
                    iface_ip = get_if_addr(default_iface)
                    self.log(f"[+] Standard-Schnittstelle: {default_iface}")
                    self.log(f"[+] Schnittstellen-IP: {iface_ip}")
                    self.log(f"[+] Lokale MAC-Adresse: {local_mac}")
                except Exception:
                    self.log("[!] Schnittstellen-Details konnten nicht automatisch ermittelt werden.")

            except socket.gaierror:
                self.log("[!] Fehler: Lokale Host-Informationen konnten nicht abgerufen werden.")
            except Exception as e:
                self.log(f"[!] Fehler: {e}")

        btn = ctk.CTkButton(self.input_frame, text="Info Abrufen", command=execute)
        btn.pack(side="left")
        execute()

    # 7. Packet Sniffer
    def show_sniffer(self):
        self.clear_inputs()
        self.title_label.configure(text="Paket-Sniffer (Root/Admin erforderlich)")

        entry_iface = ctk.CTkEntry(self.input_frame, placeholder_text="Interface (Optional)", width=160)
        entry_iface.pack(side="left", padx=(0, 5))

        entry_filter = ctk.CTkEntry(self.input_frame, placeholder_text="Filter (tcp, udp, arp)", width=160)
        entry_filter.pack(side="left", padx=(0, 5))

        entry_count = ctk.CTkEntry(self.input_frame, placeholder_text="Anzahl (z.B. 5)", width=110)
        entry_count.pack(side="left", padx=(0, 10))

        def worker(iface, flt, count):
            try:
                self.log("[-] Paket-Mitchneiden gestartet...")
                capture = sniff(iface=iface, filter=flt, count=count)
                self.log(f"\n[+] Sniffing erfolgreich! Erfasste Pakete: {len(capture)}\n" + "="*50)

                for index, pkt in enumerate(capture, start=1):
                    self.log(f"Paket #{index}")
                    if pkt.haslayer('IP'):
                        self.log(f"  ├── Quell-IP     : {pkt['IP'].src}")
                        self.log(f"  └── Ziel-IP      : {pkt['IP'].dst}")
                        if pkt.haslayer('TCP'):
                            self.log(f"      Protokoll    : TCP | Quell-Port: {pkt['TCP'].sport} -> Ziel-Port: {pkt['TCP'].dport}")
                        elif pkt.haslayer('UDP'):
                            self.log(f"      Protokoll    : UDP | Quell-Port: {pkt['UDP'].sport} -> Ziel-Port: {pkt['UDP'].dport}")
                    else:
                        self.log(f"  └── Layer 2 / Sonstiges: {pkt.summary()}")
                    self.log("-" * 50)

            except PermissionError:
                self.log("[!] Fehler: Für das Abfangen von Paketen sind Admin-/Root-Rechte erforderlich!")
            except Exception as e:
                self.log(f"[!] Fehler: {e}")

        def start_sniff():
            iface = entry_iface.get().strip() or None
            flt = entry_filter.get().strip() or None
            cnt_str = entry_count.get().strip()
            
            try:
                count = int(cnt_str) if cnt_str else 5
                if count <= 0: raise ValueError
            except ValueError:
                self.log("[!] Paketanzahl muss eine Zahl > 0 sein.")
                return

            self.clear_output()
            self.run_thread(worker, iface, flt, count)

        btn = ctk.CTkButton(self.input_frame, text="Sniffing Starten", command=start_sniff)
        btn.pack(side="left")

    # 8. Interfaces & Routes
    def show_interfaces_routes(self):
        self.clear_inputs()
        self.title_label.configure(text="Netzwerkschnittstellen & Routen")

        def show_ifaces():
            self.clear_output()
            self.log("[-] Schnittstellen (conf.ifaces):")
            self.log(str(conf.ifaces))
            self.log("\n[-] Liste von Interface-Namen (get_if_list):")
            self.log(str(get_if_list()))

        def show_routes():
            self.clear_output()
            self.log("[-] Scapy Routing-Tabelle:")
            self.log(str(conf.route))
            try:
                target = "8.8.8.8"
                route_info = conf.route.route(target)
                self.log(f"\n[-] Route für Ziel {target}:")
                self.log(f"    Interface:  {route_info[0]}")
                self.log(f"    Gateway IP: {route_info[1]}")
                self.log(f"    Quell-IP:   {route_info[2]}")
            except Exception as e:
                self.log(f"[!] Fehler: {e}")

        btn1 = ctk.CTkButton(self.input_frame, text="Schnittstellen anzeigen", command=show_ifaces)
        btn1.pack(side="left", padx=(0, 10))

        btn2 = ctk.CTkButton(self.input_frame, text="Routing-Tabelle anzeigen", command=show_routes)
        btn2.pack(side="left")

    # 9. ARP Scanner
    def show_arp_scan(self):
        self.clear_inputs()
        self.title_label.configure(text="ARP Netzwerk Scanner (Root/Admin erforderlich)")

        entry_net = ctk.CTkEntry(self.input_frame, placeholder_text="CIDR (z.B. 192.168.1.0/24)", width=260)
        entry_net.pack(side="left", padx=(0, 10))

        def worker(target_ip):
            try:
                self.log(f"[-] Scanne Netzwerk {target_ip} per ARP...")
                arp_request = ARP(pdst=target_ip)
                broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
                arp_request_broadcast = broadcast / arp_request

                answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]

                self.log(f"\n[+] Aktive Geräte gefunden: {len(answered_list)}\n")
                self.log(f"{'IP-Adresse':<20} | {'MAC-Adresse'}")
                self.log("-" * 45)

                for element in answered_list:
                    ip = element[1].psrc
                    mac = element[1].hwsrc
                    self.log(f"{ip:<20} | {mac}")

            except PermissionError:
                self.log("[!] Fehler: Admin-/Root-Rechte für ARP-Scans erforderlich!")
            except Exception as e:
                self.log(f"[!] Fehler: {e}")

        def start_scan():
            target_ip = entry_net.get().strip()
            self.clear_output()
            if not target_ip:
                self.log("[!] Bitte gib einen Netzwerkbereich an.")
                return
            try:
                ipaddress.ip_network(target_ip, strict=False)
            except ValueError:
                self.log("[!] Fehler: Ungültiges CIDR-Format.")
                return

            self.run_thread(worker, target_ip)

        btn = ctk.CTkButton(self.input_frame, text="ARP-Scan Starten", command=start_scan)
        btn.pack(side="left")


if __name__ == "__main__":
    app = NetworkToolGUI()
    app.mainloop()
