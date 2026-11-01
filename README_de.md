Netzwerk-Dienstprogramm (Network Utility Tool)

Ein auf Python basierendes Netzwerk-Dienstprogramm und Sicherheits-Tool

Entwickelt von Marwan Al Khateeb

Überblick

Das „Network Utility Tool“ ist eine auf Python basierende Anwendung, die für gängige Aufgaben der Netzwerkdiagnose und -analyse konzipiert wurde.

Das Projekt umfasst zwei Versionen:

- CLI-Version: Eine Befehlszeilenschnittstelle (Command Line Interface) für Benutzer, die eine terminalbasierte Interaktion bevorzugen.
- GUI-Version: Eine grafische Benutzeroberfläche (Graphical User Interface), die mit Tkinter erstellt wurde, um die Bedienung zu erleichtern.

Das Projekt wurde entwickelt, um praktische Kenntnisse in der Python-Programmierung, in Computernetzwerken und in der IT-Sicherheit zu vertiefen.

Projektstruktur

Network_Utility_Tool/
│
├── README_en.md
├── README_de.md
├── .gitignore
│
├── Console-Version/
│   ├── network_utility.py
│   └── README.md
│
└── GUI-Version/
├── network_utility_gui.py
└── README.md

Funktionen

CLI-Version

- DNS-Abfrage (DNS Lookup)
- Reverse-DNS-Abfrage
- Ermittlung von TCP-Dienstnamen
- Zuordnung von TCP-Ports zu Diensten
- TCP-Port-Scanning
- Informationen zum lokalen Host
- Scannen von Hosts im Netzwerk
- Informationen zu Netzwerkschnittstellen
- Abfrage der Routing-Tabelle
- Netzwerk-Paket-Analyse (Packet Sniffing)
- ARP-Scanning

GUI-Version

- Grafische Benutzeroberfläche, erstellt mit Python und Tkinter
- DNS-Abfrage
- Reverse-DNS-Abfrage
- Ermittlung von TCP-Diensten
- Port-Scanning
- Informationen zum lokalen Netzwerk
- Scannen von Hosts im Netzwerk
- Anzeige der Konsolenausgabe

Verwendete Technologien

- Python
- Tkinter
- Socket-Programmierung
- Scapy
- ThreadPoolExecutor
- Verarbeitung von IP-Adressen
- Netzwerkprotokolle

Voraussetzungen

- Python 3
- Scapy
- Tkinter
- Administrator- oder Root-Rechte für bestimmte Netzwerkoperationen

Installation von Scapy:

pip install scapy

Tkinter ist in vielen Python-Installationen bereits enthalten. Auf einigen Linux-Distributionen muss es separat installiert werden. Installation

Klonen Sie das Repository:

git clone https://github.com/07X0/Network_Utiliy_tool.git

Wechseln Sie in das Projektverzeichnis:

cd Network_Utiliy_tool

Verwendung

CLI-Version

python Console-Version/network_utility.py

GUI-Version

python GUI-Version/network_utility_gui.py

Sicherheitshinweis

Dieses Tool ist für Bildungszwecke, Netzwerkdiagnosen und autorisierte Sicherheitstests vorgesehen.

Scannen Sie ausschließlich Systeme und Netzwerke, die Ihnen gehören oder für deren Überprüfung Sie eine ausdrückliche Genehmigung haben.

Einige Funktionen, wie z. B. Packet-Sniffing und ARP-Scans, erfordern möglicherweise erweiterte Zugriffsrechte.

Autor

Marwan Al Khateeb

GitHub: https://github.com/07X0

Copyright

Copyright (c) 2026 Marwan Al Khateeb. Alle Rechte vorbehalten.

Eine unbefugte Weiterverbreitung oder kommerzielle Nutzung ist ohne die Zustimmung des Autors nicht gestattet.
