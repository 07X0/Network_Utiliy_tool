Network Utility Tool – CLI-Version

Überblick

Die CLI-Version des Network Utility Tools ist eine auf Python basierende Befehlszeilenanwendung zur Durchführung von Netzwerkdiagnosen und grundlegenden netzwerksicherheitsrelevanten Aufgaben.

Funktionen

- DNS-Abfrage (DNS Lookup)
- Reverse-DNS-Abfrage
- Ermittlung von TCP-Dienstnamen
- Ermittlung von Diensten anhand von TCP-Ports
- TCP-Port-Scanning
- Informationen zum lokalen Host
- Netzwerk-Host-Scanning
- Auflistung der Netzwerkschnittstellen
- Abfrage der Routing-Tabelle
- Netzwerk-Paket-Analyse (Packet Sniffing)
- ARP-Scanning

Technologien

- Python 3
- Socket-Programmierung
- Scapy
- ThreadPoolExecutor
- Verarbeitung von IP-Adressen

Voraussetzungen

Installieren Sie Python 3 und Scapy.

pip install scapy

Ausführung

Vom Hauptverzeichnis des Projekts aus:

python Console-Version/network_utility.py

Oder navigieren Sie in das entsprechende Verzeichnis und führen Sie folgenden Befehl aus:

python network_utility.py

Sicherheitshinweis

Verwenden Sie die Scan- und Paket-Erfassungsfunktionen nur in Netzwerken und auf Systemen, die Ihnen gehören oder für deren Überprüfung Sie ausdrücklich autorisiert sind.

Für einige Vorgänge sind möglicherweise Administrator- oder Root-Rechte erforderlich.

Autor

Marwan Al Khateeb

GitHub: https://github.com/07X0
