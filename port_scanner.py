import sys
import nmap
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QLabel, QLineEdit, QPushButton,
    QVBoxLayout, QWidget, QTextEdit, QCheckBox, QComboBox
)
from PyQt5.QtCore import Qt

class PortScannerApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Advanced Port Scanner Tool")
        self.setGeometry(100, 100, 600, 400)
        
        # Main Layout
        layout = QVBoxLayout()

        # Input for target IP
        self.target_label = QLabel("Target (IP or Domain):")
        self.target_input = QLineEdit()
        layout.addWidget(self.target_label)
        layout.addWidget(self.target_input)

        # Protocol Selection
        self.protocol_label = QLabel("Select Protocol:")
        self.protocol_combo = QComboBox()
        self.protocol_combo.addItems(["Both", "TCP", "UDP"])
        layout.addWidget(self.protocol_label)
        layout.addWidget(self.protocol_combo)

        # Port Range Inputs
        self.port_label = QLabel("Ports (comma separated or range):")
        self.port_input = QLineEdit()
        layout.addWidget(self.port_label)
        layout.addWidget(self.port_input)

        # Scan All Ports Checkbox
        self.scan_all_checkbox = QCheckBox("Scan All Ports (1-65535)")
        layout.addWidget(self.scan_all_checkbox)

        # Output Area
        self.output_area = QTextEdit()
        self.output_area.setReadOnly(True)
        layout.addWidget(self.output_area)

        # Scan Button
        self.scan_button = QPushButton("Scan")
        self.scan_button.clicked.connect(self.scan_ports)
        layout.addWidget(self.scan_button)

        # Set Main Layout
        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

    def scan_ports(self):
        target = self.target_input.text().strip()
        ports = self.port_input.text().strip()
        protocol = self.protocol_combo.currentText()
        scan_all = self.scan_all_checkbox.isChecked()

        if not target:
            self.output_area.append("Please enter a target IP or domain.")
            return
        
        scanner = nmap.PortScanner()
        try:
            if scan_all:
                port_range = "1-65535"
            else:
                port_range = ports or "1-1024"
            
            self.output_area.append(f"Scanning {target} on ports {port_range} ({protocol})...")
            
            # Adjust protocol and run the scan
            if protocol == "Both":
                scanner.scan(hosts=target, ports=port_range, arguments="-sS -sU")
            elif protocol == "TCP":
                scanner.scan(hosts=target, ports=port_range, arguments="-sS")
            elif protocol == "UDP":
                scanner.scan(hosts=target, ports=port_range, arguments="-sU")
            
            for host in scanner.all_hosts():
                self.output_area.append(f"\nHost: {host} ({scanner[host].hostname()})")
                self.output_area.append(f"State: {scanner[host].state()}")
                for proto in scanner[host].all_protocols():
                    self.output_area.append(f"\nProtocol: {proto}")
                    ports = scanner[host][proto].keys()
                    for port in sorted(ports):
                        state = scanner[host][proto][port]['state']
                        self.output_area.append(f"Port: {port}\tState: {state}")

        except Exception as e:
            self.output_area.append(f"Error: {str(e)}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PortScannerApp()
    window.show()
    sys.exit(app.exec_())
