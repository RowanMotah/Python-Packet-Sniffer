"""
Packet Sniffer GUI

A simple cross-platform packet sniffer with a PyQt5 GUI, built using Scapy.
Features:
- Real-time packet capture and display
- Protocol filtering (TCP, UDP, ICMP, DNS)
- Basic anomaly detection (port scan heuristic)
- Save captured packets to PCAP
- Export detected anomalies to log file

Author: Your Name
License: MIT
"""

import sys
import os
import threading
import time
from PyQt5 import QtWidgets, QtGui, QtCore
from scapy.all import sniff, wrpcap, Ether
from scapy.layers.inet import IP, TCP, UDP, ICMP
from datetime import datetime

# Thread-safe signal emitter for communicating between threads and the GUI


class PacketSignal(QtCore.QObject):
    # Signal emitted when a packet is received (log string, protocol)
    packet_received = QtCore.pyqtSignal(str, str)
    # Signal emitted when an anomaly is detected (anomaly log string)
    anomaly_detected = QtCore.pyqtSignal(str)


class PacketSnifferGUI(QtWidgets.QMainWindow):
    """
    Main GUI class for the packet sniffer.
    Handles UI setup, packet capture, filtering, anomaly detection, and exporting.
    """

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Packet Sniffer GUI")
        self.setGeometry(100, 100, 1000, 700)

        # Signals for thread-safe GUI updates
        self.packet_signal = PacketSignal()
        self.packet_signal.packet_received.connect(self.update_packet_view)
        self.packet_signal.anomaly_detected.connect(
            self.update_packet_view_anomaly)

        # State variables
        self.running = False
        self.anomalies = []
        self.suspicious_ips = set()
        self.packets = []

        self.setup_ui()

    def setup_ui(self):
        """
        Set up the main window UI components: dropdowns, buttons, and packet display.
        """
        main_layout = QtWidgets.QVBoxLayout()

        # Network interface dropdown (Linux: lists /sys/class/net)
        self.interface_dropdown = QtWidgets.QComboBox()
        self.interface_dropdown.addItems(os.listdir('/sys/class/net'))

        # Protocol filter dropdown
        self.filter_dropdown = QtWidgets.QComboBox()
        self.filter_dropdown.addItems(["All", "TCP", "UDP", "ICMP", "DNS"])

        # Log level filter dropdown
        self.log_level = QtWidgets.QComboBox()
        self.log_level.addItems(["ALL", "INFO", "WARNING", "ANOMALY"])

        # Control buttons
        self.start_button = QtWidgets.QPushButton("Start Sniffing")
        self.stop_button = QtWidgets.QPushButton("Stop Sniffing")
        self.save_button = QtWidgets.QPushButton("Save PCAP")
        self.export_anomalies_button = QtWidgets.QPushButton(
            "Export Anomalies")

        # Connect button actions to methods
        self.start_button.clicked.connect(self.start_sniffing)
        self.stop_button.clicked.connect(self.stop_sniffing)
        self.save_button.clicked.connect(self.save_pcap)
        self.export_anomalies_button.clicked.connect(self.export_anomalies)

        # Packet display area (read-only, monospace font)
        self.packet_display = QtWidgets.QTextEdit()
        self.packet_display.setReadOnly(True)
        self.packet_display.setFont(QtGui.QFont("Courier", 10))

        # Layout arrangement
        top_layout = QtWidgets.QHBoxLayout()
        top_layout.addWidget(self.interface_dropdown)
        top_layout.addWidget(self.filter_dropdown)
        top_layout.addWidget(self.log_level)
        top_layout.addWidget(self.start_button)
        top_layout.addWidget(self.stop_button)
        top_layout.addWidget(self.save_button)
        top_layout.addWidget(self.export_anomalies_button)

        main_layout.addLayout(top_layout)
        main_layout.addWidget(self.packet_display)

        container = QtWidgets.QWidget()
        container.setLayout(main_layout)
        self.setCentralWidget(container)

    def start_sniffing(self):
        """
        Start the packet sniffing thread on the selected interface.
        """
        self.running = True
        interface = self.interface_dropdown.currentText()
        t = threading.Thread(target=self.sniff_packets,
                             args=(interface,), daemon=True)
        t.start()

    def stop_sniffing(self):
        """
        Stop the packet sniffing process.
        """
        self.running = False

    def sniff_packets(self, interface):
        """
        Capture packets on the given interface using Scapy's sniff function.
        """
        sniff(iface=interface, prn=self.process_packet,
              store=True, stop_filter=lambda _: not self.running)

    def process_packet(self, packet):
        """
        Process each captured packet:
        - Extract protocol and address info
        - Log and display packet
        - Detect anomalies (basic port scan detection)
        """
        if Ether in packet:
            eth = packet[Ether]
            proto = "UNKNOWN"
            info = ""

            if IP in packet:
                ip = packet[IP]
                proto = ip.proto

                if proto == 6:
                    proto_str = "TCP"
                    sport, dport = packet[TCP].sport, packet[TCP].dport
                elif proto == 17:
                    proto_str = "UDP"
                    sport, dport = packet[UDP].sport, packet[UDP].dport
                elif proto == 1:
                    proto_str = "ICMP"
                    sport = dport = "-"
                else:
                    proto_str = "OTHER"
                    sport = dport = "-"

                # Format log entry for the packet
                log = f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - ETH | {eth.src} -> {eth.dst} | {proto_str} | {ip.src}:{sport} -> {ip.dst}:{dport}"
                self.packets.append(packet)

                # Emit signal to update GUI with packet info
                self.packet_signal.packet_received.emit(log, proto_str)

                # Anomaly detection: check for port scan
                if self.is_anomaly(ip.src, ip.dst):
                    anomaly_log = f"[! Anomaly detected: possible scan] from {ip.src} -> {ip.dst}"
                    self.anomalies.append(anomaly_log)
                    self.suspicious_ips.add(ip.src)
                    self.packet_signal.anomaly_detected.emit(anomaly_log)

    def is_anomaly(self, src, dst):
        """
        Basic port scan heuristic:
        If more than 5 packets from the same src->dst within 2 seconds, flag as anomaly.
        """
        now = time.time()
        self.anomaly_tracker = getattr(self, 'anomaly_tracker', {})
        key = (src, dst)
        timestamps = self.anomaly_tracker.get(key, [])
        # Keep only recent timestamps (last 2 seconds)
        timestamps = [t for t in timestamps if now - t < 2]
        timestamps.append(now)
        self.anomaly_tracker[key] = timestamps
        return len(timestamps) > 5

    def update_packet_view(self, log, proto):
        """
        Update the packet display with a new packet log, respecting protocol and log level filters.
        """
        if self.filter_dropdown.currentText() != "All" and proto != self.filter_dropdown.currentText():
            return
        if self.log_level.currentText() == "ANOMALY":
            return
        self.packet_display.append(log)

    def update_packet_view_anomaly(self, log):
        """
        Display anomaly logs in red, depending on log level filter.
        """
        if self.log_level.currentText() != "ANOMALY" and self.log_level.currentText() != "ALL":
            return
        self.packet_display.setTextColor(QtGui.QColor("red"))
        self.packet_display.append(log)
        self.packet_display.setTextColor(QtGui.QColor("black"))

    def save_pcap(self):
        """
        Save all captured packets to a PCAP file using a file dialog.
        """
        if not self.packets:
            return
        filename, _ = QtWidgets.QFileDialog.getSaveFileName(
            self, "Save PCAP", "packets.pcap", "PCAP Files (*.pcap)")
        if filename:
            wrpcap(filename, self.packets)

    def export_anomalies(self):
        """
        Export all detected anomalies to a log file using a file dialog.
        """
        if not self.anomalies:
            return
        filename, _ = QtWidgets.QFileDialog.getSaveFileName(
            self, "Export Anomalies", "anomalies.log", "Text Files (*.log)")
        if filename:
            with open(filename, 'w') as f:
                for line in self.anomalies:
                    f.write(line + "\n")


if __name__ == '__main__':
    # Entry point: launch the PyQt5 application
    app = QtWidgets.QApplication(sys.argv)
    window = PacketSnifferGUI()
    window.show()
    sys.exit(app.exec_())
