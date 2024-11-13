import threading
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import *
import time
from scapy.all import sniff
from PyQt5.QtCore import QThread, pyqtSignal,QCoreApplication
from ui_mainwindow import Ui_MainWindow
class PacketSniffer(QThread):
    packet_received = pyqtSignal(object)

    def __init__(self, interface, filter_condition):
        super().__init__()
        self.interface = interface
        self.filter_condition = filter_condition
        self.sniffing = True
        self.packet_list = []

    def run(self):
        time.sleep(2)
        QCoreApplication.processEvents()
        sniff(iface=self.interface, filter=self.filter_condition, prn=self.emit_packet, stop_filter=lambda x: not self.sniffing)
    
    def emit_packet(self, packet):
    #    with self.lock:
            if self.sniffing:  # 只有在 snififng 为真时才发出信号
                self.packet_received.emit(packet)
 
    def stop(self):
        self.sniffing = False



