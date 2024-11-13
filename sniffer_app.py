from PyQt5 import QtWidgets,QtCore
from scapy.all import*
from sniffer import PacketSniffer
from ui_mainwindow import Ui_MainWindow
from PyQt5.QtCore import QTimer
from PyQt5.QtCore import QTimer, QCoreApplication
from PyQt5.QtWidgets import *
from PyQt5.QtCore import Qt

#from PyQt5.QtCore import qRegisterMetaType, QVector

show_interfaces()

class SnifferApp(QtWidgets.QMainWindow, Ui_MainWindow):
    def __init__(self):
        super().__init__()
        #qRegisterMetaType(QVector, 'QVector<int>')
        # self.sniffing = False
        # self.thread = None

        self.sniff_thread = None
        self.packetCounter = 0
        self.packet_storage = [] #存储数据包 -> queue
        
        self.setupUi(self) #UI
        self.show_network_interface() #填充网卡下拉框
        self.clicked_connect() #点击事件处理

    def clicked_connect(self):
        #信号连接
        self.startButton.clicked.connect(self.start_button_clicked)#连接开始的点击事件
        self.stopButton.clicked.connect(self.stop_button_clicked)#连接结束按钮的点击事件
        self.packetListWidget.itemClicked.connect(self.show_packet_details_and_hex)#显示packet_details_and_hex
        self.saveAction.triggered.connect(self.save_packet_list)  # 连接保存菜单
        self.exitAction.triggered.connect(self.close)  # 连接退出菜单
        self.analyzeAction.triggered.connect(self.save_current_packet)#连接当前数据包分析

    def show_network_interface(self):
        #interfaces = get_if_list()
        interfaces_list = []
        for item in get_working_ifaces():
            interfaces_list.append(item.name)
        print("interface:")
        print(interfaces_list)
        self.interfaceComboBox.addItems(interfaces_list)

    def start_button_clicked(self):
        try:
            # 在开始新的嗅探之前检查有没有嗅探线程在运行
            if self.sniff_thread :
                self.stop_button_clicked()  # 调用停止按钮的逻辑
            self.packetListWidget.setRowCount(0)  # 清空packet_list
            print("Packet list cleared.")  # 确认清空操作
            self.packetDetailsTreeWidget.clear() 
            self.packetHexTextEdit.clear()
            self.packet_storage.clear()
            self.packetCounter = 0

            select_interface = self.interfaceComboBox.currentText()
            filter_condition = self.filterInput.text()
            print(select_interface) 
            print(filter_condition)
            self.sniff_thread = PacketSniffer(select_interface, filter_condition)
            #self.sniff_thread.packet_received.connect(self.update_packet_list)  # 连接信号
            self.sniff_thread.packet_received.connect(self.update_packet_list, Qt.BlockingQueuedConnection)  # 使用阻塞队列连接
            self.sniff_thread.start()

        except PermissionError as e:
            print(f"Permission denied for interface {select_interface}: {e}")
        except Exception as e:
            print(f"Error while stopping sniffing:{e}")
    
    def stop_button_clicked(self):
        try:
            if self.sniff_thread:
                self.sniff_thread.stop()
            print("stoped")

        except Exception as e:
            print(f"Error while stopping sniffing: {e}")

    #call_back
    def update_packet_list(self, packet):
        # 处理并显示数据包信息
        self.packet_storage.append(packet)
        #No
        self.packetCounter += 1
        print(self.packetCounter)
       
        pkt_hex = hexdump(packet,dump=True) ## 获取原始内容
        # print(f"hex{pkt_hex}")
        # print('packet:')
        # print(packet)

        #time
        packet_time = datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S')  # 获取捕获时间并格式化
        # print(packet_time)
        #src dst
        if IP in packet:
            # print("ip in packet")
            src = packet[IP].src
            dst = packet[IP].dst
        else :
            src = packet.src
            dst = packet.dst
        # print(src)
        # print(dst)
        #protocol
        layer = None
        for var in self.get_packet_layers(packet):
            if not isinstance(var,(Padding, Raw)):
                layer = var #找到第一个有效层，非padding和非raw层
        protocol = layer.name 
        # print(protocol)

        #length
        length = f"{len(packet)}"
        # print(length)

        #info
        try:
            info = str(packet.summary())
        except:
            info = "error"
        #show
        # 将信息添加到 packetListWidget
        row_position = self.packetListWidget.rowCount()  # 获取当前行数，以便插入新行
        self.packetListWidget.insertRow(row_position)  # 在最后一行插入新行
        self.packetListWidget.setItem(row_position, 0, QtWidgets.QTableWidgetItem(packet_time))  # Time
        self.packetListWidget.setItem(row_position, 1, QtWidgets.QTableWidgetItem(src))  # Source
        self.packetListWidget.setItem(row_position, 2, QtWidgets.QTableWidgetItem(dst))  # Destination
        self.packetListWidget.setItem(row_position, 3, QtWidgets.QTableWidgetItem(protocol))  # Protocol
        self.packetListWidget.setItem(row_position, 4, QtWidgets.QTableWidgetItem(length))  # Length
        self.packetListWidget.setItem(row_position, 5, QtWidgets.QTableWidgetItem(info))  # Info
        # 滚动到最后一行
        self.packetListWidget.scrollToBottom()
        QCoreApplication.processEvents()

    def show_packet_details_and_hex(self,item):
        try:
            #获取对应的包
            selected_row = item.row()
            selected_packet = self.packet_storage[selected_row]
            self.show_packet_details(selected_packet)
            self.show_packet_hex(selected_packet)
        except IndexError:
            print("Selected packet does not exist in storage.")
        except Exception as e:
            print(f"Error while displaying packet details: {e}")
       
    def show_packet_details(self, packet):
        self.packetDetailsTreeWidget.clear()  # 清空之前的细节
        self.populate_packet_details(packet)  # 填充新的数据包细节

    def populate_packet_details(self, packet):
        # 遍历数据包中的每一层并添加到树形控件中
        for layer in self.get_packet_layers(packet):
            # 为该层创建一个顶级项
            layer_item = QtWidgets.QTreeWidgetItem([layer.name])  # 层名称
            self.packetDetailsTreeWidget.addTopLevelItem(layer_item)

            # 将层的每个字段添加为子项
            for field_name, field_value in layer.fields.items():  # 使用 items() 方法获取字段名和对应的值
                field_item = QtWidgets.QTreeWidgetItem([field_name, str(field_value)])  # 创建子项
                layer_item.addChild(field_item)

            # 添加项用于展开/收起层的细节
            layer_item.setExpanded(False)  # 初始为收起状态


    # 获取对应的层
    def get_packet_layers(self, packet):
        counter = 0
        while True:
            layer = packet.getlayer(counter)
            if layer is None:  
                break
            yield layer  # 返回当前层
            counter += 1  # 递增计数器以获取下一层

    
    def show_packet_hex(self,packet):
        self.packetHexTextEdit.clear()
        pkt_hex = hexdump(packet,dump=True) ## 获取原始内容
        self.packetHexTextEdit.append(pkt_hex)
        self.packetDetailsTreeWidget.verticalScrollBar().setValue(self.packetDetailsTreeWidget.verticalScrollBar().maximum())


    def save_packet_list(self):
        if not self.packet_storage:  # 检查是否有数据包
            QtWidgets.QMessageBox.warning(self, "警告", "没有数据包可保存。")
            return

        options = QFileDialog.Options()
        save_path, _ = QFileDialog.getSaveFileName(self, "保存数据包", "", "pcap(*.pcap);;All Files (*)", options=options)
        
        if save_path:
            try:
                # 使用 wrpcap 函数保存数据包
                wrpcap(save_path, self.packet_storage, append=False)
                QtWidgets.QMessageBox.information(self, "成功", "数据包已成功保存。")
            except Exception as e:
                print(e)
                QtWidgets.QMessageBox.critical(self, "错误", f"保存数据包时发生错误: {e}")
                sys.exit(6)  

    #generate_pdf
    def save_current_packet(self):
        if not self.packet_storage:
            QtWidgets.QMessageBox.warning(self, "警告", "没有数据包可保存。")
            return

        selected_item = self.packetListWidget.currentItem()
        if not selected_item:
            QtWidgets.QMessageBox.warning(self, "警告", "请选择一个数据包进行保存。")
            return
        
        selected_row = selected_item.row()
        selected_packet = self.packet_storage[selected_row]

        options = QFileDialog.Options()
        self.filename, _ = QFileDialog.getSaveFileName(self, "保存当前数据包为PDF", "", "PDF Files (*.pdf);;All Files (*)", options=options)
        
        if self.filename:
            try:
                selected_packet.canvas_dump().writePDFfile(self.filename)
                QtWidgets.QMessageBox.information(self, "成功", "当前数据包已成功保存为PDF。")
            except Exception as e:
                print(f"Error while saving PDF: {e}")
                QtWidgets.QMessageBox.critical(self, "错误", f"保存当前数据包时发生错误: {e}")
