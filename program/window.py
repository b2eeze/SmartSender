# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'window.ui'
#
# Created by: PyQt5 UI code generator 5.15.9
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_eLauncher(object):
    def setupUi(self, eLauncher):
        eLauncher.setObjectName("eLauncher")
        eLauncher.resize(1033, 667)
        self.centralwidget = QtWidgets.QWidget(eLauncher)
        self.centralwidget.setObjectName("centralwidget")
        self.tabWidget = QtWidgets.QTabWidget(self.centralwidget)
        self.tabWidget.setGeometry(QtCore.QRect(0, 0, 1051, 701))
        font = QtGui.QFont()
        font.setFamily("Candara")
        font.setPointSize(11)
        self.tabWidget.setFont(font)
        self.tabWidget.setMouseTracking(True)
        self.tabWidget.setTabletTracking(False)
        self.tabWidget.setAcceptDrops(False)
        self.tabWidget.setToolTip("")
        self.tabWidget.setAutoFillBackground(False)
        self.tabWidget.setTabPosition(QtWidgets.QTabWidget.North)
        self.tabWidget.setUsesScrollButtons(False)
        self.tabWidget.setDocumentMode(False)
        self.tabWidget.setTabsClosable(False)
        self.tabWidget.setMovable(True)
        self.tabWidget.setTabBarAutoHide(False)
        self.tabWidget.setObjectName("tabWidget")
        self.ip_tab = QtWidgets.QWidget()
        self.ip_tab.setObjectName("ip_tab")
        self.line_16 = QtWidgets.QFrame(self.ip_tab)
        self.line_16.setGeometry(QtCore.QRect(0, 300, 1061, 21))
        self.line_16.setFrameShape(QtWidgets.QFrame.HLine)
        self.line_16.setFrameShadow(QtWidgets.QFrame.Sunken)
        self.line_16.setObjectName("line_16")
        self.layer2 = QtWidgets.QStackedWidget(self.ip_tab)
        self.layer2.setGeometry(QtCore.QRect(10, 320, 1021, 331))
        self.layer2.setStyleSheet("")
        self.layer2.setObjectName("layer2")
        self.default_2 = QtWidgets.QWidget()
        self.default_2.setObjectName("default_2")
        self.label_14 = QtWidgets.QLabel(self.default_2)
        self.label_14.setGeometry(QtCore.QRect(240, 100, 721, 41))
        font = QtGui.QFont()
        font.setFamily("Calibri")
        font.setPointSize(16)
        font.setBold(True)
        font.setItalic(True)
        font.setWeight(75)
        self.label_14.setFont(font)
        self.label_14.setObjectName("label_14")
        self.layer2.addWidget(self.default_2)
        self.TCP_page = QtWidgets.QWidget()
        self.TCP_page.setObjectName("TCP_page")
        self.label_64 = QtWidgets.QLabel(self.TCP_page)
        self.label_64.setGeometry(QtCore.QRect(260, 90, 101, 21))
        self.label_64.setObjectName("label_64")
        self.label_65 = QtWidgets.QLabel(self.TCP_page)
        self.label_65.setGeometry(QtCore.QRect(530, 50, 101, 21))
        self.label_65.setObjectName("label_65")
        self.label_66 = QtWidgets.QLabel(self.TCP_page)
        self.label_66.setGeometry(QtCore.QRect(530, 90, 81, 21))
        self.label_66.setObjectName("label_66")
        self.tcp_data = QtWidgets.QTextEdit(self.TCP_page)
        self.tcp_data.setGeometry(QtCore.QRect(110, 170, 521, 111))
        self.tcp_data.setObjectName("tcp_data")
        self.label_67 = QtWidgets.QLabel(self.TCP_page)
        self.label_67.setGeometry(QtCore.QRect(10, 130, 101, 21))
        self.label_67.setObjectName("label_67")
        self.tcp_dst_port = QtWidgets.QLineEdit(self.TCP_page)
        self.tcp_dst_port.setGeometry(QtCore.QRect(360, 50, 121, 21))
        self.tcp_dst_port.setObjectName("tcp_dst_port")
        self.label_68 = QtWidgets.QLabel(self.TCP_page)
        self.label_68.setGeometry(QtCore.QRect(780, 50, 91, 21))
        self.label_68.setObjectName("label_68")
        self.label_69 = QtWidgets.QLabel(self.TCP_page)
        self.label_69.setGeometry(QtCore.QRect(10, 90, 101, 21))
        self.label_69.setObjectName("label_69")
        self.tcp_win = QtWidgets.QLineEdit(self.TCP_page)
        self.tcp_win.setGeometry(QtCore.QRect(360, 90, 121, 21))
        self.tcp_win.setObjectName("tcp_win")
        self.label_70 = QtWidgets.QLabel(self.TCP_page)
        self.label_70.setGeometry(QtCore.QRect(260, 50, 91, 21))
        self.label_70.setObjectName("label_70")
        self.layoutWidget_3 = QtWidgets.QWidget(self.TCP_page)
        self.layoutWidget_3.setGeometry(QtCore.QRect(630, 90, 371, 25))
        self.layoutWidget_3.setObjectName("layoutWidget_3")
        self.horizontalLayout_3 = QtWidgets.QHBoxLayout(self.layoutWidget_3)
        self.horizontalLayout_3.setContentsMargins(0, 0, 0, 0)
        self.horizontalLayout_3.setObjectName("horizontalLayout_3")
        self.tcp_URG = QtWidgets.QCheckBox(self.layoutWidget_3)
        self.tcp_URG.setObjectName("tcp_URG")
        self.horizontalLayout_3.addWidget(self.tcp_URG)
        self.tcp_ACK = QtWidgets.QCheckBox(self.layoutWidget_3)
        self.tcp_ACK.setObjectName("tcp_ACK")
        self.horizontalLayout_3.addWidget(self.tcp_ACK)
        self.tcp_PSH = QtWidgets.QCheckBox(self.layoutWidget_3)
        self.tcp_PSH.setObjectName("tcp_PSH")
        self.horizontalLayout_3.addWidget(self.tcp_PSH)
        self.tcp_RST = QtWidgets.QCheckBox(self.layoutWidget_3)
        self.tcp_RST.setObjectName("tcp_RST")
        self.horizontalLayout_3.addWidget(self.tcp_RST)
        self.tcp_SYN = QtWidgets.QCheckBox(self.layoutWidget_3)
        self.tcp_SYN.setObjectName("tcp_SYN")
        self.horizontalLayout_3.addWidget(self.tcp_SYN)
        self.tcp_FIN = QtWidgets.QCheckBox(self.layoutWidget_3)
        self.tcp_FIN.setObjectName("tcp_FIN")
        self.horizontalLayout_3.addWidget(self.tcp_FIN)
        self.tcp_src_port = QtWidgets.QLineEdit(self.TCP_page)
        self.tcp_src_port.setGeometry(QtCore.QRect(110, 50, 121, 21))
        self.tcp_src_port.setObjectName("tcp_src_port")
        self.label_72 = QtWidgets.QLabel(self.TCP_page)
        self.label_72.setGeometry(QtCore.QRect(10, 50, 91, 21))
        self.label_72.setObjectName("label_72")
        self.label_105 = QtWidgets.QLabel(self.TCP_page)
        self.label_105.setGeometry(QtCore.QRect(10, 170, 81, 21))
        self.label_105.setObjectName("label_105")
        self.tcp_seq = QtWidgets.QLineEdit(self.TCP_page)
        self.tcp_seq.setGeometry(QtCore.QRect(630, 50, 121, 21))
        self.tcp_seq.setObjectName("tcp_seq")
        self.tcp_checksum = QtWidgets.QLineEdit(self.TCP_page)
        self.tcp_checksum.setGeometry(QtCore.QRect(110, 130, 371, 21))
        self.tcp_checksum.setReadOnly(True)
        self.tcp_checksum.setObjectName("tcp_checksum")
        self.tcp_send = QtWidgets.QPushButton(self.TCP_page)
        self.tcp_send.setGeometry(QtCore.QRect(890, 240, 111, 31))
        self.tcp_send.setObjectName("tcp_send")
        self.tcp_off = QtWidgets.QLineEdit(self.TCP_page)
        self.tcp_off.setGeometry(QtCore.QRect(110, 90, 121, 21))
        self.tcp_off.setObjectName("tcp_off")
        self.tcp_ack = QtWidgets.QLineEdit(self.TCP_page)
        self.tcp_ack.setGeometry(QtCore.QRect(880, 50, 121, 21))
        self.tcp_ack.setObjectName("tcp_ack")
        self.label_110 = QtWidgets.QLabel(self.TCP_page)
        self.label_110.setGeometry(QtCore.QRect(10, 10, 161, 21))
        font = QtGui.QFont()
        font.setFamily("Calibri")
        font.setPointSize(12)
        font.setBold(True)
        font.setItalic(True)
        font.setWeight(75)
        self.label_110.setFont(font)
        self.label_110.setObjectName("label_110")
        self.tcp_option = QtWidgets.QLineEdit(self.TCP_page)
        self.tcp_option.setGeometry(QtCore.QRect(630, 130, 371, 21))
        self.tcp_option.setReadOnly(True)
        self.tcp_option.setObjectName("tcp_option")
        self.label_73 = QtWidgets.QLabel(self.TCP_page)
        self.label_73.setGeometry(QtCore.QRect(530, 130, 81, 21))
        self.label_73.setObjectName("label_73")
        self.layer2.addWidget(self.TCP_page)
        self.UDP_page = QtWidgets.QWidget()
        self.UDP_page.setObjectName("UDP_page")
        self.udp_checksum = QtWidgets.QLineEdit(self.UDP_page)
        self.udp_checksum.setGeometry(QtCore.QRect(120, 90, 361, 21))
        self.udp_checksum.setReadOnly(True)
        self.udp_checksum.setObjectName("udp_checksum")
        self.label_63 = QtWidgets.QLabel(self.UDP_page)
        self.label_63.setGeometry(QtCore.QRect(10, 130, 71, 21))
        self.label_63.setObjectName("label_63")
        self.udp_dst_port = QtWidgets.QLineEdit(self.UDP_page)
        self.udp_dst_port.setGeometry(QtCore.QRect(340, 50, 141, 21))
        self.udp_dst_port.setObjectName("udp_dst_port")
        self.label_150 = QtWidgets.QLabel(self.UDP_page)
        self.label_150.setGeometry(QtCore.QRect(10, 50, 91, 21))
        self.label_150.setObjectName("label_150")
        self.udp_send = QtWidgets.QPushButton(self.UDP_page)
        self.udp_send.setGeometry(QtCore.QRect(890, 210, 111, 31))
        self.udp_send.setObjectName("udp_send")
        self.label_71 = QtWidgets.QLabel(self.UDP_page)
        self.label_71.setGeometry(QtCore.QRect(260, 50, 71, 21))
        self.label_71.setObjectName("label_71")
        self.udp_data = QtWidgets.QTextEdit(self.UDP_page)
        self.udp_data.setGeometry(QtCore.QRect(120, 130, 521, 111))
        self.udp_data.setObjectName("udp_data")
        self.udp_src_port = QtWidgets.QLineEdit(self.UDP_page)
        self.udp_src_port.setGeometry(QtCore.QRect(120, 50, 141, 21))
        self.udp_src_port.setObjectName("udp_src_port")
        self.label_106 = QtWidgets.QLabel(self.UDP_page)
        self.label_106.setGeometry(QtCore.QRect(10, 90, 101, 21))
        self.label_106.setObjectName("label_106")
        self.label_111 = QtWidgets.QLabel(self.UDP_page)
        self.label_111.setGeometry(QtCore.QRect(10, 10, 221, 21))
        font = QtGui.QFont()
        font.setFamily("Calibri")
        font.setPointSize(12)
        font.setBold(True)
        font.setItalic(True)
        font.setWeight(75)
        self.label_111.setFont(font)
        self.label_111.setObjectName("label_111")
        self.layer2.addWidget(self.UDP_page)
        self.ICMP_page = QtWidgets.QWidget()
        self.ICMP_page.setObjectName("ICMP_page")
        self.icmp_type = QtWidgets.QComboBox(self.ICMP_page)
        self.icmp_type.setGeometry(QtCore.QRect(110, 50, 371, 21))
        self.icmp_type.setMaxVisibleItems(11)
        self.icmp_type.setObjectName("icmp_type")
        self.icmp_type.addItem("")
        self.icmp_type.addItem("")
        self.icmp_type.addItem("")
        self.icmp_type.addItem("")
        self.icmp_type.addItem("")
        self.icmp_type.addItem("")
        self.icmp_type.addItem("")
        self.icmp_type.addItem("")
        self.icmp_type.addItem("")
        self.label_107 = QtWidgets.QLabel(self.ICMP_page)
        self.label_107.setGeometry(QtCore.QRect(10, 50, 71, 21))
        self.label_107.setObjectName("label_107")
        self.icmp_send = QtWidgets.QPushButton(self.ICMP_page)
        self.icmp_send.setGeometry(QtCore.QRect(890, 210, 111, 31))
        self.icmp_send.setObjectName("icmp_send")
        self.label_109 = QtWidgets.QLabel(self.ICMP_page)
        self.label_109.setGeometry(QtCore.QRect(10, 90, 91, 21))
        self.label_109.setObjectName("label_109")
        self.icmp_checksum = QtWidgets.QLineEdit(self.ICMP_page)
        self.icmp_checksum.setGeometry(QtCore.QRect(110, 90, 371, 21))
        self.icmp_checksum.setReadOnly(True)
        self.icmp_checksum.setObjectName("icmp_checksum")
        self.label_112 = QtWidgets.QLabel(self.ICMP_page)
        self.label_112.setGeometry(QtCore.QRect(10, 130, 71, 21))
        self.label_112.setObjectName("label_112")
        self.icmp_data = QtWidgets.QTextEdit(self.ICMP_page)
        self.icmp_data.setGeometry(QtCore.QRect(110, 130, 531, 111))
        self.icmp_data.setObjectName("icmp_data")
        self.label_113 = QtWidgets.QLabel(self.ICMP_page)
        self.label_113.setGeometry(QtCore.QRect(10, 10, 221, 21))
        font = QtGui.QFont()
        font.setFamily("Calibri")
        font.setPointSize(12)
        font.setBold(True)
        font.setItalic(True)
        font.setWeight(75)
        self.label_113.setFont(font)
        self.label_113.setObjectName("label_113")
        self.label_117 = QtWidgets.QLabel(self.ICMP_page)
        self.label_117.setGeometry(QtCore.QRect(10, 250, 91, 21))
        self.label_117.setText("")
        self.label_117.setObjectName("label_117")
        self.layer2.addWidget(self.ICMP_page)
        self.splitter = QtWidgets.QSplitter(self.ip_tab)
        self.splitter.setGeometry(QtCore.QRect(120, 140, 371, 23))
        self.splitter.setOrientation(QtCore.Qt.Horizontal)
        self.splitter.setObjectName("splitter")
        self.label_114 = QtWidgets.QLabel(self.ip_tab)
        self.label_114.setGeometry(QtCore.QRect(20, 20, 101, 21))
        font = QtGui.QFont()
        font.setFamily("Calibri")
        font.setPointSize(12)
        font.setBold(True)
        font.setItalic(True)
        font.setWeight(75)
        self.label_114.setFont(font)
        self.label_114.setObjectName("label_114")
        self.layer1 = QtWidgets.QStackedWidget(self.ip_tab)
        self.layer1.setGeometry(QtCore.QRect(10, 50, 1021, 251))
        font = QtGui.QFont()
        font.setFamily("Candara")
        font.setPointSize(11)
        font.setBold(False)
        font.setItalic(False)
        font.setWeight(50)
        self.layer1.setFont(font)
        self.layer1.setObjectName("layer1")
        self.page_5 = QtWidgets.QWidget()
        self.page_5.setObjectName("page_5")
        self.label_18 = QtWidgets.QLabel(self.page_5)
        self.label_18.setGeometry(QtCore.QRect(250, 80, 471, 41))
        font = QtGui.QFont()
        font.setFamily("Calibri")
        font.setPointSize(16)
        font.setBold(True)
        font.setItalic(True)
        font.setWeight(75)
        self.label_18.setFont(font)
        self.label_18.setObjectName("label_18")
        self.layer1.addWidget(self.page_5)
        self.page_3 = QtWidgets.QWidget()
        self.page_3.setObjectName("page_3")
        self.label_9 = QtWidgets.QLabel(self.page_3)
        self.label_9.setGeometry(QtCore.QRect(240, 90, 101, 21))
        self.label_9.setObjectName("label_9")
        self.ip_checksum = QtWidgets.QLineEdit(self.page_3)
        self.ip_checksum.setGeometry(QtCore.QRect(640, 130, 361, 21))
        self.ip_checksum.setReadOnly(True)
        self.ip_checksum.setObjectName("ip_checksum")
        self.ip_option = QtWidgets.QLineEdit(self.page_3)
        self.ip_option.setGeometry(QtCore.QRect(110, 210, 371, 21))
        self.ip_option.setObjectName("ip_option")
        self.label_12 = QtWidgets.QLabel(self.page_3)
        self.label_12.setGeometry(QtCore.QRect(10, 170, 91, 21))
        self.label_12.setObjectName("label_12")
        self.label_7 = QtWidgets.QLabel(self.page_3)
        self.label_7.setGeometry(QtCore.QRect(10, 90, 101, 21))
        self.label_7.setObjectName("label_7")
        self.ip_id = QtWidgets.QLineEdit(self.page_3)
        self.ip_id.setGeometry(QtCore.QRect(110, 90, 121, 21))
        self.ip_id.setObjectName("ip_id")
        self.label_10 = QtWidgets.QLabel(self.page_3)
        self.label_10.setGeometry(QtCore.QRect(540, 90, 101, 21))
        self.label_10.setObjectName("label_10")
        self.label_11 = QtWidgets.QLabel(self.page_3)
        self.label_11.setGeometry(QtCore.QRect(540, 130, 141, 21))
        self.label_11.setObjectName("label_11")
        self.label_13 = QtWidgets.QLabel(self.page_3)
        self.label_13.setGeometry(QtCore.QRect(540, 170, 101, 21))
        self.label_13.setObjectName("label_13")
        self.label_2 = QtWidgets.QLabel(self.page_3)
        self.label_2.setGeometry(QtCore.QRect(10, 50, 81, 21))
        self.label_2.setObjectName("label_2")
        self.ip_ttl = QtWidgets.QLineEdit(self.page_3)
        self.ip_ttl.setGeometry(QtCore.QRect(870, 90, 131, 21))
        self.ip_ttl.setObjectName("ip_ttl")
        self.ip_frag = QtWidgets.QLineEdit(self.page_3)
        self.ip_frag.setGeometry(QtCore.QRect(640, 90, 111, 21))
        self.ip_frag.setObjectName("ip_frag")
        self.label_8 = QtWidgets.QLabel(self.page_3)
        self.label_8.setGeometry(QtCore.QRect(770, 90, 101, 21))
        self.label_8.setObjectName("label_8")
        self.ip_src_ip = QtWidgets.QLineEdit(self.page_3)
        self.ip_src_ip.setGeometry(QtCore.QRect(110, 170, 371, 21))
        self.ip_src_ip.setObjectName("ip_src_ip")
        self.label_6 = QtWidgets.QLabel(self.page_3)
        self.label_6.setGeometry(QtCore.QRect(10, 130, 121, 21))
        self.label_6.setObjectName("label_6")
        self.ip_dst_ip = QtWidgets.QLineEdit(self.page_3)
        self.ip_dst_ip.setGeometry(QtCore.QRect(640, 170, 361, 21))
        self.ip_dst_ip.setObjectName("ip_dst_ip")
        self.label_17 = QtWidgets.QLabel(self.page_3)
        self.label_17.setGeometry(QtCore.QRect(10, 210, 91, 21))
        self.label_17.setObjectName("label_17")
        self.label_116 = QtWidgets.QLabel(self.page_3)
        self.label_116.setGeometry(QtCore.QRect(10, 10, 101, 21))
        font = QtGui.QFont()
        font.setFamily("Calibri")
        font.setPointSize(12)
        font.setBold(True)
        font.setItalic(True)
        font.setWeight(75)
        self.label_116.setFont(font)
        self.label_116.setObjectName("label_116")
        self.layoutWidget = QtWidgets.QWidget(self.page_3)
        self.layoutWidget.setGeometry(QtCore.QRect(310, 90, 171, 25))
        self.layoutWidget.setObjectName("layoutWidget")
        self.horizontalLayout_4 = QtWidgets.QHBoxLayout(self.layoutWidget)
        self.horizontalLayout_4.setContentsMargins(0, 0, 0, 0)
        self.horizontalLayout_4.setObjectName("horizontalLayout_4")
        self.ip_MF = QtWidgets.QCheckBox(self.layoutWidget)
        self.ip_MF.setObjectName("ip_MF")
        self.horizontalLayout_4.addWidget(self.ip_MF)
        self.ip_DF = QtWidgets.QCheckBox(self.layoutWidget)
        self.ip_DF.setCheckable(False)
        self.ip_DF.setObjectName("ip_DF")
        self.horizontalLayout_4.addWidget(self.ip_DF)
        self.layoutWidget1 = QtWidgets.QWidget(self.page_3)
        self.layoutWidget1.setGeometry(QtCore.QRect(171, 131, 311, 29))
        self.layoutWidget1.setObjectName("layoutWidget1")
        self.horizontalLayout_5 = QtWidgets.QHBoxLayout(self.layoutWidget1)
        self.horizontalLayout_5.setContentsMargins(0, 0, 0, 0)
        self.horizontalLayout_5.setObjectName("horizontalLayout_5")
        self.TCP_button = QtWidgets.QPushButton(self.layoutWidget1)
        self.TCP_button.setObjectName("TCP_button")
        self.horizontalLayout_5.addWidget(self.TCP_button)
        self.UDP_button = QtWidgets.QPushButton(self.layoutWidget1)
        self.UDP_button.setObjectName("UDP_button")
        self.horizontalLayout_5.addWidget(self.UDP_button)
        self.ICMP_button = QtWidgets.QPushButton(self.layoutWidget1)
        self.ICMP_button.setObjectName("ICMP_button")
        self.horizontalLayout_5.addWidget(self.ICMP_button)
        self.layoutWidget2 = QtWidgets.QWidget(self.page_3)
        self.layoutWidget2.setGeometry(QtCore.QRect(110, 50, 891, 25))
        self.layoutWidget2.setObjectName("layoutWidget2")
        self.horizontalLayout_6 = QtWidgets.QHBoxLayout(self.layoutWidget2)
        self.horizontalLayout_6.setContentsMargins(0, 0, 0, 0)
        self.horizontalLayout_6.setObjectName("horizontalLayout_6")
        self.min_delay = QtWidgets.QCheckBox(self.layoutWidget2)
        self.min_delay.setObjectName("min_delay")
        self.horizontalLayout_6.addWidget(self.min_delay)
        self.max_th = QtWidgets.QCheckBox(self.layoutWidget2)
        self.max_th.setObjectName("max_th")
        self.horizontalLayout_6.addWidget(self.max_th)
        self.max_rel = QtWidgets.QCheckBox(self.layoutWidget2)
        self.max_rel.setObjectName("max_rel")
        self.horizontalLayout_6.addWidget(self.max_rel)
        self.min_cost = QtWidgets.QCheckBox(self.layoutWidget2)
        self.min_cost.setObjectName("min_cost")
        self.horizontalLayout_6.addWidget(self.min_cost)
        self.normal = QtWidgets.QCheckBox(self.layoutWidget2)
        self.normal.setObjectName("normal")
        self.horizontalLayout_6.addWidget(self.normal)
        self.IP_sender = QtWidgets.QPushButton(self.page_3)
        self.IP_sender.setGeometry(QtCore.QRect(890, 210, 111, 31))
        self.IP_sender.setObjectName("IP_sender")
        self.layer1.addWidget(self.page_3)
        self.page_4 = QtWidgets.QWidget()
        self.page_4.setObjectName("page_4")
        self.ipv6_dst_ip = QtWidgets.QLineEdit(self.page_4)
        self.ipv6_dst_ip.setGeometry(QtCore.QRect(640, 170, 361, 21))
        self.ipv6_dst_ip.setObjectName("ipv6_dst_ip")
        self.label_35 = QtWidgets.QLabel(self.page_4)
        self.label_35.setGeometry(QtCore.QRect(10, 170, 91, 21))
        self.label_35.setObjectName("label_35")
        self.label_36 = QtWidgets.QLabel(self.page_4)
        self.label_36.setGeometry(QtCore.QRect(540, 170, 101, 21))
        self.label_36.setObjectName("label_36")
        self.layoutWidget_8 = QtWidgets.QWidget(self.page_4)
        self.layoutWidget_8.setGeometry(QtCore.QRect(171, 71, 311, 29))
        self.layoutWidget_8.setObjectName("layoutWidget_8")
        self.horizontalLayout_12 = QtWidgets.QHBoxLayout(self.layoutWidget_8)
        self.horizontalLayout_12.setContentsMargins(0, 0, 0, 0)
        self.horizontalLayout_12.setObjectName("horizontalLayout_12")
        self.TCP_button_v6 = QtWidgets.QPushButton(self.layoutWidget_8)
        self.TCP_button_v6.setObjectName("TCP_button_v6")
        self.horizontalLayout_12.addWidget(self.TCP_button_v6)
        self.UDP_button_v6 = QtWidgets.QPushButton(self.layoutWidget_8)
        self.UDP_button_v6.setObjectName("UDP_button_v6")
        self.horizontalLayout_12.addWidget(self.UDP_button_v6)
        self.ICMP_button_v6 = QtWidgets.QPushButton(self.layoutWidget_8)
        self.ICMP_button_v6.setObjectName("ICMP_button_v6")
        self.horizontalLayout_12.addWidget(self.ICMP_button_v6)
        self.ipv6_src_ip = QtWidgets.QLineEdit(self.page_4)
        self.ipv6_src_ip.setGeometry(QtCore.QRect(110, 170, 371, 21))
        self.ipv6_src_ip.setObjectName("ipv6_src_ip")
        self.label_37 = QtWidgets.QLabel(self.page_4)
        self.label_37.setGeometry(QtCore.QRect(10, 70, 121, 21))
        self.label_37.setObjectName("label_37")
        self.ipv6_hlim = QtWidgets.QLineEdit(self.page_4)
        self.ipv6_hlim.setGeometry(QtCore.QRect(880, 120, 121, 21))
        self.ipv6_hlim.setText("")
        self.ipv6_hlim.setObjectName("ipv6_hlim")
        self.label_143 = QtWidgets.QLabel(self.page_4)
        self.label_143.setGeometry(QtCore.QRect(770, 120, 101, 21))
        self.label_143.setObjectName("label_143")
        self.label_144 = QtWidgets.QLabel(self.page_4)
        self.label_144.setGeometry(QtCore.QRect(260, 120, 71, 21))
        self.label_144.setObjectName("label_144")
        self.ipv6_fl = QtWidgets.QLineEdit(self.page_4)
        self.ipv6_fl.setGeometry(QtCore.QRect(350, 120, 131, 21))
        self.ipv6_fl.setText("")
        self.ipv6_fl.setObjectName("ipv6_fl")
        self.label_145 = QtWidgets.QLabel(self.page_4)
        self.label_145.setGeometry(QtCore.QRect(10, 10, 101, 21))
        font = QtGui.QFont()
        font.setFamily("Calibri")
        font.setPointSize(12)
        font.setBold(True)
        font.setItalic(True)
        font.setWeight(75)
        self.label_145.setFont(font)
        self.label_145.setObjectName("label_145")
        self.IPv6_sender = QtWidgets.QPushButton(self.page_4)
        self.IPv6_sender.setGeometry(QtCore.QRect(890, 210, 111, 31))
        self.IPv6_sender.setObjectName("IPv6_sender")
        self.label_146 = QtWidgets.QLabel(self.page_4)
        self.label_146.setGeometry(QtCore.QRect(10, 120, 101, 21))
        self.label_146.setObjectName("label_146")
        self.ipv6_tc = QtWidgets.QLineEdit(self.page_4)
        self.ipv6_tc.setGeometry(QtCore.QRect(110, 120, 131, 21))
        self.ipv6_tc.setText("")
        self.ipv6_tc.setObjectName("ipv6_tc")
        self.label_147 = QtWidgets.QLabel(self.page_4)
        self.label_147.setGeometry(QtCore.QRect(540, 120, 101, 21))
        self.label_147.setObjectName("label_147")
        self.ipv6_nh = QtWidgets.QLineEdit(self.page_4)
        self.ipv6_nh.setGeometry(QtCore.QRect(640, 120, 121, 21))
        self.ipv6_nh.setText("")
        self.ipv6_nh.setObjectName("ipv6_nh")
        self.layer1.addWidget(self.page_4)
        self.ip_version = QtWidgets.QPushButton(self.ip_tab)
        self.ip_version.setGeometry(QtCore.QRect(730, 12, 91, 31))
        self.ip_version.setObjectName("ip_version")
        self.version = QtWidgets.QLineEdit(self.ip_tab)
        self.version.setGeometry(QtCore.QRect(680, 20, 21, 21))
        self.version.setObjectName("version")
        self.label_19 = QtWidgets.QLabel(self.ip_tab)
        self.label_19.setGeometry(QtCore.QRect(650, 20, 21, 21))
        self.label_19.setObjectName("label_19")
        self.label_20 = QtWidgets.QLabel(self.ip_tab)
        self.label_20.setGeometry(QtCore.QRect(550, 20, 91, 21))
        self.label_20.setObjectName("label_20")
        self.line_16.raise_()
        self.layer2.raise_()
        self.splitter.raise_()
        self.label_114.raise_()
        self.layer1.raise_()
        self.ip_version.raise_()
        self.label_19.raise_()
        self.label_20.raise_()
        self.version.raise_()
        self.tabWidget.addTab(self.ip_tab, "")
        self.arp_tab = QtWidgets.QWidget()
        self.arp_tab.setObjectName("arp_tab")
        self.arp_dst_ip = QtWidgets.QLineEdit(self.arp_tab)
        self.arp_dst_ip.setGeometry(QtCore.QRect(180, 120, 301, 21))
        self.arp_dst_ip.setObjectName("arp_dst_ip")
        self.label_79 = QtWidgets.QLabel(self.arp_tab)
        self.label_79.setGeometry(QtCore.QRect(20, 120, 131, 21))
        self.label_79.setObjectName("label_79")
        self.label_76 = QtWidgets.QLabel(self.arp_tab)
        self.label_76.setGeometry(QtCore.QRect(20, 60, 131, 21))
        self.label_76.setObjectName("label_76")
        self.arp_src_ip = QtWidgets.QLineEdit(self.arp_tab)
        self.arp_src_ip.setGeometry(QtCore.QRect(180, 60, 301, 21))
        self.arp_src_ip.setObjectName("arp_src_ip")
        self.label_80 = QtWidgets.QLabel(self.arp_tab)
        self.label_80.setGeometry(QtCore.QRect(540, 60, 151, 21))
        self.label_80.setObjectName("label_80")
        self.label_81 = QtWidgets.QLabel(self.arp_tab)
        self.label_81.setGeometry(QtCore.QRect(540, 120, 151, 21))
        self.label_81.setObjectName("label_81")
        self.arp_src_mac = QtWidgets.QLineEdit(self.arp_tab)
        self.arp_src_mac.setGeometry(QtCore.QRect(710, 60, 301, 21))
        self.arp_src_mac.setObjectName("arp_src_mac")
        self.arp_dst_mac = QtWidgets.QLineEdit(self.arp_tab)
        self.arp_dst_mac.setGeometry(QtCore.QRect(710, 120, 301, 21))
        self.arp_dst_mac.setObjectName("arp_dst_mac")
        self.label_83 = QtWidgets.QLabel(self.arp_tab)
        self.label_83.setGeometry(QtCore.QRect(20, 180, 141, 21))
        self.label_83.setObjectName("label_83")
        self.arp_hw = QtWidgets.QLineEdit(self.arp_tab)
        self.arp_hw.setGeometry(QtCore.QRect(180, 180, 161, 21))
        self.arp_hw.setObjectName("arp_hw")
        self.label_82 = QtWidgets.QLabel(self.arp_tab)
        self.label_82.setGeometry(QtCore.QRect(20, 300, 131, 21))
        self.label_82.setObjectName("label_82")
        self.label_84 = QtWidgets.QLabel(self.arp_tab)
        self.label_84.setGeometry(QtCore.QRect(20, 240, 121, 21))
        self.label_84.setObjectName("label_84")
        self.arp_pro = QtWidgets.QLineEdit(self.arp_tab)
        self.arp_pro.setGeometry(QtCore.QRect(180, 240, 161, 21))
        self.arp_pro.setObjectName("arp_pro")
        self.arp_send = QtWidgets.QPushButton(self.arp_tab)
        self.arp_send.setGeometry(QtCore.QRect(890, 290, 121, 31))
        self.arp_send.setObjectName("arp_send")
        self.label_115 = QtWidgets.QLabel(self.arp_tab)
        self.label_115.setGeometry(QtCore.QRect(20, 20, 141, 21))
        font = QtGui.QFont()
        font.setFamily("Calibri")
        font.setPointSize(12)
        font.setBold(True)
        font.setItalic(True)
        font.setWeight(75)
        self.label_115.setFont(font)
        self.label_115.setObjectName("label_115")
        self.layoutWidget3 = QtWidgets.QWidget(self.arp_tab)
        self.layoutWidget3.setGeometry(QtCore.QRect(180, 300, 301, 25))
        self.layoutWidget3.setObjectName("layoutWidget3")
        self.horizontalLayout = QtWidgets.QHBoxLayout(self.layoutWidget3)
        self.horizontalLayout.setContentsMargins(0, 0, 0, 0)
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.arp_reply = QtWidgets.QRadioButton(self.layoutWidget3)
        self.arp_reply.setObjectName("arp_reply")
        self.horizontalLayout.addWidget(self.arp_reply)
        self.arp_request = QtWidgets.QRadioButton(self.layoutWidget3)
        self.arp_request.setObjectName("arp_request")
        self.horizontalLayout.addWidget(self.arp_request)
        self.tabWidget.addTab(self.arp_tab, "")
        eLauncher.setCentralWidget(self.centralwidget)
        self.statusbar = QtWidgets.QStatusBar(eLauncher)
        self.statusbar.setObjectName("statusbar")
        eLauncher.setStatusBar(self.statusbar)

        self.retranslateUi(eLauncher)
        self.tabWidget.setCurrentIndex(0)
        self.layer2.setCurrentIndex(1)
        self.icmp_type.setCurrentIndex(0)
        self.layer1.setCurrentIndex(2)
        QtCore.QMetaObject.connectSlotsByName(eLauncher)

    def retranslateUi(self, eLauncher):
        _translate = QtCore.QCoreApplication.translate
        eLauncher.setWindowTitle(_translate("eLauncher", "MainWindow"))
        self.label_14.setText(_translate("eLauncher", "please choose the type of protocol !"))
        self.label_64.setText(_translate("eLauncher", "window size"))
        self.label_65.setText(_translate("eLauncher", "seq  number"))
        self.label_66.setText(_translate("eLauncher", "flag"))
        self.label_67.setText(_translate("eLauncher", "checksum "))
        self.label_68.setText(_translate("eLauncher", "ack number"))
        self.label_69.setText(_translate("eLauncher", "data offset"))
        self.label_70.setText(_translate("eLauncher", "dst port"))
        self.tcp_URG.setText(_translate("eLauncher", "URG"))
        self.tcp_ACK.setText(_translate("eLauncher", "ACK"))
        self.tcp_PSH.setText(_translate("eLauncher", "PSH"))
        self.tcp_RST.setText(_translate("eLauncher", "RST"))
        self.tcp_SYN.setText(_translate("eLauncher", "SYN"))
        self.tcp_FIN.setText(_translate("eLauncher", "FIN"))
        self.label_72.setText(_translate("eLauncher", "src port"))
        self.label_105.setText(_translate("eLauncher", "data"))
        self.tcp_send.setText(_translate("eLauncher", "send"))
        self.label_110.setText(_translate("eLauncher", "TCP packet"))
        self.label_73.setText(_translate("eLauncher", "option"))
        self.label_63.setText(_translate("eLauncher", "data"))
        self.label_150.setText(_translate("eLauncher", "src port"))
        self.udp_send.setText(_translate("eLauncher", "send"))
        self.label_71.setText(_translate("eLauncher", "   dst port"))
        self.label_106.setText(_translate("eLauncher", "checksum "))
        self.label_111.setText(_translate("eLauncher", "UDP packet"))
        self.icmp_type.setItemText(0, _translate("eLauncher", "Echo Reply"))
        self.icmp_type.setItemText(1, _translate("eLauncher", "Host Unreacheable"))
        self.icmp_type.setItemText(2, _translate("eLauncher", "Port Unreachable"))
        self.icmp_type.setItemText(3, _translate("eLauncher", "Fragmentation needed but no frag. bit set"))
        self.icmp_type.setItemText(4, _translate("eLauncher", "Communication administratively prohibited by filtering"))
        self.icmp_type.setItemText(5, _translate("eLauncher", "Redirect for Host"))
        self.icmp_type.setItemText(6, _translate("eLauncher", "Echo Request"))
        self.icmp_type.setItemText(7, _translate("eLauncher", "Time Exceeded"))
        self.icmp_type.setItemText(8, _translate("eLauncher", "IP header bad (catchall error)"))
        self.label_107.setText(_translate("eLauncher", "type"))
        self.icmp_send.setText(_translate("eLauncher", "send"))
        self.label_109.setText(_translate("eLauncher", "checksum"))
        self.label_112.setText(_translate("eLauncher", "data"))
        self.label_113.setText(_translate("eLauncher", "ICMP packet"))
        self.label_114.setText(_translate("eLauncher", "IP packet"))
        self.label_18.setText(_translate("eLauncher", "please choose the IP version !"))
        self.label_9.setText(_translate("eLauncher", "flags"))
        self.label_12.setText(_translate("eLauncher", "src address"))
        self.label_7.setText(_translate("eLauncher", "id"))
        self.label_10.setText(_translate("eLauncher", "fragment"))
        self.label_11.setText(_translate("eLauncher", "checksum"))
        self.label_13.setText(_translate("eLauncher", "dst address"))
        self.label_2.setText(_translate("eLauncher", "service"))
        self.label_8.setText(_translate("eLauncher", "time to live"))
        self.label_6.setText(_translate("eLauncher", "type of protocol"))
        self.label_17.setText(_translate("eLauncher", "option"))
        self.label_116.setText(_translate("eLauncher", "IPv4"))
        self.ip_MF.setText(_translate("eLauncher", "MF"))
        self.ip_DF.setText(_translate("eLauncher", "DF"))
        self.TCP_button.setText(_translate("eLauncher", "TCP"))
        self.UDP_button.setText(_translate("eLauncher", "UDP"))
        self.ICMP_button.setText(_translate("eLauncher", "ICMP"))
        self.min_delay.setText(_translate("eLauncher", "minimize delay"))
        self.max_th.setText(_translate("eLauncher", "maximize throughput"))
        self.max_rel.setText(_translate("eLauncher", "maximize reliability"))
        self.min_cost.setText(_translate("eLauncher", "minimize monetary cost"))
        self.normal.setText(_translate("eLauncher", "normal service "))
        self.IP_sender.setText(_translate("eLauncher", "send"))
        self.label_35.setText(_translate("eLauncher", "src address"))
        self.label_36.setText(_translate("eLauncher", "dst address"))
        self.TCP_button_v6.setText(_translate("eLauncher", "TCP"))
        self.UDP_button_v6.setText(_translate("eLauncher", "UDP"))
        self.ICMP_button_v6.setText(_translate("eLauncher", "ICMP"))
        self.label_37.setText(_translate("eLauncher", "type of protocol"))
        self.label_143.setText(_translate("eLauncher", "hop limit"))
        self.label_144.setText(_translate("eLauncher", "flow label"))
        self.label_145.setText(_translate("eLauncher", "IPv6"))
        self.IPv6_sender.setText(_translate("eLauncher", "send"))
        self.label_146.setText(_translate("eLauncher", "traffic label"))
        self.label_147.setText(_translate("eLauncher", "next header"))
        self.ip_version.setText(_translate("eLauncher", "OK"))
        self.label_19.setText(_translate("eLauncher", "IPv"))
        self.label_20.setText(_translate("eLauncher", "IP version: "))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.ip_tab), _translate("eLauncher", "IP packet"))
        self.label_79.setText(_translate("eLauncher", "dst IP address"))
        self.label_76.setText(_translate("eLauncher", "src IP address"))
        self.label_80.setText(_translate("eLauncher", "src MAC address"))
        self.label_81.setText(_translate("eLauncher", "dst MAC address"))
        self.label_83.setText(_translate("eLauncher", "hardware type"))
        self.label_82.setText(_translate("eLauncher", "operation type"))
        self.label_84.setText(_translate("eLauncher", "protocol type"))
        self.arp_send.setText(_translate("eLauncher", "send"))
        self.label_115.setText(_translate("eLauncher", "ARP packet"))
        self.arp_reply.setText(_translate("eLauncher", "reply"))
        self.arp_request.setText(_translate("eLauncher", "request"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.arp_tab), _translate("eLauncher", "ARP packet"))
