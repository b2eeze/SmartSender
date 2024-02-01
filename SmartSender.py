# coding=utf-8

from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from scapy.all import *
import sys
import uuid
import socket
from program.window import Ui_eLauncher


class MyMainWindow(QMainWindow, Ui_eLauncher):  # 继承 QMainWindow类和 Ui_MainWindow界面类
    # 界面初始化，包括信号槽的设置、默认显示值的设置
    def __init__(self, parent=None):
        super(MyMainWindow, self).__init__(parent)  # 初始化父类
        self.setupUi(self)  # 继承 Ui_MainWindow 界面类

        # 设置标题
        self.setWindowTitle('e-Launcher')
        # self.setWindowIcon(QIcon('Logo.ico'))

        # 设置默认显示的标签页
        self.layer1.setCurrentIndex(0)
        self.layer2.setCurrentIndex(0)
        # self.layer2.setStyleSheet("background-color: #f0ebe5;")

        # 信号槽设置
        # 当填入期待的IP version, 按‘OK’进行页面跳转
        self.ip_version.clicked.connect(self.ip_input)

        # 点击TCP/UDP/ICMP，进行页面跳转
        self.TCP_button.clicked.connect(self.tcp_layer)
        self.UDP_button.clicked.connect(self.udp_layer)
        self.ICMP_button.clicked.connect(self.icmp_layer)

        self.TCP_button_v6.clicked.connect(self.tcp_layer)
        self.UDP_button_v6.clicked.connect(self.udp_layer)
        self.ICMP_button_v6.clicked.connect(self.icmp_layer)

        # 当各页签中的send按钮被点击时，调用相应的成员函数完成报文的发送
        self.IP_sender.clicked.connect(self.ip_sender)
        self.IPv6_sender.clicked.connect(self.ip_sender)
        self.tcp_send.clicked.connect(self.tcp_sender)
        self.udp_send.clicked.connect(self.udp_sender)
        self.arp_send.clicked.connect(self.arp_sender)
        self.icmp_send.clicked.connect(self.icmp_sender)

        # 默认值设置

        # 获取本机的IP地址，并设置为默认source
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip_addr = s.getsockname()[0]
        s.close()
        self.ip_src_ip.setText(ip_addr)
        self.arp_src_ip.setText(ip_addr)
        self.ip_dst_ip.setText('192.168.1.1')
        self.arp_dst_ip.setText('0.0.0.0')

        # 获取 IPv6 地址，并设置为默认 source
        addresses = socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET6)
        ipv6_addresses = [addr[4][0] for addr in addresses]
        ipv6_addr = ipv6_addresses[0]
        self.ipv6_src_ip.setText(ipv6_addr)

        # ip默认值
        self.ip_id.setText('1')
        self.ip_frag.setText('0')
        self.ip_ttl.setText('128')
        self.ipv6_hlim.setText('64')
        self.ipv6_fl.setText('0')
        self.ipv6_tc.setText('0')
        self.ipv6_nh.setText('59')

        # tcp默认值
        self.tcp_src_port.setText('20001')
        self.tcp_dst_port.setText('80')
        self.tcp_seq.setText('0')
        self.tcp_ack.setText('0')
        self.tcp_off.setText('0')
        self.tcp_win.setText('0')

        # udp默认值
        self.udp_src_port.setText('20001')
        self.udp_dst_port.setText('80')

        # icmp默认值

        # arp 默认值
        # 获取本机的MAC地址，并设置为默认source
        mac = uuid.UUID(int=uuid.getnode()).hex[-12:]
        mac_addr = ":".join([mac[e:e + 2] for e in range(0, 11, 2)])
        self.arp_src_mac.setText(mac_addr)
        self.arp_dst_mac.setText('00:00:00:00:00:00')
        self.arp_pro.setText('2048')
        self.arp_hw.setText('1')
        self.arp_request.setChecked(True)

    def tcp_layer(self):
        self.layer2.setCurrentIndex(1)
        return

    def udp_layer(self):
        self.layer2.setCurrentIndex(2)
        return

    def icmp_layer(self):
        self.layer2.setCurrentIndex(3)
        return

    # 根据用户选择的version(4/6)跳转到相应的表单
    def ip_input(self):
        value = int(self.version.text())
        if value == 6:
            self.layer1.setCurrentIndex(2)
            return
        else:
            if value == 4:
                self.layer1.setCurrentIndex(1)
                return
            else:
                QMessageBox.critical(self, 'error', 'Invalid IP version! ')
                return

    def ip_sender(self):
        # 判断使用的协议类型
        value = int(self.version.text())
        if value == 6:
            # IPv6
            # source address
            if self.ipv6_src_ip.text() == "":
                QMessageBox.critical(self, 'error', 'Source Address should be specified!')
                return
            else:
                src_ip = self.ipv6_src_ip.text()

            if self.ipv6_dst_ip.text() == "":
                QMessageBox.critical(self, 'error', 'Destination Address should be specified!')
                return
            else:
                dst_ip = self.ipv6_dst_ip.text()

            # fl，默认为0
            if self.ipv6_fl.text() == "":
                QMessageBox.critical(self, 'error', 'Flow label should be specified!')
                return
            else:
                if self.ipv6_fl.text().isdigit():
                    fl = int(self.ipv6_fl.text())
                else:
                    QMessageBox.critical(self, 'error in Flow label', 'input should be an decimal integral')
                    return

            # traffic label，默认为0
            if self.ipv6_tc.text() == "":
                QMessageBox.critical(self, 'error', 'Traffic label should be specified!')
                return
            else:
                if self.ipv6_tc.text().isdigit():
                    tc = int(self.ipv6_tc.text())
                else:
                    QMessageBox.critical(self, 'error in Traffic label', 'input should be an decimal integral')
                    return

            # hlim，默认为1
            if self.ipv6_hlim.text() == "":
                QMessageBox.critical(self, 'error', 'Hop limit should be specified!')
                return
            else:
                if self.ipv6_hlim.text().isdigit():
                    hlim = int(self.ipv6_hlim.text())
                else:
                    QMessageBox.critical(self, 'error in Hop limit', 'input should be an decimal integral')
                    return

            if self.ipv6_nh.text() == "":
                QMessageBox.critical(self, 'error', 'Next header type should be specified!')
                return
            else:
                if self.ipv6_nh.text().isdigit():
                    nh = int(self.ipv6_nh.text())
                else:
                    QMessageBox.critical(self, 'error in Next header type', 'input should be an decimal integral')
                    return

            ip = IPv6(src=src_ip, dst=dst_ip, tc=tc, fl=fl, hlim=hlim, nh=nh)

        else:
            if value == 4:
                # IPv4

                # source address, 默认为本机ip
                if self.ip_src_ip.text() == "":
                    QMessageBox.critical(self, 'error', 'Source Address should be specified!')
                    return
                else:
                    ip_list = self.ip_src_ip.text().split('.')
                    if len(ip_list) != 4:
                        QMessageBox.critical(self, 'error in Source Address', 'There should be 4 integers divided by "." ')
                        return
                    for i in range(0, 4):
                        if int(ip_list[i]) > 255 or int(ip_list[i]) < 0:
                            QMessageBox.critical(self, 'error in Source Address', 'Each integer should be in [0, 255] ')
                            return
                    src_ip = self.ip_src_ip.text()

                # destination address, 默认为192.168.1.1
                if self.ip_dst_ip.text() == "":
                    QMessageBox.critical(self, 'error', 'Destination Address should be specified!')
                    return
                else:
                    ip_list = self.ip_dst_ip.text().split('.')
                    if len(ip_list) != 4:
                        QMessageBox.critical(self, 'error in Destination Address',
                                             'There should be 4 integers divided by "." ')
                        return
                    for i in range(0, 4):
                        if int(ip_list[i]) > 255 or int(ip_list[i]) < 0:
                            QMessageBox.critical(self, 'error in Destination Address',
                                                 'Each integer should be in [0, 255] ')
                            return
                    dst_ip = self.ip_dst_ip.text()

                # header length，自动计算，无需用户填充
                # total length自动计算，无需用户填充

                # type of service，默认为0x0000
                tos = 0
                if self.min_cost.isChecked():
                    tos = tos | 0x02
                if self.max_rel.isChecked():
                    tos = tos | 0x04
                if self.max_th.isChecked():
                    tos = tos | 0x08
                if self.min_delay.isChecked():
                    tos = tos | 0x10

                # id，默认为1
                if self.ip_id.text() == "":
                    QMessageBox.critical(self, 'error', 'ID should be specified!')
                    return
                else:
                    if self.ip_id.text().isdigit():
                        id = int(self.ip_id.text())
                    else:
                        QMessageBox.critical(self, 'error in ID', 'input should be an decimal integral')
                        return

                # flags，默认为0
                ipv4_flag = 0
                if self.ip_MF.isChecked():
                    ipv4_flag = ipv4_flag | 0x01
                if self.ip_DF.isChecked():
                    ipv4_flag = ipv4_flag | 0x10

                # fragment，默认为0
                if self.ip_frag.text() == "":
                    QMessageBox.critical(self, 'error', 'Fragment should be specified!')
                    return
                else:
                    if self.ip_frag.text().isdigit():
                        frag = int(self.ip_frag.text())
                    else:
                        QMessageBox.critical(self, 'error in Fragment', 'input should be an decimal integral')
                        return


                # time to live，默认为128
                if self.ip_ttl.text() == "":
                    QMessageBox.critical(self, 'error', 'Time to live should be specified!')
                    return
                else:
                    if self.ip_ttl.text().isdigit():
                        ttl = int(self.ip_ttl.text())
                    else:
                        QMessageBox.critical(self, 'error in Time to live', 'input should be an decimal integral')
                        return
            else:
                QMessageBox.critical(self, 'error in Time to live', 'invalid version')

            ip = IP(src=src_ip, dst=dst_ip, tos=tos, id=id, flags=ipv4_flag, frag=frag, ttl=ttl)


        ip_packet = ip

        ip_packet.show()
        send(ip_packet)



    # 获取用户输入的信息，构造TCP报文并发送和添加记录；对错误输入给予提示
    def tcp_sender(self):

        # step 1: 检查ip packet部分

        # 判断使用的协议类型
        value = int(self.version.text())
        if value == 6:
            # IPv6
            # source address
            if self.ipv6_src_ip.text() == "":
                QMessageBox.critical(self, 'error', 'Source Address should be specified!')
                return
            else:
                src_ip = self.ipv6_src_ip.text()

            if self.ipv6_dst_ip.text() == "":
                QMessageBox.critical(self, 'error', 'Destination Address should be specified!')
                return
            else:
                dst_ip = self.ipv6_dst_ip.text()

            # fl，默认为0
            if self.ipv6_fl.text() == "":
                QMessageBox.critical(self, 'error', 'Flow label should be specified!')
                return
            else:
                if self.ipv6_fl.text().isdigit():
                    fl = int(self.ipv6_fl.text())
                else:
                    QMessageBox.critical(self, 'error in Flow label', 'input should be an decimal integral')
                    return

            # traffic label，默认为0
            if self.ipv6_tc.text() == "":
                QMessageBox.critical(self, 'error', 'Traffic label should be specified!')
                return
            else:
                if self.ipv6_tc.text().isdigit():
                    tc = int(self.ipv6_tc.text())
                else:
                    QMessageBox.critical(self, 'error in Traffic label', 'input should be an decimal integral')
                    return

            # hlim，默认为1
            if self.ipv6_hlim.text() == "":
                QMessageBox.critical(self, 'error', 'Hop limit should be specified!')
                return
            else:
                if self.ipv6_hlim.text().isdigit():
                    hlim = int(self.ipv6_hlim.text())
                else:
                    QMessageBox.critical(self, 'error in Hop limit', 'input should be an decimal integral')
                    return

            if self.ipv6_nh.text() == "":
                QMessageBox.critical(self, 'error', 'Next header type should be specified!')
                return
            else:
                if self.ipv6_nh.text().isdigit():
                    nh = int(self.ipv6_nh.text())
                else:
                    QMessageBox.critical(self, 'error in Next header type', 'input should be an decimal integral')
                    return

            ip = IPv6(src=src_ip, dst=dst_ip, tc=tc, fl=fl, hlim=hlim, nh=nh)

        else:
            if value == 4:
                # IPv4

                # source address, 默认为本机ip
                if self.ip_src_ip.text() == "":
                    QMessageBox.critical(self, 'error', 'Source Address should be specified!')
                    return
                else:
                    ip_list = self.ip_src_ip.text().split('.')
                    if len(ip_list) != 4:
                        QMessageBox.critical(self, 'error in Source Address', 'There should be 4 integers divided by "." ')
                        return
                    for i in range(0, 4):
                        if int(ip_list[i]) > 255 or int(ip_list[i]) < 0:
                            QMessageBox.critical(self, 'error in Source Address', 'Each integer should be in [0, 255] ')
                            return
                    src_ip = self.ip_src_ip.text()

                # destination address, 默认为192.168.1.1
                if self.ip_dst_ip.text() == "":
                    QMessageBox.critical(self, 'error', 'Destination Address should be specified!')
                    return
                else:
                    ip_list = self.ip_dst_ip.text().split('.')
                    if len(ip_list) != 4:
                        QMessageBox.critical(self, 'error in Destination Address',
                                             'There should be 4 integers divided by "." ')
                        return
                    for i in range(0, 4):
                        if int(ip_list[i]) > 255 or int(ip_list[i]) < 0:
                            QMessageBox.critical(self, 'error in Destination Address',
                                                 'Each integer should be in [0, 255] ')
                            return
                    dst_ip = self.ip_dst_ip.text()

                # header length，自动计算，无需用户填充
                # total length自动计算，无需用户填充

                # type of service，默认为0x0000
                tos = 0
                if self.min_cost.isChecked():
                    tos = tos | 0x02
                if self.max_rel.isChecked():
                    tos = tos | 0x04
                if self.max_th.isChecked():
                    tos = tos | 0x08
                if self.min_delay.isChecked():
                    tos = tos | 0x10

                # id，默认为1
                if self.ip_id.text() == "":
                    QMessageBox.critical(self, 'error', 'ID should be specified!')
                    return
                else:
                    if self.ip_id.text().isdigit():
                        id = int(self.ip_id.text())
                    else:
                        QMessageBox.critical(self, 'error in ID', 'input should be an decimal integral')
                        return

                # flags，默认为0
                ipv4_flag = 0
                if self.ip_MF.isChecked():
                    ipv4_flag = ipv4_flag | 0x01
                if self.ip_DF.isChecked():
                    ipv4_flag = ipv4_flag | 0x10

                # fragment，默认为0
                if self.ip_frag.text() == "":
                    QMessageBox.critical(self, 'error', 'Fragment should be specified!')
                    return
                else:
                    if self.ip_frag.text().isdigit():
                        frag = int(self.ip_frag.text())
                    else:
                        QMessageBox.critical(self, 'error in Fragment', 'input should be an decimal integral')
                        return


                # time to live，默认为128
                if self.ip_ttl.text() == "":
                    QMessageBox.critical(self, 'error', 'Time to live should be specified!')
                    return
                else:
                    if self.ip_ttl.text().isdigit():
                        ttl = int(self.ip_ttl.text())
                    else:
                        QMessageBox.critical(self, 'error in Time to live', 'input should be an decimal integral')
                        return
            else:
                QMessageBox.critical(self, 'error', 'invalid IP version')

            ip = IP(src=src_ip, dst=dst_ip, tos=tos, id=id, flags=ipv4_flag, frag=frag, ttl=ttl)

        # step 2: 检查tcp packet部分

        # source port, 默认为20001
        if self.tcp_src_port.text() == "":
            QMessageBox.critical(self, 'error', 'Source Port should be specified!')
            return
        else:
            if int(self.tcp_src_port.text()) > 65535 or int(self.tcp_src_port.text()) < 0:
                QMessageBox.critical(self, 'error', 'Source Port should be in [0, 65535]')
                return
            src_port = int(self.tcp_src_port.text())

        # destination port, 默认为80
        if self.tcp_dst_port.text() == "":
            QMessageBox.critical(self, 'error', 'Destination Port should be specified!')
            return
        else:
            if int(self.tcp_dst_port.text()) > 65535 or int(self.tcp_dst_port.text()) < 0:
                QMessageBox.critical(self, 'error', 'Destinaion Port should be in [0, 65535]')
                return
            dst_port = int(self.tcp_dst_port.text())

        # seq number, 默认为0
        if self.tcp_seq.text() == "":
            QMessageBox.critical(self, 'error', 'The Sequence number should be specified!')
            return
        else:
            seq_num = int(self.tcp_seq.text())

        # ack number, 默认为0
        if self.tcp_ack.text() == "":
            QMessageBox.critical(self, 'error', 'The ACK number should be specified!')
            return
        else:
            ack_num = int(self.tcp_ack.text())

        # window size, 默认为2048
        if self.tcp_win.text() == "":
            QMessageBox.critical(self, 'error', 'Window Size should be specified!')
            return
        else:
            window_size = int(self.tcp_win.text())

        if self.tcp_off.text() == "":
            QMessageBox.critical(self, 'error', 'Offset should be specified!')
            return
        else:
            offset = int(self.tcp_off.text())

        # flags
        flag = 0
        if self.tcp_URG.isChecked():
            flag = flag | 0x20
        if self.tcp_ACK.isChecked():
            flag = flag | 0x10
        if self.tcp_PSH.isChecked():
            flag = flag | 0x08
        if self.tcp_RST.isChecked():
            flag = flag | 0x04
        if self.tcp_SYN.isChecked():
            flag = flag | 0x02
        if self.tcp_FIN.isChecked():
            flag = flag | 0x01

        print(flag)

        tcp = TCP(dport=dst_port, sport=src_port,seq=seq_num, ack=ack_num,dataofs=offset, flags=flag, window=window_size)
        # 判断使用的协议类型
        tcp_packet = ip/tcp

        # data不为空, 增加load内容
        if self.tcp_data.toPlainText() != "":
            data = self.tcp_data.toPlainText()
            tcp_packet = tcp_packet/data

        tcp_packet.show()
        send(tcp_packet)

        # 存储log到列表中

        # self.tcp_log_list.append(detail)
        # self.add_tcp_log()
        # self.log_list.append(detail)
        # self.add_log()

    def udp_sender(self):

        # step 1: 检查ip packet部分

        # 判断使用的协议类型
        value = int(self.version.text())
        if value == 6:
            # IPv6
            # source address
            if self.ipv6_src_ip.text() == "":
                QMessageBox.critical(self, 'error', 'Source Address should be specified!')
                return
            else:
                src_ip = self.ipv6_src_ip.text()

            if self.ipv6_dst_ip.text() == "":
                QMessageBox.critical(self, 'error', 'Destination Address should be specified!')
                return
            else:
                dst_ip = self.ipv6_dst_ip.text()

            # fl，默认为0
            if self.ipv6_fl.text() == "":
                QMessageBox.critical(self, 'error', 'Flow label should be specified!')
                return
            else:
                if self.ipv6_fl.text().isdigit():
                    fl = int(self.ipv6_fl.text())
                else:
                    QMessageBox.critical(self, 'error in Flow label', 'input should be an decimal integral')
                    return

            # traffic label，默认为0
            if self.ipv6_tc.text() == "":
                QMessageBox.critical(self, 'error', 'Traffic label should be specified!')
                return
            else:
                if self.ipv6_tc.text().isdigit():
                    tc = int(self.ipv6_tc.text())
                else:
                    QMessageBox.critical(self, 'error in Traffic label', 'input should be an decimal integral')
                    return

            # hlim，默认为1
            if self.ipv6_hlim.text() == "":
                QMessageBox.critical(self, 'error', 'Hop limit should be specified!')
                return
            else:
                if self.ipv6_hlim.text().isdigit():
                    hlim = int(self.ipv6_hlim.text())
                else:
                    QMessageBox.critical(self, 'error in Hop limit', 'input should be an decimal integral')
                    return

            if self.ipv6_nh.text() == "":
                QMessageBox.critical(self, 'error', 'Next header type should be specified!')
                return
            else:
                if self.ipv6_nh.text().isdigit():
                    nh = int(self.ipv6_nh.text())
                else:
                    QMessageBox.critical(self, 'error in Next header type', 'input should be an decimal integral')
                    return

            ip = IPv6(src=src_ip, dst=dst_ip, tc=tc, fl=fl, hlim=hlim, nh=nh)

        else:
            if value == 4:
                # IPv4

                # source address, 默认为本机ip
                if self.ip_src_ip.text() == "":
                    QMessageBox.critical(self, 'error', 'Source Address should be specified!')
                    return
                else:
                    ip_list = self.ip_src_ip.text().split('.')
                    if len(ip_list) != 4:
                        QMessageBox.critical(self, 'error in Source Address', 'There should be 4 integers divided by "." ')
                        return
                    for i in range(0, 4):
                        if int(ip_list[i]) > 255 or int(ip_list[i]) < 0:
                            QMessageBox.critical(self, 'error in Source Address', 'Each integer should be in [0, 255] ')
                            return
                    src_ip = self.ip_src_ip.text()

                # destination address, 默认为192.168.1.1
                if self.ip_dst_ip.text() == "":
                    QMessageBox.critical(self, 'error', 'Destination Address should be specified!')
                    return
                else:
                    ip_list = self.ip_dst_ip.text().split('.')
                    if len(ip_list) != 4:
                        QMessageBox.critical(self, 'error in Destination Address',
                                             'There should be 4 integers divided by "." ')
                        return
                    for i in range(0, 4):
                        if int(ip_list[i]) > 255 or int(ip_list[i]) < 0:
                            QMessageBox.critical(self, 'error in Destination Address',
                                                 'Each integer should be in [0, 255] ')
                            return
                    dst_ip = self.ip_dst_ip.text()

                # header length，自动计算，无需用户填充
                # total length自动计算，无需用户填充

                # type of service，默认为0x0000
                tos = 0
                if self.min_cost.isChecked():
                    tos = tos | 0x02
                if self.max_rel.isChecked():
                    tos = tos | 0x04
                if self.max_th.isChecked():
                    tos = tos | 0x08
                if self.min_delay.isChecked():
                    tos = tos | 0x10

                # id，默认为1
                if self.ip_id.text() == "":
                    QMessageBox.critical(self, 'error', 'ID should be specified!')
                    return
                else:
                    if self.ip_id.text().isdigit():
                        id = int(self.ip_id.text())
                    else:
                        QMessageBox.critical(self, 'error in ID', 'input should be an decimal integral')
                        return

                # flags，默认为0
                ipv4_flag = 0
                if self.ip_MF.isChecked():
                    ipv4_flag = ipv4_flag | 0x01
                if self.ip_DF.isChecked():
                    ipv4_flag = ipv4_flag | 0x10

                # fragment，默认为0
                if self.ip_frag.text() == "":
                    QMessageBox.critical(self, 'error', 'Fragment should be specified!')
                    return
                else:
                    if self.ip_frag.text().isdigit():
                        frag = int(self.ip_frag.text())
                    else:
                        QMessageBox.critical(self, 'error in Fragment', 'input should be an decimal integral')
                        return


                # time to live，默认为128
                if self.ip_ttl.text() == "":
                    QMessageBox.critical(self, 'error', 'Time to live should be specified!')
                    return
                else:
                    if self.ip_ttl.text().isdigit():
                        ttl = int(self.ip_ttl.text())
                    else:
                        QMessageBox.critical(self, 'error in Time to live', 'input should be an decimal integral')
                        return
            else:
                QMessageBox.critical(self, 'error in Time to live', 'invalid version')

            ip = IP(src=src_ip, dst=dst_ip, tos=tos, id=id, flags=ipv4_flag, frag=frag, ttl=ttl)

        # step 2: 检查udp packet部分

        # source port, 默认为20001
        if self.udp_src_port.text() == "":
            QMessageBox.critical(self, 'error', 'Source Port should be specified!')
            return
        else:
            if int(self.udp_src_port.text()) > 65535 or int(self.udp_src_port.text()) < 0:
                QMessageBox.critical(self, 'error', 'Source Port should be in [0, 65535]')
                return
            src_port = int(self.udp_src_port.text())

        # destination port, 默认为80
        if self.udp_dst_port.text() == "":
            QMessageBox.critical(self, 'error', 'Destination Port should be specified!')
            return
        else:
            if int(self.udp_dst_port.text()) > 65535 or int(self.udp_dst_port.text()) < 0:
                QMessageBox.critical(self, 'error', 'Destinaion Port should be in [0, 65535]')
                return
            dst_port = int(self.udp_dst_port.text())


        udp = UDP(dport=dst_port, sport=src_port)
        # 判断使用的协议类型
        udp_packet = ip/udp

        # data不为空, 增加load内容
        if self.udp_data.toPlainText() != "":
            data = self.udp_data.toPlainText()
            udp_packet = udp_packet/data

        udp_packet.show()
        send(udp_packet)

    def icmp_sender(self):

        # step 1: 检查ip packet部分

        # 判断使用的协议类型
        value = int(self.version.text())
        if value == 6:
            # IPv6
            # source address
            if self.ipv6_src_ip.text() == "":
                QMessageBox.critical(self, 'error', 'Source Address should be specified!')
                return
            else:
                src_ip = self.ipv6_src_ip.text()

            if self.ipv6_dst_ip.text() == "":
                QMessageBox.critical(self, 'error', 'Destination Address should be specified!')
                return
            else:
                dst_ip = self.ipv6_dst_ip.text()

            # fl，默认为0
            if self.ipv6_fl.text() == "":
                QMessageBox.critical(self, 'error', 'Flow label should be specified!')
                return
            else:
                if self.ipv6_fl.text().isdigit():
                    fl = int(self.ipv6_fl.text())
                else:
                    QMessageBox.critical(self, 'error in Flow label', 'input should be an decimal integral')
                    return

            # traffic label，默认为0
            if self.ipv6_tc.text() == "":
                QMessageBox.critical(self, 'error', 'Traffic label should be specified!')
                return
            else:
                if self.ipv6_tc.text().isdigit():
                    tc = int(self.ipv6_tc.text())
                else:
                    QMessageBox.critical(self, 'error in Traffic label', 'input should be an decimal integral')
                    return

            # hlim，默认为1
            if self.ipv6_hlim.text() == "":
                QMessageBox.critical(self, 'error', 'Hop limit should be specified!')
                return
            else:
                if self.ipv6_hlim.text().isdigit():
                    hlim = int(self.ipv6_hlim.text())
                else:
                    QMessageBox.critical(self, 'error in Hop limit', 'input should be an decimal integral')
                    return

            if self.ipv6_nh.text() == "":
                QMessageBox.critical(self, 'error', 'Next header type should be specified!')
                return
            else:
                if self.ipv6_nh.text().isdigit():
                    nh = int(self.ipv6_nh.text())
                else:
                    QMessageBox.critical(self, 'error in Next header type', 'input should be an decimal integral')
                    return

            ip = IPv6(src=src_ip, dst=dst_ip, tc=tc, fl=fl, hlim=hlim, nh=nh)

        else:
            if value == 4:
                # IPv4

                # source address, 默认为本机ip
                if self.ip_src_ip.text() == "":
                    QMessageBox.critical(self, 'error', 'Source Address should be specified!')
                    return
                else:
                    ip_list = self.ip_src_ip.text().split('.')
                    if len(ip_list) != 4:
                        QMessageBox.critical(self, 'error in Source Address', 'There should be 4 integers divided by "." ')
                        return
                    for i in range(0, 4):
                        if int(ip_list[i]) > 255 or int(ip_list[i]) < 0:
                            QMessageBox.critical(self, 'error in Source Address', 'Each integer should be in [0, 255] ')
                            return
                    src_ip = self.ip_src_ip.text()

                # destination address, 默认为192.168.1.1
                if self.ip_dst_ip.text() == "":
                    QMessageBox.critical(self, 'error', 'Destination Address should be specified!')
                    return
                else:
                    ip_list = self.ip_dst_ip.text().split('.')
                    if len(ip_list) != 4:
                        QMessageBox.critical(self, 'error in Destination Address',
                                             'There should be 4 integers divided by "." ')
                        return
                    for i in range(0, 4):
                        if int(ip_list[i]) > 255 or int(ip_list[i]) < 0:
                            QMessageBox.critical(self, 'error in Destination Address',
                                                 'Each integer should be in [0, 255] ')
                            return
                    dst_ip = self.ip_dst_ip.text()

                # header length，自动计算，无需用户填充
                # total length自动计算，无需用户填充

                # type of service，默认为0x0000
                tos = 0
                if self.min_cost.isChecked():
                    tos = tos | 0x02
                if self.max_rel.isChecked():
                    tos = tos | 0x04
                if self.max_th.isChecked():
                    tos = tos | 0x08
                if self.min_delay.isChecked():
                    tos = tos | 0x10

                # id，默认为1
                if self.ip_id.text() == "":
                    QMessageBox.critical(self, 'error', 'ID should be specified!')
                    return
                else:
                    if self.ip_id.text().isdigit():
                        id = int(self.ip_id.text())
                    else:
                        QMessageBox.critical(self, 'error in ID', 'input should be an decimal integral')
                        return

                # flags，默认为0
                ipv4_flag = 0
                if self.ip_MF.isChecked():
                    ipv4_flag = ipv4_flag | 0x01
                if self.ip_DF.isChecked():
                    ipv4_flag = ipv4_flag | 0x10

                # fragment，默认为0
                if self.ip_frag.text() == "":
                    QMessageBox.critical(self, 'error', 'Fragment should be specified!')
                    return
                else:
                    if self.ip_frag.text().isdigit():
                        frag = int(self.ip_frag.text())
                    else:
                        QMessageBox.critical(self, 'error in Fragment', 'input should be an decimal integral')
                        return


                # time to live，默认为128
                if self.ip_ttl.text() == "":
                    QMessageBox.critical(self, 'error', 'Time to live should be specified!')
                    return
                else:
                    if self.ip_ttl.text().isdigit():
                        ttl = int(self.ip_ttl.text())
                    else:
                        QMessageBox.critical(self, 'error in Time to live', 'input should be an decimal integral')
                        return
            else:
                QMessageBox.critical(self, 'error in Time to live', 'invalid version')

            ip = IP(src=src_ip, dst=dst_ip, tos=tos, id=id, flags=ipv4_flag, frag=frag, ttl=ttl)

        code = 0
        type = 0
        # step 2: 检查icmp packet部分
        if self.icmp_type.currentText() == 'Echo Reply':
            type = 0
            code = 0
        if self.icmp_type.currentText() == 'Host Unreacheable':
            type = 3
            code = 1
        if self.icmp_type.currentText() == 'Port Unreachable':
            type = 3
            code = 3
        if self.icmp_type.currentText() == 'Fragmentation needed but no frag. bit set':
            type = 3
            code = 4
        if self.icmp_type.currentText() == 'Communication administratively prohibited by filtering':
            type = 3
            code = 13
        if self.icmp_type.currentText() == 'Redirect for Host':
            type = 5
            code = 1
        if self.icmp_type.currentText() == 'Echo Request':
            type = 8
            code = 0
        if self.icmp_type.currentText() == 'Time Exceeded':
            type = 11
            code = 0
        if self.icmp_type.currentText() == 'IP header bad (catchall error)':
            type = 12
            code = 0

        icmp = ICMP(code=code, type=type)
        # 判断使用的协议类型
        icmp_packet = ip/icmp

        # data不为空, 增加load内容
        if self.icmp_data.toPlainText() != "":
            data = self.icmp_data.toPlainText()
            icmp_packet = icmp_packet/data

        icmp_packet.show()
        send(icmp_packet)

    def arp_sender(self):
        hex_num = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
                   'a', 'b', 'c', 'd', 'e', 'f', 'A', 'B', 'C', 'D', 'E', 'F']
        if self.arp_src_mac.text() == '':
            QMessageBox.critical(self, 'error', 'Source MAC Address should be specified!')
            return
        else:
            mac_list = self.arp_src_mac.text().split(':')
            if len(mac_list) != 6:
                QMessageBox.critical(self, 'error in Source MAC Address', 'There should be 6 HEX divided by ":" ')
                return
            for i in range(0, 6):
                if len(mac_list[i]) != 2:
                    QMessageBox.critical(self, 'error in Source MAC Address',
                                         'There should be two digits in each HEX number!')
                    return
                for j in range(0, 2):
                    if mac_list[i][j] not in hex_num:
                        QMessageBox.critical(self, 'error in Source MAC Address',
                                             'Wrong HEX digits. Should be 0-9 or a-f or A-F ')
                        return

            hwsrc = self.arp_src_mac.text()

        if self.arp_src_ip.text() == '':
            QMessageBox.critical(self, 'error', 'Source IP Address should be specified!')
            return
        else:
            ip_list = self.arp_src_ip.text().split('.')
            if len(ip_list) != 4:
                QMessageBox.critical(self, 'error in Source IP Address', 'There should be 4 integers divided by "." ')
                return
            for i in range(0, 4):
                if int(ip_list[i]) > 255 or int(ip_list[i]) < 0:
                    QMessageBox.critical(self, 'error in Source IP Address',
                                         'Each integer should be in [0, 255] ')
                    return
            psrc = self.arp_src_ip.text()

        if self.arp_dst_mac.text() == '':
            QMessageBox.critical(self, 'error', 'Destination MAC Address should be specified!')
            return
        else:
            mac_list = self.arp_dst_mac.text().split(':')
            if len(mac_list) != 6:
                QMessageBox.critical(self, 'error in Destination MAC Address', 'There should be 6 HEX divided by ":" ')
                return
            for i in range(0, 6):
                if len(mac_list[i]) != 2:
                    QMessageBox.critical(self, 'error in Destination MAC Address',
                                         'There should be two digits in each HEX number!')
                    return
                for j in range(0, 2):
                    if mac_list[i][j] not in hex_num:
                        QMessageBox.critical(self, 'error in Destination MAC Address',
                                             'Wrong HEX digits. Should be 0-9 or a-f or A-F ')
                        return
            hwdst = self.arp_dst_mac.text()

        if self.arp_dst_ip.text() == '':
            QMessageBox.critical(self, 'error', 'Destination IP Address should be specified!')
            return
        else:
            ip_list = self.arp_dst_ip.text().split('.')
            if len(ip_list) != 4:
                QMessageBox.critical(self, 'error in Destination IP Address',
                                     'There should be 4 integers divided by "." ')
                return
            for i in range(0, 4):
                if int(ip_list[i]) > 255 or int(ip_list[i]) < 0:
                    QMessageBox.critical(self, 'error in Destination IP Address',
                                         'Each integer should be in [0, 255] ')
                    return
            pdst = self.arp_dst_ip.text()

        # operation type
        op = 1
        if self.arp_reply.isChecked():
            op = 2

        # hardware type，默认为0
        if self.arp_hw.text() == "":
            QMessageBox.critical(self, 'error', 'Hardware type should be specified!')
            return
        else:
            if self.arp_hw.text().isdigit():
                hwtype = int(self.arp_hw.text())
            else:
                QMessageBox.critical(self, 'error in Hardware type', 'input should be an decimal integral')
                return

        # protocol type，默认为0
        if self.arp_pro.text() == "":
            QMessageBox.critical(self, 'error', 'Protocol type should be specified!')
            return
        else:
            if self.arp_pro.text().isdigit():
                ptype = int(self.arp_pro.text())
            else:
                QMessageBox.critical(self, 'error in Protocol type', 'input should be an decimal integral')
                return

        arp_packet = ARP(op=op, hwsrc=hwsrc, hwdst=hwdst, psrc=psrc, pdst=pdst, hwtype=hwtype, ptype=ptype)
        arp_packet.show()
        send(arp_packet)


if __name__ == '__main__':
    app = QApplication(sys.argv)  # 在 QApplication 方法中使用，创建应用程序对象
    myWin = MyMainWindow()  # 实例化 MyMainWindow 类，创建主窗口
    myWin.show()  # 在桌面显示控件 myWin
    sys.exit(app.exec_())  # 结束进程，退出程序

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
