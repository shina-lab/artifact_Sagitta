# パケットデータ
INPUT_DIR = "../input-file/34c773c1bffb7389c434899395211077dcebf8c9"
with open(f"{INPUT_DIR}/000130", "rb") as f:
    tls1 = f.read()
with open(f"{INPUT_DIR}/crash-000005", "rb") as f:
    tls2 = f.read()

# pip install scapy
from scapy.all import *
import binascii

def generate_packet(tls_binary_data):
    # Etherフレーム、IPヘッダー、TCPヘッダーと組み合わせてTLSのバイナリデータを作成
    ether = Ether(dst="00:11:22:33:44:55", src="66:77:88:99:aa:bb")
    ip = IP(dst="192.168.1.1", src="192.168.1.2")
    tcp = TCP(dport=443, sport=12345, seq=1000, ack=0, flags="PA")

    # TLSデータをペイロードとしてセット
    packet = ether / ip / tcp / Raw(load=tls_binary_data)

    return packet

# pcapファイルに書き込む
wrpcap('result/poc-SSL020.pcap', [generate_packet(tls1), generate_packet(tls2)])