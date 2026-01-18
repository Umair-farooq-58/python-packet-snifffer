#network packet sniffer

import socket
import struct
import textwrap

#Colors
BLUE   = "\033[94m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
MAGENTA= "\033[95m"
RESET  = "\033[0m"
#tabss
TAB_1= '\t - '
TAB_2= '\t\t - '  
TAB_3= '\t\t\t - '
DATA_TAB_3= '\t\t\t   '

#unpack ethernet frame (first 14 bytes)
#sender 6, receiver 6, type 2(protocol)
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('!6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

#return properly formatted mac addressss (like AA:BB:CC:DD:EE:FF)
def get_mac_addr(bytes_addr):
    bytes_str= map('{:02x}'.format, bytes_addr)
    mac_addr=':'.join(bytes_str).upper()
    return mac_addr

#unpack ipv4 packet
def ipv4_packet(data):
    version_header_length= data[0]
    version = version_header_length >> 4
    header_length= (version_header_length & 15) *4
    ttl, proto, src, target= struct.unpack('!8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

#return properly formatted ipv4 address
def ipv4(addr):
    return '.'.join(map(str, addr))

#unpacks icmp packett
def icmp_packet(data):
    icmp_type, code, checksum= struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

#unpacks tcp packet
def tcp_segment(data):
    (src_port, dest_port, seq, acknowledgment, offset_reserved_flags)= struct.unpack('!H H L L', data[:14])
    offset= (offset_reserved_flags >> 12) *4
    flag_urg= (offset_reserved_flags & 32) >>5
    flag_ack= (offset_reserved_flags & 16) >>4
    flag_psh= (offset_reserved_flags & 8) >>3
    flag_rst= (offset_reserved_flags & 4) >>2
    flag_syn= (offset_reserved_flags & 2) >>1
    flag_fin= offset_reserved_flags & 1
    return src_port, dest_port, seq, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

#unpacks udp packet
def udp_segment(data):
    src_port, dest_port, size= struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

#format mmultiline data
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string= ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size%2:
            size -=1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

def main():
    conns= socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        raw_data, addr = conns.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print(f"{BLUE}\nEthernet Frame:{RESET}")
        print(TAB_1 +f"Destination: {dest_mac}, Source: {src_mac}, Protocol: {eth_proto}")
        #8 is for ipv4
        if eth_proto==8:
            (version, header_length, ttl, proto, src, target, data)= ipv4_packet(data)
            print(TAB_1 + f"{GREEN}IPv4 Packet:{RESET}")
            print(TAB_2 +f"Version:{version}, Header Lenght:{header_length}, TTL:{ttl}")
            print(TAB_2 +f"Protocol:{proto}, Source:{src}, Target:{target}")

 #1 is for icmp, 6 is for tcp, 17 is for udp
            #icmp
            if proto==1:
                icmp_type, code, checksum, data= icmp_packet(data)
                print(TAB_1 + f"{YELLOW}ICMP Packet:{RESET}")
                print(TAB_2 +f"Type:{icmp_type}, Code:{code}, Checksum:{checksum}")
                print(TAB_2 + "Data:")
                print(format_multi_line(DATA_TAB_3, data))
            #tcp
            elif proto==6:
                (src_port, dest_port, seq, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data)= tcp_segment(data)
                print(TAB_1 + f"{RED}TCP Segment:{RESET}")
                print(TAB_2 +f"Source Port:{src_port}, Destination Port:{dest_port}")
                print(TAB_2 +f"Sequence:{seq}, Acknowledgment:{acknowledgment}")
                print(TAB_2 +f"{MAGENTA}Flags:{RESET}")
                print(TAB_3 +f"URG:{flag_urg}, ACK:{flag_ack}, PSH:{flag_psh}, RST:{flag_rst}, SYN:{flag_syn}, FIN:{flag_fin}")
                print(TAB_2 + "Data:")
                print(format_multi_line(DATA_TAB_3, data))
            #udp
            elif proto==17:
                src_port, dest_port, size, data= udp_segment(data)
                print(TAB_1 + f"{CYAN}UDP Segment:{RESET}")
                print(TAB_2 +f"Source Port:{src_port}, Destination Port:{dest_port}, Size:{size}")
                print(TAB_2 + "Data:")
                print(format_multi_line(DATA_TAB_3, data))


if __name__== '__main__':
    main()