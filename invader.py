import socket, sys , struct, time
import uuid

ETH_P_ALL = 0x0003

def checksum(msg):
    s = 0
    # add padding if not multiple of 2 (16 bits)
    msg = (msg + b'\x00') if len(msg)%2 else msg
    for i in range(0, len(msg), 2):
        w = msg[i] + (msg[i+1] << 8)
        s = s + w
        s = (s & 0xffff) + (s >> 16)
    s = ~s & 0xffff
    return socket.ntohs(s)


def send_advertisement(mac_dest, mac_source, ip_dest, ip_source):
    # Create socket
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.getprotobyname("icmp"))
    except OSError as msg:
        print('Error'+str(msg))
        sys.exit(1)

    # s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
   
    

   
    #Header para o icmpv6 router solicitation
    icmp_type = 134
    icmp_code = 0
    icmp_checksum = 0
    icmp_hop_limit = 255
    icmp_autoconfig = 0
    icmp_lifetime = 5
    icmp_reachable = 1000
    icmp_retrans = 1000



    icmp_header = struct.pack("!BBHBBHLL"  , icmp_type, icmp_code, icmp_checksum,icmp_hop_limit, icmp_autoconfig, icmp_lifetime, icmp_reachable, icmp_retrans)
    icmp_checksum = checksum(icmp_header)
    icmp_header = struct.pack("!BBHBBHLL"  , icmp_type, icmp_code, icmp_checksum,icmp_hop_limit, icmp_autoconfig, icmp_lifetime, icmp_reachable, icmp_retrans)
    
    
    
    ip_ver = 6
    # ip_tc = 0
    # ip_fl = 0
    ip_f4 = (ip_ver << 4)
    ip_payload_length = len(icmp_header) 
    ip_next_header = 58
    ip_hop_limit = 3
    ip_saddr = ip_source
    ip_daddr = ip_dest

    ip_header = struct.pack("!BBHHBB16s16s", ip_f4, 255, 255, ip_payload_length, ip_next_header, ip_hop_limit, ip_saddr,ip_daddr)

    mac=uuid.UUID(int = uuid.getnode()).hex[-12:] 
    mac_byte = bytes.fromhex(mac)

    eth_type = 0x86dd
    eth = struct.pack("!6s6sH",mac_dest, mac_byte, eth_type)

   


    ip_addr_str = socket.inet_ntop(socket.AF_INET6, ip_dest)
    addr = socket.getaddrinfo(ip_addr_str, 0)
    
    s.sendto(eth + ip_header + icmp_header, (addr[0][4][0],0))

# [('<AddressFamily.AF_INET6: 10>', '<SocketKind.SOCK_STREAM: 1>', 6, '', ('fe80::200:ff:feaa:3', 0, 0, 0)), 
# ('<AddressFamily.AF_INET6: 10>', '<SocketKind.SOCK_DGRAM: 2>', 17, '', ('fe80::200:ff:feaa:3', 0, 0, 0)), 
# ('<AddressFamily.AF_INET6: 10>', '<SocketKind.SOCK_RAW: 3>', 0, '', ('fe80::200:ff:feaa:3', 0, 0, 0))]



try:
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
except OSError as msg:
    print('Error'+str(msg))
    sys.exit(1)
s.bind(('eth0',0))
print('Socket created!')


while True:
    (packet,addr) = s.recvfrom(65536)
    eth_length = 14
    eth_header = packet[:14]
    eth = struct.unpack("!6s6sH",eth_header)
    mac_dest = eth[0]
    mac_source = eth[1]
    

    if eth[2] != 0x86dd:
    	continue
    if eth[2] == 0x86dd :
        ip_len = 40
        ip_header = packet[eth_length:ip_len+eth_length]
        iph = struct.unpack("!LHBB16s16s", ip_header)
        version_ihl = iph[0] >> 28

        ip_payload_length = iph[1] 
        ip_next_header = iph[2]
        ip_hop_limit = iph[3]
        ip_saddr = iph[4]
        ip_daddr = iph[5]
        
       

        if(ip_next_header == 58):

            init = eth_length+ip_len
            icmp_len = ip_payload_length 
            
            icmp_header = packet[init: icmp_len + init]
            icmp_data_len = int(ip_payload_length) - 8



            icmph = struct.unpack("!BBHHH%ds" %icmp_data_len, icmp_header)

            icmp_type = icmph[0]
            icmp_code = icmph[1]
            icmp_checksum = icmph[2]
            icmp_identifier = icmph[3]
            icmp_seqnumber = icmph[4]
            icmp_payload = icmph[5]
            
            print(icmp_type)
            if icmp_type == 133:
                print("ROUTER REQUEST")
                send_advertisement(mac_source, mac_dest, ip_saddr, ip_daddr)



            

