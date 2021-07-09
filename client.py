import socket, sys,struct


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


def send_solicitation(source_ip, dest_ip):

    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.getprotobyname("icmp"))
    except OSError as msg:
        print('Error'+str(msg))
        sys.exit(1)

    
    

    
    #Header para o icmpv6 router solicitation
    icmp_type = 133
    icmp_code = 0
    icmp_checksum = 0
    icmp_payload = b'routersolicitation'
    icmp_identifier = 12
    icmp_seqnumber = 0

    icmp_header = struct.pack("!BBHHH%ds" %len(icmp_payload), icmp_type, icmp_code, icmp_checksum,icmp_identifier, icmp_seqnumber, icmp_payload)
    icmp_checksum = checksum(icmp_header)
    icmp_header = struct.pack("!BBHHH%ds" %len(icmp_payload), icmp_type, icmp_code, icmp_checksum,icmp_identifier, icmp_seqnumber, icmp_payload)


    ip_ver = 6
    # ip_tc = 0
    # ip_fl = 0
    ip_f4 = (ip_ver << 28)

    print(len(icmp_header))

    ip_payload_length = len(icmp_header) 
    ip_next_header = 58
    ip_hop_limit = 3
    ip_saddr = socket.inet_pton(socket.AF_INET6, source_ip)
    ip_daddr = socket.inet_pton(socket.AF_INET6,dest_ip)

    ip_header = struct.pack("!LHBB16s16s", ip_f4, ip_payload_length, ip_next_header, ip_hop_limit, ip_saddr,ip_daddr)

    
    s.sendto(ip_header + icmp_header, (dest_ip,0))
    

send_solicitation("2001:0::10", "2001:0::")

    





    