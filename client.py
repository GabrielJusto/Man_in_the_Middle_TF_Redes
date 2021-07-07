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


def send_solicitation():

    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.getprotobyname("icmp"))
    except OSError as msg:
        print('Error'+str(msg))
        sys.exit(1)

    
    
    source_ip = ''
    dest_ip = ''
    
    #Header para o icmpv6 router solicitation
    icmp_type = 133
    icmp_code = 0
    icmp_checksum = 0
    icmp_payload = b'routersolicitation'

    icmp_header = struct.pack("!BBHHH%ds" %len(icmp_payload), icmp_type, icmp_code, icmp_checksum, icmp_payload)
    icmp_checksum = checksum(icmp_header)
    icmp_header = struct.pack("!BBHHH%ds" %len(icmp_payload), icmp_type, icmp_code, icmp_checksum, icmp_payload)

    ip_ver = 6
    ip_ihl = 5
    ip_tos = 0
    ip_tot_len = 20 + len(icmp_header) # Total datagram size (header=20 + icmp packet)
    ip_id = 54321
    ip_frag_off = 0
    ip_ttl = 255
    ip_proto = socket.IPPROTO_ICMPV6
    ip_check = 0
    ip_saddr = socket.inet_aton(source_ip)
    ip_daddr = socket.inet_aton(dest_ip)
    ip_ihl_ver = (ip_ver << 4) + ip_ihl
    # Pack IP header fields
    ip_header = struct.pack("!BBHHHBBH4s4s", ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl,
        ip_proto, ip_check, ip_saddr, ip_daddr)
    
    s.sendto(ip_header+icmp_header, (dest_ip,0))
    
    
    





    