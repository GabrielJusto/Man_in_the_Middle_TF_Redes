import socket, sys , struct, time

ETH_P_ALL = 0x0003

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
            

            if icmp_type == 133:

            



        