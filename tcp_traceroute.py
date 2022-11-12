import argparse
import socket
from sys import flags
from scapy.all import IP, TCP, Ether, ICMP, IPerror, raw
import time

MAX_HOPS = 30
DST_PORT = 80
TARGET = ""
time_to_send = 0


# sends a single probe with specified ttl
def sendProbe(my_ttl, my_id):
    ip = IP(dst=TARGET, ttl=my_ttl, id = my_id)
    tcp = TCP(sport=my_id, dport=DST_PORT, flags="S", seq=my_id)
    packet = ip/tcp
    #packet.show()

    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    s.sendto(bytes(packet), (TARGET, DST_PORT))

# recieves a probe, will listen until timeout
def recieveProbe():
    recv_sock.settimeout(1)
    try:
        msgFromServer = recv_sock.recv(4096)
        recieved = Ether(msgFromServer)
        return recieved
    except Exception as e:
        return 0

# sends the traceroute probes. sends entire group and creates a dictionary with
# key value pairs. The key = (ttl, id), and the value = time in ns we sent it
def sendTraces():
    sent_packets = {}
    id = 12400
    
    for i in range(1, MAX_HOPS + 1):
        for j in range(3):
            sent_packets[id] = [time.time_ns(), i]
            sendProbe(i, id)
            id = id + 1
    
    return sent_packets

# given a dictionary of probes, determine if a reply
# is a reply to a probe
def isProbe(probe_dict, recieved_packet):
    # if ip packet is an icmp packet, parse it as such
    # looking for icmp error payload with one of our sent probes in it
    if recieved_packet[IP].proto == 1:
        icmp= recieved_packet[ICMP]
        if icmp.type != 11 or icmp.code != 0:
            return False
        #return True
        icmp_error = icmp[IPerror]
        if icmp_error.id in probe_dict:
            probe_dict[icmp_error.id][0] = (time.time_ns() - probe_dict[icmp_error.id][0])/1000000
            print(icmp_error.id)
            #print(probe_dict[icmp_error.id][0])
            return True
        else:
            return False
    # if a tcp packet, it is a reply from the server
    elif recieved_packet[IP].proto == 6:
        tcp_pac = recieved_packet[TCP]
        #print(tcp_pac.ack)
        if (tcp_pac.ack - 1) in probe_dict and tcp_pac.flags == "SA" and tcp_pac.sport == DST_PORT and tcp_pac.dport ==(tcp_pac.ack - 1):
            probe_dict[(tcp_pac.ack - 1)][0] = (time.time_ns() - probe_dict[(tcp_pac.ack - 1)][0])/1000000
            print(probe_dict[(tcp_pac.ack - 1)])
            return True
    else:
        return False

# drives the traceroute program, sends all probes and listens for them
def traceroute_driver():
    sent_probes = sendTraces()
    total_probes = len(sent_probes)
    timeout_count = 0
    #print(sent_probes)

    while total_probes != 0 and timeout_count != 10:
        returnedProbe = recieveProbe()

        # if there was no returned probe, it is a timeout
        if returnedProbe == 0:
            timeout_count = timeout_count + 1
            print('timeout')
        # if the probe is in the list, it is a probe reply
        elif isProbe(sent_probes, returnedProbe):
            total_probes = total_probes - 1
            #print(total_probes)
    


def setParams():
    parser = argparse.ArgumentParser()
    parser.add_argument('-m', metavar='MAX_HOPS', type=int, help="Max hops to probe (default = 30)")
    parser.add_argument('-p', metavar='DST_PORT', type=str, help="TCP destination port (default = 80)")
    parser.add_argument('-t', metavar='TARGET', type=str,
                        help="Target domain or IP")


    # parse arguments and put into args
    args = parser.parse_args()
    global TARGET, MAX_HOPS, DST_PORT

    # a target must always be specified
    if not args.t:
        print("No target specified. Terminating.")
        exit()
    else:
        TARGET = args.t
    
    # set optional arguments
    if args.m:
        MAX_HOPS = args.m
    if args.p:
        DST_PORT = args.p


if __name__ == '__main__':
    setParams()

    TARGET = socket.gethostbyname(TARGET)

    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    
    ETH_P_IP = 0x800
    #print(ETH_P_IP)
    recv_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_IP)) 
    recv_sock.bind(('ens3', 0))

    #sendProbe(1, 1)
    #sendProbe(1, 2)
    traceroute_driver()
    # recieved_packet = recieveProbe()
    # print(isProbe(None, recieved_packet))
    # print(recieved_packet[IP].proto)
    # icmp_error = recieved_packet[ICMP]
    # print(icmp_error.type)
    # print(icmp_error.code)
    # icmp = icmp_error[IPerror]
    # icmp.show()
    
    #packet_tuple = (recieved_packet[IP][ICMP][IP].ttl, recieved_packet[IP][ICMP][IP].id)
    #print(packet_tuple)

    #print(time.time_ns())
    