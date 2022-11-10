import argparse
import socket
from sys import flags
from scapy.all import IP, TCP, Ether, ICMP, IPerror
import time

MAX_HOPS = 30
DST_PORT = 80
TARGET = ""



# sends a single probe with specified ttl
def sendProbe(my_ttl, my_id):
    ip = IP(dst=TARGET, ttl=my_ttl, id = my_id)
    tcp = TCP(sport=recv_sock.getsockname()[1], dport=DST_PORT, flags="S")
    packet = ip/tcp
    #print(IP(raw(packet))[IP].id)

    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    s.sendto(bytes(packet), (TARGET, DST_PORT))

# recieves a probe, will listen until timeout
def recieveProbe():
    recv_sock.settimeout(1)
    try:
        msgFromServer = recv_sock.recv(65565)
        recieved = Ether(msgFromServer)
        return recieved
    except Exception as e:
        return 0

# sends the traceroute probes. sends entire group and creates a dictionary with
# key value pairs. The key = (ttl, id), and the value = time in ns we sent it
def sendTraces():
    sent_packets = {}

    for i in range(MAX_HOPS):
        for j in range(3):
            sent_packets[(i, j)] = time.time_ns()
            sendProbe(i, j)

    return sent_packets

# given a dictionary of probes, determine if a reply
# is a reply to a probe
def isProbe(probe_dict, recieved_packet):
    packet_tuple = (recieved_packet[IP][ICMP].ttl, recieved_packet[IP][ICMP].id)
    if packet_tuple in probe_dict:
        print(packet_tuple)
        return True
    else:
        return False

# drives the traceroute program, sends all probes and listens for them
def traceroute_driver():
    sent_probes = sendTraces()
    total_probes = len(sent_probes)
    timeout_count = 0

    while total_probes != 0 and timeout_count != 10:
        returnedProbe = recieveProbe()

        # if there was no returned probe, it is a timeout
        if returnedProbe == 0:
            timeout_count = timeout_count + 1
        # if the probe is in the list, it is a probe reply
        elif isProbe(sent_probes, returnedProbe):
            total_probes = total_probes - 1
    


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
    
    ETH_P_IP = 0x0800
    recv_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_IP)) 
    recv_sock.bind(('ens3', 0))

    #sendProbe(1, 1)
    sendProbe(1, 2)
    #traceroute_driver()
    recieved_packet = recieveProbe()
    #recieved_packet.show()
    icmp_error = recieved_packet[ICMP]
    #icmp_error.show()
    icmp = icmp_error[IPerror]
    icmp.show()
    
    #packet_tuple = (recieved_packet[IP][ICMP][IP].ttl, recieved_packet[IP][ICMP][IP].id)
    #print(packet_tuple)

    #print(time.time_ns())
    