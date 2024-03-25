import os

from scapy.layers.dns import DNS
from scapy.layers.inet import IP
from scapy.utils import PcapReader

resolver_ip_list = {'172.22.', '172.17.'}

# By default, each docker container will has two network interface, one with the network we created, and one with the default docker network.
# The default docker network is using IP range 172.17.0.x
# The network we created is using IP range 172.22.x.x
# So here we use this to distinguish the traffic between `client and resolver` and between `resolver and upstream server`.

def parse_pcap(filepath: str):
    if os.path.exists(filepath) and os.path.isfile(filepath):
        return PcapReader(filepath).read_all()
    return None


class TrafficAnalyzer:
    def __init__(self, filepath, count_handshake=True):
        self.filepath = filepath
        self.is_valid = True
        self.count_handshake = count_handshake
        # client side traffic: recv: received from client; send: sent to client
        self.client_recv = {"packets": [], "count": 0, "size": 0}
        self.client_send = {"packets": [], "count": 0, "size": 0}
        # upstream side traffic: recv: received from up stream; send: sent to upstream
        self.up_stream_recv = {"packets": [], "count": 0, "size": 0}
        self.up_stream_send = {"packets": [], "count": 0, "size": 0}
        self.ratio_size = -1
        self.ratio_count = -1
        self.analyze_traffic()

    def analyze_traffic(self):
        packets = parse_pcap(self.filepath)
        if packets:
            for packet in packets:
                if not (not packet.haslayer(DNS) and not self.count_handshake) and packet.haslayer(IP):
                    if packet[IP].dst[:11] == "172.22.101.":
                        self.client_send["packets"].append(packet)
                        self.client_send["count"] += 1
                        self.client_send["size"] += packet.payload.len
                    elif packet[IP].src[:11] == "172.22.101.":
                        self.client_recv["packets"].append(packet)
                        self.client_recv["count"] += 1
                        self.client_recv["size"] += packet.payload.len
                    elif packet[IP].dst[:11] == "172.22.201.":
                        self.up_stream_send["packets"].append(packet)
                        self.up_stream_send["count"] += 1
                        self.up_stream_send["size"] += packet.payload.len
                    elif packet[IP].src[:11] == "172.22.201.":
                        self.up_stream_recv["packets"].append(packet)
                        self.up_stream_recv["count"] += 1
                        self.up_stream_recv["size"] += packet.payload.len
                    elif packet[IP].src[:7] in resolver_ip_list:
                        self.up_stream_send["packets"].append(packet)
                        self.up_stream_send["count"] += 1
                        self.up_stream_send["size"] += packet.payload.len
                    else:
                        self.up_stream_recv["packets"].append(packet)
                        self.up_stream_recv["count"] += 1
                        self.up_stream_recv["size"] += packet.payload.len
            self.ratio_count = self.client_send['count'] + self.up_stream_send['count'] + self.up_stream_recv['count']
            if len(self.client_recv['packets']) > 0:
                self.ratio_size = (self.client_send['size'] + self.up_stream_send['size'] + self.up_stream_recv[
                    'size']) / self.client_recv['size']
        else:
            self.is_valid = False
