import argparse

import django
from scapy.all import *

from packet_processing import packet_processor

django.setup()

parser = argparse.ArgumentParser(description='WiFi Passive Server')
parser.add_argument('-r', dest='pcap', action='store', help='pcap file to read')
parser.add_argument('-i', dest='interface', action='store', default='mon0', help='interface to sniff (default mon0)')
args = parser.parse_args()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# count of scapy packets received
total_pkt_count = 0

interface = "mon0"


def filter_and_send_packet(pkt):
    global total_pkt_count
    total_pkt_count += 1

    # Quick way to indicate that the sniffing is still continuing
    if total_pkt_count % 10000 == 0:
        logger.info(str(datetime.now()) + 'Total Packet Count thus far: ' + str(total_pkt_count))

    # Dot11 == 802.11

    if pkt.haslayer(ARP):
        packet_processor.ingest_ARP_packet(pkt)

    elif pkt.haslayer(Dot11ProbeReq):
        packet_processor.ingest_dot11_probe_req_packet(pkt)

    # elif pkt.haslayer(Dot11AssoReq) or pkt.haslayer(Dot11AssoResp) or pkt.haslayer(Dot11ReassoReq) or pkt.haslayer(
    #         Dot11ReassoResp):
    #     # logger.debug('Packet with Asso Req:')
    #     # logger.debug('Packet Summary: ' + str(pkt.summary()))
    #     # logger.debug('Packet Fields: ' + str(pkt.fields))
    #     pass

    if pkt.haslayer(Dot11) and pkt.haslayer(UDP) and pkt.dst == '224.0.0.251':
        packet_processor.ingest_mdns_packet(pkt)

if args.pcap:
    logger.info('Reading PCAP file %s...' % args.pcap)
    sniff(offline=args.pcap, prn=lambda x: filter_and_send_packet(x), store=0)
else:
    logger.info('Realtime Sniffing on interface %s...' % args.interface)
    sniff(iface=args.interface, prn=lambda x: filter_and_send_packet(x), store=0)

logger.info('Summary of devices detected:')

# for mac in client:
#     print '%s [%s] probed for %s' % (get_manuf(mac), mac, ', '.join(map(ascii_printable, client[mac])))
