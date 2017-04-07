import argparse
import binascii
import logging

import django
from django.core.exceptions import *

# for mdns/bonjour name parsing
from dnslib import DNSRecord
from netaddr import EUI

from scapy.all import *

from color import *
from security_ssid.models import Client, AP

django.setup()
parser = argparse.ArgumentParser(description='WiFi Passive Sniff Server')
parser.add_argument('-r', dest='pcap', action='store', help='pcap file to read')
parser.add_argument('-i', dest='interface', action='store', default='mon0', help='interface to sniff (default mon0)')
args = parser.parse_args()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# count of scapy packets processed
total_pkt_count = 0

client = defaultdict(list)
interface = "mon0"


def ascii_printable(s):
    return ''.join(i for i in s if ord(i) > 31 and ord(i) < 128)


def get_manuf(m):
    try:
        mac = EUI(m)
        manuf = mac.oui.records[0]['org'].split(' ')[0].replace(',', '')
    # .replace(', Inc','').replace(' Inc.','')
    except:
        manuf = 'unknown'
    return ascii_printable(manuf)


def create_or_update_client(mac_addr, utc, name=None):
    try:
        c = Client.objects.get(mac=mac_addr)
        if c.lastseen_date < utc:
            c.lastseen_date = utc
            # print 'Updated time on object %s' % mac
    except ObjectDoesNotExist:
        c = Client(mac=mac_addr, lastseen_date=utc, manufacturer=get_manuf(mac_addr))
    # print 'Created new object %s' % mac
    if name:
        c.name = name
        print 'Updated name of %s to %s' % (c, c.name)
    c.save()
    return c


def update_database(client_mac=None, time=None, SSID='', BSSID=''):
    utc_time = datetime.utcfromtimestamp(time)
    if SSID:
        try:
            access_pt = AP.objects.get(SSID=SSID)
        except ObjectDoesNotExist:
            access_pt = AP(SSID=SSID, lastprobed_date=utc_time, manufacturer='Unknown')
    elif BSSID:
        try:
            access_pt = AP.objects.get(BSSID=BSSID)
        except ObjectDoesNotExist:
            access_pt = AP(BSSID=BSSID, lastprobed_date=utc_time, manufacturer=get_manuf(BSSID))

    if access_pt.lastprobed_date and access_pt.lastprobed_date < utc_time:
        access_pt.lastprobed_date = utc_time

    # avoid ValueError: 'AP' instance needs to have a primary key value before a many-to-many relationship can be used.
    access_pt.save()
    access_pt.client.add(create_or_update_client(client_mac, utc_time))
    access_pt.save()


def sniff_wifi_access_points(pkt):
    if pkt.haslayer(Dot11):
        # Packet Type 0 and Subtype of Binary 1000 (decimal 8) is a Management-Beacon packet
        if pkt.type == 0 and pkt.subtype == 8:
            logger.info("Management Beacon Packet: Access Point MAC: %s with SSID: %s " % (pkt.addr2, pkt.info))
            # addr1 is usually ff:ff:ff:ff:ff:ff
            logger.info(pkt.addr1)


def process_packet(pkt):
    # TODO: Refactor this to send every packet to a queue in order to process in a distributed fashion
    # New iteration of processing will need to catalogue every packet from certain MAC Addresses,
    # which are defined in a singular RDS Postgres table
    global total_pkt_count
    total_pkt_count += 1

    # Quick way to indicate that the sniffing is still continuing
    if total_pkt_count % 10000 == 0:
        print 'Total Packet Count thus far: ' + str(total_pkt_count)
        print str(datetime.now())

    # print pkt.summary()
    # print pkt.getlayer(Dot11).addr2

    # Dot11 == 802.11
    if pkt.haslayer(ARP):
        print '----ARP packet'
        arp = pkt.getlayer(ARP)
        dot11 = pkt.getlayer(Dot11)
        mode = ''
        try:
            target_bssid = dot11.addr1  # on wifi, BSSID (mac) of AP currently connected to
            source_mac = dot11.addr2  # wifi client mac
            target_mac = dot11.addr3  # if we're sniffing wifi (mon0) the other-AP bssid disclosure will be here in 802.11 dest
            if dot11.FCfield == 1 and target_bssid != 'ff:ff:ff:ff:ff:ff' and arp.op == 1 and target_mac != 'ff:ff:ff:ff:ff:ff' and source_mac != target_mac:
                print ('%s [%s] ' + great_success('ARP') + ' who has %s? tell %s -> %s [%s] on BSSID %s') % \
                      (get_manuf(source_mac), source_mac, arp.pdst, arp.psrc, get_manuf(target_mac), target_mac,
                       target_bssid)
                update_database(client_mac=source_mac, time=pkt.time, BSSID=target_mac)
                # code.interact(local=locals())
            else:
                print 'Skipping ARP packet'

        except:
            try:
                if pkt.haslayer(Ether):
                    source_mac = pkt.getlayer(
                        Ether).src  # wifi client mac when sniffing a tap interface (e.g. at0 provided by airbase-ng)
                    target_mac = pkt.getlayer(
                        Ether).dst  # we won't get any 802.11/SSID probes but the bssid disclosure will be in the ethernet dest
                    if target_mac != 'ff:ff:ff:ff:ff:ff' and arp.op == 1:
                        print ('%s [%s] ' + great_success('ARP') + ' who has %s? tell %s -> %s [%s] (Ether)') % \
                              (get_manuf(source_mac), source_mac, arp.pdst, arp.psrc, get_manuf(target_mac), target_mac)
                        update_database(client_mac=source_mac, time=pkt.time, BSSID=target_mac)
                else:
                    print 'Skipping Ether packet'
            except IndexError:
                pass

    elif pkt.haslayer(Dot11ProbeReq):
        # if pkt.type == 0 and pkt.subtype == 4:  # mgmt, probe request
        # print '----Dot11 Probe Req found'
        mac = pkt.getlayer(Dot11).addr2
        # print mac

        # if pkt.haslayer(Dot11Elt) and pkt.info:
        #     probed_ssid = pkt.info.decode('utf8')
        #     print 'Main Packet SSID: ' + probed_ssid

        if pkt.haslayer(Dot11Elt) and pkt.info:
            try:
                probed_ssid = pkt.info.decode('utf8')
            except UnicodeDecodeError:
                probed_ssid = 'HEX:%s' % binascii.hexlify(pkt.info)
                print '%s [%s] probed for non-UTF8 SSID (%s bytes, converted to "%s")' % (
                    get_manuf(mac), mac, len(pkt.info), probed_ssid)
            if len(probed_ssid) > 0 and probed_ssid not in client[mac]:
                client[mac].append(probed_ssid)
                # unicode goes in DB for browser display
                update_database(client_mac=mac, time=pkt.time, SSID=probed_ssid)

                if pkt.notdecoded is not None:
                    signal_strength = -(256 - ord(pkt.notdecoded[-4:-3]))
                else:
                    signal_strength = -100
                    logger.debug("No signal strength found")

                # ascii only for console print
                return "%s [%s] probeReq for %s, signal strength: %s" % (
                    get_manuf(mac), mac, ascii_printable(probed_ssid), signal_strength)
        else:
            logger.debug('Dot11Elt and info missing from sub packet in Dot11ProbeReq')

    elif pkt.haslayer(Dot11AssoReq) or pkt.haslayer(Dot11AssoResp) or pkt.haslayer(Dot11ReassoReq) or pkt.haslayer(Dot11ReassoResp):
        # logger.debug('Packet with Asso Req:')
        # logger.debug('Packet Summary: ' + str(pkt.summary()))
        # logger.debug('Packet Fields: ' + str(pkt.fields))
        pass

    if pkt.haslayer(Dot11) and pkt.haslayer(UDP) and pkt.dst == '224.0.0.251':
        print '----Packet with Dot11 and UDP and Apple mDNS:'
        print pkt.summary()

        # only parse MDNS names for 802.11 layer sniffing for now, easy to see what's a request from a client
        for pkt in pkt:
            if pkt.dport == 5353:
                print 'Packet destination port 5353'
                try:
                    d = DNSRecord.parse(pkt['Raw.load'])
                    for q in d.questions:
                        if q.qtype == 255 and '_tcp.local' not in str(q.qname):
                            try:
                                src = pkt.getlayer('Dot11').addr3
                                name = str(q.qname).strip('.local')
                                print great_success('%s is %s') % (src, name)
                                # code.interact(local=locals())
                                if src != '01:00:5e:00:00:fb':
                                    create_or_update_client(src, datetime.utcfromtimestamp(pkt.time), name)
                            except AttributeError:
                                print warning('Error parsing MDNS')
                except IndexError:
                    pass


if args.pcap:
    print 'Reading PCAP file %s...' % args.pcap
    sniff(offline=args.pcap, prn=lambda x: process_packet(x), store=0)
else:
    print 'Realtime Sniffing on interface %s...' % args.interface
    sniff(iface=args.interface, prn=lambda x: process_packet(x), store=0)


print
print 'Summary'
print '-------'
print

for mac in client:
    print '%s [%s] probed for %s' % (get_manuf(mac), mac, ', '.join(map(ascii_printable, client[mac])))
