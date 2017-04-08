import binascii

from django.core.exceptions import *
# for mdns/bonjour name parsing
from dnslib import DNSRecord
from netaddr import EUI
from scapy.all import *

from security_ssid.models import Client, AP

logger = logging.getLogger(__name__)

client = defaultdict(list)


def ascii_printable(s):
    return ''.join(i for i in s if ord(i) > 31 and ord(i) < 128)


def ingest_dot11_probe_req_packet(probe_pkt):
    # Transform beacon packet and insert into InfluxDB in realtime
    # if pkt.type == 0 and pkt.subtype == 4:  # mgmt, probe request
    logger.debug('Dot11 Probe Req found')
    mac = probe_pkt.getlayer(Dot11).addr2

    # if pkt.haslayer(Dot11Elt) and pkt.info:
    #     probed_ssid = pkt.info.decode('utf8')
    #     print 'Main Packet SSID: ' + probed_ssid

    if probe_pkt.haslayer(Dot11Elt) and probe_pkt.info:
        try:
            probed_ssid = probe_pkt.info.decode('utf8')
        except UnicodeDecodeError:
            probed_ssid = 'HEX:%s' % binascii.hexlify(probe_pkt.info)
            print '%s [%s] probed for non-UTF8 SSID (%s bytes, converted to "%s")' % (
                get_manuf(mac), mac, len(probe_pkt.info), probed_ssid)
        if len(probed_ssid) > 0 and probed_ssid not in client[mac]:
            client[mac].append(probed_ssid)
            # unicode goes in DB for browser display
            update_summary_database(client_mac=mac, time=probe_pkt.time, SSID=probed_ssid)

            if probe_pkt.notdecoded is not None:
                signal_strength = -(256 - ord(probe_pkt.notdecoded[-4:-3]))
            else:
                signal_strength = -100
                logger.debug("No signal strength found")

            # ascii only for console print
            return "%s [%s] probeReq for %s, signal strength: %s" % (
                get_manuf(mac), mac, ascii_printable(probed_ssid), signal_strength)
    else:
        logger.debug('Dot11Elt and info missing from sub packet in Dot11ProbeReq')

    return None


def ingest_ARP_packet(arp_pkt):
    logger.debug('ARP packet detected.')
    arp = arp_pkt.getlayer(ARP)
    dot11 = arp_pkt.getlayer(Dot11)
    mode = ''
    try:
        # On wifi, BSSID (mac) of AP (Access Point) that the client is currently connected to
        target_bssid = dot11.addr1

        # Wifi client mac address
        source_mac = dot11.addr2

        # While sniffing wifi (mon0), the other-AP bssid disclosure will be here in 802.11 dest
        target_mac = dot11.addr3

        if target_bssid != 'ff:ff:ff:ff:ff:ff' and target_mac != 'ff:ff:ff:ff:ff:ff':
            if dot11.FCfield == 1 and arp.op == 1 and source_mac != target_mac:
                print ('%s [%s] ' + 'ARP' + ' who has %s? tell %s -> %s [%s] on BSSID %s') % \
                      (get_manuf(source_mac), source_mac, arp.pdst, arp.psrc, get_manuf(target_mac), target_mac,
                       target_bssid)
                update_summary_database(client_mac=source_mac, time=arp_pkt.time, BSSID=target_mac)
            else:
                logger.debug('Skipping ARP packet Code 1')
        else:
            logger.debug('Skipping ARP packet Code 2')

    except:
        try:
            if arp_pkt.haslayer(Ether):
                # wifi client mac when sniffing a tap interface (e.g. at0 provided by airbase-ng)
                source_mac = arp_pkt.getlayer(Ether).src

                # we won't get any 802.11/SSID probes but the bssid disclosure will be in the ethernet dest
                target_mac = arp_pkt.getlayer(Ether).dst

                if target_mac != 'ff:ff:ff:ff:ff:ff' and arp.op == 1:
                    print ('%s [%s] ' + 'ARP' + ' who has %s? tell %s -> %s [%s] (Ether)') % \
                          (get_manuf(source_mac), source_mac, arp.pdst, arp.psrc, get_manuf(target_mac), target_mac)
                    update_summary_database(client_mac=source_mac, time=arp_pkt.time, BSSID=target_mac)
            else:
                print 'Skipping ARP Ether packet'
        except IndexError:
            pass

    return None


def ingest_mdns_packet(mdns_pkt):
    logger.debug('Packet with Dot11, UDP, and Apple mDNS')
    logger.debug(mdns_pkt.summary())

    # only parse MDNS names for 802.11 layer sniffing for now, easy to see what's a request from a client
    for mdns_pkt in mdns_pkt:
        if mdns_pkt.dport == 5353:
            print 'Packet destination port 5353'
            try:
                d = DNSRecord.parse(mdns_pkt['Raw.load'])
                for q in d.questions:
                    if q.qtype == 255 and '_tcp.local' not in str(q.qname):
                        try:
                            src = mdns_pkt.getlayer('Dot11').addr3
                            name = str(q.qname).strip('.local')
                            if src != '01:00:5e:00:00:fb':
                                create_or_update_client(src, datetime.utcfromtimestamp(mdns_pkt.time), name)
                        except AttributeError:
                            logger.error('Error parsing MDNS packet')
            except IndexError:
                pass


def get_manuf(m):
    try:
        mac = EUI(m)
        manuf = mac.oui.records[0]['org'].split(' ')[0].replace(',', '')
    except:
        manuf = 'unknown'
    # logger.debug('Manufacturer: %s', ascii_printable(manuf))
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


def update_summary_database(client_mac=None, time=None, SSID='', BSSID=''):
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
