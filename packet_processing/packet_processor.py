import binascii

from django.core.exceptions import *

# for mdns/bonjour name parsing
from dnslib import DNSRecord
from netaddr import EUI
from pytz import utc

from scapy.all import *
from scapy.layers.dot11 import Dot11Elt, Dot11
from scapy.layers.l2 import ARP, Ether

from db import influx
from mac_parser import manuf

from security_ssid.models import Client, AP

logger = logging.getLogger(__name__)
client = defaultdict(list)
mac_parser_ws = manuf.MacParser()


def ingest_dot11_probe_req_packet(probe_pkt):
    # Transform beacon packet and insert into InfluxDB in realtime
    # if pkt.type == 0 and pkt.subtype == 4:  # mgmt, probe request
    logger.debug('Dot11 Probe Req found')
    client_mac = probe_pkt.getlayer(Dot11).addr2

    # if pkt.haslayer(Dot11Elt) and pkt.info:
    #     probed_ssid = pkt.info.decode('utf8')
    #     print 'Main Packet SSID: ' + probed_ssid

    if probe_pkt.haslayer(Dot11Elt) and probe_pkt.info:
        try:
            probed_ssid = probe_pkt.info.decode('utf8')
        except UnicodeDecodeError:
            probed_ssid = 'HEX:%s' % binascii.hexlify(probe_pkt.info)
            logger.info('%s [%s] probed for non-UTF8 SSID (%s bytes, converted to "%s")' % (
                get_manuf(client_mac), client_mac, len(probe_pkt.info), probed_ssid))
        if len(probed_ssid) > 0 and probed_ssid not in client[client_mac]:
            client[client_mac].append(probed_ssid)
            # unicode goes in DB for browser display
            update_summary_database(client_mac=client_mac, pkt_time=probe_pkt.time, SSID=probed_ssid)

        if len(probed_ssid) > 0:
            if probe_pkt.notdecoded is not None:
                # The location of the RSSI strength is dependent on the physical NIC
                # Alfa AWUS 036N
                # client_signal_strength = -(256 - ord(probe_pkt.notdecoded[-4:-3]))

                # Alfa AWUS 036NHA (Atheros AR9271)
                client_signal_strength = -(256 - ord(probe_pkt.notdecoded[-2:-1]))

            else:
                client_signal_strength = -100
                logger.debug("No client signal strength found")

            # ascii only for console print
            logger.info("%s [%s] probeReq for %s, signal strength: %s" % (
                get_manuf(client_mac), client_mac, ascii_printable(probed_ssid), client_signal_strength))
            send_client_data_to_influxdb(client_mac,
                                         probe_pkt.time,
                                         client_signal_strength,
                                         ascii_printable(probed_ssid))
    else:
        logger.debug('Dot11Elt and info missing from sub packet in Dot11ProbeReq')


def ingest_ARP_packet(arp_pkt):
    logger.info('ARP packet detected.')
    arp = arp_pkt.getlayer(ARP)
    dot11 = arp_pkt.getlayer(Dot11)
    mode = ''
    try:
        # On wifi, BSSID (mac) of AP (Access Point) that the client is currently connected to
        target_ap_bssid = dot11.addr1

        # Wifi client mac address
        source_client_mac = dot11.addr2

        # While sniffing wifi (mon0), the other-AP bssid disclosure will be here in 802.11 dest
        target_mac = dot11.addr3

        if target_ap_bssid != 'ff:ff:ff:ff:ff:ff' and target_mac != 'ff:ff:ff:ff:ff:ff':
            if dot11.FCfield == 1 and arp.op == 1 and source_client_mac != target_mac:
                logger.info('%s [%s] ' + 'ARP' + ' who has %s? tell %s -> %s [%s] on BSSID %s') % \
                (get_manuf(source_client_mac), source_client_mac, arp.pdst, arp.psrc, get_manuf(target_mac),
                 target_mac, target_ap_bssid)
                update_summary_database(client_mac=source_client_mac, pkt_time=arp_pkt.time, BSSID=target_mac)
            else:
                logger.debug('Skipping ARP packet Code 1')
        else:
            logger.debug('Skipping ARP packet Code 2')

    except:
        try:
            if arp_pkt.haslayer(Ether):
                # wifi client mac when sniffing a tap interface (e.g. at0 provided by airbase-ng)
                source_client_mac = arp_pkt.getlayer(Ether).src

                # we won't get any 802.11/SSID probes but the bssid disclosure will be in the ethernet dest
                target_mac = arp_pkt.getlayer(Ether).dst

                if target_mac != 'ff:ff:ff:ff:ff:ff' and arp.op == 1:
                    logger.info('%s [%s] ' + 'ARP' + ' who has %s? tell %s -> %s [%s] (Ether)') % \
                    (get_manuf(source_client_mac), source_client_mac, arp.pdst, arp.psrc,
                     get_manuf(target_mac), target_mac)
                    update_summary_database(client_mac=source_client_mac, pkt_time=arp_pkt.time, BSSID=target_mac)
            else:
                logger.info('Skipping ARP Ether packet. Code 3')
        except IndexError:
            pass


def ingest_mdns_packet(mdns_pkt):
    logger.info('Packet with Dot11, UDP, and Apple mDNS')
    logger.debug(mdns_pkt.summary())

    # only parse MDNS names for 802.11 layer sniffing for now, easy to see what's a request from a client
    for mdns_pkt in mdns_pkt:
        if mdns_pkt.dport == 5353:
            logger.debug('Packet destination port 5353')
            try:
                d = DNSRecord.parse(mdns_pkt['Raw.load'])
                for q in d.questions:
                    if q.qtype == 255 and '_tcp.local' not in str(q.qname):
                        try:
                            src = mdns_pkt.getlayer('Dot11').addr3
                            name = str(q.qname).strip('.local')

                            # An mDNS Ethernet frame is a multicast UDP packet to:
                            # MAC address 01:00:5E:00:00:FB (for IPv4) or 33:33:00:00:00:FB (for IPv6)
                            # IPv4 address 224.0.0.251 or IPv6 address FF02::FB
                            # UDP port 5353
                            if src != '01:00:5e:00:00:fb':
                                create_or_update_client(src, datetime.utcfromtimestamp(mdns_pkt.time), name)
                        except AttributeError:
                            logger.error('Error parsing MDNS packet')
            except IndexError:
                pass


def get_manuf(mac_addr):
    # Try 2 different parsers on the mac address to find the Manufacturer
    try:
        mac = EUI(mac_addr)
        calced_manufacturer = mac.oui.records[0]['org'].split(' ')[0].replace(',', '')
    except:
        try:
            calced_manufacturer = mac_parser_ws.get_manuf(mac_addr)
        except:
            calced_manufacturer = 'unknown'

    return ascii_printable(calced_manufacturer)


def create_or_update_client(mac_addr, utc, name=None):
    utc = utc.localize(utc)
    logger.debug('Create or update client for mac addr.: ' + str(mac_addr))
    try:
        _client = Client.objects.get(mac=mac_addr)

        # Check if the client device has been seen previously, and if so, update the last seen time to now
        if _client.lastseen_date < utc:
            logger.debug('Updating client last seen date')
            _client.lastseen_date = utc

    # if the client doesn't already exist, we create a new Client to represent this mobile device
    except ObjectDoesNotExist:
        logger.debug('Creating new client')
        _client = Client(mac=mac_addr, lastseen_date=utc, manufacturer=get_manuf(mac_addr))

    if name:
        _client.name = name
        logger.info('Updated name of %s to %s' % (_client, _client.name))
    _client.save()
    return _client


def ascii_printable(s):
    if s is not None:
        return ''.join(i for i in s if ord(i) > 31 and ord(i) < 128)
    else:
        return ''


def update_summary_database(client_mac=None, pkt_time=None, SSID='', BSSID=''):
    utc_pkt_time = datetime.utcfromtimestamp(pkt_time)
    if SSID:
        try:
            access_pt = AP.objects.get(SSID=SSID)
        except ObjectDoesNotExist:
            access_pt = AP(SSID=SSID, lastprobed_date=utc_pkt_time, manufacturer='Unknown')
    elif BSSID:
        try:
            access_pt = AP.objects.get(BSSID=BSSID)
        except ObjectDoesNotExist:
            access_pt = AP(BSSID=BSSID, lastprobed_date=utc_pkt_time, manufacturer=get_manuf(BSSID))

    if access_pt.lastprobed_date and access_pt.lastprobed_date < utc.localize(utc_pkt_time):
        access_pt.lastprobed_date = utc_pkt_time

    # avoid ValueError: 'AP' instance needs to have a primary key value before a many-to-many relationship can be used.
    access_pt.save()

    access_pt.client.add(create_or_update_client(client_mac, utc_pkt_time))
    access_pt.save()


def sniff_wifi_access_points(pkt):
    if pkt.haslayer(Dot11):
        # Packet Type 0 and Subtype of Binary 1000 (decimal 8) is a Management-Beacon packet
        if pkt.type == 0 and pkt.subtype == 8:
            logger.info("Management Beacon Packet: Access Point MAC: %s with SSID: %s " % (pkt.addr2, pkt.info))
            # addr1 is usually ff:ff:ff:ff:ff:ff
            logger.info(pkt.addr1)


def send_client_data_to_influxdb(client_mac_addr, pkt_time, client_sig_rssi, probed_ssid_name):
    # Send client mac address, time of observation, and signal strength to influxDB measurement (table)
    influx_formatted_data = influx.assemble_json(measurement='clientdevices',
                                                 pkt_timestamp=pkt_time,
                                                 rssi_value=client_sig_rssi,
                                                 client_mac_addr=client_mac_addr,
                                                 probed_ssid=probed_ssid_name)
    influx.write_data(influx_formatted_data)
    logger.debug('Client data sent to influxdb')
