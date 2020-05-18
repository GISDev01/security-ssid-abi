# Mostly taken from paper by François-Xavier Aguessy and Côme Demoustier
# http://fxaguessy.fr/rapport-pfe-interception-ssl-analyse-donnees-localisation-smartphones/
# Updates in 2020 based on this article: https://appelsiini.net/2017/reverse-engineering-location-services/

import requests

from location_utils import BSSIDApple_pb2
from location_utils import GSM_pb2


def padBSSID(bssid):
    result = ''
    for e in bssid.split(':'):
        if len(e) == 1:
            e = '0%s' % e
        result += e + ':'
    return result.strip(':')


def ListWifiGrannySmith(wifi_list):
    access_points_from_wloc = {}
    for wifi in wifi_list.wifi:
        if wifi.HasField('location'):
            lat = wifi.location.latitude * pow(10, -8)
            lon = wifi.location.longitude * pow(10, -8)
            mac = padBSSID(wifi.bssid)
            access_points_from_wloc[mac] = (lat, lon)

    return access_points_from_wloc


def ProcessMobileResponse(cell_list):
    operators = {1: 'Telstra',
                 2: 'Optus',
                 3: 'Vodafone',
                 6: 'Three'}
    celldict = {}
    celldesc = {}

    # kml = simplekml.Kml()
    for cell in cell_list.cell:
        if cell.HasField('location') and cell.CID != -1:  # exclude "LAC" type results (usually 20 in each response)
            lat = cell.location.latitude * pow(10, -8)
            lon = cell.location.longitude * pow(10, -8)
            cellid = '%s:%s:%s:%s' % (cell.MCC, cell.MNC, cell.LAC, cell.CID)
            # kml.newpoint(name=cellid, coords=[(lon,lat)])
            try:
                #				cellname = '%s LAC:%s CID:%s [%s %s %s] [%s %s]' % (operators[cell.MNC],cell.LAC,cell.CID,\
                #					cell.location.data3,cell.location.data4,cell.location.data12,\
                #					cell.data6,cell.data7)
                cellname = '%s LAC:%s CID:%s' % (operators[cell.MNC], cell.LAC, cell.CID)
            except:
                cellname = 'MNC:%s LAC:%s CID:%s' % (cell.MNC, cell.LAC, cell.CID)
            try:
                if cell.HasField('channel'):
                    cellname += ' Channel:%s' % cell.channel
            except ValueError:
                pass
            celldict[cellid] = (lat, lon)
            celldesc[cellid] = cellname
        else:
            pass
            # print 'Weird cell: %s' % cell
            # kml.save("test.kml")
            # f=file('result.txt','w')
            # for (cid,desc) in celldesc.items():
            # print cid, desc
            # f.write('%s %s\n'%(cid,desc))
            # f.close()
            # print 'Wrote result.txt'
    return (celldict, celldesc)


def QueryBSSID(bssid_list):
    bssid_wifi_list_pbuf = BSSIDApple_pb2.BlockBSSIDApple()

    if type(bssid_list) == str:
        bssid_list = [bssid_list]
    elif type(bssid_list) == list:
        bssid_list = bssid_list
    else:
        raise TypeError('Provide 1 BSSID as string or multiple BSSIDs as list of strings')

    for bssid in bssid_list:
        wifi = bssid_wifi_list_pbuf.wifi.add()
        wifi.bssid = bssid

    wifi_list_string = bssid_wifi_list_pbuf.SerializeToString()
    wifi_list_string_length = len(wifi_list_string)

    wloc_headers = {'Content-Type': 'application/x-www-form-urlencoded',
                    'Accept': '*/*',
                    "Accept-Charset": "utf-8",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "en-us",
                    'User-Agent': 'locationd (6.9) CFNetwork/548.1.4 Darwin/14.0.0'}

    binary_header = "\x00\x01\x00\x05" + \
                    "en_US" + \
                    "\x00\x00\x00\x09" + \
                    "5.1.9B177" + \
                    "\x00\x00\x00\x01\x00\x00\x00"

    data_bytes_wloc = binary_header.encode() + \
                      chr(wifi_list_string_length).encode() + \
                      wifi_list_string

    # Format of request: [header][size][message] in 'data'
    # CN of cert on this hostname is sometimes *.ls.apple.com / ls.apple.com, so have to disable SSL verify
    wloc_req = requests.post('https://gs-loc.apple.com/clls/wloc',
                             headers=wloc_headers,
                             data=data_bytes_wloc,
                             verify=False)

    bssid_wifi_list_pbuf = BSSIDApple_pb2.BlockBSSIDApple()
    bssid_wifi_list_pbuf.ParseFromString(wloc_req.content[10:])

    return ListWifiGrannySmith(bssid_wifi_list_pbuf)


def QueryMobile(cellid, LTE=False):
    (MCC, MNC, LAC, CID) = map(int, cellid.split(':'))
    if LTE:
        req = GSM_pb2.CellReqToApple25()  # Request type 25 -> Response type 22 (LTE?)
        req.cell.MCC = MCC
        req.cell.MNC = MNC
        req.cell.LAC = LAC
        req.cell.CID = CID
    else:
        req = GSM_pb2.CellReqToApple1()  # Request 1 -> Response type 1 (GSM/3G?)
        cell = req.cell.add()
        cell.MCC = MCC
        cell.MNC = MNC
        cell.LAC = LAC
        cell.CID = CID
        # cell2 = req.cell.add() #505:2:33300:151564484
        # cell2.MCC = 505
        # cell2.MNC = 3
        # cell2.LAC = 334
        # cell2.CID = 87401254
        req.param3 = 0  # this affects whether you get cells or LAC areas
        req.param4 = 1  #
        req.ua = 'com.apple.Maps'

    req_string = req.SerializeToString()
    headers = {'Content-Type': 'application/x-www-form-urlencoded', 'Accept': '*/*', "Accept-Charset": "utf-8",
               "Accept-Encoding": "gzip, deflate", \
               "Accept-Language": "en-us", 'User-Agent': 'locationd/1753.17 CFNetwork/711.1.12 Darwin/14.0.0'}
    data = "\x00\x01\x00\x05" + "en_US" + "\x00\x13" + "com.apple.locationd" + "\x00\x0c" + "7.0.3.11B511" + "\x00\x00\x00\x01\x00\x00\x00" + chr(
        len(req_string)) + req_string;
    # data = "\x00\x01\x00\x05"+"en_US"+"\x00\x13"+"com.apple.locationd"+"\x00\x0c"+"6.1.1.10B145"+"\x00\x00\x00\x01\x00\x00\x00"+chr(len(req_string)) + req_string;
    # f=file('request.bin','wb')
    # f.write(req_string)
    # print('Wrote request.bin')
    # f.close()
    cellid = '%s:%s:%s:%s' % (MCC, MNC, LAC, CID)
    print('Querying %s' % cellid)
    r = requests.post('https://gs-loc.apple.com/clls/wloc', headers=headers, data=data,
                      verify=False)  # the remote SSL cert CN on this server doesn't match hostname anymore
    if LTE:
        response = GSM_pb2.CellInfoFromApple22()
    else:
        response = GSM_pb2.CellInfoFromApple1()
    response.ParseFromString(r.content[1:])
    # f=file(cellid+'.bin','wb')
    # f.write(r.content[1:])
    # f.close()
    # print 'Wrote %s' % (cellid+'.bin')

    return ProcessMobileResponse(response)

# res = QueryBSSID('b4:5d:50:8f:27:c1')