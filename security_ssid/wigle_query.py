import settings
from security_ssid import wigle_lib

wigle_apiname = settings.wigle_username
wigle_apitoken = settings.wigle_username


def get_location(BSSID='', SSID=''):
    wigle = wigle_lib.WigleSearch(wigle_apiname, wigle_apitoken)
    results = wigle.search(ssidlike=SSID)
    apdict = {}
    count = 1
    for result in results:
        lat = float(result['trilat'])
        lon = float(result['trilong'])
        ssid_result = result['ssid']  # match any number of non-& characters
        bssid_result = result['netid']
        if SSID and ssid_result == SSID:  # exact case sensitive match
            id = '%s [%s] [%s]' % (SSID, bssid_result, count)
            apdict[id] = (lat, lon)
            count += 1
    return apdict
