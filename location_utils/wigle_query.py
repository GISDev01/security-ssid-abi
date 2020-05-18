import security_ssid.settings
from location_utils import wigle_lib

wigle_apiname = security_ssid.settings.wigle_username
wigle_apitoken = security_ssid.settings.wigle_password


def get_location(SSID=''):
    wigle_search_client = wigle_lib.WigleSearch(wigle_apiname, wigle_apitoken)
    wigle_results = wigle_search_client.search(ssid=SSID)

    access_point_results = {}
    count_matches = 1

    for result in wigle_results:
        lat = float(result['trilat'])
        lon = float(result['trilong'])
        ssid_result = result['ssid']
        bssid_result = result['netid']

        # Exact case-sensitive match
        if SSID and ssid_result == SSID:
            id = '%s [%s] [%s]' % (SSID, bssid_result, count_matches)
            access_point_results[id] = (lat, lon)
            count_matches += 1

    return access_point_results