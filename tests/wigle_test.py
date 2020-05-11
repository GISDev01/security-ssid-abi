import requests

WIGLE_ENDPOINT_API_V2 = 'https://api.wigle.net/api/v2/network/search'

class WigleSearch():
    def __init__(self, user, password):
        self.user = user
        self.password = password

    def search(self, lat_range=None, long_range=None, variance=None,
               bssid=None, ssid=None, ssidlike=None,
               last_update=None,
               address=None, state=None, zipcode=None,
               on_new_page=None, max_results=100):
        """
        Credit to: https://github.com/viraptor/wigle/blob/master/wigle/__init__.py
        Search the Wigle wifi database for matching entries. The following
        criteria are supported:
        Args:
            lat_range ((float, float)): latitude range
            long_range ((float, float)): longitude range
            variance (float): radius tolerance in degrees
            bssid (str): BSSID/MAC of AP
            ssid (str): SSID of network
            last_update (datetime): when was the AP last seen
            address (str): location, address
            state (str): location, state
            zipcode (str): location, zip code
            on_new_page (func(int)): callback to notify when requesting new
                page of results
            max_results (int): maximum number of results from search query
        Returns:
            [dict]: list of dicts describing matching wifis
        """

        # onlymine=false&freenet=false&paynet=false&ssidlike=starbucks

        params = {
            'latrange1': lat_range[0] if lat_range else "",
            'latrange2': lat_range[1] if lat_range else "",
            'longrange1': long_range[0] if long_range else "",
            'longrange2': long_range[1] if long_range else "",
            'variance': str(variance) if variance else "0.01",
            'netid': bssid or "",
            'ssid': ssid or "",
            'ssidlike': ssidlike or "",
            # Filter points by how recently they've been updated, condensed date/time numeric string format 'yyyyMMddhhmmss'
            'lastupdt': last_update.strftime("%Y%m%d%H%M%S") if last_update else "",
            'onlymine': 'false',
            'freenet': 'false',
            'paynet': 'false',
            'addresscode': address or "",
            'statecode': state or "",
            'zipcode': zipcode or "",
        }

        result_wifi = []

        while True:
            if on_new_page:
                on_new_page(params.get('first', 1))
            resp = requests.get(WIGLE_ENDPOINT_API_V2, auth=(self.user, self.password), params=params)
            data = resp.json()
            if not data['success']:
                raise_wigle_error(data)

            for result in data['results'][:max_results - len(result_wifi)]:
                fix_latlong_nums(result)
                result_wifi.append(result)

            if data['resultCount'] < 100 or len(result_wifi) >= max_results:
                break

            params['first'] = data['last'] + 1

        print(result_wifi)
        return result_wifi


def fix_latlong_nums(net):
    net['trilat'] = float(net['trilat'])
    net['trilong'] = float(net['trilong'])


def raise_wigle_error(data):
    message = data.get('message')
    if message == "too many queries":
        raise WigleRatelimitExceeded()
    else:
        raise WigleRequestFailure(message)


class WigleError(Exception):
    pass


class WigleRequestFailure(WigleError):
    pass


class WigleRatelimitExceeded(WigleRequestFailure):
    pass

