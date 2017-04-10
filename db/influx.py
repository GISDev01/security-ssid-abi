import time

from db import influxdb_client


def assemble_json(measurement, pkt_timestamp, rssi_value, client_mac_addr, probed_ssid):
    return {
        "measurement": measurement,
        "tags": {
            "clientmac": client_mac_addr,
            "probedssid": probed_ssid,
            "location": "001",
            "sensor": "001"
        },
        "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.localtime(int(pkt_timestamp))),
        "fields": {
            "rssi": rssi_value
        }
    }


def write_data(data_points):
    influxdb_client.write_points([data_points])
