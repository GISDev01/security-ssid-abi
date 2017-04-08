import time

from db import influxdb_client


def assemble_json(measurement, value, timestamp, tags):
    return {
        "measurement": measurement,
        "tags": tags,
        "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.localtime(int(timestamp))),
        "fields": {
            "value": value
        }
    }


def write_data(data_points):
    influxdb_client.write_points(data_points)
