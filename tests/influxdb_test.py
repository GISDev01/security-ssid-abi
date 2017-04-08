from db.influx import influxdb_client
import logging

mobile_measurement_name = 'mobiledevices'
access_pts_measurement_name = 'accesspoints'


mobile_test_data_json = [
    {
        "measurement": mobile_measurement_name,
        "tags": {
            "macaddress": "01:ab:03:cd",
            "sensor": "001",
            "location": "001"
        },
        "fields": {
            "value": -55
        }
    }
]
influxdb_client.write_points(mobile_test_data_json)

# Yes, SQLi vuln introduced with string concatenation temporarily
result = influxdb_client.query('select * from ' + mobile_measurement_name + ';')

print("Mobile Result: {0}".format(result))


ap_test_data_json = [
    {
        "measurement": access_pts_measurement_name,
        "tags": {
            "macaddress": "04:ef:06:gh",
            "sensor": "001",
            "location": "001"
        },
        "fields": {
            "value": -56
        }
    }
]
influxdb_client.write_points(ap_test_data_json)

# Yes, SQLi vuln introduced with string concatenation temporarily
result = influxdb_client.query('select * from ' + access_pts_measurement_name + ';')

print("Access Points Result: {0}".format(result))


