from db import influxdb_client

query = """
        SHOW TAG VALUES FROM "clientdevices" WITH KEY IN ("probedssid")
        """
result_set = influxdb_client.query(query)
print("Result: {0}".format(result_set))

for result in result_set:
    ssid_list = [ssid['value'] for ssid in result]

print ssid_list
for ssid in ssid_list:
    ssid = "'" + ssid.replace("'", r"\'") + "'"
    ssid_query = 'SELECT * FROM "clientdevices" WHERE "probedssid" = ' + ssid
    print(ssid_query)
    ssid_results = influxdb_client.query(ssid_query)
    print("ssid_results: {0}".format(ssid_results))







