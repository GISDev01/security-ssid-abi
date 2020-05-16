from db import influxdb_client

query = """
        SHOW TAG VALUES FROM "clientdevices" WITH KEY IN ("probedssid")
        """

result_set = influxdb_client.query(query)
print("Result: {0}".format(result_set))

for result in result_set:
    ssid_list = [ssid['value'] for ssid in result]

print('SSID List: {}'.format(ssid_list))


##########################################################################
# Loop through all of the detected SSID names in the DB, for all timeframes
for ssid in ssid_list:
    ssid = "'" + ssid.replace("'", r"\'") + "'"
    ssid_query = 'SELECT * FROM "clientdevices" WHERE "probedssid" = ' + ssid
    #print(ssid_query)
    #ssid_results = influxdb_client.query(ssid_query)
    #print("ssid_results: {0}".format(ssid_results))


##############################################
# Hardcoded test for dynamic MEAN calc on RSSI
ssid_name = 'linksys'
ssid_name = "'" + ssid_name.replace("'", r"\'") + "'"

field_name = 'rssi'
mean_field =  field_name.replace("'", r"\'")

ssid_test_query_mean = 'SELECT MEAN("' + mean_field + '") ' \
                                                      'FROM "clientdevices" ' \
                                                      'WHERE "probedssid" = ' + ssid_name
print(ssid_test_query_mean)

ssid_test_results = influxdb_client.query(ssid_test_query_mean)
print("Mean RRSI: {} for SSID: {}".format(ssid_test_results, ssid_name))



