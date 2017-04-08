from influxdb import InfluxDBClient

json_body = [
    {
        "measurement": "test_measurement",
        "tags": {
            "host": "server01",
            "region": "us-west"
        },
        "time": "2009-11-10T23:00:00Z",
        "fields": {
            "value": 0.64
        }
    }
]

client = InfluxDBClient(host='192.99.1.26', port=8086, database='test_py_client')
client.create_database('test_py_client')
client.write_points(json_body)
result = client.query('select value from test_measurement;')
print("Result: {0}".format(result))
