from influxdb import InfluxDBClient

db_name = 'securityssid'

influx_client = InfluxDBClient('192.99.1.26', 8086, database=db_name)
influx_client.create_database(db_name)

