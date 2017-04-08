from influxdb import InfluxDBClient

import security_ssid.settings as settings

influxdb_client = InfluxDBClient(settings.INFLUX_HOST,
                                 settings.INFLUX_PORT,
                                 settings.INFLUX_USER,
                                 settings.INFLUX_PASSWORD,
                                 settings.INFLUX_DB,
                                 timeout=settings.INFLUX_TIMEOUT_SEC)

influxdb_client.create_database(settings.INFLUX_DB)
