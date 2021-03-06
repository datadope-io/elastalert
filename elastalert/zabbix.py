import json
from datetime import datetime

from pyzabbix import ZabbixSender, ZabbixMetric, ZabbixAPI

from .alerts import Alerter
from .minio_client import MinIOClient
from .util import elastalert_logger, EAException


def find_value(source, path):
    current_path = path.pop(0)
    if current_path in source:
        if len(path) == 0:
            return source[current_path]
        else:
            return find_value(source[current_path], path)
    else:
        return None


def get_fields(match, fields):
    extra_fields = {}
    for field in fields:
        extra_fields[field] = find_value(match, field.split('.'))
    return extra_fields


class ZabbixClient(ZabbixAPI):

    def __init__(self, url='http://localhost', use_authenticate=False, user='Admin', password='zabbix',
                 sender_host='localhost', sender_port=10051):
        self.url = url
        self.use_authenticate = use_authenticate
        self.sender_host = sender_host
        self.sender_port = sender_port
        self.metrics_chunk_size = 200
        self.aggregated_metrics = []

        super(ZabbixClient, self).__init__(url=self.url,
                                           use_authenticate=self.use_authenticate,
                                           user=user,
                                           password=password)

    def send_metric(self, hostname, key, data):
        zm = ZabbixMetric(hostname, key, data)
        if self.send_aggregated_metrics:
            self.aggregated_metrics.append(zm)
            if len(self.aggregated_metrics) > self.metrics_chunk_size:
                elastalert_logger.info("Sending: %s metrics" % (len(self.aggregated_metrics)))
                try:
                    ZabbixSender(zabbix_server=self.sender_host, zabbix_port=self.sender_port) \
                        .send(self.aggregated_metrics)
                    self.aggregated_metrics = []
                except Exception as e:
                    elastalert_logger.exception(e)
        else:
            try:
                ZabbixSender(zabbix_server=self.sender_host, zabbix_port=self.sender_port).send([zm])
            except Exception as e:
                elastalert_logger.exception(e)


class ZabbixAlerter(Alerter):
    # By setting required_options to a set of strings
    # You can ensure that the rule config file specifies all
    # of the options. Otherwise, ElastAlert will throw an exception
    # when trying to load the rule.
    required_options = frozenset(['zbx_sender_host', 'zbx_sender_port', 'zbx_host', 'zbx_key'])

    def __init__(self, *args):
        super(ZabbixAlerter, self).__init__(*args)

        self.zbx_sender_host = self.rule.get('zbx_sender_host', 'localhost')
        self.zbx_sender_port = self.rule.get('zbx_sender_port', 10051)
        self.zbx_host = self.rule.get('zbx_host')
        self.zbx_key = self.rule.get('zbx_key')
        self.zbx_key_minio_data = self.rule.get('zbx_key_minio_data')
        self.timestamp_field = self.rule.get('timestamp_field', '@timestamp')
        self.timestamp_type = self.rule.get('timestamp_type', 'iso')
        self.timestamp_strptime = self.rule.get('timestamp_strptime', '%Y-%m-%dT%H:%M:%S.%fZ')

        self.extra_data = self.rule.get('extra_data')

        self.minio_endpoint = self.rule.get('minio_endpoint', 'localhost:9000')
        self.minio_ak = self.rule.get('minio_ak', 'access_key')
        self.minio_sk = self.rule.get('minio_sk', 'secret_key')
        self.minio_bucket = self.rule.get('minio_bucket', 'elastalert')
        self.minio_secure = self.rule.get('minio_secure', False)

        if self.extra_data:
            self.minio_client = MinIOClient(endpoint=self.minio_endpoint,
                                            access_key=self.minio_ak,
                                            secret_key=self.minio_sk,
                                            secure=self.minio_secure)

            self.zbx_client = ZabbixClient(url=self.rule.get('zbx_endpoint'),
                                           user=self.rule.get('zbx_username'),
                                           password=self.rule.get('zbx_password'))

    # Alert is called
    def alert(self, matches):
        zbx_host = self.zbx_host.strip()

        # Matches is a list of match dictionaries.
        # It contains more than one match when the alert has
        # the aggregation option set
        zm = []
        ts_epoch = None
        for match in matches:
            if zbx_host.startswith('{{') and zbx_host.endswith('}}'):
                host_field = zbx_host[2:-2].strip()
                zbx_host = find_value(match, host_field.split('.'))
                if not zbx_host:
                    elastalert_logger.error(f"Missing host field '%s' for dynamic host, alert will be discarded"
                                            % host_field)
                    return
            if ':' not in match[self.timestamp_field] or '-' not in match[self.timestamp_field]:
                ts_epoch = int(match[self.timestamp_field])
            else:
                try:
                    ts_epoch = int(datetime.strptime(match[self.timestamp_field], self.timestamp_strptime)
                                   .strftime('%s'))
                except ValueError:
                    ts_epoch = int(datetime.strptime(match[self.timestamp_field], '%Y-%m-%dT%H:%M:%SZ')
                                   .strftime('%s'))
            zm.append(ZabbixMetric(host=zbx_host, key=self.zbx_key, value='1', clock=ts_epoch))

        try:
            if self.extra_data:
                extra_data = []

                for match in matches:
                    for related_event in match.get('related_events', []):
                        extra_data.append(get_fields(related_event, self.extra_data['fields']))
                    extra_data.append(get_fields(match, self.extra_data['fields']))

                data = {
                    'template': self.extra_data['template'],
                    'data': extra_data
                }

                object_name = self.minio_client.upload_random_object(bucket_name=self.minio_bucket,
                                                                     data=json.dumps(data, indent=2))

                if object_name:
                    zm.append(ZabbixMetric(host=zbx_host,
                                           key=self.zbx_key_minio_data,
                                           value=object_name,
                                           clock=ts_epoch - 1))
                else:
                    elastalert_logger.warning("Data couldn't be uploaded to MinIO, it won't be provided with the alert")
                    zm.append(ZabbixMetric(host=zbx_host,
                                           key=self.zbx_key_minio_data,
                                           value='MinIO data upload failed',
                                           clock=ts_epoch - 1))

            response = ZabbixSender(zabbix_server=self.zbx_sender_host, zabbix_port=self.zbx_sender_port).send(zm)
            if response.failed:
                elastalert_logger.warning("Missing zabbix host '%s' or host's item '%s', alert will be discarded"
                                          % (zbx_host, self.zbx_key))
            else:
                elastalert_logger.info("Alert sent to Zabbix")
        except Exception as e:
            raise EAException("Error sending alert to Zabbix: %s" % e)

    # get_info is called after an alert is sent to get data that is written back
    # to Elasticsearch in the field "alert_info"
    # It should return a dict of information relevant to what the alert does
    def get_info(self):
        return {'type': 'zabbix Alerter'}
