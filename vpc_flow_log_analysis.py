import elasticsearch
import socket

from argparse import ArgumentParser
from collections import defaultdict
from datetime import datetime
from google.cloud import bigquery
from pprint import pprint


_ip_to_service_cache = {}
def _ip_to_service(ip):
    """Translate an IP adress to a TS service name."""
    # Look up in cache first.
    if ip in _ip_to_service_cache:
        return _ip_to_service_cache[ip]

    if ip in MSSQL_IPS:
        return 'mssql'

    service_name = 'other'
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        for prefix, service in HOSTNAME_PREFIX_TO_SERVICE_MAP.items():
            if hostname.startswith(prefix):
                service_name = service
    except:
        service_name = 'unknown'

    _ip_to_service_cache[ip] = service_name
    return service_name


def _ip_to_datacenter(ip):
    """Translate an IP address to a TS datacenter name."""
    for prefix, datacenter in IP_PREFIX_TO_DATACENTER_MAP.items():
        if ip.startswith(prefix):
            return datacenter
    return 'other'


def _vpc_flow_log_table(date_suffix):
    """Return the vpc flow log table name given the date suffix."""
    return ('artsyviet-prod.vpc_flow_logs.'
        'compute_googleapis_com_vpc_flows_{0}').format(date_suffix)


def _record_bytes_sent_by_service(
        es_client, es_index, bytes_sent_by_service, dt):
    for project_id, service_bytes in bytes_sent_by_service.items():
        for service, bytes_sent in service_bytes.items():
            doc = {
                'project_id': project_id,
                'timestamp': dt,
                'service': service,
                'bytes_sent': bytes_sent
            }
            print(doc)
            es_client.index(
                index=es_index + '_bytes_send_by_service',
                body=doc)


def _record_bytes_sent_by_dc(
        es_client, es_index, bytes_sent_by_dc, dt):
    for project_id, dc_bytes in bytes_sent_by_dc.items():
        for dc, bytes_sent in dc_bytes.items():
            doc = {
                'project_id': project_id,
                'timestamp': dt,
                'datacenter': dc,
                'bytes_sent': bytes_sent
            }
            print(doc)
            es_client.index(
                index=es_index + '_bytes_sent_by_dc',
                body=doc)


def _record_bytes_sent_region_dc(
        es_client, es_index, bytes_sent_region_dc, dt):
    for region, dc_bytes in bytes_sent_region_dc.items():
        for dc, bytes_sent in dc_bytes.items():
            doc = {
                'region': region,
                'timestamp': dt,
                'dc': dc,
                'bytes_sent': bytes_sent
            }
            print(doc)
            es_client.index(
                index=es_index + '_bytes_sent_region_dc',
                body=doc)


def _analyze_flow_data(query_job):
    """Analyze the VPC flow log data."""
    # Outer map's key is project_id. Inner map's key is service/dc name.
    bytes_sent_by_service = {}
    bytes_sent_by_dc = {}

    # Outer map's key is gcp region. Inner map's key is dc name.
    bytes_sent_region_dc = {}
    for row in query_job:
        service = _ip_to_service(row.onprem_ip)
        dc = _ip_to_datacenter(row.onprem_ip)

        if row.gcp_project not in bytes_sent_by_service:
            bytes_sent_by_service[row.gcp_project] = defaultdict(int)
        bytes_sent_by_service[row.gcp_project][service] += row.bytes_sent
        bytes_sent_by_service[row.gcp_project]['total'] += row.bytes_sent

        if row.gcp_project not in bytes_sent_by_dc:
            bytes_sent_by_dc[row.gcp_project] = defaultdict(int)
        bytes_sent_by_dc[row.gcp_project][dc] += row.bytes_sent
        bytes_sent_by_dc[row.gcp_project]['total'] += row.bytes_sent

        if row.gcp_region not in bytes_sent_region_dc:
            bytes_sent_region_dc[row.gcp_region] = defaultdict(int)
        bytes_sent_region_dc[row.gcp_region][dc] += row.bytes_sent

    return (bytes_sent_by_service, bytes_sent_by_dc, bytes_sent_region_dc)


def interconnect_to_gcp_group_by_receive_hour_bytes_sent(
        bq_client, es_client, table, dt):
    print('Analyzing interconnect data from TS to GCP')
    sql = """
        SELECT
            SUM(CAST(jsonPayload.bytes_sent as INT64)) as bytes_sent,
            jsonPayload.connection.src_ip as onprem_ip,
            jsonPayload.dest_instance.project_id as gcp_project,
            jsonPayload.dest_instance.region as gcp_region
        FROM
            `{0}`
        GROUP BY
            onprem_ip,
            gcp_project,
            gcp_region
    """.format(table)
    query_job = bq_client.query(sql, location='US')

    bytes_sent_by_service, bytes_sent_by_dc, bytes_sent_region_dc = (
        _analyze_flow_data(query_job))
    _record_bytes_sent_by_service(
        es_client, 'interconnect_ts_to_gcp', bytes_sent_by_service, dt)
    _record_bytes_sent_by_dc(
        es_client, 'interconnect_ts_to_gcp', bytes_sent_by_dc, dt)
    _record_bytes_sent_region_dc(
        es_client, 'interconnect_ts_to_gcp', bytes_sent_region_dc, dt)


def interconnect_to_ts_group_by_receive_hour_bytes_sent(
        bq_client, es_client, table, dt):
    print('Analyzing interconnect data from GCP to TS')
    sql = """
        SELECT
            SUM(CAST(jsonPayload.bytes_sent as INT64)) as bytes_sent,
            jsonPayload.connection.dest_ip as onprem_ip,
            jsonPayload.src_instance.project_id as gcp_project,
            jsonPayload.src_instance.region as gcp_region
        FROM
            `{0}`
        GROUP BY
            onprem_ip,
            gcp_project,
            gcp_region
    """.format(table)
    query_job = bq_client.query(sql, location='US')

    bytes_sent_by_service, bytes_sent_by_dc, bytes_sent_region_dc = (
        _analyze_flow_data(query_job))
    _record_bytes_sent_by_service(
        es_client, 'interconnect_gcp_to_ts', bytes_sent_by_service, dt)
    _record_bytes_sent_by_dc(
        es_client, 'interconnect_gcp_to_ts', bytes_sent_by_dc, dt)
    _record_bytes_sent_region_dc(
        es_client, 'interconnect_gcp_to_ts', bytes_sent_region_dc, dt)


def _parse_argument():
    """Parse command line arguments."""
    parser = ArgumentParser()
    parser.add_argument(
        '-d', '--date-suffix',
        action='store',
        default=''
    )
    return parser.parse_args()


def main():
    options = _parse_argument()
    print(options)

    suffix = options.date_suffix
    if not suffix:
        suffix = datetime.today().strftime('%Y%m%d')
    dt = datetime.strptime(suffix, '%Y%m%d')
    print('Query VPC flow log for date %s' % dt)

    table = _vpc_flow_log_table(suffix)
    print('Query from vpc flow log table %s' % table)

    bq_client = bigquery.Client()
    es_client = elasticsearch.Elasticsearch(
        hosts='127.0.0.1',
        port=9200,
        timeout=30)

    interconnect_to_gcp_group_by_receive_hour_bytes_sent(
        bq_client, es_client, table, dt)
    interconnect_to_ts_group_by_receive_hour_bytes_sent(
        bq_client, es_client, table, dt)


if __name__ == '__main__':
    main()