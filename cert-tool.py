#!/usr/bin/env python3

import os
import logging
import argparse
import requests
import json

ALLOWED_RECORD_TYPES = ['TXT']

logging.basicConfig(filename='file.log', format='%(asctime)s %(name)s %(levelname)s %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=logging.DEBUG)


class Domain:

    def __init__(self, id, name, extension):
        self.id = id
        self.name = f'{name}.{extension}'

    def __str__(self):
        return self.name


class DomainProvider:

    def __init__(self, username, password):
        self.base_url = 'https://www.domeny.tv'
        self.headers = {'X-Requested-With': 'XMLHttpRequest'}
        self.session = requests.session()
        self.init_session(username, password)

    def init_session(self, username, password):
        url = f'{self.base_url}/api/auth/login'
        payload = {'username': username, 'password': password, 'remember': 'false'}
        response = self.session.post(url, json=payload, headers=self.headers)
        if not response.ok:
            raise ConnectionRefusedError(f'Authorization failed for "{username}" user with status code "{response.status_code}" to "{url}"')

    def get_domain_by_fqdn(self, fqdn):
        domains = self.get_domain_list()
        for domain_entry in domains:
            if f'{domain_entry["domain_name"]}.{domain_entry["domain_ext"]}' == fqdn:
                return Domain(domain_entry['domain_id'], domain_entry['domain_name'], domain_entry['domain_ext'])

    def get_domain_list(self):
        return self.get_data(f'{self.base_url}/api/domains/getPlDomains/0')['list']

    def add_dns_record(self, domain, subdomain, record_type, value, priority=0, ttl=86400):
        dns_records = self.get_records(domain)
        new_dns_record = {
            'caa_flag': "1",
            'caa_tag': 'issue',
            'caa_value': '',
            'subdomain': subdomain,
            'ttl': ttl,
            'type': record_type,
            'value': value,
            'priority': priority,
        }
        dns_records.append(new_dns_record)
        response = self.update_records(dns_records)
        if response.ok:
            logging.info(f'DNS record "{json.dumps(new_dns_record)}" added to "{domain.name}" domain')
        else:
            raise ValueError(f'Adding DNS record "{json.dumps(new_dns_record)}" failed for "{domain.name}" domain with status code "{response.status_code}"')

    def remove_dns_record(self, domain, subdomain, record_type, value):
        dns_records = self.get_records(domain)
        new_dns_records = []
        for dns_record in dns_records:
            if not (dns_record['subdomain'] == subdomain and dns_record['type'] == record_type and dns_record['value'] == value):
                new_dns_records.append(dns_record)
        if len(dns_records) == len(new_dns_records):
            raise LookupError(f'Cannot found DNS record "{{"subdomain": "{subdomain}", "type": "{record_type}", "value": "{value}"}}" in "{domain.name}" domain configuration')

        response = self.update_records(new_dns_records)
        if response.ok:
            logging.info(f'DNS record "{{"subdomain": "{subdomain}", "type": "{record_type}", "value": "{value}"}}" removed from "{domain.name}" domain')
        else:
            raise ValueError(f'Removing DNS record "{{"subdomain": "{subdomain}", "type": "{record_type}", "value": "{value}"}}" failed for "{domain.name} with status code "{response.status_code}"')

    def update_records(self, records):
        url = f'{self.base_url}/api/DNSServer/saveRecords/{domain.id}'
        payload = {'records': records, 'srv': []}
        return self.session.post(url, json=payload, headers=self.headers)

    def get_records(self, domain):
        return self.get_data(f'{self.base_url}/api/DNSServer/getRecords/{domain.id}')['records']

    def get_data(self, url):
        response_content = self.session.get(url, headers=self.headers).content
        return json.loads(response_content.decode('utf-8'))


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--username', required=True, help='')
    parser.add_argument('-p', '--password', required=True, help='')
    parser.add_argument('-d', '--domains', nargs='+', required=True, help='')
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    try:
        domain_provider = DomainProvider(args.username, args.password)
        domain = domain_provider.get_domain_by_fqdn('some_domain')
        #domain_provider.add_dns_record(domain, 'test', 'TXT', '1.1.1.1')
        #domain_provider.remove_dns_record(domain, 'test', 'TXT', '1.1.1.1')
    except (ConnectionRefusedError, ValueError, LookupError) as e:
        logging.error(f'{os.path.basename(__file__)}: {e}')
        print(f'{os.path.basename(__file__)}: {e}')
