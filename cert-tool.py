#!/usr/bin/env python3

import os
import logging
import argparse
import requests
import json

ALLOWED_RECORD_TYPES = ['TXT']

logging.basicConfig(filename='file.log', format='%(asctime)s %(name)s %(levelname)s %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=logging.DEBUG)


class Provider:
    def __init__(self, username, password):
        self.base_url = 'https://www.domeny.tv'
        self.headers = {'X-Requested-With': 'XMLHttpRequest'}
        self.session = requests.session()
        self.__init_session(username, password)

    def __init_session(self, username, password):
        url = f'{self.base_url}/api/auth/login'
        payload = {'username': username, 'password': password, 'remember': 'false'}
        response = self.session.post(url, json=payload, headers=self.headers)
        if not response.ok:
            raise ConnectionRefusedError(f'Authorization failed for "{username}" user with status code "{response.status_code}" to "{url}"')

    def get_domain_by_fqdn(self, fqdn):
        domains = self.get_all_domains()
        for domain in domains:
            if domain.name == fqdn:
                return domain

    def get_all_domains(self):
        domains = []
        for domain_json in self.get_data(f'{self.base_url}/api/domains/getPlDomains/0')['list']:
            domains.append(Domain(domain_json['domain_id'], domain_json['domain_name'], domain_json['domain_ext']))
        return domains

    def get_records(self, domain):
        return self.get_data(f'{self.base_url}/api/DNSServer/getRecords/{domain.id}')['records']

    def update_records(self, domain, records):
        url = f'{self.base_url}/api/DNSServer/saveRecords/{domain.id}'
        payload = {'records': records, 'srv': []}
        return self.session.post(url, json=payload, headers=self.headers)

    def get_data(self, url):
        response_content = self.session.get(url, headers=self.headers).content
        return json.loads(response_content.decode('utf-8'))


class Domain:
    def __init__(self, provider, id, name, extension):
        self.provider = provider
        self.id = id
        self.name = f'{name}.{extension}'

    def __str__(self):
        return self.name

    def add_dns_record(self, subdomain, record_type, value, priority=0, ttl=86400):
        dns_records = self.provider.get_records(self)
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
        response = self.provider.update_records(self, dns_records)
        if response.ok:
            logging.info(f'DNS record "{json.dumps(new_dns_record)}" added to "{self}" domain')
        else:
            raise ValueError(f'Adding DNS record "{json.dumps(new_dns_record)}" failed for "{self}" domain with status code "{response.status_code}"')

    def remove_dns_record(self, subdomain, record_type, value):
        dns_records = self.provider.get_records(self)
        new_dns_records = []
        for dns_record in dns_records:
            if not (dns_record['subdomain'] == subdomain and dns_record['type'] == record_type and dns_record['value'] == value):
                new_dns_records.append(dns_record)
        if len(dns_records) == len(new_dns_records):
            raise LookupError(f'Cannot found DNS record "{{"subdomain": "{subdomain}", "type": "{record_type}", "value": "{value}"}}" in "{self}" domain configuration')

        response = self.provider.update_records(self, new_dns_records)
        if response.ok:
            logging.info(f'DNS record "{{"subdomain": "{subdomain}", "type": "{record_type}", "value": "{value}"}}" removed from "{self}" domain')
        else:
            raise ValueError(f'Removing DNS record "{{"subdomain": "{subdomain}", "type": "{record_type}", "value": "{value}"}}" failed for "{self} with status code "{response.status_code}"')


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--username', required=True, help='')
    parser.add_argument('-p', '--password', required=True, help='')
    parser.add_argument('-d', '--domains', nargs='+', required=True, help='')
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    try:
        provider = Provider(args.username, args.password)
        domain = provider.get_domain_by_fqdn('some_domain')
        domain.add_dns_record('test', 'TXT', '1.1.1.1')
        domain.remove_dns_record('test', 'TXT', '1.1.1.1')
    except (ConnectionRefusedError, ValueError, LookupError) as e:
        logging.error(f'{os.path.basename(__file__)}: {e}')
        print(f'{os.path.basename(__file__)}: {e}')
