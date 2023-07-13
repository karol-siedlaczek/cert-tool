#!/usr/bin/env python3

import os
import json
import logging
import argparse
import requests
import subprocess
import shlex

ALLOWED_RECORD_TYPES = ['TXT']


class Domain:
    records = []

    def __init__(self, provider, id, name, extension):
        self.provider = provider
        self.id = id
        self.name = f'{name}.{extension}'

    def add_dns_record(self, subdomain, record_type, value, priority=0, ttl=86400):
        dns_records = self.get_records()
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
            self.records = dns_records
        else:
            raise ValueError(f'Adding DNS record "{json.dumps(new_dns_record)}" failed for "{self}" domain with status code "{response.status_code}"')

    def remove_dns_record(self, subdomain, record_type, value):
        dns_records = self.get_records()
        new_dns_records = []
        for dns_record in dns_records:
            if not (dns_record['subdomain'] == subdomain and dns_record['type'] == record_type and dns_record['value'] == value):
                new_dns_records.append(dns_record)
        if len(dns_records) == len(new_dns_records):
            raise LookupError(f'Cannot found DNS record "{{"subdomain": "{subdomain}", "type": "{record_type}", "value": "{value}"}}" in "{self}" domain configuration')

        response = self.provider.update_records(self, new_dns_records)
        if response.ok:
            logging.info(f'DNS record "{{"subdomain": "{subdomain}", "type": "{record_type}", "value": "{value}"}}" removed from "{self}" domain configuration')
            self.records = new_dns_records
        else:
            raise ValueError(f'Removing DNS record "{{"subdomain": "{subdomain}", "type": "{record_type}", "value": "{value}"}}" failed for "{self} with status code "{response.status_code}"')

    def get_records(self):
        return self.records if self.records else self.provider.get_records(self)

    def __str__(self):
        return self.name


class Provider:
    domains = []

    def __init__(self, username, password):
        self.base_url = 'https://www.domeny.tv'
        self.headers = {'X-Requested-With': 'XMLHttpRequest'}
        self.session = requests.session()
        self.__init_session(username, password)
        self.__set_domains()

    def __init_session(self, username, password):
        url = f'{self.base_url}/api/auth/login'
        payload = {'username': username, 'password': password, 'remember': 'false'}
        response = self.session.post(url, json=payload, headers=self.headers)
        if not response.ok:
            raise ConnectionRefusedError(f'Authorization failed for "{username}" user with status code "{response.status_code}" to "{url}"')

    def __set_domains(self):
        for domain_json in self.__get_data(f'{self.base_url}/api/domains/getPlDomains/0')['list']:
            domain = Domain(self, domain_json['domain_id'], domain_json['domain_name'], domain_json['domain_ext'])
            self.domains.append(domain)

    def get_records(self, domain):
        return self.__get_data(f'{self.base_url}/api/DNSServer/getRecords/{domain.id}')['records']

    def __get_data(self, url):
        response_content = self.session.get(url, headers=self.headers).content
        return json.loads(response_content.decode('utf-8'))

    def get_domain_by_name(self, name):
        for domain in self.domains:
            if domain.name == name:
                return domain

    def update_records(self, domain, records):
        url = f'{self.base_url}/api/DNSServer/saveRecords/{domain.id}'
        payload = {'records': records, 'srv': []}
        return self.session.post(url, json=payload, headers=self.headers)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--username', required=False, help='')
    parser.add_argument('-p', '--password', required=False, help='')
    parser.add_argument('-d', '--domains', nargs='+', required=False, help='')
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    logging.basicConfig(filename='file.log', format='%(asctime)s %(name)s %(levelname)s %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=logging.DEBUG)
    try:
        cmd = 'touch test.txt'

        try:
            process = subprocess.run(shlex.split(command),
                                     stdin=subprocess.DEVNULL,
                                     stderr=subprocess.PIPE,
                                     stdout=subprocess.PIPE,
                                     timeout=15)

            print(process.stdout)
            print(process.stderr)
            print(process.returncode)
            #out, err = process.communicate(input=subprocess.PIPE, timeout=15)
        except subprocess.TimeoutExpired as e:
            print(e)

        #provider = Provider(args.username, args.password)
        #domain = provider.get_domain_by_name('some_domain')
        #domain.add_dns_record('test', 'TXT', '1.1.1.1')
        #domain.remove_dns_record('test', 'TXT', '1.1.1.1')
    except (ConnectionRefusedError, ValueError, LookupError) as e:
        logging.error(f'{os.path.basename(__file__)}: {e}')
        print(f'{os.path.basename(__file__)}: {e}')


#certbot -d \*.siedlaczek.org.pl -d domain --manual --preferred-challenges dns certonly