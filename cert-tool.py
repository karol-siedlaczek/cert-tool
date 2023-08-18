#!/usr/bin/env python3

import os
import re
import sys
import yaml
import json
import time
import logging
import argparse
import requests
import subprocess
import ssl
import socket

CHECK_ACTION = 'check'
INIT_ACTION = 'init'
LIST_ACTION = 'list'

DEFAULTS = {
    'ACTION_CHOICES': [CHECK_ACTION, INIT_ACTION, LIST_ACTION],
    'RECORD_TYPES': ['TXT', 'A', 'AAAA', 'MX', 'CNAME', 'REDIRECT', 'FRAME', 'CAA'],
    'STATE_FILE': f'{os.path.dirname(os.path.realpath(__file__))}/dns_challenges.yaml',
    'AUTH_FILE': os.path.join(os.path.expanduser("~"), '.cert-tool.passwd')
}


class Certificate:
    def __init__(self, path):
        if not os.path.isfile(path):
            raise FileNotFoundError(f'Certificate file {path} does not exist')
        self.path = path


class Domain:
    records = []

    def __init__(self, provider, id, name, extension):
        self.provider = provider
        self.id = id
        self.name = f'{name}.{extension}'

    def add_record(self, subdomain, record_type, value, priority=0, ttl=86400):
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
        response = self.provider.set_records(self, dns_records)
        if response.ok:
            logging.info(f'DNS record "{json.dumps(new_dns_record)}" added to "{self}" domain')
            self.records = dns_records
        else:
            raise ValueError(f'Adding DNS record "{json.dumps(new_dns_record)}" failed for "{self}" domain with status code "{response.status_code}"')

    def remove_record(self, subdomain, record_type, value):
        dns_records = self.get_records()
        new_dns_records = []
        for dns_record in dns_records:
            if not (dns_record['subdomain'] == subdomain and dns_record['type'] == record_type and dns_record['value'] == value):
                new_dns_records.append(dns_record)
        if len(dns_records) == len(new_dns_records):
            raise LookupError(f'Cannot found DNS record "{{"subdomain": "{subdomain}", "type": "{record_type}", "value": "{value}"}}" in "{self}" domain configuration')

        response = self.provider.set_records(self, new_dns_records)
        if response.ok:
            logging.info(f'DNS record "{{"subdomain": "{subdomain}", "type": "{record_type}", "value": "{value}"}}" removed from "{self}" domain configuration')
            self.records = new_dns_records
        else:
            raise ValueError(f'Removing DNS record "{{"subdomain": "{subdomain}", "type": "{record_type}", "value": "{value}"}}" failed for "{self} with status code "{response.status_code}"')

    def get_records(self):
        return self.records if self.records else self.provider.get_records(self)

    def has_record(self, record_type, value, prefix=None):
        fqdn = f"{prefix}.{self}" if prefix else self
        if record_type not in DEFAULTS['RECORD_TYPES']:
            raise ValueError(f'Cannot check "{record_type}" record with "{value}" value for "{fqdn}" domain, allowed record types are: {", ".join(DEFAULTS["RECORD_TYPES"])}')
        msg, return_code = run_command(f'dig -t {record_type} {fqdn} +short')
        try:
            msg = msg.strip().replace('"', '')
        except AttributeError:
            return False
        if msg and msg != value:
            logging.warning(f'{record_type} record for "{fqdn}" domain returned "{msg}" value, not expected "{value}" value')
            return False
        else:
            return True if msg == value else False

    # def get_cert_expire_date(self):
    #     ctx = ssl.create_default_context()
    #     with ctx.wrap_socket(socket.socket())

    def __str__(self):
        return self.name


class Provider:
    domains = []

    def __init__(self, auth_file):
        self.base_url = 'https://www.domeny.tv'
        self.headers = {'X-Requested-With': 'XMLHttpRequest'}
        self.session = requests.session()
        with open(auth_file, 'r') as f:
            credentials = f.readline().split(':')
        self.__init_session(credentials[0], credentials[1])
        self.__set_domains()

    def __init_session(self, username, password):
        url = f'{self.base_url}/api/auth/login'
        payload = {'username': username, 'password': password, 'remember': 'false'}
        response = self.session.post(url, json=payload, headers=self.headers)
        if not response.ok:
            raise ConnectionRefusedError(f'Authorization failed for "{username}" user with status code "{response.status_code}" to "{url}"')

    def __set_domains(self):
        domains = self.__get_data(f'{self.base_url}/api/domains/getPlDomains/0')['list']
        for domain_json in domains:
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
        raise AttributeError(f'Not found "{name}" domain in DNS config')

    def set_records(self, domain, records):
        url = f'{self.base_url}/api/DNSServer/saveRecords/{domain.id}'
        payload = {'records': records, 'srv': []}
        return self.session.post(url, json=payload, headers=self.headers)


class CertBot:
    server = 'https://acme-v02.api.letsencrypt.org/directory'

    def __init__(self, domain, state_file):
        self.state_file = state_file
        if not os.path.isfile(self.state_file):
            with open(self.state_file, 'w') as f:
                pass
        self.domain = domain
        self.__set_challenge_values()

    def __set_challenge_values(self):
        with open(self.state_file, 'r') as f:
            dns_challenges = yaml.safe_load(f)
        try:
            self.key = dns_challenges[self.domain.name]['txt_key']
            self.value = dns_challenges[self.domain.name]['txt_value']
            self.state = dns_challenges[self.domain.name]['state']
        except (KeyError, TypeError):
            cmd = f'certbot certonly --manual --preferred-challenges dns --email admin@{self.domain.name} --agree-tos --manual-public-ip-logging-ok --server {self.server} -d {self.domain.name} -d *.{self.domain.name} 2> /dev/null'
            print(cmd)
            logging.info(f'request for dns challenge values for "{self.domain}" domain has been sent')
            msg, return_code = run_command(cmd)
            # msg = '- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - Please deploy a DNS TXT record under the name _acme-challenge.juliakowalska.com with the following value:  gLfzfmGYM-JDh6YDB9Or9FP2-ODNbK4hI0qgdjGbhow  Before continuing, verify the record is deployed. - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - Press Enter to Continue'
            print(msg)
            challenge_values = re.search(f'name[\s]*(.*.{self.domain.name}).*value:[\s]*([a-zA-Z-_0-9]*)', msg)
            with open(self.state_file, 'a') as file:
                state = 'pending'
                yaml.dump({
                    self.domain.name: {
                        'txt_key': challenge_values.group(1),
                        'txt_value': challenge_values.group(2),
                        'state': state}}, file)
                self.key = challenge_values[0]
                self.value = challenge_values[1]
                self.state = state
            logging.info(f'new values for dns challenge "{self.domain}" domain has been saved in "{self.state_file}" with "{self.state}" state')

    def generate_cert(self):
        cmd = f'certbot certonly --manual --preferred-challenges dns --email admin@{self.domain.name} --agree-tos --manual-public-ip-logging-ok --server {self.server} -d {self.domain.name} -d *.{self.domain.name}'
        print(cmd)
        process = subprocess.Popen(cmd.split(' '), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(5)
        stdout, stderr = process.communicate(input=b'\n')
        process.wait(timeout=60)
        print(stdout)
        print('\n')
        print(stderr)
        print('\n')
        print(process.returncode)
        # msg, return_code = run_command(cmd)
        # print(msg)
        # print(return_code)


def run_command(command):
    process = subprocess.run(command, stdin=subprocess.PIPE, stderr=subprocess.PIPE, stdout=subprocess.PIPE, shell=True)
    return_code = process.returncode
    output = process.stderr if process.stderr else process.stdout
    return output.decode('utf-8').replace('\n', ' '), return_code


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=DEFAULTS['ACTION_CHOICES'])
    action_arg = parser.parse_known_args()[0].action
    parser.add_argument('-H', '--hosts', help='Host addresses where generated SSL cert will be send', nargs='+')
    parser.add_argument('-d', '--domains', nargs='+', required=False, help='')
    parser.add_argument('-p', '--password', required=False, help='')
    if action_arg == CHECK_ACTION:
        parser.add_argument('-a', '--authFile',
                            default=DEFAULTS['AUTH_FILE'],
                            help=f'Auth file with <username>:<password> format to DNS provider in '
                                 f'order to add TXT record to pass acme challange, default is {DEFAULTS["AUTH_FILE"]}')
    parser.add_argument('--stateFile', help=f'File to keep temp data about pending DNS challenges, default path is {DEFAULTS["STATE_FILE"]}', default=DEFAULTS['STATE_FILE'])
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    logging.basicConfig(filename='file.log', format='%(asctime)s %(name)s %(levelname)s %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=logging.DEBUG)
    cert = Certificate('/etc/letsencrypt/live/juliakowalska.com/cert.pem')
    sys.exit(0)
    try:
        test_domain = Domain(None, '1', 'babski-swiat', 'pl')
        test_domain_2 = Domain(None, '1', 'siedlaczek', 'org.pl')
        certbot = CertBot(test_domain, args.stateFile)
        print(f'{certbot.key}: {certbot.value}')
        print(test_domain.has_record('TXT', certbot.value, '_acme-challenge'))
        if test_domain.has_record('TXT', certbot.value, '_acme-challenge'):
            certbot.generate_cert()
        # provider = Provider(args.authFile)
        # domain = provider.get_domain_by_name('some_domain')
        # domain.add_dns_record('test', 'TXT', '1.1.1.1')
        # domain.remove_dns_record('test', 'TXT', '1.1.1.1')
    except (ConnectionRefusedError, ValueError, LookupError, FileNotFoundError) as e:
        logging.error(f'{os.path.basename(__file__)}: {e}')
        print(f'{os.path.basename(__file__)}: {e}')
        sys.exit(1)
