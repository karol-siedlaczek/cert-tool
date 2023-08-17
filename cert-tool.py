#!/usr/bin/env python3

import os
import re
import sys
import yaml
import json
import logging
import argparse
import requests
import subprocess

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
        response = self.provider.set_records(self, dns_records)
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

        response = self.provider.set_records(self, new_dns_records)
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

    def set_records(self, domain, records):
        url = f'{self.base_url}/api/DNSServer/saveRecords/{domain.id}'
        payload = {'records': records, 'srv': []}
        return self.session.post(url, json=payload, headers=self.headers)


class CertBot:
    server = 'https://acme-v02.api.letsencrypt.org/directory'
    state_file = f'{os.path.dirname(os.path.realpath(__file__))}/dns_challenges.yaml'

    def __init__(self, domain):

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
            cmd = f'certbot certonly --staging --manual --preferred-challenges dns --email admin@{self.domain.name} --agree-tos --manual-public-ip-logging-ok --server {self.server} -d {self.domain.name} -d *.{self.domain.name} 2> /dev/null'
            print(cmd)
            logging.info(f'request for dns challenge values for "{self.domain}" domain has been sent')
            msg, return_code = run_command(cmd)
            #msg = '- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - Please deploy a DNS TXT record under the name _acme-challenge.juliakowalska.com with the following value:  gLfzfmGYM-JDh6YDB9Or9FP2-ODNbK4hI0qgdjGbhow  Before continuing, verify the record is deployed. - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - Press Enter to Continue'
            print(msg)
            challenge_values = re.search(f'name[\s]*(.*.{self.domain.name}).*value:[\s]*([a-zA-Z-0-9]*)', msg)
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

    def is_txt_record_present(self):
        msg, return_code = run_command(f'dig -t txt {self.key} +short')
        try:
            msg = msg.strip().replace('"', '')
        except AttributeError:
            return False
        if msg and msg != self.value:
            logging.error(f'dig returned "{msg}", value for "{self.key}" TXT record should be "{self.value}"')
        else:
            return msg == self.value

    def get_certs(self):
        cmd = f'certbot certonly --staging --manual --preferred-challenges dns --email admin@{self.domain.name} --agree-tos --manual-public-ip-logging-ok --server {self.server} -d {self.domain.name} -d *.{self.domain.name}'
        print(cmd)
        process = subprocess.Popen(cmd.split(' '), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate(input=b'\n\n')
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
    parser.add_argument('-u', '--username', required=False, help='')
    parser.add_argument('-p', '--password', required=False, help='')
    parser.add_argument('-d', '--domains', nargs='+', required=False, help='')
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    logging.basicConfig(filename='file.log', format='%(asctime)s %(name)s %(levelname)s %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=logging.DEBUG)
    domain1 = Domain(None, '1', 'juliakowalska', 'com')
    domain2 = Domain(None, '1', 'siedlaczek', 'org.pl')
    certbot = CertBot(domain1)
    print(certbot.key)
    print(certbot.value)
    print(certbot.is_txt_record_present())
    certbot.get_certs()
    try:
        #msg, return_code = run_command('certbot certonly --dry-run  --test-cert -m admin@siedlaczek.org.pl --agree-tos --manual --manual-public-ip-logging-ok -d \*.siedlaczek.org.pl -d siedlaczek.org.pl --preferred-challenges dns > test.txt')
        #msg, return_code = run_command('certbot certonly --manual --manual-auth-hook /mnt/f/Programs/Repository/Python/cert-tool/acme-dns-auth.py --preferred-challenges dns --debug-challenges -d aap.example.com')
        print('end')

        #provider = Provider(args.username, args.password)
        #domain = provider.get_domain_by_name('some_domain')
        #domain.add_dns_record('test', 'TXT', '1.1.1.1')
        #domain.remove_dns_record('test', 'TXT', '1.1.1.1')
    except (ConnectionRefusedError, ValueError, LookupError, FileNotFoundError) as e:
        logging.error(f'{os.path.basename(__file__)}: {e}')
        print(f'{os.path.basename(__file__)}: {e}')

# dig +short -t txt siedlaczek.org.pl
#certbot certonly --manual --preferred-challenges=dns --email admin@siedlaczek.org.pl --manual-public-ip-logging-ok --server https://acme-v02.api.letsencrypt.org/directory --agree-tos -d siedlaczek.org.pl -d *.siedlaczek.org.pl
#certbot certonly -n -m admin@siedlaczek.org.pl --agree-tos --manual --manual-public-ip-logging-ok --manual-auth-hook /mnt/f/Programs/Repository/Python/cert-tool/acme-dns-auth.py -d \*.siedlaczek.org.pl -d siedlaczek.org.pl --preferred-challenges dns
#certbot -d \*.siedlaczek.org.pl --manual-public-ip-logging-ok -d siedlaczek.org.pl --manual --preferred-challenges dns certonly
#certbot certonly -m -n admin@siedlaczek.org.pl --agree-tos -d \*.siedlaczek.org.pl -d siedlaczek.org.pl --manual --preferred-challenges dns



#  pip install certbot-external-auth


# regex = fr'^(?P<txt_key>_acme-challenge.{domain.name})'
    # key = None
    # try:
    #     with open(f'{acme_values_path}/{domain.name}.txt', 'r') as f:
    #         lines = f.readlines()
    #         for line in lines:
    #             if key and line.strip() != "":
    #                 value = line.strip()
    #                 break
    #             result = re.search(regex, line)
    #             if result:
    #                 key = result.group('txt_key')
    #     print(f'{key}: {value}')
    #     return key, value
    # except Exception as e:
    #     raise type(e)(f'Failed retrieving TXT records for "{domain.name}" domain with error message: "{e}"')
