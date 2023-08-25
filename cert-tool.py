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
from datetime import datetime
from requests.exceptions import SSLError, RequestException

CHECK_ACTION = 'check-certs'
INIT_ACTION = 'init'
SHARE_ACTION = 'share'

DEFAULTS = {
    'ACTION_CHOICES': [CHECK_ACTION, INIT_ACTION, SHARE_ACTION],
    'RECORD_TYPES': ['TXT', 'A', 'AAAA', 'MX', 'CNAME', 'REDIRECT', 'FRAME', 'CAA'],
    'STATE_FILE': f'{os.path.dirname(os.path.realpath(__file__))}/.dns_challenges.yaml',
    'AUTH_FILE': os.path.join(os.path.expanduser("~"), '.cert-tool.passwd'),
    'RSYNC': {
        'PASS_FILE': os.path.join(os.path.expanduser("~"), '.cert-tool.rsyncpass'),
        'USER': 'homelab-pi',
        'MODULE': 'ssl'
    },
    'BASE_CERTS_PATH': '/etc/letsencrypt/live',
    'DAYS_TO_EXPIRE': 14
}


class Certificate:
    def __init__(self, cert_file, chain_file):
        if not os.path.isfile(cert_file) or not os.path.isfile(chain_file):
            raise FileNotFoundError(f'Certificate file "{cert_file}" or chain file "{chain_file}" does not exist or user does not have permission to read')
        self.cert_file = cert_file
        self.chain_file = chain_file
        self.__is_valid()
        self.__set_dates()

    def __is_valid(self):
        msg, exit_code = run_command(f'openssl verify -untrusted {self.chain_file} {self.cert_file}')
        if exit_code > 0:
            raise SSLError(f'Validate "{self.cert_file}" cert file with "{self.chain_file}" chain file failed with message: "{msg.strip()}" and exit code {exit_code}')

    def __set_dates(self):
        msg, exit_code = run_command(f'openssl x509 -dates -noout < {self.cert_file}')
        if exit_code > 0:
            raise SSLError(f'Checking expire date of "{self.cert_file}" cert failed with message: "{msg.strip()}" and exit code {exit_code}')
        dates = re.search('notBefore=(.*GMT)[\s]+notAfter=(.*GMT)', msg)
        date_pattern = '%b %d %H:%M:%S %Y %Z'
        self.issued_date = datetime.strptime(dates.group(1), date_pattern)
        self.expire_date = datetime.strptime(dates.group(2), date_pattern)

    def is_expiring(self, days):
        curr_time = datetime.now()
        return (self.expire_date - curr_time).days < days


class Domain:
    records = []

    def __init__(self, name, id=None, provider=None):
        self.id = id
        self.name = name
        self.provider = provider

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

    def has_record(self, record_type, key, value):
        if record_type not in DEFAULTS['RECORD_TYPES']:
            raise ValueError(f'Cannot check "{record_type}" record with "{value}" value for "{self}" domain, allowed record types are: {", ".join(DEFAULTS["RECORD_TYPES"])}')
        msg, return_code = run_command(f'dig -t {record_type} {key} +short @1.1.1.1')
        try:
            msg = msg.strip().replace('"', '')
        except AttributeError:
            return False
        if msg and msg != value:  # TODO - trzeba ten moment zlapac
            logging.warning(f'{record_type} record for "{self}" domain returned "{msg}" value, not expected "{value}" value')
            return False
        else:
            return True if msg == value else False

    def __str__(self):
        return self.name


class Provider:
    domains = []

    def __init__(self, auth_file):
        self.base_url = 'https://www.domeny.tv'
        self.headers = {'X-Requested-With': 'XMLHttpRequest',
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36'}
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
        pl_domains = self.__get_data(f'{self.base_url}/api/domains/getPlDomains/0')['list']
        foreign_domains = self.__get_data(f'{self.base_url}/api/domains/getForeignDomains/0')['list']
        domains = foreign_domains + pl_domains
        for domain_json in domains:
            domain = Domain(f'{domain_json["domain_name"]}.{domain_json["domain_ext"]}', domain_json['domain_id'], self)
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

    def __init__(self, state_file, base_certs_path):
        self.state_file = state_file
        if not os.path.isfile(self.state_file):
            with open(self.state_file, 'w') as f:
                pass
        self.base_certs_path = base_certs_path

    def set_state(self, domain, new_state):
        with open(self.state_file, 'r') as f:
            dns_challenges = yaml.safe_load(f)
        logging.info(f'status of "{domain}" domain updated from "{dns_challenges[domain.name]["state"]}" to "{new_state}" state')
        dns_challenges[domain.name]["state"] = new_state
        with open(self.state_file, 'w') as f:
            yaml.dump(dns_challenges, f)

    def remove_domain_challenge_values(self, domain):
        with open(self.state_file, 'r') as f:
            dns_challenges = yaml.safe_load(f)
        logging.info(f'domain "{domain}" has been removed from "{self.state_file}" state file')
        del dns_challenges[domain.name]
        if len(dns_challenges) == 0:
            os.remove(self.state_file)
        else:
            with open(self.state_file, 'w') as f:
                yaml.safe_dump(dns_challenges, f)

    def set_challenge_values(self, domain):
        try:
            record_type, key, value, state = self.get_challenge_values(domain)
            logging.info(f'found DNS challenge values for "{domain}" domain with "{state}" state, {record_type} record to add is '
                         f'"{key}={value}" and it is saved in "{self.state_file}" file, no changes have been made')
        except (KeyError, TypeError):
            cmd = f'certbot certonly --manual --preferred-challenges dns --force-renewal ' \
                  f'--email admin@{domain.name} --agree-tos --manual-public-ip-logging-ok ' \
                  f'--server {self.server} -d {domain.name} -d *.{domain.name} 2> /dev/null'
            logging.debug(f'request for DNS challenge values for "{domain}" domain has been sent to "{self.server}" server')
            msg, exit_code = run_command(cmd)
            challenge_values = re.search(f'name[\s]*(.*.{domain.name}).*value:[\s]*([a-zA-Z-_0-9]*)', msg)
            if not challenge_values or not challenge_values.groups():
                raise RequestException(f'An error occurred while requesting for DNS challenge values, challenge values '
                                       f'are empty, message: "{msg.strip()}" and exit code {exit_code}')
            with open(self.state_file, 'a') as file:
                yaml.dump({
                    domain.name: {
                        'type': 'TXT',
                        'key': challenge_values.group(1),
                        'value': challenge_values.group(2),
                        'state': 'new'}}, file)
            record_type, key, value, state = self.get_challenge_values(domain)
            logging.info(f'new DNS challenge values for "{domain}" domain with "{key}={value}" {record_type} record '
                         f'to add has been saved in "{self.state_file}" file')

    def get_challenge_values(self, domain):
        with open(self.state_file, 'r') as f:
            dns_challenges = yaml.safe_load(f)
        return dns_challenges[domain.name]["type"], dns_challenges[domain.name]["key"], dns_challenges[domain.name]["value"], dns_challenges[domain.name]["state"]

    def generate_cert(self, domain):
        cmd = f'certbot certonly --manual --preferred-challenges dns --email admin@{domain.name} --agree-tos ' \
              f'--manual-public-ip-logging-ok --server {self.server} -d {domain.name} -d *.{domain.name}'
        print(cmd)
        process = subprocess.Popen(cmd.split(' '), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(10)
        stdout, stderr = process.communicate(input=b'\n\n')
        process.wait(timeout=60)
        print(stdout)
        print('\n')
        print(stderr)
        print('\n')
        print(process.returncode)


def run_command(command):
    process = subprocess.run(command, stdin=subprocess.PIPE, stderr=subprocess.PIPE, stdout=subprocess.PIPE, shell=True)
    return_code = process.returncode
    output = process.stderr if process.stderr else process.stdout
    return output.decode('utf-8').replace('\n', ' '), return_code


def parse_args():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('action', choices=DEFAULTS['ACTION_CHOICES'])
    action_arg = parser.parse_known_args()[0].action
    parser.add_argument('-d', '--domains', nargs='+', required=False, help='')
    parser.add_argument('--baseCertsPath',
                        default=DEFAULTS['BASE_CERTS_PATH'],
                        help=f'Base paths to certs and chains, '
                        f'default is {DEFAULTS["BASE_CERTS_PATH"]}.\nExample chain is {DEFAULTS["BASE_CERTS_PATH"]}/<domain>/chain.pem, '
                        f'example cert is {DEFAULTS["BASE_CERTS_PATH"]}/<domain>/cert.pem')
    if action_arg == CHECK_ACTION:
        parser.add_argument('-D', '--days',
                            default=DEFAULTS['DAYS_TO_EXPIRE'],
                            help=f'Days to expire certificate when script should issue for a new SSL certificate '
                                 f'for domain, defaults is {DEFAULTS["DAYS_TO_EXPIRE"]}')
    if action_arg == INIT_ACTION:
        parser.add_argument('-a', '--authFile',
                            default=DEFAULTS['AUTH_FILE'],
                            help=f'Auth file with <username>:<password> format to DNS provider in '
                                 f'order to add TXT record to pass acme challange, default is {DEFAULTS["AUTH_FILE"]}')
    if action_arg == SHARE_ACTION:
        parser.add_argument('-H', '--hosts', help='Host addresses where generated SSL cert will be send', nargs='+')
        parser.add_argument('--passwdFile',
                            default=DEFAULTS['RSYNC']['PASS_FILE'],
                            help=f'File with rsync password to send cert, default path is {DEFAULTS["RSYNC"]["PASS_FILE"]}')
        parser.add_argument('-u', '--user',
                            default=DEFAULTS['RSYNC']['USER'],
                            help=f'User to establish rsync connection, default is {DEFAULTS["RSYNC"]["USER"]}')
        parser.add_argument('-m', '--module',
                            default=DEFAULTS['RSYNC']['MODULE'],
                            help=f'Rsync module, default is {DEFAULTS["RSYNC"]["MODULE"]}')
    parser.add_argument('--stateFile', help=f'File to keep temp data about pending DNS challenges, default path is {DEFAULTS["STATE_FILE"]}', default=DEFAULTS['STATE_FILE'])
    parser.add_argument('-h', '--help', action='help')
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    logging.basicConfig(filename='file.log', format='%(asctime)s %(name)s %(levelname)s %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=logging.DEBUG)

    try:
        certbot = CertBot(args.stateFile, args.baseCertsPath)
        if args.action == CHECK_ACTION:
            for domain_name in args.domains:
                domain = Domain(domain_name)
                try:
                    cert = Certificate(f'{certbot.base_certs_path}/{domain.name}/cert.pem', f'{certbot.base_certs_path}/{domain.name}/chain.pem')
                    generate_cert = cert.is_expiring(args.days)
                except FileNotFoundError as e:
                    generate_cert = True
                if generate_cert:
                    logging.info(f'domain "{domain}" will expire for less than {args.days} days, generating challenge values...')
                    certbot.set_challenge_values(domain)
                else:
                    print(f'no need to generate certificate for "{domain}" domain, expire date is {cert.expire_date}')
        elif args.action == INIT_ACTION:
            provider = None
            for domain_name in args.domains:
                domain = Domain(domain_name)
                record_type, key, value, state = certbot.get_challenge_values(domain)
                if state == 'new':
                    if not provider:
                        provider = Provider(args.authFile)
                    provider_domain = provider.get_domain_by_name(domain.name)
                    provider_domain.add_record(f'{key}.', record_type, value)
                    certbot.set_state(domain, 'pending')
                if domain.has_record(record_type, key, value):
                    logging.info(f'domain "{domain}" has visible {record_type} record "{key}={value}", issuing for SSL certificate...')
                    certbot.generate_cert(domain)
                    certbot.remove_domain_challenge_values(domain)
                    if not provider:
                        provider = Provider(args.authFile)
                    provider_domain = provider.get_domain_by_name(domain.name)
                    provider_domain.remove_record(f'{key}.', record_type, value)
                else:
                    print(f'{record_type} record "{key}={value}" is not presented in "{domain}" DNS config')
        elif args.action == SHARE_ACTION:
            for domain_name in args.domains:
                domain = Domain(domain_name)
                for host in args.hosts:
                    run_command(f'rsync -L --password-file="{args.passwFile}" {args.baseCertsPath}/{domain}/fullchain.pem {args.baseCertsPath}/{domain}/privkey.pem rsync://{args.user}@{host}/{args.module}/{domain_name}/')
                    print(f'rsync -L --password-file="{args.passwdFile}" {args.baseCertsPath}/{domain}/fullchain.pem {args.baseCertsPath}/{domain}/privkey.pem rsync://{args.user}@{host}/{args.module}/{domain_name}/')
                    logging.info(f'certs for "{domain}" domain has been sent to "{host}" host')
    except (ConnectionRefusedError, ValueError, LookupError, FileNotFoundError, SSLError, FileNotFoundError, RequestException) as e:
        logging.error(f'{os.path.basename(__file__)}: {e}')
        print(f'{os.path.basename(__file__)}: {e}')
        sys.exit(1)
    sys.exit(0)
