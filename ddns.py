#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
#  DigitalOcean Dynamic DNS
#  Created by LulzLoL231 at 27/10/21
#
import sys
import json
import logging
from http import HTTPStatus
from argparse import ArgumentParser
from http.client import HTTPSConnection
from typing import Dict, Optional, Tuple
from ipaddress import IPv4Address, IPv6Address


VERSION = '0.2'
TIMEOUT = 5
IPv4_HOST = 'api.ipify.org'
IPv4_PORT = 443
IPv6_HOST = 'api6.ipify.org'
IPv6_PORT = 443
DOAPI_HOST = 'api.digitalocean.com'
DOAPI_PORT = 443
DOAPI_ACCOUNT = '/v2/account'
DOAPI_DOMAINS = '/v2/domains'
DOAPI_DOMAINS_RECORDS = '/v2/domains/{}/records'
parser = ArgumentParser(
    description='Use DigitalOcean DNS as your own Dynamic DNS!',
    epilog='Repo: https://github.com/LulzLoL231/DOddns'
)
parser.add_argument(
    '-q',
    '--quite',
    help='Quite executing',
    action='store_true'
)
parser.add_argument(
    '-v',
    '--verbose',
    help='Verbose logging',
    action='store_true'
)
parser.add_argument(
    '--token',
    required=True,
    help='DigitalOcean API token (rw)'
)
parser.add_argument(
    '--domain',
    required=True,
    help='Domain for linking'
)
args = parser.parse_args()
logging.basicConfig(
    format='[%(levelname)s] %(name)s (%(lineno)d) >> %(funcName)s: %(message)s',
    level=logging.DEBUG if args.verbose else logging.INFO)
if args.quite:
    logging.getLogger('ddns').setLevel(logging.ERROR)
log = logging.getLogger('ddns')
log.info(f'DigitalOcean Dynamic DNS v{VERSION}')


def do_req(
    method: str,
    url: str,
    body: Optional[bytes] = None,
    headers: Optional[Dict[str, str]] = None) -> Tuple[int, dict]:
    '''Make DO API request.

    Args:
        method (str): HTTP method.
        url (str): API method.
        body (Optional[bytes]): Payload. Defaults to None.
        headers (Optional[Dict[str, str]]): HTTP headers. Defaults to None.

    Returns:
        Tuple[int, dict]: Tuple with HTTP status and API response.
    '''
    log.debug(f'Called with args: ({method}, {url}, {body}, {headers})')  # type: ignore
    try:
        con = HTTPSConnection(DOAPI_HOST, DOAPI_PORT, timeout=TIMEOUT)
        if headers:
            con.request(method, url, body, headers)
        else:
            con.request(method, url, body)
    except Exception:
        if args.verbose:
            log.warning('Connection error!', exc_info=sys.exc_info())
        else:
            log.warning('Connection error!')
        return (503, {'id': 'connection_error', 'message': 'Can\'t connect to api.digitalocean.com'})
    else:
        resp = con.getresponse()
        return (resp.status, json.loads(resp.read()))
    finally:
        con.close()


def get_ipv4() -> str:
    '''Returns IPv4 inet address of this device.

    Returns:
        str: IPv4 address, or empty string.
    '''
    log.debug('Called')
    try:
        con = HTTPSConnection(IPv4_HOST, IPv4_PORT, timeout=TIMEOUT)
        con.request('GET', '/')
    except Exception:
        if args.verbose:
            log.warning('Connection error!', exc_info=sys.exc_info())
        else:
            log.warning('Connection error!')
        return ''
    else:
        resp = con.getresponse().read().decode()
        log.debug(f'Response: {str(resp)}')
        try:
            IPv4Address(resp)
        except Exception as e:
            log.warning(
                f'Can\'t parse IPv4 address response from "{IPv4_HOST}": {str(e)}')
            return ''
        else:
            return resp
    finally:
        con.close()


def get_ipv6() -> str:
    '''Returns IPv6 inet address of this device.

    Returns:
        str: IPv6 address, or empty string.
    '''
    log.debug('Called')
    try:
        con = HTTPSConnection(IPv6_HOST, IPv6_PORT, timeout=TIMEOUT)
        con.request('GET', '/')
    except Exception:
        if args.verbose:
            log.warning('Connection error!', exc_info=sys.exc_info())
        else:
            log.warning('Connection error!')
        return ''
    else:
        resp = con.getresponse().read().decode()
        log.debug(f'Response: {str(resp)}')
        try:
            IPv6Address(resp)
        except Exception as e:
            log.warning(
                f'Can\'t parse IPv6 address response from "{IPv6_HOST}": {str(e)}')
            return ''
        else:
            return resp
    finally:
        con.close()


def get_all_domain_records(domain: str, type: str) -> list:
    '''Returns all DNS records for specific domain with specific records type.

    Args:
        domain (str): root domain.
        type (str): DNS records type.

    Returns:
        list: DNS records for domain.
    '''
    log.debug('Called')
    records = []
    next_url = ''
    while True:
        if next_url:
            url = next_url
        else:
            url = DOAPI_DOMAINS_RECORDS.format(domain) + f'?type={type}'
        recs = do_req(
            'GET',
            url,
            headers={
                'Content-Type': 'Application/json',
                'Authorization': f'Bearer {args.token}'
            }
        )
        if recs[0] == 200:
            for r in recs[1]['domain_records']:
                records.append(r)
            if len(records) < recs[1]['meta']['total']:
                next_url = recs[1]['links']['next'].strip('https://api.digitalocean.com')
            else:
                break
    return records


def main():
    '''Main function.
    '''
    acc = do_req(
        'GET',
        DOAPI_ACCOUNT,
        headers={
            'Content-Type': 'Application/json',
            'Authorization': f'Bearer {args.token}'
        }
    )
    if acc[0] == 0:
        log.critical(f'Can\'t work without account info. Error 0: {acc[1]}')
        sys.exit(1)
    else:
        log.debug(f'API answer "{HTTPStatus(acc[0])}": {acc[1]}')
        if acc[0] > 204:
            log.warning(f'API Error "{HTTPStatus(acc[0])}": {acc[1]["message"]}')
            log.critical(f'Can\'t work without account info. Error {acc[0]}: {acc[1]["message"]}')
            sys.exit(1)
        else:
            log.info(f'Logged in DigitalOcean as {acc[1]["account"]["email"]}')
            root_domain = args.domain.split('.')[::-1][1] + '.' + args.domain.split('.')[::-1][0]
            domain = do_req(
                'GET',
                DOAPI_DOMAINS + f'/{root_domain}',
                headers={
                    'Content-Type': 'Application/json',
                    'Authorization': f'Bearer {args.token}'
                }
            )
            log.debug(f'domain: {domain}')
            if domain[0] == 200:
                log.info(f'Found root domain registered in DO account "{root_domain}".')
                current_ipv4 = get_ipv4()
                log.debug(f'current_ipv4: {current_ipv4}')
                current_ipv6 = get_ipv6()
                log.debug(f'current_ipv6: {current_ipv6}')
                if current_ipv4:
                    recs = get_all_domain_records(root_domain, 'A')
                    log.debug(f'recs: {recs}')
                    domain_rec = list(filter(lambda d: d['name'] == args.domain.strip(f'.{root_domain}'), recs))
                    log.debug(f'domain_rec: {domain_rec}')
                    if len(domain_rec) > 0:
                        log.info(f'Found old DNS A record for "{args.domain}".')
                        if domain_rec[0]['data'] == current_ipv4:
                            log.info(
                                f'Current IPv4 address "{current_ipv4}" already linked to domain "{args.domain}"')
                        else:
                            log.info(f'Current IPv4 address "{current_ipv4}" is different from the domain "{args.domain}" refers. Updating.')
                            resp = do_req(
                                'PATCH',
                                DOAPI_DOMAINS_RECORDS.format(root_domain) + f'/{domain_rec[1]["domain_record"]["id"]}',
                                json.dumps({
                                    'data': current_ipv4
                                }),
                                {
                                    'Content-Type': 'Application/json',
                                    'Authorization': f'Bearer {args.token}'
                                }
                            )
                            log.debug(f'resp: {str(resp)}')
                            if resp[0] == 200:
                                log.info(f'Successfull changed IPv4 for domain "{args.domain}"!')
                            else:
                                log.error(f'Can\'t change IPv4 record for domain "{args.domain}": {HTTPStatus(resp[0])} - {resp[1]["message"]}')
                    else:
                        log.info(f'Not found existing DNS A record for domain "{args.domain}". Creating.')
                        resp = do_req(
                            'POST',
                            DOAPI_DOMAINS_RECORDS.format(root_domain),
                            json.dumps({
                                'type': 'A',
                                'name': args.domain.strip(f'.{root_domain}'),
                                'data': current_ipv4,
                                'ttl': 3600
                            }),
                            {
                                'Content-Type': 'Application/json',
                                'Authorization': f'Bearer {args.token}'
                            }
                        )
                        log.debug(f'resp: {str(resp)}')
                        if resp[0] == 201:
                            log.info(f'Created a new DNS A record with ID #{resp[1]["domain_record"]["id"]}!')
                        else:
                            log.error(f'Can\'t create a new DNS A record for domain "{args.domain}": {HTTPStatus(resp[0])} - {resp[1]["message"]}')
                else:
                    log.warning(f'Can\'t fetch IPv4 address for this device. Ignoring.')
                if current_ipv6:
                    recs = get_all_domain_records(root_domain, 'AAAA')
                    log.debug(f'recs: {recs}')
                    domain_rec = list(
                        filter(lambda d: d['name'] == args.domain.strip(f'.{root_domain}'), recs))
                    log.debug(f'domain_rec: {domain_rec}')
                    if len(domain_rec) > 0:
                        log.info(f'Found old DNS AAAA record about "{args.domain}".')
                        if domain_rec[0]['data'] == current_ipv6:
                            log.info(
                                f'Current IPv6 address "{current_ipv6}" already linked to domain "{args.domain}"')
                        else:
                            log.info(f'Current IPv6 address "{current_ipv6}" is different from the domain "{args.domain}" refers. Updating.')
                            resp = do_req(
                                'PATCH',
                                DOAPI_DOMAINS_RECORDS.format(root_domain) + f'/{domain_rec[1]["domain_record"]["id"]}',
                                json.dumps({
                                    'data': current_ipv6
                                }),
                                {
                                    'Content-Type': 'Application/json',
                                    'Authorization': f'Bearer {args.token}'
                                }
                            )
                            log.debug(f'resp: {str(resp)}')
                            if resp[0] == 200:
                                log.info(f'Successfull changed IPv6 for domain "{args.domain}"!')
                            else:
                                log.error(f'Can\'t change IPv6 record for domain "{args.domain}": {HTTPStatus(resp[0])} - {resp[1]["message"]}')
                    else:
                        log.info(f'Not found existing DNS AAAA record for domain "{args.domain}". Creating.')
                        resp = do_req(
                            'POST',
                            DOAPI_DOMAINS_RECORDS.format(root_domain),
                            json.dumps({
                                'type': 'AAAA',
                                'name': args.domain.strip(f'.{root_domain}'),
                                'data': current_ipv6,
                                'ttl': 3600
                            }),
                            {
                                'Content-Type': 'Application/json',
                                'Authorization': f'Bearer {args.token}'
                            }
                        )
                        log.debug(f'resp: {str(resp)}')
                        if resp[0] == 201:
                            log.info(f'Created a new DNS AAAA record with ID #{resp[1]["domain_record"]["id"]}!')
                        else:
                            log.error(f'Can\'t create a new DNS AAAA record for domain "{args.domain}": {HTTPStatus(resp[0])} - {resp[1]["message"]}')
                else:
                    log.warning(f'Can\'t fetch IPv6 address for this device. Ignoring.')
            else:
                log.critical(f'Can\'t found root domain in current DO account! {HTTPStatus(domain[0])}: {domain[1]["message"]}')


if __name__ == '__main__':
    main()
    sys.exit(0)
