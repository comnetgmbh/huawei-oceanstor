#!/usr/bin/python
# -*- encoding: utf-8; py-indent-offset: 4 -*-
# 2017, comNET GmbH, Ringo Hartmann

import argparse
import logging
import socket
import sys

from huawei import oceanstor

path = 'alarm/currentalarm'
query_items = [
    'sequence',
    'description',
    'level',
    'location',
    'startTime',
]

def get_alarm_level(value):
    if type(value) == list:
        return get_alarm_level(max(value))
    return {
        3: (1, 'warning'),
        5: (2, 'major'),
        6: (2, 'critical'),
    }.get(int(value))

def quit(state, message):
    if isinstance(message, basestring):
        message = [message]
    for line in message:
        if line[-1] != '\n':
            line += '\n'
        sys.stdout.write(line)
    sys.exit(state)

def tcp_port(string):
    try:
        port = int(string)
        if port < 1 or port > 65534:
            raise ValueError()
        return port
    except ValueError:
        msg = u'Port {} is not a valid integer in range 1-65534'.format(string)
        raise argparse.ArgumentTypeError(msg)

parser = argparse.ArgumentParser(description='Check_MK Huawei OceanStor Nagios Check - Alarms')
parser.add_argument('-P', '--port',
                    dest='port', default=8088, type=tcp_port,
                    help='TCP port to connect to')
parser.add_argument('-l', '--ldap',
                    action='store_true', dest='ldap', default=False,
                    help='Login on LDAP scope')
parser.add_argument('-i', '--insecure',
                    action='store_true', dest='insecure', default=False,
                    help='Do not validate TLS certificate')
parser.add_argument('-t', '--timeout',
                    dest='timeout', default=10, type=int,
                    help='Connection timeout')
parser.add_argument('-d', '--debug',
                    action='store_true', dest='debug', default=False,
                    help='Debug mode: raise Python exceptions')
parser.add_argument('-v', '--verbose',
                    action='store_true', dest='verbose', default=False,
                    help='Be more verbose')

parser.add_argument('host', metavar='<HOST>',
                    help='OceanStor node to connect to')
parser.add_argument('username', metavar='<USERNAME>',
                    help='Login username')
parser.add_argument('password', metavar='<PASSWORD>',
                    help='Login password')

args = parser.parse_args()

socket.setdefaulttimeout(args.timeout)

if args.debug:
    level = logging.DEBUG
elif args.verbose:
    level = logging.INFO
else:
    level = logging.WARNING
logging.basicConfig(level=level)

try:
    dm = oceanstor.DeviceManager(args.host, port=args.port,
            timeout=args.timeout, insecure=args.insecure)
    dm.authenticate(args.username, args.password, scope=1 if args.ldap else 0)

    try:
        result = dm.get(path)
        if result:
            if type(result) == dict:
                result = [result]
            elif type(result) != list:
                raise Exception('Unexpected response: {!s}'.format(result))

            # We only import and instanciate HTMLParser and datetime
            # if there are any alarms to improve performance.
            from datetime import datetime
            from HTMLParser import HTMLParser

            html_parser = HTMLParser()

            def get_alarm_message(alarm):
                # OceanStor seems to provide a timestamp based on
                # the configured timezone, not UTC. Hence, we shall
                # not use datetime.fromstimestamp().
                # It produces a naive (timezone-unaware) datetime object.
                # This prints the start time based on the timezone
                # that is configured on the storage system.
                #
                # HTMLParser.unescape is used to convert HTML entities
                # such as &#40; and &#41; to their actual string representations.
                return '{} - {}'.format(
                        datetime.utcfromtimestamp(int(alarm['startTime'])).strftime('%Y-%m-%d %H:%M:%S'),
                        html_parser.unescape(alarm['description']),
                    )

            if len(result) == 1:
                alarm = result[0]
                level = get_alarm_level(alarm['level'])
                quit(level[0], get_alarm_message(alarm))
            else:
                worst_level = get_alarm_level([x['level'] for x in result])

                # Output a summary line and additional lines (one per alarm) in order
                # to move individual alarm messages to long output
                lines = ['{} alarms, worst is {}'.format(len(result), worst_level[1])]
                for alarm in result:
                    lines.append(get_alarm_message(alarm))

                quit(worst_level[0], lines)
        else:
            quit(0, 'No alarms')
    except oceanstor.APIError as e:
        if args.debug:
            raise
        quit(3, e.description)

    dm.close()
except Exception as e:
    if args.debug:
        raise
    quit(3, u'{}: {!s}\n'.format(type(e).__name__, e))
