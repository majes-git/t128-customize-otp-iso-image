#!/usr/bin/env python3
#
# Copyright (c) Juniper Networks, Inc. 2022. All rights reserved.

import argparse
import json
import pycdlib
import re
import sys
import xml.etree.ElementTree as ET
from base64 import b64decode, b64encode
from gzip import compress, decompress
from io import BytesIO, SEEK_CUR, SEEK_SET
from uuid import uuid4


PRE_BOOTSTRAP = ''
# automatically enable dhcp client on all ethernet interfaces (prefixed by "e")
POST_BOOTSTRAP = '''#!/bin/bash\n
for interface in $(awk '/^[ ]*e/{ gsub(/:/, "", $1); print $1 }' /proc/net/dev); do
cat > /etc/sysconfig/network-scripts/ifcfg-$interface <<EOF
DEVICE=$interface
TYPE=Ethernet
BOOTPROTO=dhcp
ONBOOT=yes
EOF
done
'''

ISO_NAMES = {
    '/bootstrap.quickstart': '/BOOTSTRA.QUI;1',
    '/pre-bootstrap':        '/PRE_BOOT.;1',
    '/post-bootstrap':       '/POST_BOO.;1',
}


def parse_arguments():
    """Get commandline arguments."""
    parser = argparse.ArgumentParser(
        description='Read an 128T iso image, add a quickstart file and write a new iso.')
    parser.add_argument('--output-iso', '-o', required=True,
                        help='iso image to be written')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--conductor', '-c', action='append',
                        help='conductor host')
    group.add_argument('--quickstart', '-q', help='quickstart file')
    return parser.parse_args()


def get_iso_name(path):
    """Translate RR/Joliet names into ISO9660 names based on dictionary"""
    try:
        return ISO_NAMES[path]
    except:
        raise


def add_file(iso, content, path, file_mode=None):
    """Add a new file to output iso image"""
    file_io = BytesIO()
    if type(content) != bytes:
        content = bytes(content, 'ascii')
    file_io.write(content)
    length = file_io.tell()
    iso.add_fp(file_io, length, iso_path=get_iso_name(path),
               rr_name=path.split('/')[-1], joliet_path=path, file_mode=file_mode)


def generate_quickstart(conductors):
    """Create a minimal quickstart from template and set conductor IP(s)"""
    conductor_entry = '<authy:conductor-address>{}</authy:conductor-address>'
    conductor_config = ''.join([conductor_entry.format(c) for c in conductors]).strip()
    template = 'H4sIAJL252EC/41T226DMAz9lYr3NGulTROiqfYlKDVeiQYJi001/n5pIJRepPbNORfHOZhi/9c2qxN6Ms7uss36Ldurgjfbzxyc/TbHVeAt5Wdkl9XMXS5lqBmhtq5xx2ENrpVnOpukuud6eKKVY3N51jpveBAjkHrQCV7sQOhPBvDWP9Cr/oEY22RXRZw+n+dKgNUtqq+EBn8hF8QkIoT+zmQso7e6eWSokMCbjkP2o05YV+Eq9UmWpWxyogU/RESA6Wr0SiMJOIDYvn8k373o2q3Y93gjTpK61SDaMI1i06I4aMIqSS/cUjxdQbUOI4hFREs2YXNUZRmir3pg56ksp37e9XyZNiZ2RIvegPjtDfwQa89iVD3K9ZKlmC+6/Q6PNEXYhtzGh8XqycWzJqq9a1CF9Tq4kYnnyJhKbUYsVBHRRMginMoylqWpwuPlFTX1X8Q86tMSTp6ZSmUKT96tslz81+ofn/xZXPoDAAA='
    template_decoded = decompress(b64decode(template)).decode('ascii')
    config = template_decoded.replace('__conductors__', conductor_config)
    config = config.replace('__asset_id__', str(uuid4()))
    config = config.replace('__authority_id__', str(uuid4()))
    quickstart = {
        'n': 'generic-quickstart-router',
        'a': None,
        'c': b64encode(compress(bytes(config, 'ascii'))).decode('ascii'),
    }
    return json.dumps(quickstart)


def add_quickstart(iso, content):
    """Add quickstart file to iso image"""
    add_file(iso, content, '/bootstrap.quickstart')


def add_scriptlets(iso):
    """Add pre/post bootstrap scriptlets for automation"""
    for stage in ('pre', 'post'):
        stage_default = globals().get('{}_bootstrap'.format(stage).upper())
        path = '/{}-bootstrap'.format(stage)
        if stage_default:
            content = stage_default

            # mode (octals):
            # 0100000 S_IFREG regular
            # 0000400 S_IRUSR read permission (owner)
            # 0000100 S_IXUSR execute permission (owner)
            # 0000040 S_IRGRP read permission (group)
            # 0000010 S_IXGRP execute permission (group)
            # 0000004 S_IROTH read permission (other)
            # 0000001 S_IXOTH execute permission (other)
            add_file(iso, content, path, file_mode=0o100555)


def main():
    args = parse_arguments()
    output_iso = args.output_iso
    iso = pycdlib.PyCdlib()
    iso.new(rock_ridge='1.09', joliet=3, vol_ident='BOOTSTRAP')

    if args.conductor:
        conductors = args.conductor[:2]  # max. 2 conductors (HA) are supported
        content = generate_quickstart(conductors)
    elif args.quickstart:
        with open(args.quickstart) as fd:
            content = fd.read()
    else:
        print('ERROR: no conductor nor quickstart file given!')
        sys.exit(1)

    add_quickstart(iso, content)
    add_scriptlets(iso)

    iso.write(output_iso)
    iso.close()


if __name__ == '__main__':
    main()
