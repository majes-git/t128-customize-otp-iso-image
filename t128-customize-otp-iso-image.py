#!/usr/bin/env python3
#
# Copyright (c) Juniper Networks, Inc. 2020. All rights reserved.

"""Read an 128T iso image, add a quickstart file and write a new iso"""

import argparse
import json
import pycdlib
from base64 import b64decode, b64encode
from gzip import compress, decompress
from io import BytesIO, SEEK_CUR
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
    '/ks-otp.cfg':                     '/KS_OTP.CFG;1',
    '/ks-otp-uefi.cfg':                '/KS_OTP_U.CFG;1',
    '/bootstrap/add_quickstart.sh':    '/BOOTSTRA/ADD_QUIC.SH;1',
    '/bootstrap/bootstrap.quickstart': '/BOOTSTRA/BOOTSTRA.QUI;1',
    '/bootstrap/conductors.txt':       '/BOOTSTRA/CONDUCTO.TXT;1',
    '/bootstrap/pre-bootstrap':        '/BOOTSTRA/PRE_BOOT.;1',
    '/bootstrap/post-bootstrap':       '/BOOTSTRA/POST_BOO.;1',
}


def info(*messages):
    print('INFO:', *messages)


def parse_arguments():
    """Get commandline arguments."""
    parser = argparse.ArgumentParser(
        description='Read an 128T iso image, add a quickstart file and write a new iso.')
    parser.add_argument('--conductor', '-c', required=True, action='append',
                        help='conductor host')
    parser.add_argument('--input-iso', '-i', required=True,
                        help='iso image to be read')
    parser.add_argument('--output-iso', '-o',
                        help='iso image to be written')
    parser.add_argument('--pre-bootstrap',
                        help='include custom pre-bootstrap script')
    parser.add_argument('--post-bootstrap',
                        help='include custom post-bootstrap script')
    return parser.parse_args()


def get_iso_name(path):
    """Translate RR/Joliet names into ISO9660 names based on dictionary"""
    try:
        return ISO_NAMES[path]
    except:
        raise


def add_file(iso, content, path):
    """Add a new file to output iso image"""
    file_io = BytesIO()
    if type(content) != bytes:
        content = bytes(content, 'ascii')
    file_io.write(content)
    length = file_io.tell()
    iso.add_fp(file_io, length, iso_path=get_iso_name(path),
               rr_name=path.split('/')[-1], joliet_path=path)


def add_quickstart(iso, conductors):
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
    quickstart_json = json.dumps(quickstart)
    add_file(iso, quickstart_json, '/bootstrap/bootstrap.quickstart')


def add_conductors(iso, conductors):
    """Add a textfile with conductor IP(s) to ease iso image handling"""
    content = '\n'.join(conductors) + '\n'
    add_file(iso, content, '/bootstrap/conductors.txt')


def add_pre_post_bootstrap(iso, args):
    """Add pre/post bootstrap scripts for automation"""
    for stage in ('pre', 'post'):
        filename = args.__getattribute__('{}_bootstrap'.format(stage))
        stage_default = globals().get('{}_bootstrap'.format(stage).upper())
        path = '/bootstrap/{}-bootstrap'.format(stage)
        if filename:
            with open(filename) as fd:
                content = filename.read()
        elif stage_default:
                content = stage_default
        else:
            continue
        add_file(iso, content, path)


def add_bootstrap_script(iso):
    """Post-install hook: copy quickstart/scripts from iso image to disk"""
    content = '''#!/bin/sh
cp /mnt/install/repo/bootstrap/bootstrap.quickstart $INSTALLED_ROOT/etc/128technology/
cp /mnt/install/repo/bootstrap/*-bootstrap $INSTALLED_ROOT/etc/128technology/
chmod +x $INSTALLED_ROOT/etc/128technology/*-bootstrap
'''
    add_file(iso, content, '/bootstrap/add_quickstart.sh')


def include_bootstrap_script(iso):
    """Post-install hook: call copy script above at the end of kickstart"""
    for path in ('/ks-otp.cfg', '/ks-otp-uefi.cfg'):
        # read original file
        file_io = BytesIO()
        iso.get_file_from_iso_fp(file_io, rr_path=path)
        iso.rm_file(iso_path=get_iso_name(path), rr_name=path)
        # modify
        file_io.seek(-5, SEEK_CUR)  # jump to position before last %end
        file_io.write(bytes(
            '%include /mnt/install/repo/bootstrap/add_quickstart.sh\n\n%end',
            'ascii'))
        # write back
        add_file(iso, file_io.getvalue(), path)


def main():
    args = parse_arguments()
    conductors = args.conductor[:2]  # max. 2 conductors (HA) are supported
    output_iso = args.output_iso
    if not output_iso:
        output_iso = '{}-quickstart.iso'.format(args.input_iso.strip('.iso'))
        info('No output file specified. Using:', output_iso)

    iso = pycdlib.PyCdlib()
    iso.open(args.input_iso)
    iso.add_directory('/BOOTSTRA', rr_name='bootstrap', joliet_path='/bootstrap')
    add_quickstart(iso, conductors)
    add_conductors(iso, conductors)
    add_bootstrap_script(iso)
    add_pre_post_bootstrap(iso, args)
    include_bootstrap_script(iso)
    iso.write(output_iso)
    iso.close()


if __name__ == '__main__':
    main()
