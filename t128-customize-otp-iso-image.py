#!/usr/bin/env python3
#
# Copyright (c) Juniper Networks, Inc. 2022. All rights reserved.

"""Read an 128T iso image, add a quickstart file and write a new iso"""

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
    '/ks-otp.cfg':                     '/KS_OTP.CFG;1',
    '/ks-otp-uefi.cfg':                '/KS_OTP_U.CFG;1',
    '/ks-interactive.cfg':             '/KS_INTER.CFG;1',
    '/ks-interactive-uefi.cfg':        '/KS_IN000.CFG;1',
    '/bootstrap/add_quickstart.sh':    '/BOOTSTRA/ADD_QUIC.SH;1',
    '/bootstrap/bootstrap.quickstart': '/BOOTSTRA/BOOTSTRA.QUI;1',
    '/bootstrap/conductors.txt':       '/BOOTSTRA/CONDUCTO.TXT;1',
    '/bootstrap/pre-bootstrap':        '/BOOTSTRA/PRE_BOOT.;1',
    '/bootstrap/post-bootstrap':       '/BOOTSTRA/POST_BOO.;1',
    '/isolinux/isolinux.cfg':          '/ISOLINUX/ISOLINUX.CFG;1',
}


def error(*messages):
    print('ERROR:', *messages)
    sys.exit(1)


def info(*messages):
    print('INFO:', *messages)


def warn(*messages):
    print('WARNING:', *messages)


def parse_arguments():
    """Get commandline arguments."""
    parser = argparse.ArgumentParser(
        description='Read an 128T iso image, add a quickstart file and write a new iso.')
    parser.add_argument('--input-iso', '-i', required=True,
                        help='iso image to be read')
    parser.add_argument('--output-iso', '-o',
                        help='iso image to be written')
    parser.add_argument('--pre-bootstrap',
                        help='include custom pre-bootstrap script')
    parser.add_argument('--post-bootstrap',
                        help='include custom post-bootstrap script')
    parser.add_argument('--no-scriptlets', action='store_true',
                       help='do not generate pre/post-bootstrap files')
    parser.add_argument('--shutdown', action='store_true',
                       help='do not ask for shutdown after kickstart')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--conductor', '-c', action='append', help='conductor host')
    group.add_argument('--quickstart', '-q', help='quickstart file')
    group.add_argument('--interactive-serial', action='store_true',
                       help='change boot menu default to interactive serial')
    group.add_argument('--interactive-vga', action='store_true',
                       help='change boot menu default to interactive vga')
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


def change_menu_default(iso, match):
    """Changes the boot menu default to the one at <match>"""
    # read original isolinux.cfg
    path = '/isolinux/isolinux.cfg'
    file_io = BytesIO()
    iso.get_file_from_iso_fp(file_io, rr_path=path)
    iso.rm_file(iso_path=get_iso_name(path), rr_name=path)
    file_io.seek(0, SEEK_SET)

    # modify
    content = file_io.read().decode('utf8')
    content = re.sub(r'.*menu default\n', r'', content)
    content = re.sub(r'(.*)(menu label \^{}\n)'.format(match), r'\1\2\1menu default\n', content)
    file_io.seek(0, SEEK_SET)
    file_io.write(content.encode('utf8'))

    # write back
    add_file(iso, file_io.getvalue(), path)


def read_quickstart(filename):
    """Read custom quickstart file"""
    try:
        with open(filename) as fd:
            return fd.read()
    except:
        error('Could not read custom quickstart file:', filename)


def add_quickstart(iso, content):
    """Add quickstart file to iso image"""
    add_file(iso, content, '/bootstrap/bootstrap.quickstart')


def extract_conductors(content):
    """Extract conductor IP addresses from quickstart"""
    conductors = []
    try:
        quickstart = json.loads(content)
        b = quickstart.get('c')
        xml = decompress(b64decode(b))
        root = ET.fromstring(xml)
        for authority in root.findall('{http://128technology.com/t128/config/authority-config}authority'):
            for elem in authority.findall('{http://128technology.com/t128/config/authority-config}conductor-address'):
                conductors.append(elem.text)
    except:
        warn('Could not find conductor IP addresses in quickstart file.')
    return conductors


def add_conductors(iso, conductors):
    """Add a textfile with conductor IP(s) to ease iso image handling"""
    content = '\n'.join(conductors) + '\n'
    add_file(iso, content, '/bootstrap/conductors.txt')


def add_scriptlets(iso, args):
    """Add pre/post bootstrap scriptlets for automation"""
    for stage in ('pre', 'post'):
        filename = args.__getattribute__('{}_bootstrap'.format(stage))
        stage_default = globals().get('{}_bootstrap'.format(stage).upper())
        path = '/bootstrap/{}-bootstrap'.format(stage)
        if filename:
            try:
                with open(filename) as fd:
                    content = fd.read()
            except:
                error('Could not read custom {}-bootstrap file.'.format(stage))
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


def disable_shutdown_prompt(iso):
    """Post-install hook: remove prompt for shutdown"""
    for path in ('/ks-interactive.cfg', '/ks-interactive-uefi.cfg'):
        # read original file
        file_io = BytesIO()
        iso.get_file_from_iso_fp(file_io, rr_path=path)
        iso.rm_file(iso_path=get_iso_name(path), rr_name=path)
        file_io.seek(0, SEEK_SET)

        # modify
        content = file_io.read().decode('utf8')
        content = re.sub(r'(.*%include.*prompt_for_shutdown.*\n)', r'#\1', content)
        file_io.seek(0, SEEK_SET)
        file_io.write(content.encode('utf8'))

        # write back
        add_file(iso, file_io.getvalue(), path)


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
    output_iso = args.output_iso
    if not output_iso:
        output_iso = '{}-quickstart.iso'.format(args.input_iso.strip('.iso'))
        info('No output file specified. Using:', output_iso)

    iso = pycdlib.PyCdlib()
    iso.open(args.input_iso)
    if args.interactive_serial or args.interactive_vga:
        if args.interactive_serial:
            match = 'Install 128T Routing Software Serial Console'
        if args.interactive_vga:
            match = 'Install 128T Routing Software VGA Console'
        change_menu_default(iso, match)
        if args.shutdown:
            disable_shutdown_prompt(iso)
    else:
        iso.add_directory('/BOOTSTRA', rr_name='bootstrap', joliet_path='/bootstrap')
        if args.conductor:
            conductors = args.conductor[:2]  # max. 2 conductors (HA) are supported
            content = generate_quickstart(conductors)
        elif args.quickstart:
            content = read_quickstart(args.quickstart)
            conductors = extract_conductors(content)
        add_quickstart(iso, content)
        add_conductors(iso, conductors)
        add_bootstrap_script(iso)
        if not args.no_scriptlets:
            add_scriptlets(iso, args)
        include_bootstrap_script(iso)
    iso.write(output_iso)
    iso.close()


if __name__ == '__main__':
    main()
