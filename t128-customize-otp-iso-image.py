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
from ipaddress import ip_address, ip_interface
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
    '/ks-otp.cfg':                          '/KS_OTP.CFG;1',
    '/ks-otp-uefi.cfg':                     '/KS_OTP_U.CFG;1',
    '/ks-interactive.cfg':                  '/KS_INTER.CFG;1',
    '/ks-interactive-uefi.cfg':             '/KS_IN000.CFG;1',
    '/bootstrap/add_quickstart.sh':         '/BOOTSTRA/ADD_QUIC.SH;1',
    '/bootstrap/bootstrap.quickstart':      '/BOOTSTRA/BOOTSTRA.QUI;1',
    '/bootstrap/pre-bootstrap':             '/BOOTSTRA/PRE_BOOT.;1',
    '/bootstrap/post-bootstrap':            '/BOOTSTRA/POST_BOO.;1',
    '/conductors.txt':                      '/CONDUCTO.TXT;1',
    '/install.sh':                          '/INSTALL.SH;1',
    '/isolinux/isolinux.cfg':               '/ISOLINUX/ISOLINUX.CFG;1',
    '/onboarding/add_onboarding_config.sh': '/ONBOARDI/ADD_ONBO.SH;1',
    '/onboarding/create_factory_ibu.sh':    '/ONBOARDI/CREATE_F.SH;1',
    '/onboarding/onboarding-config.json':   '/ONBOARDI/ONBOARDI.JSO;1',
    '/onboarding/pre-bootstrap':            '/ONBOARDI/PRE_BOOT.;1',
    '/onboarding/post-bootstrap':           '/ONBOARDI/POST_BOT.;1',
    '/EFI/BOOT/grub.cfg':                   '/EFI/BOOT/GRUB.CFG;1',
}

RWX = 0o100555


def error(*messages):
    print('ERROR:', *messages)
    sys.exit(1)


def info(*messages):
    print('INFO:', *messages)


def warn(*messages):
    print('WARNING:', *messages)


class ValidatePCIAddress(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if not re.match('^[0-9a-f]{4}\:[0-9a-f]{2}\:[0-9a-f]{2}\.[0-9a-f]$', values):
            parser.error(f'Interface is not in PCI address format. Got: {values}')
        setattr(namespace, self.dest, values)


class ValidateIPPrefix(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        try:
            address = ip_interface(values)
        except ValueError:
            address = False
        if not address or (len(values.split('/')) != 2):
            parser.error(f'Please enter a valid IP address/prefix length. Got: {values}')
        setattr(namespace, self.dest, values)


class ValidateGateway(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        try:
            gateway = ip_address(values)
        except ValueError:
            parser.error('Gateway address is not a valid IP address.')
        # TODO: verify if gateway is part of the same subnet
        # network = namespace.ip_address.network
        # if gateway not in network:
        #     parser.error(f'Gateway address is not reachable from IP address. Network: {network} | Gateway: {gateway}')
        setattr(namespace, self.dest, values)


def parse_arguments():
    """Get commandline arguments."""
    parser = argparse.ArgumentParser(
        description='Read an 128T iso image, add a quickstart/onboarding file and write a new iso.')
    parser.add_argument('--input-iso', '-i', required=True,
                        help='iso image to be read')
    parser.add_argument('--output-iso', '-o',
                        help='iso image to be written')
    parser.add_argument('--pre-script',
                        help='include custom pre-bootstrap script')
    parser.add_argument('--post-script',
                        help='include custom post-bootstrap script')
    parser.add_argument('--no-scriptlets', action='store_true',
                       help='do not generate pre/post-bootstrap files')
    parser.add_argument('--shutdown', action='store_true',
                       help='do not ask for shutdown after kickstart')
    parser.add_argument('--factory-ibu', action='store_true',
                       help='create factory-ibu volume')
    parser.add_argument('--no-mmc', action='store_true',
                       help='disable MMC driver (e.g. for VEP devices)')
    parser.add_argument('--interface', '--int',
                        help='interface for static config')
    parser.add_argument('--ip-address', '--ip', action=ValidateIPPrefix,
                        help='IP address (plus prefix length) for static config')
    parser.add_argument('--gateway', '--gw', action=ValidateGateway,
                        help='gateway address for static config')
    parser.add_argument('--dns-server', '--dns', type=ip_address,
                        help='DNS server address for static config')
    parser.add_argument('--router-name', '-n',
                        help='router name')
    parser.add_argument('--registration-code', '-r',
                        help='Mist registration code')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--conductor', '-c', action='append', help='conductor host')
    group.add_argument('--quickstart', '-q', help='quickstart file (PBU)')
    group.add_argument('--onboarding', '-b', help='onboarding config file (IBU)')
    group.add_argument('--mist', action='store_true',
                       help='automatically onboard the router to Mist (IBU)')
    group.add_argument('--interactive-serial', action='store_true',
                       help='change boot menu default to interactive serial (PBU)')
    group.add_argument('--interactive-vga', action='store_true',
                       help='change boot menu default to interactive vga (PBU)')
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


def is_ibu(iso):
    """Determine if ISO image is IBU based"""
    found_ibu = False
    for dirname, dirlist, filelist in iso.walk(joliet_path='/'):
        if dirname != '/':
            break
        for file in filelist:
            if file.endswith('.ibu-v1.tar'):
                found_ibu = True
                break
    return found_ibu


def generate_onboarding_config_conductors(conductors, parameters):
    """Create a minimal onboarding config and set conductor IP(s)"""
    content = {
        'mode': 'conductor-managed',
        'conductor-hosts': conductors,
    }
    content.update(parameters)
    return json.dumps(content)


def generate_onboarding_config_mist(parameters):
    """Create a minimal onboarding config for Mist"""
    content = {
        'mode': 'mist-managed',
    }
    content.update(parameters)
    return json.dumps(content)


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


def modify_file(iso, path, replacement_rules):
    """Modifies file contents on iso image"""
    file_io = BytesIO()
    iso.get_file_from_iso_fp(file_io, rr_path=path)
    iso.rm_file(iso_path=get_iso_name(path), rr_name=path)
    file_io.seek(0, SEEK_SET)

    # modify
    content = file_io.read().decode('utf8')
    for rule in replacement_rules:
        content = re.sub(rule[0], rule[1], content)
    file_io.seek(0, SEEK_SET)
    file_io.write(content.encode('utf8'))

    # write back
    add_file(iso, file_io.getvalue(), path)


def change_menu_default(iso, match):
    """Changes the boot menu default to the one at <match>"""
    replacement_rules = (
        (r'.*menu default\n', r''),
        (r'(.*)(menu label \^{}\n)'.format(match), r'\1\2\1menu default\n'),
    )
    modify_file(iso, '/isolinux/isolinux.cfg', replacement_rules)


def blacklist_mmc(iso):
    """Changes the kernel commandline to blacklist mmc"""
    replacement_rules = (
        (r'(\n  append .*)', r'\1 mmc_block.blacklist=1'),
    )
    modify_file(iso, '/isolinux/isolinux.cfg', replacement_rules)

    replacement_rules = (
        (r'(linuxefi .*)', r'\1 mmc_block.blacklist=1'),
    )
    modify_file(iso, '/EFI/BOOT/grub.cfg', replacement_rules)


def read_onboarding_config(filename):
    """Read custom onboarding config file"""
    try:
        with open(filename) as fd:
            return json.load(fd)
    except:
        error('Could not read custom onboarding config file:', filename)


def read_quickstart(filename):
    """Read custom quickstart file"""
    try:
        with open(filename) as fd:
            return fd.read()
    except:
        error('Could not read custom quickstart file:', filename)


def add_onboarding_config(iso, content):
    """Add onboarding_config file to iso image"""
    add_file(iso, content, '/onboarding/onboarding-config.json')


def add_quickstart(iso, content):
    """Add quickstart file to iso image"""
    add_file(iso, content, '/bootstrap/bootstrap.quickstart')


def extract_conductors_json(content):
    """Extract conductor IP addresses from onboarding config"""
    conductors = []
    try:
        config = json.loads(content)
        if 'conductor-hosts' in config:
            conductors.extend(config['conductor-hosts'])
    except:
        warn('Could not find conductor IP addresses in onboarding config file.')
    return conductors


def extract_conductors_xml(content):
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
    if conductors:
        content = '\n'.join(conductors) + '\n'
        add_file(iso, content, '/conductors.txt')


def add_scriptlets_ibu(iso, args):
    """Add pre/post bootstrap scriptlets for automation (IBU)"""
    for stage in ('pre', 'post'):
        filename = args.__getattribute__('{}_script'.format(stage))
        path = '/onboarding/{}-bootstrap'.format(stage)
        if filename:
            try:
                with open(filename) as fd:
                    content = fd.read()
            except:
                error('Could not read custom {}-script file.'.format(stage))
        else:
            continue
        add_file(iso, content, path, file_mode=RWX)


def add_scriptlets_pbu(iso, args):
    """Add pre/post bootstrap scriptlets for automation (PBU)"""
    for stage in ('pre', 'post'):
        filename = args.__getattribute__('{}_script'.format(stage))
        stage_default = globals().get('{}_script'.format(stage).upper())
        path = '/bootstrap/{}-bootstrap'.format(stage)
        if filename:
            try:
                with open(filename) as fd:
                    content = fd.read()
            except:
                error('Could not read custom {}-script file.'.format(stage))
        elif stage_default:
                content = stage_default
        else:
            continue
        add_file(iso, content, path, file_mode=RWX)


def add_factory_ibu_script(iso):
    """Post-install hook: create factory ibu on disk"""
    content = '''#!/bin/sh
exec >/dev/null
exec 2>/dev/null
repo=/mnt/install/repo
dev=$(pvdisplay -c | awk -F: '{ print $1 }')
disk=$(echo $dev | sed 's|\([a-z/]\+\)[0-9]|\\1|')
part_num=$(echo $dev | sed 's|[a-z/]\+\([0-9]\)|\\1|')

# extend LVM partition
parted $disk resizepart $part_num 100%
pvresize $dev
# write IBU image to new LV "factory-ibu"
ibu=$repo/*.ibu-v1.tar
lvcreate --size $(ls -l $ibu | awk "{ print \$5 }")b --name factory-ibu vg00
dd if=$(ls -1 $ibu) of=/dev/vg00/factory-ibu bs=100M
# resize root and altroot LV (50 percent each)
total=$(vgdisplay -c | awk -F: '{ print $15 }')
factory_ibu_le=$(lvdisplay -c | awk -F: '/factory-ibu/{ print $8 }')
root_le=$(expr \( $total - $factory_ibu_le \) / 2)
lvextend -l 7855 /dev/vg00/root
lvcreate --extents "100%FREE" --name altroot vg00
'''
    add_file(iso, content, '/onboarding/create_factory_ibu.sh', file_mode=RWX)


def add_onboarding_config_script(iso):
    """Post-install hook: copy onboarding_config/scripts from iso image to disk"""
    content = '''#!/bin/sh
mnt_root=/mnt/install/root
dest=$mnt_root/etc/128T-hardware-bootstrapper/
mkdir $mnt_root
vgchange --activate y > /dev/null
#/bin/bash
mount -L 128T_ROOT $mnt_root
cp /mnt/install/repo/onboarding/onboarding-config.json $dest/
cp /mnt/install/repo/onboarding/*-scriptlet $dest/
umount $mnt_root
'''
    add_file(iso, content, '/onboarding/add_onboarding_config.sh', file_mode=RWX)


def add_bootstrap_script(iso):
    """Post-install hook: copy quickstart/scripts from iso image to disk"""
    content = '''#!/bin/sh
cp /mnt/install/repo/bootstrap/bootstrap.quickstart $INSTALLED_ROOT/etc/128technology/
cp /mnt/install/repo/bootstrap/*-bootstrap $INSTALLED_ROOT/etc/128technology/
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


def include_onboarding_config_script(iso, conductors, factory_ibu=False):
    """Post-install hook: call onboarding_config script after unpacker"""
    path = '/install.sh'
    # read original file
    file_io = BytesIO()
    iso.get_file_from_iso_fp(file_io, rr_path=path)
    iso.rm_file(iso_path=get_iso_name(path), rr_name=path)
    file_io.seek(0, SEEK_SET)

    # modify
    replace_string = r'\1    echo "--- t128-customize-otp-iso-image ---"\n    ' \
                      'echo "Adding onboarding-config"\n    ' \
                      '/run/install/repo/onboarding/add_onboarding_config.sh\n    '
    if conductors:
        replace_string += 'echo "Automatically onboard to conductor IP address(es):"\n    '
        for conductor in conductors:
            replace_string += f'echo "- {conductor}"\n    '

    if factory_ibu:
        replace_string += 'echo "Creating factory-ibu"\n    ' \
                          '/run/install/repo/onboarding/create_factory_ibu.sh\n    '
    replace_string += 'echo "------------------------------------"\n'
    content = file_io.read().decode('utf8')
    content = re.sub(r'(.* /run/install/repo/unpacker.sh.*\n)', replace_string, content)
    file_io.seek(0, SEEK_SET)
    file_io.write(content.encode('utf8'))
    # write back
    add_file(iso, file_io.getvalue(), path, file_mode=RWX)


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


def process_ibu(args, iso):
    """Process IBU based ISO images"""
    if args.no_mmc:
        blacklist_mmc(iso)

    iso.add_directory('/ONBOARDI', rr_name='onboarding', joliet_path='/onboarding')
    parameters = {}
    conductors = []
    if args.interface:
        parameters['interface-name'] = args.interface
        if args.ip_address:
            parameters['node-ip'] = args.ip_address
            if args.gateway:
                parameters['node-gateway'] = args.gateway
            if args.dns_server:
                parameters['dns-servers'] = [args.dns_server]
    if args.router_name:
        parameters['name'] = args.router_name

    if args.conductor:
        conductors = args.conductor[:2]  # max. 2 conductors (HA) are supported
        content = generate_onboarding_config_conductors(conductors, parameters)
    elif args.mist:
        if args.registration_code:
            parameters['registration-code'] = args.registration_code
        content = generate_onboarding_config_mist(parameters)
    elif args.onboarding:
        content = read_onboarding_config(args.onboarding)
        conductors = extract_conductors_json(content)
    add_onboarding_config(iso, content)
    add_conductors(iso, conductors)
    add_onboarding_config_script(iso)
    if args.factory_ibu:
        add_factory_ibu_script(iso)
    add_scriptlets_ibu(iso, args)
    include_onboarding_config_script(iso, conductors, args.factory_ibu)


def process_pbu(args, iso):
    """Process PBU based ISO images (legacy)"""
    if args.no_mmc:
        blacklist_mmc(iso)

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
            conductors = extract_conductors_xml(content)
        add_quickstart(iso, content)
        add_conductors(iso, conductors)
        add_bootstrap_script(iso)
        if not args.no_scriptlets:
            add_scriptlets_pbu(iso, args)
        include_bootstrap_script(iso)


def main():
    args = parse_arguments()
    output_iso = args.output_iso

    iso = pycdlib.PyCdlib()
    iso.open(args.input_iso)
    suffix = 'quickstart'
    if is_ibu(iso):
        suffix = 'onboarding'
        process_ibu(args, iso)
    else:
        process_pbu(args, iso)

    if not output_iso:
        output_iso = '{}-{}.iso'.format(args.input_iso.strip('.iso'), suffix)
        info('No output file specified. Using:', output_iso)

    iso.write(output_iso)
    iso.close()


if __name__ == '__main__':
    main()
