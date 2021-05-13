##
# Copyright 2020-2021 IT Aveiro, João Fonseca
# All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
##
from charmhelpers.core.hookenv import (
    config,
    log,
    status_set,
    action_get,
    action_fail,
    action_set
)
from charms.reactive import (
    clear_flag,
    when,
    when_not,
    set_flag
)

import glob
import charms.sshproxy
from subprocess import CalledProcessError

config = config()


def ssh_command(cmd):
    result = err = None
    try:
        result, err = charms.sshproxy._run(cmd)
    except CalledProcessError as e:
        status_set('blocked', 'Command failed: {}, errors: {}'.format(e, e.output))
    else:
        log({'output': result, "errors": err})
    finally:
        return result, err


def valid_command(cmd, err, flag):
    if err is not None and len(err):
        set_flag(flag)
        status_set('blocked', 'Command failed: {}, errors: {}'.format(cmd, err))
        return False
    return True


@when('sshproxy.configured')
@when_not('wireguard.start')
@when_not('wireguardvdu.installed')
def install_packages():
    status_set('maintenance', 'Installing wireguard')

    package = "wireguard"
    cmd = ['sudo apt update']
    result, err = ssh_command(cmd)
    if not valid_command(cmd, err, 'wireguardvdu.apt.not_installed'):
        return
    log("updated packages")

    cmd = ['sudo apt install {} -y'.format(package)]
    result, err = ssh_command(cmd)
    if not valid_command(cmd, err, 'wireguardvdu.apt.not_installed'):
        return
    set_flag('wireguardvdu.apt.installed')

    status_set('maintenance', 'Package Wireguard Installed')


@when('wireguardvdu.apt.installed')
@when_not('wireguard.start')
@when_not('wireguardvdu.installed')
def wireguard_version_check():
    log('setting application version')

    cmd = ['wg --version']
    result, err = ssh_command(cmd)
    if not valid_command(cmd, err, 'wireguardvdu.apt.not_installed'):
        log('command failed:' + err)
        log('wireguard not installed')
        return

    status_set('maintenance', result)

    if config['import_tunnel_keys']:
        files = glob.glob("files/*key")
        count = 0
        for x in files:
            with open(x) as f:
                if f.read() is not None:
                    count += 1
            f.close()
        if count == 2:
            set_flag('config.loadkey')
        else:
            log("Only one key provided. Generation of keys started")
            set_flag('config.keygen')
    else:
        set_flag('config.keygen')


@when('config.keygen')
@when_not('wireguard.start')
@when_not('wireguardvdu.installed')
def configuration_keygen():
    status_set('maintenance', 'Wireguard Key generation')

    private_key_path = "/etc/wireguard/privatekey"
    public_key_path = "/etc/wireguard/publickey"
    key_location = [private_key_path, public_key_path]

    log('Key Generation start')

    cmd = ['wg genkey | sudo tee {} | wg pubkey | sudo tee {}'.format(key_location[0], key_location[1])]
    result, err = ssh_command(cmd)

    if not valid_command(cmd, err, 'keygen.failed'):
        return

    set_flag('keygen.done')
    status_set('maintenance', 'Keygen Done')
    status_set('maintenance', result)

    for x in key_location:
        cmd = ['sudo cat {}'.format(x)]
        result, err = ssh_command(cmd)
        if not valid_command(cmd, err, 'keygen.failed'):
            log('cat ' + x + ' failed')
            break
        log(x + ":" + result)

    set_flag('keygen.done')
    log("Key Generation done")
    set_flag('wireguard.config')


@when('config.loadkey')
@when_not('wireguard.start')
@when_not('wireguardvdu.installed')
def configuration_loadkey():
    status_set('maintenance', 'Wireguard Load Keys')

    private_key_path = "/etc/wireguard/privatekey"
    public_key_path = "/etc/wireguard/publickey"
    key_location = [private_key_path, public_key_path]

    cfg = charms.sshproxy.get_config()
    host = charms.sshproxy.get_host_ip()
    user = cfg['ssh-username']

    for remote_key in key_location:
        local_key = "files/" + remote_key.lstrip('/etc/wireguard/')

        result, err = charms.sshproxy.sftp(local_key, remote_key, host, user)
        if not valid_command("sftp", err, 'wireguardvdu.load.keys.failed'):
            log('Command sftp ' + remote_key + ' failed')
            break
    set_flag('loadkeys.done')
    status_set('maintenance', 'Load Keys Done')

    set_flag('wireguard.config')


@when('wireguard.config')
@when_not('wireguardvdu.installed')
@when_not('wireguard.start')
def wireguard_config():
    status_set('maintenance', 'Server wireguard configuration started')

    filename = "/etc/wireguard/privatekey"
    cmd = ['sudo cat {}'.format(filename)]
    key, err = ssh_command(cmd)
    if not valid_command(cmd, err, 'config.keygen'):
        clear_flag('wireguard.config')
        return

    conf = "/etc/wireguard/" + config['forward_interface'] + ".conf"

    with open("files/wg0.conf.template", "rb") as f:
        x = f.read()
    f.close()

    wg_conf = (x.decode()).format(config['tunnel_address'],
                                  str(config['save_config']),
                                  str(config['listen_port']),
                                  key,
                                  config['external_interface'],
                                  config['forward_interface'],
                                  config['external_interface'],
                                  config['forward_interface']
                                  )

    log(wg_conf)
    with open("files/wg_conf.conf", "w") as f:
        f.write(wg_conf)
    f.close()

    cfg = charms.sshproxy.get_config()
    host = charms.sshproxy.get_host_ip()
    user = cfg['ssh-username']
    result, err = charms.sshproxy.sftp(wg_conf, conf, host, user)

    if not valid_command("sftp", err, 'wireguard.config.failed'):
        log('Command sftp ' + conf + ' failed')
        return

    log(result)
    set_flag('wireguard.start')


@when('wireguard.start')
@when_not('wireguardvdu.installed')
def start_wireguard():
    status_set('maintenance', 'Wireguard quick start')

    cmd = ['sudo wg-quick down {} || sudo wg-quick up {}'.format(config['forward_interface'],
                                                                 config['forward_interface'])]
    result, err = ssh_command(cmd)
    if not valid_command(cmd, err, 'wireguard.start.failed'):
        return

    if result is not None:
        log("Wireguard interface up:\n" + result)
    else:
        return

    cmd = ['sudo wg show {}'.format(config['forward_interface'])]
    result, err = ssh_command(cmd)
    if not valid_command(cmd, err, 'wireguard.server.start.failed'):
        return

    log("Wireguard config:\n" + result)
    status_set('active', 'Wireguard installed and configured')
    set_flag('wireguardvdu.installed')
    status_set('active', 'Ready!')


#
# Actions
#


@when('actions.touch')
@when('wireguardvdu.installed')
def touch():
    filename = action_get('filename')
    cmd = ['touch {}'.format(filename)]
    result, err = ssh_command(cmd)
    if not valid_command(cmd, err, 'action.touch.failed'):
        action_fail('command failed:' + err)
        return

    action_set({'output': result, "errors": err})
    clear_flag('actions.touch')


##############

@when('actions.addpeer')
@when('wireguardvdu.installed')
def addpeer():

    peer_endpoint = action_get('peer_endpoint')
    peer_public_key = action_get('peer_public_key')
    peer_listen_port = action_get('peer_listen_port')
    allowed_ips = action_get('peer_allowed_ips')

    conf = "/etc/wireguard/" + config['forward_interface'] + ".conf"

    with open("files/addpeer.conf.template", "rb") as f:
        x = f.read()
    f.close()

    wgconf = (x.decode()).format(peer_endpoint, peer_listen_port, peer_public_key, allowed_ips)
    cmd = ['echo {} |sudo tee -a {}'.format(wgconf, conf)]

    result, err = ssh_command(cmd)
    if not valid_command(cmd, err, 'wireguard.server.start.failed'):
        action_fail('command failed:' + err)
        action_set({'output': result, "errors": err})
        clear_flag('actions.addpeer')
        return

    log(result)

    cmd = ['sudo wg-quick down {} && sudo wg-quick up {}'.format(config['forward_interface'],
                                                                 config['forward_interface'])]
    result, err = ssh_command(cmd)
    if not valid_command(cmd, err, 'wireguard.server.start.failed'):
        action_fail('command failed:' + err)
        action_set({'output': result, "errors": err})
        clear_flag('actions.addpeer')
        return

    action_set({'output': result, "errors": err})
    log(result)
    clear_flag('actions.addpeer')


@when('actions.getserverinfo')
@when('wireguardvdu.installed')
def get_server_info():
    filename = "/etc/wireguard/publickey"
    cmd = ['sudo cat {}'.format(filename)]
    pubkey, err = ssh_command(cmd)
    if not valid_command(cmd, err, 'config.keygen'):
        action_fail('command failed:' + err)
        action_set({'output': pubkey, "errors": err})
        clear_flag('actions.get_server_info')
        return

    host = charms.sshproxy.get_host_ip()

    action_set(
        {
            'endpoint': host,
            'listen_port':     str(config['listen_port']),
            'tunnel_address':     config['tunnel_address'],
            'publickey': pubkey
        }
    )
    clear_flag('actions.getserverinfo')
