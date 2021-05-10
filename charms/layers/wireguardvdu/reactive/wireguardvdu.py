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
    if len(err):
        set_flag(flag)
        status_set('blocked', 'Command failed: {}, errors: {}'.format(cmd, err))
        return False
    return True


@when('sshproxy.configured')
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

    if config['import_config']:
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
@when_not('wireguardvdu.installed')
def configuration_keygen():
    status_set('maintenance', 'Wireguard Key generation')

    private_key_path = "/etc/wireguard/privatekey"
    public_key_path = "/etc/wireguard/publickey"
    key_location = [private_key_path, public_key_path]

    log('Key Generation start')

    cmd = ['wg genkey | sudo tee {} | wg pubkey | sudo tee {}'.format(key_location[0], key_location[1])]
    result, err = charms.sshproxy._run(cmd)

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
    if config['wg_server']:
        set_flag('wireguardvdu.server.config')
    else:
        set_flag('wireguardvdu.client.config')


@when('config.loadkey')
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

    status_set('maintenance', 'Load Keys Done')
    set_flag('loadkeys.done')

    if config['wg_server']:
        set_flag('wireguardvdu.server.config')
    else:
        set_flag('wireguardvdu.client.config')


@when('wireguardvdu.server.config')
@when_not('wireguardvdu.installed')
def wireguard_server_configuration():
    status_set('maintenance', 'Server wireguard configuration started')

    filename = "/etc/wireguard/privatekey"
    cmd = ['sudo cat {}'.format(filename)]
    key, err = charms.sshproxy._run(cmd)
    if not valid_command(cmd, err, 'config.keygen'):
        clear_flag('wireguardvdu.server.config')
        return

    conf = "/etc/wireguard/" + config['forward_interface'] + ".conf"

    wg_conf = "[Interface]\nAddress = " + config['server_tunnel_address'] + \
              "\nSaveConfig = " + str(config['save_config']) + \
              "\nListenPort = " + str(config['listen_port']) + \
              "\nPrivateKey = " + key + \
              "\nPostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o " + \
              config['forward_interface'] + \
              " -j MASQUERADE" + \
              "\nPostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o " + \
              config['forward_interface'] + " -j MASQUERADE"
    log(wg_conf)

    cmd = ['echo "{}" |sudo tee {}'.format(wg_conf, conf)]
    result, err = charms.sshproxy._run(cmd)

    if not valid_command(cmd, err, 'wireguard.server.config.failed'):
        return
    log(result)
    set_flag('wireguard.start')


@when('wireguardvdu.client.config')
@when_not('wireguardvdu.installed')
def wireguard_client_configuration():
    status_set('maintenance', 'Client wireguard configuration started')

    key_location = ["/etc/wireguard/privatekey", "/etc/wireguard/publickey"]
    keys = []
    for x in key_location:
        cmd = ['sudo cat {}'.format(x)]
        result, err = ssh_command(cmd)
        if not valid_command(cmd, err, 'wireguard.client.config.failed'):
            break
        keys.append(x)
    [clientprivatekey, serverpubkey] = keys

    conf = "/etc/wireguard/" + config['forward_interface'] + ".conf"
    wg_conf = "[Interface]\nPrivateKey= " + clientprivatekey + \
              "\nAddress = " + config['client_tunnel_address'] + \
              "\nListenPort = " + str(config['listen_port']) + \
              "\n\n[Peer]\nPublicKey= " + serverpubkey + \
              "\nEndpoint = " + config['server_public_address'].split('/')[0] + ":" + str(config['listen_port']) + \
              "\nAllowedIPs = 0.0.0.0/0"
    log(wg_conf)

    cmd = ['echo "{}" |sudo tee {}'.format(wg_conf, conf)]
    result, err = charms.sshproxy._run(cmd)
    if not valid_command(cmd, err, 'wireguard.client.config.failed'):
        return

    log(result)
    set_flag('wireguard.start')


@when('wireguard.start')
@when_not('wireguardvdu.installed')
def start_wireguard():
    if not config['wg_server']:
        status_set('active', 'Wireguard Client installed and configured')
        set_flag('wireguardvdu.installed')
    else:
        status_set('maintenance', 'Wireguard quick start')

        forward_interface = config['forward_interface']

        cmd = ['sudo wg-quick up {}'.format(forward_interface)]
        result, err = ssh_command(cmd)
        if not valid_command(cmd, err, 'wireguard.server.start.failed'):
            return

        log("Wireguard interface up:\n" + result)

        cmd = ['sudo wg show {}'.format(config['forward_interface'])]
        result, err = ssh_command(cmd)
        if not valid_command(cmd, err, 'wireguard.server.config.failed'):
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
    result, err = charms.sshproxy._run(cmd)
    if not valid_command(cmd, err, 'action.touch.failed'):
        action_fail('command failed:' + err)
        return

    action_set({'output': result, "errors": err})
    clear_flag('actions.touch')

##############


@when('actions.confclient')
@when('wireguardvdu.client.config')
@when('wireguardvdu.installed')
def configure_client():
    status_set('maintenance', 'Client wireguard configuration started')

    filename = "/etc/wireguard/privatekey"
    cmd = ['sudo cat {}'.format(filename)]
    result, err = ssh_command(cmd)
    if not valid_command(cmd, err, 'action.touch.failed'):
        action_fail('command failed:' + err)
        return

    log('command failed:' + err)
    clientprivatekey = result

    serverpubkey = action_get('server_public_key')
    server_public_address = action_get('server_public_address')
    log(type(serverpubkey))
    log(type(server_public_address))
    log(server_public_address.split('/')[0])

    conf = "/etc/wireguard/" + config['forward_interface'] + ".conf"

    wg_conf = "[Interface]\nPrivateKey= " + clientprivatekey + \
              "\nAddress = " + config['client_tunnel_address'] + \
              "\nListenPort = " + str(config['listen_port']) + \
              "\n\n[Peer]\nPublicKey= " + serverpubkey + \
              "\nEndpoint = " + server_public_address.split('/')[0] + ":" + str(config['listen_port']) + \
              "\nAllowedIPs = 0.0.0.0/0"

    log(wg_conf)

    cmd = ['echo "{}" |sudo tee {}'.format(wg_conf, conf)]
    result, err = ssh_command(cmd)
    if not valid_command(cmd, err, 'action.touch.failed'):
        action_fail('command failed:' + err)
        return

    action_set({'output': result, "errors": err})

    set_flag('tunnel.configured')
    clear_flag('actions.confclient')


####

@when('actions.connserver')
@when('tunnel.configured')
@when('wireguardvdu.installed')
def connect_server():
    if not action_get('confirmation'):
        action_fail('Command failed; Confirmation needed')
    else:
        status_set('maintenance', 'Wireguard client quick start')

        cmd = ['sudo wg-quick up {}'.format(config['forward_interface'])]
        result, err = ssh_command(cmd)
        if not valid_command(cmd, err, 'wireguard.server.start.failed'):
            action_fail('command failed:' + err)
            return

        action_set({'output': result, "errors": err})
        log("Wireguard interface up:\n" + result)

        cmd = ['sudo wg show {}'.format(config['forward_interface'])]
        result, err = ssh_command(cmd)
        if not valid_command(cmd, err, 'wireguard.server.start.failed'):
            action_fail('command failed:' + err)
            return

        action_set({'output': result, "errors": err})
        clear_flag('actions.connserver')
        log("Wireguard config:\n" + result)

        status_set('active', 'Wireguard installed and configured')
        status_set('active', 'Tunnel Ready!')


@when('actions.addpeer')
@when('wireguardvdu.server.config')
@when('wireguardvdu.installed')
def addpeer():
    endpoint = action_get('endpoint')
    client_public_key = action_get('client_public_key')

    conf = "/etc/wireguard/" + config['forward_interface'] + ".conf"
    wgconf = "\n\n[Peer]\nPublicKey= " + client_public_key + \
             "\nEndpoint = " + endpoint + ":" + str(config['listen_port']) + \
             "\nAllowedIPs = 10.0.0.2/32"
    cmd = ['echo {} |sudo tee -a {}'.format(wgconf, conf)]

    result, err = ssh_command(cmd)
    if not valid_command(cmd, err, 'wireguard.server.start.failed'):
        action_fail('command failed:' + err)
        return

    log(result)

    cmd = ['sudo wg-quick down {} && sudo wg-quick up {}'.format(config['forward_interface'],
                                                                 config['forward_interface'])]
    result, err = ssh_command(cmd)
    if not valid_command(cmd, err, 'wireguard.server.start.failed'):
        action_fail('command failed:' + err)
        return

    action_set({'output': result, "errors": err})
    log(result)
    clear_flag('actions.addpeer')
