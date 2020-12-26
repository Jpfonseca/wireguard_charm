import glob
import subprocess as sp
#from charms import apt
from charms.reactive import (
    hook,
    clear_flag,
    when,
    when_not,
    set_flag
)

import charms.sshproxy
from charmhelpers.core import hookenv
from charmhelpers.core.hookenv import (
    application_version_set,
    config,
    log,
    status_set,
    action_get,
    action_fail,
    action_set
)
from charmhelpers.fetch import get_upstream_version

config=config()

#@when('sshproxy.configured')
#@when_not('wireguardvdu.installed')
#def install_packages():
#    err = ''
#    status_set('active', 'Ready!')
#    try:
#        filename="/tmp/test0"
#        cmd = ['touch {}'.format(filename)]
#        result, err = charms.sshproxy._run(cmd)
#    except:
#        log('command failed:' + err)
#    else:
#        set_flag('wireguardvdu.installed')
        

@when('sshproxy.configured')
@when_not('wireguardvdu.installed')
def install_packages():
    status_set('maintenance', 'Installing wireguard')
    result=err = ''
    try:
        package="wireguard"
        cmd = ['sudo apt update']
        result, err = charms.sshproxy._run(cmd)
        log("updated packages")
        cmd = ['sudo apt install {} -y'.format(package)]
        result, err = charms.sshproxy._run(cmd)
    except:
        log('command failed:' + err)
    else:
        set_flag('wireguardvdu.apt.not_installed')
    finally:
        set_flag('wireguardvdu.apt.installed')
        status_set('maintenance', 'Package Wireguard Installed')

@when('wireguardvdu.apt.installed')
@when_not('wireguardvdu.installed')
def wireguard_version_check():
    log('setting application version')
    
    result=err = ''
    
    try: 
        cmd = ['wg --version']
        result, err = charms.sshproxy._run(cmd)
    except:
        log('command failed:' + err)
        log('wireguard not installed')
    finally:
        status_set('maintenance', result)
        
        files=glob.glob("files/*key")
        count=0

        if not config['wg_server']:
            set_flag('config.keygen')
        else:
            for x in files:
                with open(x) as f:
                    if f.read() is not None:
                        count+=1        
                f.close()
            if count==2:
                set_flag('config.keygen')
            else:
                set_flag('config.loadkey')

@when('config.keygen')
@when_not('wireguardvdu.installed')
def configuration_keygen():
    status_set('maintenance', 'Wireguard Key generation')
        
    private_key_path="/etc/wireguard/privatekey"
    public_key_path="/etc/wireguard/publickey"
    key_location=[private_key_path,public_key_path]
 
    log('Key Generation start')
    result=err = ''
    
    try:
        
        cmd = ['wg genkey | sudo tee {} | wg pubkey | sudo tee {}'.format(key_location[0],key_location[1])]
        result, err = charms.sshproxy._run(cmd)
    except:
        log('command failed:' + err)
    else:
        set_flag('keygen.failed')
    finally:
        set_flag('keygen.done')
        status_set('maintenance', 'Keygen Done')
    
        status_set('maintenance',result)
    
    for x in key_location:
        result=err = ''
        try:
            cmd = ['sudo cat {}'.format(x)]
            result, err = charms.sshproxy._run(cmd)
        except:
            log('command failed:' + err)
            log('cat '+x+' failed')
        else:
            set_flag('keygen.failed')
        finally:
            log(x+":"+result);
        
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

    private_key_path="/etc/wireguard/privatekey"
    public_key_path="/etc/wireguard/publickey"
    key_location=[private_key_path,public_key_path]
    
    for x in key_location:
        key=""
        y="files/"+x.lstrip('/etc/wireguard/')
        
        with open(y,'r') as f:
            key=f.read()
        f.close()
        result=err = ''
        try:
            cmd = ['echo {} |sudo tee {}'.format(key,x)]
            result, err = charms.sshproxy._run(cmd)
        except:
            log('command failed:' + err)
        else:
            set_flag('wireguardvdu.load.keys.failed')
        finally:
            key=result
    status_set('maintenance', 'Load Keys')
    set_flag('wireguardvdu.server.config')

@when('wireguardvdu.server.config')
@when_not('wireguardvdu.installed')
def wireguard_server_configuration():
    status_set('maintenance', 'Server wireguard configuration started')
    text="example"
    result=err = ''
    try:
        filename="/etc/wireguard/privatekey"
        cmd = ['sudo cat {}'.format(filename)]
        result, err = charms.sshproxy._run(cmd)
    except:
        log('command failed:' + err)
    else:
        set_flag('wireguardvdu.load.keys.failed')
    finally:
        key=result
  
    conf="/etc/wireguard/"+config['forward_interface']+".conf"

    wg_conf="[Interface]\nAddress = "+config['server_tunnel_address']+"\nSaveConfig = "+str(config['save_config'])+"\nListenPort = "+str(config['listen_port'])+"\nPrivateKey = "+key+"\nPostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o "+config['forward_interface']+" -j MASQUERADE"+"\nPostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o "+config['forward_interface']+" -j MASQUERADE"
    log(wg_conf)

    result=err = ''
    try:
        cmd = ['echo "{}" |sudo tee {}'.format(wg_conf,conf)]
        result, err = charms.sshproxy._run(cmd)
    except:
        log('command failed:' + err)
    else:
        set_flag('wireguard.server.config.failed')
    finally:
        log(result)
        set_flag('wireguard.start')
    

@when('wireguardvdu.client.config')
@when_not('wireguardvdu.installed')
def wireguard_client_configuration():
    status_set('maintenance', 'Client wireguard configuration started')
    
    result=err = ''
    try:
        filename="/etc/wireguard/privatekey"
        cmd = ['sudo cat {}'.format(filename)]
        result, err = charms.sshproxy._run(cmd)
    except:
        log('command failed:' + err)
    else:
        set_flag('wireguardvdu.load.keys.failed')
    finally:
        clientprivatekey=result
    
    with open("files/privatekey",'r') as f:
        serverkey=f.read()
    f.close()
    
    with open("files/publickey",'r') as f:
        serverpubkey=f.read()
    f.close()
    
    conf="/etc/wireguard/"+config['forward_interface']+".conf"

    wg_conf="[Interface]\nPrivateKey= "+clientprivatekey+"\nAddress = "+config['client_tunnel_address']+"\n\n[Peer]\nPublicKey= "+serverpubkey+"\nEndpoint = "+config['server_public_address'].split('/')[0]+":"+str(config['listen_port'])+"\nAllowedIPs = 0.0.0.0/0"
    

    log(wg_conf)

    result=err = ''
    try:
        cmd = ['echo "{}" |sudo tee {}'.format(wg_conf,conf)]
        result, err = charms.sshproxy._run(cmd)
    except:
        log('command failed:' + err)
    else:
        set_flag('wireguard.server.config.failed')
    finally:
        log(result)
        set_flag('wireguard.start')

@when('wireguard.start')
@when_not('wireguardvdu.installed')
def start_wireguard():
    if not config['wg_server']:
        status_set('active','Wireguard Client installed and configured')
        set_flag('wireguardvdu.installed')

    else:
        status_set('maintenance','Wireguard quick start')
        result=err = ''
        try:
            forward_interface=config['forward_interface']
            
            cmd = ['sudo wg-quick up {}'.format(forward_interface)]
            result, err = charms.sshproxy._run(cmd)
        except:
            log('command failed:' + err)
        else:
            set_flag('wireguard.server.start.failed')
        finally:
            log(result)

        log("Wireguard interface up:\n"+result)
       
        result=err = ''
        try:
            cmd = ['sudo wg show {}'.format(config['forward_interface'])]
            result, err = charms.sshproxy._run(cmd)
        except:
            log('command failed:' + err)
        else:
            set_flag('wireguard.server.config.failed')
        finally:
            log(result)
        
        log("Wireguard config:\n"+result)
        status_set('active','Wireguard installed and configured')
        set_flag('wireguardvdu.installed')
        status_set('active', 'Ready!')
@when('actions.touch')
@when('wireguardvdu.installed')
def touch():
    result=err = ''
    try:
        filename = action_get('filename')
        cmd = ['touch {}'.format(filename)]
        result, err = charms.sshproxy._run(cmd)
    except:
        action_fail('command failed:' + err)
    else:
        action_set({'output': result, "errors": err})
    finally:
        clear_flag('actions.touch')


