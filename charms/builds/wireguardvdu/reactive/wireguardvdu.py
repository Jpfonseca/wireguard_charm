from charms import apt
from charms.reactive import hook
from charms.reactive import when, when_not, set_flag

import glob
from charmhelpers.core import hookenv
from charmhelpers.core.hookenv import application_version_set, config, log, status_set
from charmhelpers.fetch import get_upstream_version
import subprocess as sp

config=config()

@when_not('apt.installed.wireguard')
def install_packages():
    apt.queue_install('wireguard')
    status_set('active', 'Package Wireguard Installed')

@when('apt.installed.wireguard')
def wireguard_version_check():
    log('setting application version')
    application_version_set(get_upstream_version('wireguard'))
    
    message =sp.check_output(["wg","--version"], stderr=sp.STDOUT)
    status_set('maintenance', message)
    
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
def configuration_keygen():
    status_set('maintenance', 'Wireguard Key generation')
        
    private_key_path="/etc/wireguard/privatekey"
    public_key_path="/etc/wireguard/publickey"
    key_location=[private_key_path,public_key_path]
 
    log('Key Generation start')
    
    cmd="wg genkey | tee "+key_location[0]+" | wg pubkey | tee "+key_location[1]
    gen=sp.check_output(cmd,shell=True, stderr=sp.STDOUT)

    status_set('maintenance',gen)
    for x in key_location:
        with open(x,'r')as f:
            log(x+":"+f.read());
        f.close()
    log("Key Generation done")
    if config['wg_server']:
        set_flag('wireguardvdu.server.config')
    else:
        set_flag('wireguardvdu.client.config')

@when('config.loadkey')
def configuration_loadkey():
    status_set('maintenance', 'Wireguard Load Keys')

    private_key_path="/etc/wireguard/privatekey"
    public_key_path="/etc/wireguard/publickey"
    key_location=[private_key_path,public_key_path]
    
    
    for x in key_location:
        key=""
        y="files/"+x.lstrip('/etc/wireguard/')
        
        with open(y,'r')as f:
            key=f.read()
        f.close()
        with open(x,'w') as f:
            f.write(key)
        f.close()

    status_set('maintenance', 'Load Keys')
    set_flag('wireguardvdu.server.config')

@when('wireguardvdu.server.config')
def wireguard_server_configuration():
    status_set('maintenance', 'Server wireguard configuration started')
    text="example"
    with open("/etc/wireguard/privatekey",'r') as f:
        key=f.read()
    f.close()
    
    conf="/etc/wireguard/"+config['forward_interface']+".conf"

    wg_conf="[Interface]\nAddress = "+config['server_address']+"\nSaveConfig = "+str(config['save_config'])+"\nListenPort = "+str(config['listen_port'])+"\nPrivateKey = "+key+"PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o "+config['forward_interface']+" -j MASQUERADE"+"\nPostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o "+config['forward_interface']+" -j MASQUERADE"

    log(wg_conf)
    with open(conf,"w") as f:
        f.write(wg_conf)
    f.close()

@when('wireguardvdu.client.config')
def wireguard_server_configuration():
    status_set('maintenance', 'Client wireguard configuration started')
    with open("files/privatekey",'r') as f:
        serverkey=f.read()
    f.close()
    
    with open("files/publickey",'r') as f:
        serverpubkey=f.read()
    f.close()
    
    conf="/etc/wireguard/"+config['forward_interface']+".conf"

    wg_conf="[Interface]\nPrivateKey="+key+"Address = "+config['client_address']+"\n\n[Peer]\nPublicKey= "+serverpubkey+"Endpoint = "+config['server_address'].split('/')[0]+":"+config['listen_port']+"\nAllowedIPs = 0.0.0.0/0"

    log(wg_conf)
    with open(conf,"w") as f:
        f.write(wg_conf)
    f.close()

@hook('start')
def start_wireguard():
    status_set('maintenance','Wireguard quik start')

    cmd="wg-quick up "+config['forward_interface']
    gen=sp.check_output(cmd,shell=True, stderr=sp.STDOUT)

    log("Wireguard interface up:\n"+gen.decode("utf-8"))
    
    cmd="wg show "+config['forward_interface']
    gen=sp.check_output(cmd,shell=True, stderr=sp.STDOUT)
    log("Wireguard config:\n"+gen.decode("utf-8"))
    
    status_set('active','Wireguard installed and configured')
    set_flag('wireguardvdu.installed')
