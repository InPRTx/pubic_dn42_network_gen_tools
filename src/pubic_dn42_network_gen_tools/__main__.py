import argparse
import asyncio
import copy
import ipaddress
import json
import logging
import os
import re
import time
import tomllib
from enum import Enum
from typing import Optional, List, Dict, Union

import pycountry
from pydantic import BaseModel, constr, IPvAnyAddress, conint, Field

is_develop = os.path.exists('./is_develop.txt')
is_host_mode = os.path.exists('./is_host_mode.txt')
is_debug_mode = os.path.exists('./is_debug_mode.txt')
if is_debug_mode:
    logging.basicConfig(level=logging.DEBUG)
else:
    logging.basicConfig(level=logging.INFO)
try:
    __a = re.match(r'^(.*)-(.*)-as(.*)-inprtx$', os.uname().nodename)
    node_name = __a.group(1) + __a.group(2)
except AttributeError:  # 不是我的命名方式或者，为win开发模式
    node_name = open('self_node_name.txt').read().strip()
develop_lxc_device_show_result = """root:
  path: /
  pool: pub-ibgp
  type: disk
ztaleisaz3:
  name: ztaleisaz3
  nictype: physical
  parent: ztaleisaz3
  type: nic
ztrfynox7p:
  name: ztrfynox7p
  nictype: physical
  parent: ztrfynox7p
  type: nic"""
develop_ping_result = """PING 1.1.1.1 (1.1.1.1) 56(84) bytes of data.
64 bytes from 1.1.1.1: icmp_seq=1 ttl=55 time=169 ms
64 bytes from 1.1.1.1: icmp_seq=2 ttl=55 time=169 ms
64 bytes from 1.1.1.1: icmp_seq=3 ttl=55 time=169 ms
64 bytes from 1.1.1.1: icmp_seq=5 ttl=55 time=168 ms
^C
--- 1.1.1.1 ping statistics ---
5 packets transmitted, 4 received, 20% packet loss, time 4078ms
rtt min/avg/max/mdev = 168.299/169.035/169.382/0.440 ms"""


async def run_command(command: str) -> tuple[int, bytes, bytes]:
    process = await asyncio.create_subprocess_shell(
        command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    logging.debug(f'执行了命令 {command}')
    stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=60)
    logging.debug(f'输出的结果为 {stdout}')
    return process.returncode, stdout, stderr


def run_commands(cmds: list[str]):
    for cmd in cmds:
        logging.info(f'执行{cmd}', )
        if is_develop:
            continue
        os.popen(cmd)
        if ('lxc config device add' in cmd or
                'lxc config device rm' in cmd or
                'wg-quick' in cmd):
            time.sleep(0.2)  # 休眠0.2秒，防止lxc设备未创建完成


def host_mode_command(command: str) -> str:
    return command if is_host_mode else f'lxc exec pub-ibgp -- {command}'


def host_mode_file_path(file_path: str) -> str:
    return file_path if is_host_mode else f'/var/lib/lxd/containers/pub-ibgp/rootfs{file_path}'


def ipaddress_to_gre_fe80(ip_addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> ipaddress.IPv6Address:
    """
    ipv4/6  地址转gre fe80::
    :param ip_addr:
    :return:
    """
    if ip_addr.version == 4:
        return ipaddress.ip_address('fe80:' + "".join(
            f"{':' if i % 2 == 0 else ''}{int(b):02x}" for i, b in enumerate(ip_addr.exploded.split('.'))))
    else:
        return ipaddress.ip_address(
            'fe80:' + "".join(f":{b}" if b != "0000" else '' for b in ip_addr.exploded.split(':')[6:]))


class PingResult(BaseModel):
    min: float
    avg: float
    max: float
    mdev: float
    packet_loss: int = 100
    cost: int = 65535
    text: str = 'fail ping'
    full_text: Optional[str]
    interface_name: Optional[str] = None
    mtu: int = 1500

    def __init__(self, **data):
        if data.get('packet_loss') is None or int(data.get('packet_loss')) == 100:
            data['cost'] = 65535
            data['text'] = 'fail ping'
        else:
            packet_loss = int(data.get('packet_loss'))
            avg = int(float(data['avg']))

            data['cost'] = avg * 100 / (100 - packet_loss) * 10
            data['text'] = data.get('full_text').splitlines()[
                               -1] + f"loss/cost = {packet_loss}%/{data['cost']}"
        super().__init__(**data)


class WGPeer(BaseModel):
    public_key: constr(strip_whitespace=True, min_length=44, max_length=44)  # WireGuard 公钥长度通常是 44
    preshared_key: constr(strip_whitespace=True, min_length=44, max_length=44) = None  # 可选
    allowed_ips: list[IPvAnyAddress]
    endpoint: str = None  # 可选
    persistent_keepalive: conint(ge=0, le=65535) = None  # 可选
    name: Optional[str] = Field(description="这是 my_field 的描述。")
    mtu: int = 1500


class WGInterface(BaseModel):
    private_key: constr(strip_whitespace=True, min_length=44, max_length=44)  # WireGuard 私钥长度通常是 44
    address: list[IPvAnyAddress]
    listen_port: conint(ge=0, le=65535) = None  # 可选
    mtu: conint(ge=68, le=2800) = 2800  # 可选


# 定义 WireGuard 配置
class WireGuardConfig(BaseModel):
    interface: WGInterface
    peers: list[WGPeer]
    name: Optional[str]
    middle_char: str


class WGNetworkTypeEnum(Enum):
    pub_v4: str = 'pub_v4'
    pub_v6: str = 'pub_v6'


class WGNetwork(BaseModel):
    port: int
    mode: WGNetworkTypeEnum
    member: List


class BirdIPAddressOtherSubnet:
    def __init__(self):
        self.other_subnet = []
        self.other_subnet_bird_static_reject_str = ''

    def add_new_other_subnet(self, address_str: str) -> None:
        a = ipaddress.ip_network(address_str, strict=False)
        self.other_subnet.append(a)
        self.other_subnet_bird_static_reject_str += f'\n    route {a.compressed} reject;'


class BirdIPAddress(BaseModel):
    address: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
    mask: int
    subnet: Union[ipaddress.IPv4Network, ipaddress.IPv6Network]  # 最大广播
    other_subnet: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]  # 其他应该广播的子网
    other_subnet_bird_static_reject_str: Optional[str]
    iid: Optional[str] = None

    def __init__(self, **data):
        address = ipaddress.ip_address(data['address'].split('/')[0])
        # 根据网络类型，直接定义好子网 IPv4/6 DN42/pub (32/32) (64/48)
        mask = 32 if address.version == 4 else 64 if address not in ipaddress.ip_network('2000::/3') else 48
        other_subnet = BirdIPAddressOtherSubnet()
        if mask == 32 and address in ipaddress.ip_network('100.64.0.192/27'):  # 公网段
            other_subnet.add_new_other_subnet(f"{address}/28")
        elif mask == 32 and address in ipaddress.ip_network('172.20.229.192/27'):  # 国际段
            other_subnet.add_new_other_subnet(f"{address}/27")
        elif mask == 32 and address in ipaddress.ip_network('172.23.173.160/28'):  # 中国段
            other_subnet.add_new_other_subnet(f"{address}/28")
        elif mask == 32 and address in ipaddress.ip_network('172.20.197.176/29'):  # anycast段将由BGP获取
            pass
        elif mask == 64 and address in ipaddress.ip_network('fdf4:56da:a360:f1c0::/60'):  # pub中国段
            other_subnet.add_new_other_subnet(f"{address}/60")
        elif mask == 64:
            other_subnet.add_new_other_subnet(f"{address}/63")
            other_subnet.add_new_other_subnet(f"{address}/60")
        elif mask == 48 and address in ipaddress.ip_network('2a13:a5c3:f1c0::/44'):  # pub中国段
            other_subnet.add_new_other_subnet(f"{address}/44")
            data['iid'] = address.compressed.split('::')[0].split('2a13:a5c3:')[-1]
        elif mask == 48:
            other_subnet.add_new_other_subnet(f"{address}/47")
            other_subnet.add_new_other_subnet(f"{address}/44")
            data['iid'] = address.compressed.split('::')[0].split('2a13:a5c3:')[-1]

        data['address'] = address
        data['mask'] = mask
        data['subnet'] = ipaddress.ip_network(f"{address}/{mask}", strict=False)
        data['other_subnet'] = other_subnet.other_subnet
        data['other_subnet_bird_static_reject_str'] = other_subnet.other_subnet_bird_static_reject_str
        super().__init__(**data)


class VpsInterface(BaseModel):
    if_name: str = 'eth0'
    ip_local: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
    ip_public: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
    gre_fe80: Union[ipaddress.IPv6Address]
    mtu: int = 1500

    def __init__(self, **data):
        ip_local: ipaddress.IPv4Address | ipaddress.IPv6Address = ipaddress.ip_address(data.get('ip'))
        if not data.get('ip_public'):
            data['ip_public'] = ip_local
        data['ip_local'] = ip_local
        data['gre_fe80'] = ipaddress_to_gre_fe80(ip_local)
        super().__init__(**data)


class Node(BaseModel):
    zt_id: str
    ipv4_dn42: BirdIPAddress
    ipv6_dn42: BirdIPAddress
    ipv4_pub: Optional[BirdIPAddress] = None
    ipv6_pub: BirdIPAddress
    interface: List[VpsInterface] = None
    region_code: int = 52
    county: str
    is_transit: bool = False
    is_send_tier1_large_net_to_ibgp: bool = False
    is_wire_tier1_large_net_to_kernel: bool = False
    is_rr_client: bool = False
    wg_pub: Optional[str] = None

    def __init__(self, **data):
        data['ipv4_dn42'] = BirdIPAddress(address=data['ipv4_dn42'])
        data['ipv6_dn42'] = BirdIPAddress(address=data['ipv6_dn42']) if data.get('ipv6_dn42') else None
        data['ipv4_pub'] = BirdIPAddress(address=data['ipv4']) if data.get('ipv4') else None
        data['ipv6_pub'] = BirdIPAddress(address=data['ipv6'])
        if data.get('is_transit'):
            data['ipv6_pub'].other_subnet_bird_static_reject_str += f'\n    route 2000::/3 reject;'
        super().__init__(**data)


class ConfigToml(BaseModel):
    ibgp_network: Dict[str, List]
    wg_network: Dict[str, WGNetwork]
    node: Dict[str, Node]


config = ConfigToml(**tomllib.loads(open('config.toml', 'r').read()))
node_node = config.node.get(node_name)

ping_result_fail = PingResult(min=300, avg=300, max=300, mdev=300, packet_loss=100, text='fail ping',
                              packet_loss_percentage=100)


class BirdHeadGen:
    def __init__(self):
        self.iso3166_code = pycountry.countries.get(alpha_2=node_node.county).numeric

    def gen_bird_head(self):
        a = f"""# This file is generated by bird_head_gen.py
define OWNIPv4 =  {node_node.ipv4_pub.address};
define OWNNET = {node_node.ipv4_pub.subnet};
define OWNIPv6 =  {node_node.ipv6_pub.address};
define OWNNETv6 = {node_node.ipv6_pub.subnet};

define OWN42IPv4 = {node_node.ipv4_dn42.address};
define OWN42IPv6 = {node_node.ipv6_dn42.address};
define OWN42NET = {node_node.ipv4_dn42.subnet};
define OWN42NETv6 = {node_node.ipv6_dn42.subnet};

define REGION = {node_node.region_code};
define COUNTY = {self.iso3166_code};
define COUNTY42 = 1{self.iso3166_code};
define FULL_TABLE = false; # 保留的抛弃参数
define IS_SEND_TIER1_LARGE_NET_TO_IBGP = {'true' if node_node.is_send_tier1_large_net_to_ibgp else 'false'};
define IS_WIRE_TIER1_LARGE_NET_TO_KERNEL = {'true' if node_node.is_wire_tier1_large_net_to_kernel else 'false'};
define IS_TRANSIT = {'true' if node_node.is_transit else 'false'};

router id OWN42IPv4;

protocol static {{
    ipv4;
    route OWNNET reject;{node_node.ipv4_pub.other_subnet_bird_static_reject_str}
    
    route OWN42NET reject;{node_node.ipv4_dn42.other_subnet_bird_static_reject_str}
}}

protocol static {{
    ipv6;
    route OWNNETv6 reject;{node_node.ipv6_pub.other_subnet_bird_static_reject_str}
    
    route OWN42NETv6 reject;{node_node.ipv6_dn42.other_subnet_bird_static_reject_str}
}}"""

        if is_develop:
            print(a)
        else:
            file_path = host_mode_file_path('/etc/bird/head.conf')
            open(file_path, 'w').write(a)
            logging.info(f'写入{file_path}完成')

    def gen_network_interface_d(self):
        dummy_dn42_str = f"""# This file is generated by bird_head_gen.py
auto dummydn42
iface dummydn42 inet6 manual
pre-up ip link del dummydn42 || true
pre-up ip link add dummydn42 type dummy || true
post-up ip addr add {node_node.ipv4_dn42.address}/32 dev dummydn42
post-up ip addr add {node_node.ipv6_dn42.address}/128 dev dummydn42"""
        dummy_pub_str = f"""# This file is generated by bird_head_gen.py
auto dummypub
iface dummypub inet6 manual
pre-up ip link del dummypub || true
pre-up ip link add dummypub type dummy || true
post-up ip addr add {node_node.ipv4_pub.address}/32 dev dummypub
post-up ip -6 addr add {node_node.ipv6_pub.address}/128 dev dummypub"""
        open(host_mode_file_path('/etc/network/interfaces.d/dummydn42'), 'w').write(dummy_dn42_str)
        open(host_mode_file_path('/etc/network/interfaces.d/dummypub'), 'w').write(dummy_pub_str)
        logging.info('写入/etc/network/interfaces.d/dummydn42完成')
        logging.info('写入/etc/network/interfaces.d/dummypub完成')

    def gen_network_netplan(self):
        with open(host_mode_file_path('/etc/netplan/01-dummy.yaml'), 'w') as f:
            f.write(f"""# This file is generated by bird_head_gen.py
network:
  version: 2
  renderer: networkd
  dummy-devices:
    dummydn42:
      addresses:
        - \"{node_node.ipv4_dn42.address}/32\"
        - \"{node_node.ipv6_dn42.address}/128\"
    dummypub:
      addresses:
        - \"{node_node.ipv4_pub.address}/32\"
        - \"{node_node.ipv6_pub.address}/128\"""")
            logging.info('写入/etc/netplan/01-dummy.yaml完成')
        os.chmod(host_mode_file_path('/etc/netplan/01-dummy.yaml'), 0o600)
        if not os.path.exists(host_mode_file_path('/etc/netplan/02-netcfg.yaml')):
            with open(host_mode_file_path('/etc/netplan/02-netcfg.yaml'), 'w') as f:
                f.write(f"""# This file is generated by bird_head_gen.py
network:
  version: 2
  renderer: networkd
  ethernets:
    eth0:
      dhcp4: false
      dhcp6: false
      accept-ra: false
      addresses:
        - \"fe80::21:2623:1/64\"""")
                logging.info('写入/etc/netplan/02-netcfg.yaml完成')
        os.chmod(host_mode_file_path('/etc/netplan/02-netcfg.yaml'), 0o600)
        if not os.path.exists(host_mode_file_path('/etc/netplan/10-ebgp.yaml')):
            with open(host_mode_file_path('/etc/netplan/10-ebgp.yaml'), 'w') as f:
                f.write(f"""# This file is generated by bird_head_gen.py
network:
  version: 2
  renderer: networkd""")
                logging.info('写入/etc/netplan/10-ebgp.yaml完成')
        os.chmod(host_mode_file_path('/etc/netplan/10-ebgp.yaml'), 0o600)

    def gen_network_iptables(self):
        open(host_mode_file_path('/etc/iptables/rules.v4'), 'w').write(f"""# This file is generated by bird_head_gen.py
*mangle
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
COMMIT
*nat
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s 172.20.197.176/29 -j SNAT --to-source {node_node.ipv4_dn42.address}
-A POSTROUTING -s 100.64.0.2/32 -j SNAT --to-source {node_node.ipv4_pub.address}
COMMIT""")

        open(host_mode_file_path('/etc/iptables/rules.v6'), 'w').write(f"""# This file is generated by bird_head_gen.py
*mangle
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
COMMIT
*nat
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s fdf4:56da:a360::/63 -j SNAT --to-source {node_node.ipv6_dn42.address}
-A POSTROUTING -s 2a13:a5c3:f100::/47 -j SNAT --to-source {node_node.ipv6_pub.address}
COMMIT""")


class NetWorkTools:
    def gen_host_gre_cmd2(self):
        host_devices = self.get_host_gre()
        lxc_devices = self.__get_lxc_device_show()
        host_cmd_runs = []
        for c in host_devices:
            if c in lxc_devices:
                continue
            host_cmd_runs.append(
                f"lxc config device add pub-ibgp {c} nic nictype=physical parent={c} name={c}")
            host_cmd_runs.append(
                f"lxc exec pub-ibgp -- ip link set {c} up")
        run_commands(host_cmd_runs)

    def remove_lxc_gre(self):
        lxc_devices = self.__get_lxc_device_show()
        host_cmd_runs = []
        for c in lxc_devices:
            if c[:5] not in ['grei4', 'grei6', 'greif']:
                continue
            host_cmd_runs.append(f"lxc config device rm pub-ibgp {c}")
        run_commands(host_cmd_runs)

    def gen_bird_ibgp(self):
        filenames = []
        for network_name, peers_name in config.ibgp_network.items():
            for peer_name in peers_name:
                if node_name not in peers_name or peer_name == node_name or peer_name in filenames:
                    continue
                bird_ibgp_conf = f"""# This file is generated by bird_head_gen.py
protocol bgp ibgp_{peer_name} from IBGP {{
    local as OWNAS;
    source address {config.node.get(node_name).ipv6_pub.address.compressed};
    neighbor {config.node.get(peer_name).ipv6_pub.address.compressed} as OWNAS;
}}"""
                filenames.append(peer_name)
                if not is_develop:
                    file_path = host_mode_file_path(f'/etc/bird/ibgps/{network_name}_{peer_name}.conf')
                    open(file_path, 'w').write(bird_ibgp_conf)
                    logging.info(f'写入{file_path}完成')

    def __get_lxc_device_show(self):
        result = []
        a = develop_lxc_device_show_result if is_develop else os.popen('lxc config device show pub-ibgp').read()
        for b in a.split('\n'):
            b1 = b.strip()
            if b != b1:
                continue
            b = b.replace(':', '')
            if b in ["root"]:
                continue
            result.append(b)
        return result

    def get_host_gre(self) -> list:
        result = []
        for b in json.loads(os.popen('ip -json addr show').read()):
            if b['link_type'] != 'gre6':
                continue
            if b['ifname'][:5] not in ['grei4', 'grei6', 'greif']:
                continue
            result.append(b['ifname'])
        return result


class NetWorkWG:
    def gen_wg_conf(self):
        for network_name, network_items in config.wg_network.items():
            if network_items.mode == WGNetworkTypeEnum.pub_v4:
                fd_network_prefix, wg_interface_name = 'fde7:5d84:20a6:f36a:4000::', 'wgi4'
            elif network_items.mode == WGNetworkTypeEnum.pub_v6:
                fd_network_prefix, wg_interface_name = 'fde7:5d84:20a6:f36a:6000::', 'wgi6'
            else:
                fd_network_prefix, wg_interface_name = 'fde7:5d84:20a6:f36a:f000::', 'wgif'
            private_key = open(
                '/etc/wireguard/privatekey').read().strip() if not is_develop else 'gEmWFlVLvPEwfB7fWWrlwC00xME0zA8yOdTrwtBZP24='
            wg_interface = WGInterface(private_key=private_key,
                                       address=[
                                           ipaddress.IPv6Address(
                                               fd_network_prefix + config.node.get(node_name).ipv6_pub.iid)],
                                       listen_port=network_items.port)
            wg_peers = []
            for wg_peer_node_name in network_items.member:
                node_interface = None
                for a in node_node.interface:
                    if (network_items.mode == WGNetworkTypeEnum.pub_v4 and a.ip_local.version == 4) or (
                            network_items.mode == WGNetworkTypeEnum.pub_v6 and a.ip_local.version == 6):
                        node_interface = a
                if node_name not in network_items.member or node_name == wg_peer_node_name:
                    continue
                node = config.node.get(wg_peer_node_name)
                for vps_interface in node.interface:
                    if (vps_interface.ip_local.version == 4 and network_items.mode != WGNetworkTypeEnum.pub_v4 or
                            vps_interface.ip_local.version == 6 and network_items.mode != WGNetworkTypeEnum.pub_v6):
                        continue
                    wg_peer_mtu = vps_interface.mtu if vps_interface.mtu < node_interface.mtu else node_interface.mtu  # 设置为双方最小协商的mtu
                    wg_peer_mtu = 1500 if 1500 < wg_peer_mtu else wg_peer_mtu  # 大于1500的mtu统一设置为1500
                    wg_peer_mtu = wg_peer_mtu - 112 if vps_interface.ip_local.version == 4 else wg_peer_mtu - 132 \
                        if wg_peer_mtu not in [1500, 9000] else 1500
                    wg_peers.append(WGPeer(public_key=node.wg_pub,
                                           allowed_ips=[
                                               ipaddress.IPv6Address(fd_network_prefix + node.ipv6_pub.iid)],
                                           endpoint=f"{vps_interface.ip_public}:{network_items.port}",
                                           name=wg_peer_node_name, mtu=wg_peer_mtu))
            wg_config = WireGuardConfig(interface=wg_interface, peers=wg_peers, name=wg_interface_name,
                                        middle_char=wg_interface_name[-1], )
            logging.info(f'写入 /etc/wireguard/{wg_interface_name}.conf 配置文件')

            if is_develop:
                print(self.generate_wg_conf(wg_config))
            else:
                open(f'/etc/wireguard/{wg_interface_name}.conf', 'w').write(self.generate_wg_conf(wg_config))
                run_commands([f'wg-quick down {wg_interface_name}||true',
                              f'wg-quick up {wg_interface_name}',
                              f'systemctl enable wg-qucik@{wg_interface_name}'])

    def generate_wg_conf(self, a: WireGuardConfig) -> str:
        # 生成 Interface 部分
        interface_conf = "[Interface]\n"
        if a.name:
            interface_conf += f"# {a.name}\n"
        interface_conf += f"PrivateKey = {a.interface.private_key}\n"
        interface_conf += f"Address = {a.interface.address[0].__str__()}/128\n"
        if a.interface.listen_port:
            interface_conf += f"ListenPort = {a.interface.listen_port}\n"
        interface_conf += f"MTU = {a.interface.mtu}\n"

        # 生成 Peer 部分
        peer_confs = ""
        for peer in a.peers:
            peer_conf = "\n[Peer]\n"
            if peer.name:
                peer_conf += f"# name {peer.name}\n"
            peer_conf += f'# {peer.name} host grei{a.middle_char}{peer.name} ping {peer.allowed_ips[0].__str__()} -M do -s {peer.mtu}\n'
            peer_conf += f'# {peer.name} lxc exec pub-ibgp -- ping fe80::{peer.allowed_ips[0].__str__().split(":")[-1]}%grei{a.middle_char}{peer.name} -c 3 -M do -s 16 -W 10\n'
            peer_conf += f"PublicKey = {peer.public_key}\n"
            if peer.preshared_key:
                peer_conf += f"PresharedKey = {peer.preshared_key}\n"
            peer_conf += f"AllowedIPs = {peer.allowed_ips[0].__str__()}/128\n"
            interface_conf += f'PostUp = ip tunnel add grei{a.middle_char}{peer.name} mode ip6gre local {a.interface.address[0].__str__()} remote {peer.allowed_ips[0].__str__()} ttl 30 || true\n'
            interface_conf += f'PostUp = ip link set dev grei{a.middle_char}{peer.name} mtu {peer.mtu} || true\n'
            interface_conf += f'PostUp = ip link set grei{a.middle_char}{peer.name} up || true\n'
            interface_conf += f'PostDown = ip link del grei{a.middle_char}{peer.name} || true\n'
            if peer.endpoint:
                peer_conf += f"Endpoint = {peer.endpoint}\n"
            if peer.persistent_keepalive:
                peer_conf += f"PersistentKeepalive = {peer.persistent_keepalive}\n"
            peer_confs += peer_conf
        return interface_conf + peer_confs


class NetworkOSPF:
    async def __get_ping_result(self, __test_ip: ipaddress.IPv4Address | ipaddress.IPv6Address, interface_name=None,
                                count=10, size=16, in_lxc=True) -> PingResult | None:
        if is_develop:
            stdout = develop_ping_result.encode()
        else:
            __test_ip2 = f'{__test_ip}%{interface_name}' if __test_ip in ipaddress.ip_network(
                "fe80::/64") else __test_ip
            if in_lxc:
                returncode, stdout, stderr = await run_command(
                    host_mode_command(f'ping -c {count} {__test_ip2} -M do -s {size} -W 10'))
            else:
                returncode, stdout, stderr = await run_command(
                    f'ping -c {count} {__test_ip2} -M do -s {size} -W 10')

        __ping_result = '\n'.join(line for line in stdout.decode().splitlines() if line.strip())  # 去除空行
        packet_loss_match = re.search(r'(\d+)% packet loss', __ping_result)
        if not packet_loss_match:
            return  # 如果没有匹配到，返回None
        packet_loss_percentage = int(packet_loss_match.group(1))
        if packet_loss_percentage == 100:
            return  # 如果丢包率100%，返回None
        __a = __ping_result.splitlines()[-1].split(' ')[-2].split('/')
        result = PingResult(min=__a[0], avg=__a[1], max=__a[2], mdev=__a[3], packet_loss=packet_loss_percentage,
                            interface_name=interface_name, full_text=__ping_result,
                            mtu=size + 48 if __test_ip.version == 6 else 28)
        return result

    async def ping_ip(self, __test_ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
                      interface_name=None) -> PingResult:
        # 最大尝试3次，如果ping失败，返回300ms
        result = copy.deepcopy(ping_result_fail)
        result.interface_name = interface_name
        if not await self.__get_ping_result(__test_ip, interface_name, 1):  # 当第一次ping无效时候，接下来不做测试
            logging.warning(f'测试 {__test_ip} None ping')
            return result
        result = await self.__get_ping_result(__test_ip, interface_name)
        logging.info(f'测试 {__test_ip} {interface_name} {result.text}')
        return result  # 如果超过10次，返回300ms

    async def ping_mtu(self, __test_ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
                       interface_name=None) -> PingResult:
        result = copy.deepcopy(ping_result_fail)
        result.interface_name = interface_name
        get_ping_result = await self.__get_ping_result(__test_ip, interface_name, 2, in_lxc=False)
        if get_ping_result and get_ping_result.cost != 100:
            test_mtus = [1504] + list(range(1320, 1280, -4))  # 1328
            for test_mtu in test_mtus:
                for_result = await self.__get_ping_result(__test_ip, interface_name, 2, test_mtu, in_lxc=False)
                if for_result and for_result.cost != 100:
                    for_result.mtu = test_mtu
                    return for_result
        return result

    async def __test_all_ip(self, __type='mdev') -> [PingResult, ]:
        files_to_check, lxc_pub_gre_list = [
            '/etc/network/interfaces.d/lxcpubgre',
            '/etc/network/interfaces.d/lxcpub2gre',
            '/etc/wireguard/wgi4.conf',
            '/etc/wireguard/wgi6.conf',
            '/etc/wireguard/wgif.conf'
        ], ''
        if is_develop:
            lxc_pub_gre_list = open('lxcpubgre.txt', 'r').read()
        else:
            for file_path in files_to_check:
                lxc_pub_gre_list += open(file_path, 'r').read() if os.path.exists(file_path) else ''
        if not lxc_pub_gre_list:
            logging.warning('测试延迟ping命令 /etc/network/interfaces.d/lxcpubgre 为空')
            logging.error('获取延迟失败')
            return
        test_ips = []
        for lxc_pub_gre in lxc_pub_gre_list.split('\n'):
            if __type == 'mdev':
                match_re = re.match('^# (.*) lxc exec pub-ibgp -- ping ([^ ]+)%([^ ]+)', lxc_pub_gre)
                if match_re:
                    address, interface_name = match_re.group(2), match_re.group(3)
                    test_ips.append((ipaddress.ip_address(address), interface_name))
            else:  # mtu
                match_re = re.match('^# (.*) host ([^ ]+) ping ([^ ]+) ', lxc_pub_gre)
                if match_re:
                    address, interface_name = match_re.group(3), match_re.group(2)
                    test_ips.append((ipaddress.ip_address(address), interface_name))
        logging.debug(f'测试以下ip{test_ips}')
        if __type == 'mdev':
            result = await asyncio.gather(
                *(self.ping_ip(fe80_address, interface_name) for fe80_address, interface_name in
                  test_ips))
        else:
            result = await asyncio.gather(
                *(self.ping_mtu(fe80_address, interface_name) for fe80_address, interface_name in
                  test_ips))
        return result

    def gen_mtu(self):
        ping_results: List[PingResult] = asyncio.run(self.__test_all_ip('mtu'))
        host_cmds = []
        for ping_result in ping_results:
            if ping_result.packet_loss == 100:
                continue
            host_cmds.append(
                host_mode_command(f'ip link set dev {ping_result.interface_name} mtu {ping_result.mtu - 4}'))
        run_commands(host_cmds)
        logging.info(f'设置了{len(host_cmds)}台主机')

    def gen_ospf_config(self, ospf_interface_str: str = ''):
        ping_results: List[PingResult] = asyncio.run(self.__test_all_ip('mdev'))
        for ping_result in ping_results:
            ospf_interface_str += f'\n        interface "{ping_result.interface_name}" {{type ptp; cost {ping_result.cost}; }}; # {ping_result.text}'
        ospf_config = f"""  # This file is generated by bird_head_gen.py
protocol ospf v3 aospf6 {{
    ipv6{{
        import filter{{
            if !is_self_net_v6() || !(net.len <= 48 || net.len=128) then reject;
            if (COUNTY ~ [156] && net ~ [2a13:a5c3:f1d0::/44+]) then reject;
            accept;
        }};
        export filter{{
            if !is_self_net_v6() || !(net.len <= 48 || net.len=128) then reject;
            if ((65535, 666) ~ bgp_community || bgp_large_community ~ [(OWNAS, 4, *), (OWNAS, 5, *)]) then reject; # 过滤掉黑洞和不可达
            accept;
        }};
    }};
    area 0 {{
        interface "dummypub";{ospf_interface_str}
    }};
}}"""
        file_path = host_mode_file_path('/etc/bird/conf/ospf.conf')
        if not is_develop:
            open(file_path, 'w').write(ospf_config)
        logging.info(f'写入{file_path}完成')


if __name__ == '__main__':
    if is_develop:
        logging.info('已开启开发模式')
    parser = argparse.ArgumentParser(description='Calculate cylinder volume')
    parser.add_argument("module", type=str,
                        choices=["gen_bird_head", 'gen_network_interface_d', "gen_netplan", "gen_bird_ibgp",
                                 "gen_iptables", "gen_wg", "gen_gre", "gen_mtu", "remove_gre", "gen_ospf_cost"])
    args = parser.parse_args()
    if args.module == 'gen_bird_head':
        bird_head_gen = BirdHeadGen()
        bird_head_gen.gen_bird_head()
    elif args.module == 'gen_network_interface_d':
        bird_head_gen = BirdHeadGen()
        bird_head_gen.gen_network_interface_d()
    elif args.module == 'gen_netplan':
        bird_head_gen = BirdHeadGen()
        bird_head_gen.gen_network_netplan()
    elif args.module == 'gen_iptables':
        bird_head_gen = BirdHeadGen()
        bird_head_gen.gen_network_iptables()
    elif args.module == 'gen_bird_ibgp':
        network_tools = NetWorkTools()
        network_tools.gen_bird_ibgp()
    elif args.module == 'gen_wg':
        network_wg = NetWorkWG()
        network_wg.gen_wg_conf()
    elif args.module == 'gen_gre':
        network_tools = NetWorkTools()
        network_tools.gen_host_gre_cmd2()
    elif args.module == 'gen_mtu':
        network_tools = NetworkOSPF()
        network_tools.gen_mtu()
    elif args.module == 'remove_gre':
        network_tools = NetWorkTools()
        network_tools.remove_lxc_gre()
    elif args.module == 'gen_ospf_cost':
        network_ospf = NetworkOSPF()
        network_ospf.gen_ospf_config()
    os.system(host_mode_command('birdc c')) if not is_develop else None  # 非开发模式直接birdc reload
