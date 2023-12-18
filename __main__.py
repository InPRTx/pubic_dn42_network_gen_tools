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
from typing import Optional, List, Union

import pycountry
from pydantic import BaseModel, constr, IPvAnyAddress, conint

logging.basicConfig(level=logging.INFO)
is_develop = os.path.exists('./is_develop.txt')
is_host_mode = os.path.exists('./is_host_mode.txt')
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


async def run_command(command) -> tuple[int, bytes, bytes]:
    process = await asyncio.create_subprocess_shell(
        command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    stdout, stderr = await process.communicate()
    return process.returncode, stdout, stderr


def host_mode_command(command: str) -> str:
    if is_host_mode:
        return command
    else:
        return f'lxc exec pub-ibgp -- {command}'


def host_mode_file_path(file_path: str) -> str:
    if is_host_mode:
        return file_path
    else:
        return f'/var/lib/lxd/containers/pub-ibgp/rootfs{file_path}'


def ipaddress_to_gre_fe80(ip_addr: str):
    a = ipaddress.ip_address(ip_addr)
    c = "fe80:"
    if a.version == 4:
        for i, b in enumerate(a.__str__().split('.')):
            if i % 2 == 0:
                c += ":"
            c += '{:02x}'.format(int(b))
    else:
        for i, b in enumerate(a.exploded.__str__().split(':')):
            if i in [6, 7] and b:
                d = f":{b}"
                if d == ":0000":
                    continue
                c += d.replace(":000", ":").replace(":00", ":").replace(":0", ":")
    return c


class BirdIPAddress(BaseModel):
    address: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
    mask: int
    subnet: Union[ipaddress.IPv4Network, ipaddress.IPv6Network]  # 最大广播
    other_subnet: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]  # 其他应该广播的子网
    other_subnet_bird_static_reject_str: Optional[str]
    suffix: Optional[str] = None

    def __init__(self, **data):
        address = ipaddress.ip_address(data['address'].split('/')[0])
        # 根据网络类型，直接定义好子网
        if address.version == 4:  # DN42 IPv4
            mask = 32
        elif address not in ipaddress.ip_network('2000::/3'):
            mask = 64  # DN42 IPv6
        else:
            mask = 48  # 公网 IPv4

        other_subnet = []
        other_subnet_bird_static_reject_str = ""
        if mask == 32 and address in ipaddress.ip_network('23.146.72.192/27'):  # 公网段
            other_subnet.append(ipaddress.ip_network(f"{address}/28", strict=False))
            other_subnet_bird_static_reject_str += f'\n    route {other_subnet[-1].compressed} reject;'
        elif mask == 32 and address in ipaddress.ip_network('172.20.229.192/27'):  # 国际段
            other_subnet.append(ipaddress.ip_network(f"{address}/31", strict=False))
            other_subnet.append(ipaddress.ip_network(f"{address}/27", strict=False))
            other_subnet_bird_static_reject_str += f'\n    route {other_subnet[-2].compressed} reject;'
            other_subnet_bird_static_reject_str += f'\n    route {other_subnet[-1].compressed} reject;'
        elif mask == 32 and address in ipaddress.ip_network('172.23.173.160/28'):  # 中国段
            other_subnet.append(ipaddress.ip_network(f"{address}/28", strict=False))
            other_subnet_bird_static_reject_str += f'\n    route {other_subnet[-1].compressed} reject;'
        elif mask == 32 and address in ipaddress.ip_network('172.20.197.176/29'):  # anycast段将由BGP获取
            pass
        elif mask == 64 and address in ipaddress.ip_network('fdf4:56da:a360:42d0::/60'):  # pub中国段
            other_subnet.append(ipaddress.ip_network(f"{address}/60", strict=False))
            other_subnet_bird_static_reject_str += f'\n    route {other_subnet[-1].compressed} reject;'
        elif mask == 64:
            other_subnet.append(ipaddress.ip_network(f"{address}/63", strict=False))
            other_subnet.append(ipaddress.ip_network(f"{address}/60", strict=False))
            other_subnet_bird_static_reject_str += f'\n    route {other_subnet[-2].compressed} reject;'
            other_subnet_bird_static_reject_str += f'\n    route {other_subnet[-1].compressed} reject;'
        elif mask == 48 and address in ipaddress.ip_network('2a13:b487:42d0::/44'):  # pub中国段
            other_subnet.append(ipaddress.ip_network(f"{address}/44", strict=False))
            other_subnet_bird_static_reject_str += f'\n    route {other_subnet[-1].compressed} reject;'
            data['suffix'] = address.compressed.split('::')[0].split('2a13:b487:')[-1]
        elif mask == 48:
            other_subnet.append(ipaddress.ip_network(f"{address}/47", strict=False))
            other_subnet.append(ipaddress.ip_network(f"{address}/44", strict=False))
            other_subnet_bird_static_reject_str += f'\n    route {other_subnet[-2].compressed} reject;'
            other_subnet_bird_static_reject_str += f'\n    route {other_subnet[-1].compressed} reject;'
            data['suffix'] = address.compressed.split('::')[0].split('2a13:b487:')[-1]

        data['address'] = address
        data['mask'] = mask
        data['subnet'] = ipaddress.ip_network(f"{address}/{mask}", strict=False)
        data['other_subnet'] = other_subnet
        data['other_subnet_bird_static_reject_str'] = other_subnet_bird_static_reject_str
        super().__init__(**data)


class VpsInterface(BaseModel):
    if_name: str = 'eth0'
    ip_version: int = 4
    ip_local: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
    ip_public: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
    gre_fe80: Union[ipaddress.IPv6Address]
    mtu: int = 1500

    def __init__(self, **data):
        if 'ip_public' not in data and 'ip_local' in data:
            data['ip_public'] = data['ip_local']
        ip_public: ipaddress.IPv4Address | ipaddress.IPv6Address = data['ip_local']
        data['ip_version'] = ip_public.version
        data['gre_fe80'] = ipaddress_to_gre_fe80(data['ip_local'])
        super().__init__(**data)


class BirdHeadConfig(BaseModel):
    zt_id: str
    asn: int
    ipv4_dn42: BirdIPAddress
    ipv6_dn42: BirdIPAddress
    ipv4_pub: BirdIPAddress = None
    ipv6_pub: BirdIPAddress
    vps_interface: List[VpsInterface]
    region_code: int = 52
    county: str
    is_transit: bool = False
    is_send_tier1_large_net_to_ibgp: bool = False
    is_wire_tier1_large_net_to_kernel: bool = False
    wg_pub: Optional[str] = None


class PingResult(BaseModel):
    min: float
    avg: float
    max: float
    mdev: float
    packet_loss: int
    cost: int = 65535
    text: str = ''
    interface_name: Optional[str] = None


class WGPeer(BaseModel):
    public_key: constr(strip_whitespace=True, min_length=44, max_length=44)  # WireGuard 公钥长度通常是 44
    preshared_key: constr(strip_whitespace=True, min_length=44, max_length=44) = None  # 可选
    allowed_ips: list[IPvAnyAddress]
    endpoint: str = None  # 可选
    persistent_keepalive: conint(ge=0, le=65535) = None  # 可选
    name: Optional[str] = None


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


class BirdHeadGen:
    def __init__(self, __node_name):
        self.config_toml = tomllib.loads(open('config.toml', 'r').read())
        self.node_name = __node_name
        node_keys = self.config_toml['node'][self.node_name]
        self.iso3166_code = pycountry.countries.get(alpha_2=node_keys['county']).numeric
        node_keys2 = copy.deepcopy(node_keys)
        del node_keys2['ipv4_dn42']
        del node_keys2['ipv6_dn42']
        del node_keys2['ipv6']
        if 'vps_ip' in node_keys2:
            del node_keys2['vps_ip']
        vps_interface = self.__class_vps_interface(node_keys)
        self.node_keys = BirdHeadConfig(ipv4_dn42=BirdIPAddress(address=node_keys['ipv4_dn42']),
                                        ipv6_dn42=BirdIPAddress(address=node_keys['ipv6_dn42']),
                                        ipv4_pub=BirdIPAddress(address=node_keys['ipv4']),
                                        ipv6_pub=BirdIPAddress(address=node_keys['ipv6']),
                                        vps_interface=vps_interface,
                                        # vps_ip=vps_ip,
                                        **node_keys2)
        if self.node_keys.is_transit:
            self.node_keys.ipv6_pub.other_subnet_bird_static_reject_str += f'\n    route 2000::/3 reject;'

    def __class_vps_interface(self, node_keys: dict) -> list[VpsInterface]:
        args = []
        interface_len = 0
        if 'vps_ip' not in node_keys:  # 针对采用zerotier组网机器
            return []
        for i, a in enumerate(node_keys['vps_ip']):
            args.append({})
            args[i]['ip_local'] = ipaddress.ip_address(a)
            interface_len += 1
        if 'vps_public_ip' in node_keys:
            for i, a in enumerate(node_keys['vps_public_ip']):
                if a:
                    args[i]['ip_public'] = ipaddress.ip_address(a)
        if 'vps_ifname' in node_keys:
            for i, a in enumerate(node_keys['vps_ifname']):
                if a:
                    args[i]['if_name'] = a
        if 'vps_mtu' in node_keys:
            for i, a in enumerate(node_keys['vps_mtu']):
                if a:
                    args[i]['mtu'] = a
        result = []
        for arg in args:
            result.append(VpsInterface(**arg))
        return result

    def gen_bird_head(self):
        a = f"""# This file is generated by bird_head_gen.py
define OWNIPv4 =  {self.node_keys.ipv4_pub.address};
define OWNNET = {self.node_keys.ipv4_pub.subnet};
define OWNIPv6 =  {self.node_keys.ipv6_pub.address};
define OWNNETv6 = {self.node_keys.ipv6_pub.subnet};

define OWN42IPv4 = {self.node_keys.ipv4_dn42.address};
define OWN42IPv6 = {self.node_keys.ipv6_dn42.address};
define OWN42NET = {self.node_keys.ipv4_dn42.subnet};
define OWN42NETv6 = {self.node_keys.ipv6_dn42.subnet};

define REGION = {self.node_keys.region_code};
define COUNTY = {self.iso3166_code};
define COUNTY42 = 1{self.iso3166_code};
define FULL_TABLE = false; # 保留的抛弃参数
define IS_SEND_TIER1_LARGE_NET_TO_IBGP = {'true' if self.node_keys.is_send_tier1_large_net_to_ibgp else 'false'};
define IS_WIRE_TIER1_LARGE_NET_TO_KERNEL = {'true' if self.node_keys.is_wire_tier1_large_net_to_kernel else 'false'};
define IS_TRANSIT = {'true' if self.node_keys.is_transit else 'false'};

router id OWN42IPv4;

protocol static {{
    ipv4;
    route OWNNET reject;{self.node_keys.ipv4_pub.other_subnet_bird_static_reject_str}
    
    route OWN42NET reject;{self.node_keys.ipv4_dn42.other_subnet_bird_static_reject_str}
}}

protocol static {{
    ipv6;
    route OWNNETv6 reject;{self.node_keys.ipv6_pub.other_subnet_bird_static_reject_str}
    
    route OWN42NETv6 reject;{self.node_keys.ipv6_dn42.other_subnet_bird_static_reject_str}
}}"""
        file_path = host_mode_file_path('/etc/bird/head.conf')
        if is_develop:
            print(a)
        else:
            open(file_path, 'w').write(a)

        logging.info(f'写入{file_path}完成')

    def gen_network_interface_d(self):
        dummy_dn42_str = f"""# This file is generated by bird_head_gen.py
auto dummydn42
iface dummydn42 inet6 manual
pre-up ip link del dummydn42 || true
pre-up ip link add dummydn42 type dummy || true
post-up ip addr add {self.node_keys.ipv4_dn42.address}/32 dev dummydn42
post-up ip addr add {self.node_keys.ipv6_dn42.address}/128 dev dummydn42"""
        dummy_pub_str = f"""# This file is generated by bird_head_gen.py
auto dummypub
iface dummypub inet6 manual
pre-up ip link del dummypub || true
pre-up ip link add dummypub type dummy || true
post-up ip addr add {self.node_keys.ipv4_pub.address}/32 dev dummypub
post-up ip -6 addr add {self.node_keys.ipv6_pub.address}/128 dev dummypub"""
        if is_host_mode:
            open('/etc/network/interfaces.d/dummydn42', 'w').write(dummy_dn42_str)
            open('/etc/network/interfaces.d/dummypub', 'w').write(dummy_pub_str)
        else:
            open('/var/lib/lxd/containers/pub-ibgp/rootfs/etc/network/interfaces.d/dummydn42', 'w').write(
                dummy_dn42_str)
            open('/var/lib/lxd/containers/pub-ibgp/rootfs/etc/network/interfaces.d/dummypub', 'w').write(dummy_pub_str)
        logging.info('写入/etc/network/interfaces.d/dummydn42完成')
        logging.info('写入/etc/network/interfaces.d/dummypub完成')


class NetWorkTools:
    def __init__(self, __node_name):
        self.config_toml = tomllib.loads(open('config.toml', 'r').read())
        self.node_name = __node_name

    def gen_host_create_gre_ip_cmd_yield(self, local_node: str, remote_node: str):
        local_bird_head_gen = BirdHeadGen(local_node)
        remote_bird_head_gen = BirdHeadGen(remote_node)
        local_eth_v4_i, local_eth_v6_i = '', ''
        for i, a in enumerate(local_bird_head_gen.node_keys.vps_interface):
            remote_eth_v4_i, remote_eth_v6_i = '', ''
            for i2, b in enumerate(remote_bird_head_gen.node_keys.vps_interface):
                if a.ip_version != b.ip_version:  # 如果ip版本不同，跳过
                    continue
                if a.mtu - 4 < 1400 or b.mtu - 4 < 1400:  # 如果mtu小于1400，跳过
                    continue
                if a.ip_version == 4:
                    gre_prefix = f'grei{local_eth_v4_i}4{remote_eth_v4_i}{remote_node}'
                else:
                    gre_prefix = f'grei{local_eth_v6_i}6{remote_eth_v6_i}{remote_node}'
                tunnel_mode = 'gre' if a.ip_version == 4 else 'ip6gre'
                yield a, b, gre_prefix, f"ip tunnel add {gre_prefix} mode {tunnel_mode} dev {a.if_name} local {a.ip_local} remote {b.ip_public} ttl 30"

                if a.ip_version == 4:
                    remote_eth_v4_i = remote_eth_v4_i + 1 if remote_eth_v4_i != '' else 1
                elif a.ip_version == 6:
                    remote_eth_v6_i = remote_eth_v6_i + 1 if remote_eth_v6_i != '' else 1
            # 直接对本地多接口加入计数
            if a.ip_version == 4:
                local_eth_v4_i = local_eth_v4_i + 1 if local_eth_v4_i != '' else 1
            elif a.ip_version == 6:
                local_eth_v6_i = local_eth_v6_i + 1 if local_eth_v6_i != '' else 1

    def gen_ifupdown_gre_ip_cmd(self, local_interface: VpsInterface, remote_interface: VpsInterface,
                                if_name: str, cmd: str, remote_node_name: str):
        ip_version_str = '' if local_interface.ip_version == 4 else 6
        a = f'# {remote_node_name} lxc exec pub-ibgp -- ping {remote_interface.gre_fe80}%{if_name} -c 3\n'
        a += f'auto {if_name}\n'
        a += f'iface {if_name} inet{ip_version_str} manual\n'
        a += f'   pre-up ip link del dev {if_name} || true\n'
        a += f'   pre-up {cmd}\n'
        a += f'   pre-up ip link set dev {if_name} mtu 1400\n'
        a += f'   up ip link set {if_name} up\n'
        a += f'   post-down ip link set {if_name} down\n'
        a += f'   post-down ip tunnel del {if_name}\n'
        a += f'\n'
        return a

    def exe_host_create_cmd(self, ifupdown_gre_ip_cmd: str):
        result = []
        for a in ifupdown_gre_ip_cmd.split('\n'):
            if '#' in a:  # 跳过包含注释
                continue
            if 'auto' in a:  # 跳过包含auto
                continue
            if 'iface' in a:  # 跳过包含iface
                continue
            if 'pre-down' in a:  # 跳过包含pre-down
                continue
            if 'post-down' in a:  # 跳过包含post-down
                continue
            if not a:
                continue
            result.append(a.replace('pre-up ', '').replace('up ', '').strip())
        return result

    def gen_host_gre_cmd(self):
        for network_name, peers_name in self.config_toml['gre_network'].items():
            if self.node_name not in peers_name:
                continue
            # ip_cmds = {}
            ifupdown_gre_conf = ""
            for peer_name in peers_name:
                if peer_name == self.node_name:
                    continue
                for a, b, c, d in self.gen_host_create_gre_ip_cmd_yield(self.node_name, peer_name):
                    ifupdown_gre_conf += self.gen_ifupdown_gre_ip_cmd(a, b, c, d, peer_name)
            if not is_develop:
                logging.info('写入/etc/network/interfaces.d/lxcpubgre完成')
                open('/etc/network/interfaces.d/lxcpubgre', 'w').write(ifupdown_gre_conf)
            logging.debug(ifupdown_gre_conf)
            lxc_devices = self.__get_lxc_device_show()
            for peer_name in peers_name:
                if peer_name == self.node_name:
                    continue
                for a, b, c, d in self.gen_host_create_gre_ip_cmd_yield(self.node_name, peer_name):
                    host_cmd_runs = self.exe_host_create_cmd(self.gen_ifupdown_gre_ip_cmd(a, b, c, d, peer_name))
                    if c in lxc_devices:  # 如果已经于lxc存在，跳过
                        continue
                    host_cmd_runs.append(
                        f"lxc config device add pub-ibgp {c} nic nictype=physical parent={c} name={c}")
                    host_cmd_runs.append(
                        f"lxc exec pub-ibgp -- ip link set {c} up")
                    if not is_develop:
                        for cmd in host_cmd_runs:
                            logging.info(f'执行{cmd}', )
                            os.popen(cmd)
                            time.sleep(0.2)  # 休眠0.2秒，防止lxc设备未创建完成

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
        if not is_develop:
            for cmd in host_cmd_runs:
                logging.info(f'执行{cmd}', )
                os.popen(cmd)
                time.sleep(0.2)  # 休眠0.2秒，防止lxc设备未创建完成

    def remove_lxc_gre(self):
        lxc_devices = self.__get_lxc_device_show()
        host_cmd_runs = []
        for c in lxc_devices:
            if c[:5] not in ['grei4', 'grei6', 'greif']:
                continue
            host_cmd_runs.append(
                f"lxc config device rm pub-ibgp {c}")
        if not is_develop:
            for cmd in host_cmd_runs:
                logging.info(f'执行{cmd}', )
                os.popen(cmd)
                time.sleep(0.2)  # 休眠0.2秒，防止lxc设备未创建完成

    def gen_bird_ibgp(self):
        filenames = []
        for network_name, peers_name in self.config_toml['ibgp_network'].items():
            for peer_name in peers_name:
                if self.node_name not in peers_name or peer_name == self.node_name or peer_name in filenames:
                    continue

                bird_ibgp_conf = f"""# This file is generated by bird_head_gen.py
protocol bgp ibgp_{peer_name} from IBGP {{
    local as OWNAS;
    source address {self.config_toml['node'][self.node_name]['ipv6'].split('/')[0]};
    neighbor {self.config_toml['node'][peer_name]['ipv6'].split('/')[0]} as OWNAS;
}}"""
                filenames.append(peer_name)
                if not is_develop:
                    file_path = host_mode_file_path(f'/etc/bird/ibgps/{network_name}_{peer_name}.conf')
                    open(file_path, 'w').write(bird_ibgp_conf)
                    logging.info(f'写入{file_path}完成')

    def __get_lxc_device_show(self):
        result = []
        if is_develop:
            a = develop_lxc_device_show_result
        else:
            a = os.popen('lxc config device show pub-ibgp').read()
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
        a = json.loads(os.popen('ip -json addr show').read())
        for b in a:
            if b['link_type'] != 'gre6':
                continue
            if b['ifname'][:5] not in ['grei4', 'grei6', 'greif']:
                continue
            result.append(b['ifname'])
        return result


class NetWorkWG:
    def __init__(self, __node_name):
        self.config_toml = tomllib.loads(open('config.toml', 'r').read())
        self.node_name = __node_name

    def gen_wg_conf(self):
        local_bird_head_gen = BirdHeadGen(self.node_name)
        for network_name, network_items in self.config_toml['wg_network'].items():
            if network_items['mode'] == 'pub_v4':
                fd_network_prefix = 'fde7:5d84:20a6:f36a:4000::'
                middle_char = '4'
                wg_file_name = 'wgi4.conf'
            elif network_items['mode'] == 'pub_v6':
                fd_network_prefix = 'fde7:5d84:20a6:f36a:6000::'
                middle_char = '6'
                wg_file_name = 'wgi6.conf'
            else:
                fd_network_prefix = 'fde7:5d84:20a6:f36a:f000::'
                middle_char = 'f'
                wg_file_name = 'wgif.conf'
            if is_develop:
                private_key = 'gEmWFlVLvPEwfB7fWWrlwC00xME0zA8yOdTrwtBZP24='
            else:
                private_key = open('/etc/wireguard/privatekey').read().split('\n')[0]
            wg_interface = WGInterface(private_key=private_key,
                                       address=[
                                           ipaddress.IPv6Address(
                                               fd_network_prefix + local_bird_head_gen.node_keys.ipv6_pub.suffix)],
                                       listen_port=network_items['port'])
            wg_peers = []
            for peer_name in network_items['member']:
                if self.node_name not in network_items['member'] or self.node_name == peer_name:
                    continue
                remote_bird_head_gen = BirdHeadGen(peer_name)
                for vps_interface in remote_bird_head_gen.node_keys.vps_interface:
                    if vps_interface.ip_version == 4 and network_items['mode'] != 'pub_v4':
                        continue
                    if vps_interface.ip_version == 6 and network_items['mode'] != 'pub_v6':
                        continue
                    wg_peers.append(WGPeer(public_key=remote_bird_head_gen.node_keys.wg_pub,
                                           allowed_ips=[
                                               ipaddress.IPv6Address(
                                                   fd_network_prefix + remote_bird_head_gen.node_keys.ipv6_pub.suffix)],
                                           endpoint=f"{vps_interface.ip_public}:{network_items['port']}",
                                           name=peer_name))
            wg_config = WireGuardConfig(interface=wg_interface, peers=wg_peers, name=wg_file_name.split('.')[0],
                                        middle_char=middle_char)
            logging.info(f'写入/etc/wireguard/wgi{middle_char}.conf配置文件')
            if is_develop:
                print(self.generate_wg_conf(wg_config))
            else:
                open(f'/etc/wireguard/wgi{middle_char}.conf', 'w').write(self.generate_wg_conf(wg_config))

    def generate_wg_conf(self, a: WireGuardConfig) -> str:
        # 生成 Interface 部分
        interface_conf = "[Interface]\n"
        if a.name:
            interface_conf += f"# {a.name}\n"
        interface_conf += f"PrivateKey = {a.interface.private_key}\n"
        interface_conf += f"Address = {a.interface.address[0].__str__()}/128\n"
        if a.interface.listen_port:
            interface_conf += f"ListenPort = {a.interface.listen_port}\n"
        if a.interface.mtu:
            interface_conf += f"MTU = {a.interface.mtu}\n"

        # 生成 Peer 部分
        peer_confs = ""
        for peer in a.peers:
            peer_conf = "\n[Peer]\n"
            if peer.name:
                peer_conf += f"# name {peer.name}\n"
            peer_conf += f'# ping6 {peer.allowed_ips[0].__str__()} -M do -s 2752\n'
            peer_conf += f'# {peer.name} lxc exec pub-ibgp -- ping fe80::{peer.allowed_ips[0].__str__().split(":")[-1]}%grei{a.middle_char}{peer.name} -c 3\n'
            peer_conf += f"PublicKey = {peer.public_key}\n"
            if peer.preshared_key:
                peer_conf += f"PresharedKey = {peer.preshared_key}\n"
            peer_conf += f"AllowedIPs = {peer.allowed_ips[0].__str__()}/128\n"
            interface_conf += f'PostUp = ip tunnel add grei{a.middle_char}{peer.name} mode ip6gre local {a.interface.address[0].__str__()} remote {peer.allowed_ips[0].__str__()} ttl 30 || true\n'
            interface_conf += f'PostUp = ip link set dev grei{a.middle_char}{peer.name} mtu 1500 || true\n'
            interface_conf += f'PostUp = ip link set grei{a.middle_char}{peer.name} up || true\n'
            interface_conf += f'PostDown = ip link del grei{a.middle_char}{peer.name} || true\n'
            if peer.endpoint:
                peer_conf += f"Endpoint = {peer.endpoint}\n"
            if peer.persistent_keepalive:
                peer_conf += f"PersistentKeepalive = {peer.persistent_keepalive}\n"
            peer_confs += peer_conf
        return interface_conf + peer_confs


class NetworkOSPF:
    async def __get_ping_result(self, __test_ip: str, interface_name=None, count=10) -> [PingResult, None]:
        if is_develop:
            stdout = develop_ping_result.encode()
        else:
            returncode, stdout, stderr = await run_command(
                host_mode_command(f'ping -c {count} {__test_ip}'))
        __ping_result = stdout.decode()
        __ping_result = '\n'.join(line for line in __ping_result.splitlines() if line.strip())  # 去除空行
        packet_loss_match = re.search(r'(\d+)% packet loss', __ping_result)
        if not packet_loss_match:
            return  # 如果没有匹配到，返回None
        packet_loss_percentage = int(packet_loss_match.group(1))
        if packet_loss_percentage == 100:
            return  # 如果丢包率100%，返回None
        __a = __ping_result.splitlines()[-1].split(' ')[-2].split('/')

        result = PingResult(min=__a[0], avg=__a[1], max=__a[2], mdev=__a[3], packet_loss=packet_loss_percentage,
                            interface_name=interface_name)
        result.cost = int(result.avg * 100 / (100 - packet_loss_percentage) * 10)
        result.text = __ping_result.splitlines()[-1] + f'loss/cost = {packet_loss_percentage}%/{result.cost}'
        return result

    async def ping_ip(self, __test_ip: str, interface_name=None) -> PingResult:
        """
        测试ip的延迟
        最大尝试3次，如果ping失败，返回300msF
        :param
        interface_name:
        :param
        __test_ip:
        :return:
        """
        result = PingResult(min=300, avg=300, max=300, mdev=300, packet_loss=100, text='fail ping',
                            interface_name=interface_name)
        if not await self.__get_ping_result(__test_ip, interface_name, 1):  # 当第一次ping无效时候，接下来不做测试
            logging.warning(f'测试 {__test_ip} None ping')
            return result
        result = await self.__get_ping_result(__test_ip, interface_name)

        logging.info(f'测试 {__test_ip} {result.text}')
        return result  # 如果超过10次，返回300ms

    async def __test_all_ip(self):

        if is_develop:
            lxc_pub_gre_list = open('lxcpubgre.txt', 'r').read()
        else:
            lxc_pub_gre_list = ''
            if os.path.exists('/etc/network/interfaces.d/lxcpubgre'):
                lxc_pub_gre_list += open('/etc/network/interfaces.d/lxcpubgre', 'r').read()
            if os.path.exists('/etc/network/interfaces.d/lxcpub2gre'):
                lxc_pub_gre_list += open('/etc/network/interfaces.d/lxcpub2gre', 'r').read()
            if os.path.exists('/etc/wireguard/wgi4.conf'):
                lxc_pub_gre_list += open('/etc/wireguard/wgi4.conf', 'r').read()
            if os.path.exists('/etc/wireguard/wgi6.conf'):
                lxc_pub_gre_list += open('/etc/wireguard/wgi6.conf', 'r').read()
            if os.path.exists('/etc/wireguard/wgif.conf'):
                lxc_pub_gre_list += open('/etc/wireguard/wgif.conf', 'r').read()
        if not lxc_pub_gre_list:
            logging.warning('测试延迟ping命令 /etc/network/interfaces.d/lxcpubgre 为空')
            logging.error('获取延迟失败')
            return
        lxc_pub_gre_list = lxc_pub_gre_list.split('\n')
        test_ips = []
        for lxc_pub_gre in lxc_pub_gre_list:
            if '#' not in lxc_pub_gre:
                continue
            if 'lxc exec pub-ibgp -- ping' not in lxc_pub_gre:
                continue
            fe80_address, interface_name = None, None
            for a in lxc_pub_gre.split(' '):
                if a.startswith('fe80:') and '%' in a:
                    fe80_address, interface_name = a.split('%')
            if not fe80_address:
                continue
            test_ips.append((fe80_address, interface_name))
        interface_name_list = {}
        logging.debug(f'测试以下ip{test_ips}')
        for __ping_ip_test in await asyncio.gather(
                *(self.ping_ip(f'{fe80_address}%{interface_name}', interface_name) for fe80_address, interface_name in
                  test_ips)):
            if __ping_ip_test.interface_name:
                interface_name_list[__ping_ip_test.interface_name] = {'cost': __ping_ip_test.cost,
                                                                      'text': __ping_ip_test.text}
        return interface_name_list

    def gen_ospf_config(self):
        interface_name_list = asyncio.run(self.__test_all_ip())
        ospf_interface_str = ''
        for interface_name, key in interface_name_list.items():
            ospf_interface_str += f'\n        interface "{interface_name}" {{type ptp; cost {key["cost"]}; }}; # {key["text"]}'

        ospf_config = f"""  # This file is generated by bird_head_gen.py
protocol ospf v3 aospf6 {{
    ipv6{{
        import filter{{
            if !(net.len <= 48 || net.len=128) then reject;
            if !is_self_net_v6() then reject;
            if (source = RTS_BGP && net !~ [2a13:b487:42d0::/44+]) then reject;
            accept;
        }};
        export filter{{
            if !(net.len <= 48 || net.len=128) then reject;
            if !is_self_net_v6() then reject;
            if (source = RTS_BGP && net !~ [2a13:b487:42d0::/44+]) then reject;
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
                        choices=["gen_bird_head", 'gen_network_interface_d', "gen_bird_ibgp", "gen_wg", "gen_gre",
                                 "remove_gre", "gen_ospf_cost"])
    args = parser.parse_args()
    node_name = open('self_node_name.txt', 'r').read().strip()
    if args.module == 'gen_bird_head':
        bird_head_gen = BirdHeadGen(node_name)
        bird_head_gen.gen_bird_head()
    elif args.module == 'gen_network_interface_d':
        bird_head_gen = BirdHeadGen(node_name)
        bird_head_gen.gen_network_interface_d()
    elif args.module == 'gen_bird_ibgp':
        network_tools = NetWorkTools(node_name)
        network_tools.gen_bird_ibgp()
    elif args.module == 'gen_wg':
        network_wg = NetWorkWG(node_name)
        network_wg.gen_wg_conf()
    elif args.module == 'gen_gre':
        network_tools = NetWorkTools(node_name)
        network_tools.gen_host_gre_cmd2()
    elif args.module == 'remove_gre':
        network_tools = NetWorkTools(node_name)
        network_tools.remove_lxc_gre()
    elif args.module == 'gen_ospf_cost':
        network_ospf = NetworkOSPF()
        network_ospf.gen_ospf_config()
    if not is_develop:
        os.system(host_mode_command('birdc c'))
