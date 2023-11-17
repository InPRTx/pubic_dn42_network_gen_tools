import copy
import ipaddress
import os
import time
import tomllib
from typing import Optional, List, Union

import pycountry
from pydantic import BaseModel

is_develop = os.path.exists('./is_develop.txt')
develop_lxc_device_show = """root:
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
        if mask == 32 and address in ipaddress.ip_network('172.20.229.192/27'):  # 国际段
            other_subnet.append(ipaddress.ip_network(f"{address}/31", strict=False))
            other_subnet.append(ipaddress.ip_network(f"{address}/27", strict=False))
            other_subnet_bird_static_reject_str += f'\n    route {address}/31 reject;'
            other_subnet_bird_static_reject_str += f'\n    route {address}/27 reject;'
        elif mask == 32 and address in ipaddress.ip_network('172.23.173.160/28'):  # 中国段
            other_subnet.append(ipaddress.ip_network(f"{address}/28", strict=False))
            other_subnet_bird_static_reject_str += f'\n    route {address}/28 reject;'
        elif mask == 32 and address in ipaddress.ip_network('172.20.197.176/29'):  # anycast段将由BGP获取
            pass
        elif mask == 64 and address in ipaddress.ip_network('fdf4:56da:a360:42d0::/60'):  # pub中国段
            other_subnet.append(ipaddress.ip_network(f"{address}/60", strict=False))
            other_subnet_bird_static_reject_str += f'\n    route {address}/60 reject;'
        elif mask == 64:
            other_subnet.append(ipaddress.ip_network(f"{address}/63", strict=False))
            other_subnet.append(ipaddress.ip_network(f"{address}/60", strict=False))
            other_subnet_bird_static_reject_str += f'\n    route {address}/63 reject;'
            other_subnet_bird_static_reject_str += f'\n    route {address}/60 reject;'
        elif mask == 48 and address in ipaddress.ip_network('2a13:b487:42d0::/44'):  # pub中国段
            other_subnet.append(ipaddress.ip_network(f"{address}/44", strict=False))
            other_subnet_bird_static_reject_str += f'\n    route {address}/44 reject;'
        elif mask == 48:
            other_subnet.append(ipaddress.ip_network(f"{address}/47", strict=False))
            other_subnet.append(ipaddress.ip_network(f"{address}/44", strict=False))
            other_subnet_bird_static_reject_str += f'\n    route {address}/47 reject;'
            other_subnet_bird_static_reject_str += f'\n    route {address}/44 reject;'

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
    ipv6_pub: BirdIPAddress
    vps_interface: List[VpsInterface]
    region_code: int = 52
    county: str
    is_transit: bool = False
    is_send_tier1_lage_net_to_ibgp: bool = False
    is_wire_tier1_lage_net_to_kernel: bool = False


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
        # # a = self.config_toml['node'][self.node_name]
        # print(self.node_keys.vps_interface[0].ip_public.exploded)
        # print(self.iso3166_code)

        a = f"""define OWNIPv6 =  {self.node_keys.ipv6_pub.address};
define OWNNETv6 = {self.node_keys.ipv6_pub.subnet};

define OWN42IPv4 = {self.node_keys.ipv4_dn42.address};
define OWN42IPv6 = {self.node_keys.ipv6_dn42.address};
define OWN42NET = {self.node_keys.ipv4_dn42.subnet};
define OWN42NETv6 = {self.node_keys.ipv6_dn42.subnet};

define REGION = {self.node_keys.region_code};
define COUNTY = 1{self.iso3166_code};
define FULL_TABLE = false; # 保留的抛弃参数
define IS_SEND_TIER1_LARGE_NET_TO_IBGP = {'true' if self.node_keys.is_send_tier1_lage_net_to_ibgp else 'false'};
define IS_WIRE_TIER1_LARGE_NET_TO_KERNEL = {'true' if self.node_keys.is_wire_tier1_lage_net_to_kernel else 'false'};
define IS_TRANSIT = {'true' if self.node_keys.is_transit else 'false'};

router id OWN42IPv4;

protocol static {{
    ipv4;
    route OWN42NET reject;{self.node_keys.ipv4_dn42.other_subnet_bird_static_reject_str}
}}

protocol static {{
    ipv6;
    route OWNNETv6 reject;{self.node_keys.ipv6_pub.other_subnet_bird_static_reject_str}
    
    route OWN42NETv6 reject;{self.node_keys.ipv6_dn42.other_subnet_bird_static_reject_str}
}}"""
        print(a)


class NetWorkTools:
    def __init__(self, __node_name):
        self.config_toml = tomllib.loads(open('config.toml', 'r').read())
        self.node_name = node_name

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
                print('写入/etc/network/interfaces.d/lxcpubgre完成')
                open('/etc/network/interfaces.d/lxcpubgre', 'w').write(ifupdown_gre_conf)
            print(ifupdown_gre_conf)
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
                    if not is_develop:
                        for cmd in host_cmd_runs:
                            print('执行', cmd)
                            os.popen(cmd)
                            time.sleep(0.5)
                    # print(host_cmd_runs)

    def __get_lxc_device_show(self):
        result = []
        if is_develop:
            a = develop_lxc_device_show
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


if __name__ == '__main__':
    if is_develop:
        print('已开启开发模式')
    node_name = open('self_node_name.txt', 'r').read().strip()
    # bird_head_gen = BirdHeadGen(node_name)
    # bird_head_gen = BirdHeadGen('can1')
    # bird_head_gen.gen_bird_head()
    network_tools = NetWorkTools('sin1')
    network_tools.gen_host_gre_cmd()
    # network_tools.gen_host_create_gre_ip_cmd('hkg3', 'nrt1')
    if not is_develop:
        os.system('birdc c')
    # main_test2.return_class()
