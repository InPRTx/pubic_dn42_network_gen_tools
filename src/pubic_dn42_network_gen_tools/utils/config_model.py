import ipaddress
from enum import Enum
from typing import Optional, List, Union, Dict

from pydantic import BaseModel, constr, IPvAnyAddress, Field, conint

from pubic_dn42_network_gen_tools.utils.tools import ipaddress_to_gre_fe80


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
