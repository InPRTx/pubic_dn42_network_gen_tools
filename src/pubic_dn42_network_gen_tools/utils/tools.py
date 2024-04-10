import asyncio
import ipaddress
import logging
import os
import time

from pubic_dn42_network_gen_tools.glovar import is_develop, is_host_mode


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
