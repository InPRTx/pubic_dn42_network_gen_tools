import logging
import os
import re

is_develop = os.path.exists('./is_develop.txt')
is_host_mode = os.path.exists('./is_host_mode.txt')
is_debug_mode = os.path.exists('./is_debug_mode.txt')
is_incus_mode = os.path.exists('/var/lib/incus/containers/pub-ibgp')
incus_str = 'incus' if is_incus_mode else 'lxc'
if is_debug_mode:
    logging.basicConfig(level=logging.DEBUG)
else:
    logging.basicConfig(level=logging.INFO)
try:
    __a = re.match(r'^(.*)-(.*)-as(.*)-inprtx$', os.uname().nodename)
    node_name = __a.group(1) + __a.group(2)
except AttributeError:  # 不是我的命名方式或者，为win开发模式
    try:  # 拦截掉其他tools的异常
        node_name = open('self_node_name.txt').read().strip()
    except FileNotFoundError:
        print('读取self_node_name.txt失败')
