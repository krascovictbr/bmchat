import socket

import socks


class ProxyProfile:
    __slots__ = ('name', 'proxy_type', 'host', 'port', 'username', 'password')

    def __init__(self, name='Direto', proxy_type='none', host='', port=0,
                 username='', password=''):
        self.name = name
        self.proxy_type = proxy_type
        self.host = host
        self.port = port
        self.username = username
        self.password = password

    def is_direct(self):
        return self.proxy_type == 'none'

    def describe(self):
        if self.is_direct():
            return self.name
        return '%s (%s:%s)' % (self.name, self.host, self.port)

    @property
    def kind(self):
        return {
            'socks5': socks.PROXY_TYPE_SOCKS5,
            'socks4': socks.PROXY_TYPE_SOCKS4,
            'http': socks.PROXY_TYPE_HTTP,
        }.get(self.proxy_type)

    def to_dict(self):
        return {
            'name': self.name,
            'proxy_type': self.proxy_type,
            'host': self.host,
            'port': self.port,
            'username': self.username,
            'password': self.password,
        }

    @classmethod
    def from_dict(cls, data):
        return cls(
            data.get('name', 'Direto'),
            data.get('proxy_type', 'none'),
            data.get('host', ''),
            int(data.get('port', 0)),
            data.get('username', ''),
            data.get('password', ''),
        )


DARKNET_PRESETS = [
    ProxyProfile('Tor (padrão)', 'socks5', '127.0.0.1', 9050),
    ProxyProfile('Tor (navegador)', 'socks5', '127.0.0.1', 9150),
    ProxyProfile('I2P (SOCKS)', 'socks5', '127.0.0.1', 4447),
    ProxyProfile('I2P (HTTP)', 'http', '127.0.0.1', 4444),
]


def connect_socket(host, port, proxy=None, timeout=30):
    if proxy is None or proxy.is_direct():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        return sock
    sock = socks.socksocket()
    sock.set_proxy(
        proxy.kind, proxy.host, proxy.port,
        username=proxy.username or None, password=proxy.password or None,
        rdns=True)
    sock.settimeout(timeout)
    sock.connect((host, port))
    return sock


def resolve_hostname(host, proxy=None, timeout=10):
    if proxy is not None and not proxy.is_direct() and host.endswith('.onion'):
        return host
    if proxy is not None and not proxy.is_direct() and host.endswith('.i2p'):
        return host
    return socket.gethostbyname(host)