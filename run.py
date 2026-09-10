import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from bmchat.core.client import Client
from bmchat.core.database import Database
from bmchat.crypto.pow.standard import StandardPoWStrategy
from bmchat.net.manager import NetworkManager
from bmchat.net.mock import MockNetworkManager
from bmchat.protocol.factory import ProtocolObjectFactory
from bmchat.gui.app import main


def create_client(data_dir, use_mock_net: bool = False) -> Client:
    """Factory com Dependency Injection — cria Client com todas as dependências.

    Centraliza a criação do grafo de objetos (Database, Repositories,
    Factory, Strategy, NetworkManager) para facilitar testes e substituição
    de implementações (ex.: MockNetworkManager).

    Args:
        data_dir: diretório de dados
        use_mock_net: se True injeta MockNetworkManager (para testes)

    Returns:
        Client totalmente configurado
    """
    db = Database(data_dir)
    pow_strategy = StandardPoWStrategy()
    protocol_factory = ProtocolObjectFactory()
    # Repositories são criados dentro do Client; mas poderiam ser injetados aqui:
    #   msg_repo = MessageRepository(db) etc.
    if use_mock_net:
        # Injeta mock sem I/O de rede real
        net = MockNetworkManager(data_dir, db, on_object=None, on_log=None)
    else:
        net = NetworkManager(data_dir, db, on_object=None, on_log=None)
    client = Client(
        data_dir,
        pow_strategy=pow_strategy,
        network_manager=net,
        db=db,
        protocol_factory=protocol_factory,
    )
    return client


def _ensure_writable_dir(path):
    """M4: exige diretório gravável (erro amigável em vez de falhar depois)."""
    try:
        os.makedirs(path, mode=0o700, exist_ok=True)
    except Exception as exc:
        raise SystemExit(
            'BMCHAT_DATA inválido: não foi possível criar %r (%s). '
            'Aponte para um diretório gravável.' % (path, exc))
    try:
        os.chmod(path, 0o700)
    except Exception:
        pass
    if not os.path.isdir(path) or not os.access(path, os.W_OK | os.X_OK):
        raise SystemExit(
            'BMCHAT_DATA inválido: %r não é um diretório gravável. '
            'Aponte para um diretório gravável.' % path)
    probe = os.path.join(path, '.bmchat-write-test')
    try:
        with open(probe, 'w', encoding='utf-8') as handle:
            handle.write('ok')
    except Exception:
        raise SystemExit(
            'BMCHAT_DATA inválido: sem permissão de escrita em %r. '
            'Aponte para um diretório gravável.' % path)
    try:
        os.unlink(probe)
    except Exception:
        pass
    return path


def data_dir_default():
    home = os.path.expanduser('~')
    path = os.path.join(home, '.bmchat')
    return _ensure_writable_dir(path)


if __name__ == '__main__':
    raw = os.environ.get('BMCHAT_DATA')
    if raw and raw.strip():
        directory = _ensure_writable_dir(
            os.path.abspath(os.path.expanduser(raw.strip())))
    else:
        directory = data_dir_default()
    # Dependency Injection: cria o grafo completo e injeta no App
    # Em produção usa implementação real; em testes pode usar Mock
    use_mock = os.environ.get('BMCHAT_MOCK_NET') == '1'
    client = create_client(directory, use_mock_net=use_mock)
    main(directory, client=client)
