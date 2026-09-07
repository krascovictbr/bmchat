# Auditoria anti-alucinação — `audit/anti-hallucination-20260907`

Branch isolada (sem conflito com `rolling-release`): `audit/anti-hallucination-20260907`
Data: 2026-09-07 · Base: `rolling-release@22964ff`
Escopo: todo `bmchat/` + `run.py` + `tests/` (7386 linhas)

Método: 4 frentes paralelas (imports/símbolos, APIs/assinaturas, dead-code/refs, protocolo/cripto vs PyBitmessage),
com `py_compile`, `pyflakes`/`ruff` (zero `F821`/`F822`), `import` em runtime de todos os módulos,
cruzamento AST `def` × chamadas, e reprodução executada dos suspeitos.

## 1. Alucinações reais — CORRIGIDAS

### H1 [CRÍTICO] `bmchat/core/client.py:499` — `incoming.stream` inexistente
Antes:
```python
channel_address = reverse.get(parsed.data[:32], incoming.stream)
```
`IncomingBroadcast.__slots__` (`protocol/objects.py:283`) só tem
`sender_version`/`sender_stream` — nunca `stream` (`stream` só existe em
`ParsedObject` e `AddressKeys`). Avaliação eager fazia a linha levantar
`AttributeError` em **todo** broadcast; como `_on_object` engole exceção,
tudo era logado como `erro ao processar objeto` e descartado. Além disso o
fallback seria `int` onde se espera endereço (`str`).
Teste antigo não pegava: `test_chan_subscribe_and_post` chamava
`objects.process_broadcast` direto, nunca `Client._on_broadcast`.

Depois:
```python
channel_address = reverse.get(parsed.data[:32])
if channel_address is None:
    return
```
Se a tag foi decifrada, ela está em `reverse` por construção; se houve
corrida (inscrição removida no meio), apenas ignora em vez de gravar tipo errado.

### H2 [ALTO] dono do chan sem inscrição perdia posts — `encryption_private_from_address=None`
`AddressKeys.from_private_keys`/`generate_keys`/`chan_keys_from_name` nunca
preenchem `encryption_private_from_address` (só `from_address` preenche).
`_on_broadcast` registrava a identidade chan via `self.identities.get(...)`
com esse campo `None`; `process_broadcast` → `ecies.decrypt(..., None)` →
`TypeError` → `return None` (descarte silencioso). Só funcionava por acidente
quando o dono também estava inscrito (`setdefault` preservava a entrada boa).

Correção no mesmo bloco: identidades chan agora entram via
`AddressKeys.from_address(channel['address'])` (chave de decrypt derivável
do endereço, igual ao PyBitmessage), com `try/except` e `setdefault` mantidos:
```python
for channel in self.db.all_identities(enabled_only=False):
    if channel['chan'] and channel['enabled']:
        try:
            keys = AddressKeys.from_address(channel['address'])
        except Exception:
            continue
        subscriptions.setdefault(keys.tag, keys)
        reverse.setdefault(keys.tag, channel['address'])
```

Reprodução validada (script efêmero, depois virado em teste):
- com inscrição → 1 mensagem + evento `('broadcast', addr, ...)`
- dono chan sem inscrição → 1 mensagem (antes: 0)

## 2. Verificado e LIMPO (sem alucinação)

- **Imports/símbolos:** todos os `from X import Y` conferem (`client`, `keys`,
  `ecc`, `ecies`, `objects`, `packets`, `const`, `manager`, `peer`, `proxy`,
  `app`, `dialogs`, `run`, `tests`). `py_compile` OK nos 33 arquivos.
  Terceiros conferem: `ecdsa.SECP256k1/SigningKey/VerifyingKey/Point`,
  `Crypto.Cipher.AES/Padding/RIPEMD160`, `socks.PROXY_TYPE_*/socksocket`, `tkinter`.
- **APIs/assinaturas:** `Database`, `NetworkManager`, `packets`, `objects.*`,
  `PowExecutor`, `keys.*`, `proxy.ProxyProfile`, `dialogs.*`,
  `update.check/perform/restart`, `SUPPORT_*`, `__version__` — aridades, kwargs
  e ordens de tupla conferem. `connection.is_alive()` é `Thread.is_alive` herdado.
- **Protocolo/cripto vs referência:** `MAGIC=0xE9BEB4D9`, porta `8444`, ver `3`,
  `NODE_NETWORK=1/SSL=2/DANDELION=8`, tipos `0/1/2/3`, `tor/addr/I2P`,
  `MAX_*`, comandos `version/verack/addr/inv/getdata/object/ping/pong/dinv/error`,
  layouts `version/addr/inv/getdata`, header objeto, `getpubkey v4/pubkey v4/msg v1/
  broadcast v5`, ECIES (`IV+R+CT+MAC`, `KDF=sha512(X)`), ECDSA DER/SHA256,
  fórmula PoW, janela `-1h/+28d+3h`, `ripe/tag/chan/WIF/varint/base58` — todos
  idênticos à referência (`PyBitmessage/src`, `/tmp/opencode/bmsrc`).
- **`requirements.txt`:** cobre `socks`, `Crypto`, `ecdsa`; resto é stdlib;
  `tkinter` corretamente fora (stdlib, declarado no README).
- **Paths/env:** `~/.bmchat`/`$BMCHAT_DATA`/`bmchat.db`/`knownnodes.dat`/`run.py`
  existem e batem com README. Sem `TODO/FIXME`.
- **Falso-positivo esclarecido:** `branch.md:49` dizia "checksumfailed inalcançável";
  hoje `gui/app.py:2226` trata `checksumfailed` — está vivo.

## 3. Não-alucinações documentadas (não corrigidas aqui de propósito)

Para não gerar conflito nem mudar comportamento, registrado apenas:

- **Dead code (nunca chamado):** `database.delete_identity/set_identity_label/
  set_identity_difficulty/get_message/messages_for/messages_for_contact/
  mark_conversation_read/recent_messages/object_type_of/get_pubkey`,
  `address.validate_address/add_bm_prefix`, `packets.assemble_version/
  version_packet_command/is_onion`, `proxy.resolve_hostname`, `ecc.ecdh_x`,
  `keys.public_encryption_point`, `hashing.sha256/sha512_obj/sha512_hash_id`,
  `client.create_channel/broadcast/broadcast_chan/cancel_pow`,
  `peers.PeerStore.add_peer`, `Peer.__eq__/__hash__`, `app._unread_for/
  _last_message_row/_last_message_for/_ChatTextAdapter.get/tag_names/see/config/
  _ConvListAdapter.size/get/selection_clear/selection_set/bind`,
  `varint` raise inalcançável. Constantes só definidas: `NODE_SSL/DANDELION`,
  `OBJECT_ONIONPEER/ADDR/I2P`, `MAX_ADDR/MSG/PAYLOAD/COUNT/TIME_OFFSET`,
  `DEFAULT_PORT`, `ENCODING_IGNORE/SIMPLE/EXTENDED`, `SELF_NONCE`, `X_LEN`,
  `ORDER_BYTES`, `dialogs.DIM`, `APP_NAME/APP_VERSION`.
- **Status sem consumidor específico** (caem em `else` genérico, por design):
  `address.*`, `update 'unknown'`, `app {'status':'error'}`,
  `broadcast 'error/mismatch/noname'`, `add_contact 'unsupported'`,
  `import_identity 'invalid/exists'`, evento `('status',id,'sending')`.
- **Divergências de protocolo (tolerantes, consenso-válidas, sem fix):**
  `peer.py:137` aceita 16 MB (ref 1.6 MB); `manager.py:171` tolera +44 B e sem
  mínimos por tipo; porta local hard `8444`; services sempre `1`; getpubkey
  sempre v4 (contato v3 nunca completa, mas README já diz v2/v3 recusados);
  `MSG/GETPUBKEY_TTL=4d` vs `4.25d/2.5d+backoff` ref; `address.py` frouxo em
  tamanhos ripe; só `pubkey v4/broadcast v5`; janela `addr` sem filtro stream/
  alive; onion v3 vira `0.0.0.0`; só `SHA256` (sem fallback `SHA1` legado);
  só envia `TRIVIAL`, `SIMPLE` mostra `Subject/Body` cru, `EXTENDED` vira lixo;
  `dinv` tratado como `inv`; sem PoW custom por destinatário. Nada inventado,
  só permissivo/estrito em pontos — anotado para decisão futura, fora do escopo
  anti-alucinação.

## 4. Arquivos tocados (mínimo, sem conflito)

- `bmchat/core/client.py` — bloco `_on_broadcast` (H1+H2), ~10 linhas.
- `tests/test_anti_hallucination.py` — NOVO, 2 testes de regressão.
- Este documento.

## 5. Validação

- `pytest tests/test_anti_hallucination.py -q`: **2 passed**.
- `pytest tests/ -q`: **24 passed** (suite original) + 2 novos = 26 no total da branch.
- `pyflakes`: só `F401/F841` (unused) — zero `F821/F822`.
- `compileall`: OK.

## 6. Como fundir sem conflito

```bash
git checkout rolling-release
git merge --ff-only audit/anti-hallucination-20260907
# ou, se rolling-release andou: git merge --no-ff audit/anti-hallucination-20260907
python3 -m pytest tests/ -q
```
Reversão segura: `git revert` do commit de `client.py` (testes novos podem ficar).
