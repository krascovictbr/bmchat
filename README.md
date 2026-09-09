# Bem-vindo ao bmchat

![bmchat](https://img.shields.io/badge/Rolling%20Release-bmchat-1793D1?style=flat-square&logo=bmchat&logoColor=white)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-0BSD-green)

# bmchat

Cliente de chat estilo Telegram que usa **somente o protocolo Bitmessage**
para trocar mensagens, com interface gráfica em Tkinter.

> **Aviso importante — leia antes de usar.** O bmchat é um projeto
> **experimental, em desenvolvimento ativo, sem auditoria de segurança**.
> Ele pode conter falhas, erros e vulnerabilidades — incluindo bugs que
> fazem mensagens não chegarem, corrompem dados locais ou expõem mais
> metadados do que o esperado. Não confie nele para nada em que sua
> segurança, liberdade ou sustento dependam do sigilo. Detalhes na seção
> [Limites e riscos](#11-limites-e-riscos-conhecidos).

## Índice

1. [O que é o bmchat](#1-o-que-é-o-bmchat)
2. [Como funciona um mensageiro P2P](#2-como-funciona-um-mensageiro-p2p)
3. [Prova de trabalho (PoW)](#3-prova-de-trabalho-pow)
4. [Instalação e execução](#4-instalação-e-execução)
5. [Primeiros passos](#5-primeiros-passos)
6. [Guia de uso](#6-guia-de-uso)
7. [Onde ficam os dados](#7-onde-ficam-os-dados)
8. [Como funciona por dentro (protocolo)](#8-como-funciona-por-dentro-protocolo)
9. [Estrutura do código](#9-estrutura-do-código)
- [Suporte](#suporte)
10. [Testes](#10-testes)
11. [Limites e riscos conhecidos](#11-limites-e-riscos-conhecidos)
12. [Versionamento](#12-versionamento)
- [Solução de problemas](#solução-de-problemas)

## 1. O que é o bmchat

É um programa de conversa parecido com o Telegram por fora (lista de
conversas, bolhas de mensagem, confirmações de leitura), mas por dentro ele
não usa os servidores de nenhuma empresa: ele fala **direto com a rede
Bitmessage**, que é mantida pelos próprios usuários.

Consequências práticas disso:

- Não existe cadastro, login, senha ou "esqueci minha senha".
- Sua **identidade é um par de chaves criptográficas**. Quem tem a chave
  privada controla o endereço; quem perde, perde para sempre.
- Não há empresa para reclamar se algo der errado — nem para pedir seus
  dados de volta.

## 2. Como funciona um mensageiro P2P

Num mensageiro comum (WhatsApp, Telegram), suas mensagens passam pelo
servidor da empresa, que entrega ao destinatário. Num mensageiro P2P
(*peer-to-peer*, "ponta a ponta" entre iguais), **todo mundo conectado é
ao mesmo tempo cliente e servidor**:

- **Nós e conexões.** Ao abrir, o bmchat conecta a alguns nós da rede
  (endereços descobertos por sementes DNS e por outros nós). O rodapé mostra
  `Rede: E/T` — conexões realmente estabelecidas de tentadas.
- **Objetos e inventário.** Tudo na rede (pedidos de chave, chaves,
  mensagens) é um **objeto**: um bloco de bytes com prazo de validade e
  prova de trabalho. Cada nó guarda os objetos que recebe (o **inventário**)
  e anuncia aos vizinhos só os resumos (`inv`); quem não tem pede o conteúdo
  (`getdata`). É assim que uma mensagem sua chega ao destinatário: de nó em
  nó, por retransmissão.
- **Streams.** A rede é dividida em fluxos numerados para ninguém precisar
  baixar tudo. Quase todo mundo usa o stream 1, que é o padrão aqui.
- **Endereços.** Um endereço `BM-...` embute versão, stream e um resumo das
  chaves públicas. A parte secreta (chaves privadas) nunca sai do seu
  computador.
- **Só P2P.** O bmchat trabalha apenas com mensagens diretas entre
  identidades e contatos — sem canais nem grupos na interface.

Por ser retransmissão entre voluntários, **nada é instantâneo**: entre
publicar e o outro lado receber passam minutos, e a primeira sincronização
(dezenas de milhares de objetos) pode levar de minutos a horas.

## 3. Prova de trabalho (PoW)

Para impedir spam sem precisar de cadastro, a rede exige **prova de
trabalho**: antes de publicar qualquer objeto, seu computador precisa
resolver um quebra-cabeça criptográfico (achar um `nonce` cujo SHA-512
duplo fique abaixo de uma meta). Pontos importantes:

- A dificuldade mínima é **1000/1000 por objeto** e não pode ser abaixada —
  é regra da rede, não opção do programa.
- **Custa CPU de verdade**: cada objeto (pedido de chave, chave, mensagem,
  confirmação) leva de dezenas de segundos a alguns minutos de
  processamento, dependendo da máquina. O bmchat usa vários núcleos e mostra
  `PoW: N` no rodapé enquanto calcula.
- Por isso os símbolos da conversa importam: **relógio** = ainda calculando
  ou aguardando chave; **✓✓ cinza** = publicado na rede; **✓✓ azul** =
  entregue (ACK recebido). O botão direito na mensagem mostra os detalhes.
- Fechar o programa no meio de um PoW cancela aquele cálculo; a mensagem
  pendente tenta de novo sozinha a cada 10 minutos.

## 4. Instalação e execução

Requisitos: Python 3.10+ (testado em 3.14), Tkinter e o conteúdo de
`requirements.txt` (`PySocks`, `pycryptodome`, `ecdsa`).

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 run.py
```

Diretório de dados padrão: `~/.bmchat`. Para usar outro:

```bash
BMCHAT_DATA=/caminho/para/dados python3 run.py
```

## 5. Primeiros passos

1. Na primeira abertura, uma identidade já é criada. Abra o menu ☰ →
   **Minha identidade** (ou a tela inicial) e **copie seu endereço
   `BM-...`** com o botão — é ele que você envia aos contatos por qualquer
   meio (e-mail, papel, outro mensageiro).
2. Adicione alguém: botão ✎ → **Novo contato**, colando o `BM-...` dele.
3. Abra a conversa e escreva. A mensagem aparece na hora com o relógio.
4. Nos bastidores: o bmchat publica um pedido da chave pública do contato;
   quando ela chega (minutos), a mensagem é cifrada e enviada sozinha; quando
   o outro lado recebe, vem o ACK e o `✓✓` fica azul.

## 6. Guia de uso

- **Conversas**: lista à esquerda com prévia, horário e selo de não-lidas;
  busca pela lupa; mensagens em ordem cronológica, sempre as novas embaixo.
- **Mouse**: botão direito na conversa abre/inicia (Abrir, Copiar endereço,
  Excluir conversa, Remover contato); botão direito na
  bolha copia o texto, exclui a mensagem ou mostra detalhes (estado,
  remetente, data, expiração, hash).
- **Tempo de vida das mensagens (TTL)**: toda mensagem nasce com prazo de
  validade — passado ele, a rede descarta o objeto. O padrão é **1 dia**
  para todas as mensagens de todos os contatos; mude em Sistema →
  **Tempo de vida das mensagens…** (1 hora a 21 dias, conforme as regras
  do protocolo; fora disso o valor é ajustado e avisado). TTL maior exige
  mais prova de trabalho e demora mais para enviar; o ACK expira junto.
  Os Detalhes da bolha mostram "Expira em".
- **Backup** (botão na barra da identidade ou menu): mostra as chaves
  privadas em WIF **com aviso explícito** — guarde em lugar seguro (papel,
  gerenciador de senhas, pendrive offline); **perdeu, acabou: não há como
  recuperar**. Permite salvar em arquivo, copiar, importar de volta e
  exportar/importar **`keys.dat`** (formato do PyBitmessage) para levar as
  chaves a outros clientes — e trazer de lá.
- **Proxy / darknet**: Tor (9050/9150), I2P (SOCKS 4447, HTTP 4444) ou
  conexão direta. A escolha fica salva e as conexões são refeitas.
- **Configurações de rede**: timeout de conexão e de leitura, máximo de
  conexões e intervalo da manutenção.
- **Diagnóstico de rede**: proxy, tempo ativo, conexões (estado, versão,
  streams, nota do par, divergência de relógio), tráfego total e da sessão,
  inventário; botões para copiar o relatório e **apagar todos os objetos**
  (o histórico é preservado; a rede é baixada de novo).
- **Ver log**: mostra os eventos de rede e mensagens (pedidos de chave,
  publicações, recebimentos, ACKs) com botão de copiar — útil para relatar
  problemas.
- **Legenda de confirmações**: explica cada símbolo; lembre-se de que o
  Bitmessage não tem "online" nem "visto por último" — a legenda do contato
  mostra apenas se a chave pública dele é conhecida.
- **Rodapé**: `Rede: E/T` (conexões estabelecidas de tentadas),
  `Objetos` (guardados no banco), `Pares` (conhecidos), `PoW` (cálculos
  rodando), `Pendentes` (mensagens aguardando chave) e `Proxy` em uso.

## 7. Onde ficam os dados

Tudo em `~/.bmchat` (ou `$BMCHAT_DATA`):

- `bmchat.db` (SQLite): identidades e chaves privadas, contatos, inscrições,
  mensagens, chaves públicas, objetos da rede, configurações.
- `knownnodes.dat`: pares conhecidos e reputação (para reconectar rápido).

**Faça backup das chaves** (seção 6). Quem tiver acesso a esses arquivos tem
sua identidade. O banco não é cifrado.

## 8. Como funciona por dentro (protocolo)

- Tipos de objeto usados: `getpubkey`, `pubkey` (v4), `msg` (v1, com
  `ack_data` embutido), `broadcast` (v5); comandos de rede `version`,
  `verack`, `addr`, `inv`, `getdata`, `object`, `ping`, `pong`, `dinv` e
  `error`, nos formatos exatos da especificação.
- Criptografia: ECIES (ECDH secp256k1 + AES-256-CBC + HMAC-SHA256) e ECDSA
  em DER/SHA256, interoperáveis com o PyBitmessage (verificado por testes
  cruzados com a biblioteca original).
- Validação de entrada: PoW mínimo 1000/1000, janela de validade (passado
  −1h, futuro +28d+3h), tamanho máximo e checagem de assinatura; o que falha
  é descartado em silêncio, como na rede.
- ACK: o remetente embute na mensagem um objeto pronto (com PoW); o
  destinatário valida e re-anuncia; ao ver o objeto circulando, o remetente
  marca a mensagem como entregue. ACK prova recebimento pelo programa do
  destinatário — não que um humano leu.
- Persistência de sincronia: hashes conhecidos e objetos ficam no banco; ao
  reabrir, nada já guardado é baixado de novo (a primeira sincronização,
  essa sim, baixa tudo uma vez).

## 9. Estrutura do código

```
bmchat/
  version.py    # versão rolling (git: CalVer + commits + sha)
  crypto/       # ecc (ECDSA DER), ecies, keys (endereços, WIF, chans), pow
  protocol/     # const, packets (version/addr/inv/getdata...), objects
                #   (getpubkey/pubkey/msg/broadcast + parsing/validação),
                #   address (base58, checksum)
  net/          # proxy (Tor/I2P), peers (pares + reputação), manager
                #   (inventário, relay, snapshot p/ diagnóstico), peer
                #   (handshake, comandos)
  core/         # database (SQLite) e client (orquestração: envio, ACK,
                #   backup keys.dat/WIF, retry, re-anúncio)
  gui/          # app (interface Telegram-like em canvas), dialogs
run.py          # ponto de entrada
tests/          # integração, rede local, interopands (PoW/assinaturas/chans)
```

## Suporte

Menu ☰ → **Suporte…**: explica o canal oficial de suporte, mostra o
endereço com botão de copiar e tem **Conversar agora**, que cria o contato
e abre a conversa direto. A conversa é cifrada como qualquer outra.

**Prazos realistas — leia com calma.** O suporte é atendido por pessoas,
em fila, e cada mensagem precisa atravessar a rede Bitmessage:

- **Resposta**: pode levar **horas ou dias**. Se o suporte estiver
  investigando um bug ou erro, a conversa pode se estender por **dias ou até
  semanas** (reproduzir o problema, testar correção, publicar atualização).
  Reenviar a mesma pergunta não acelera — cada nova mensagem entra no fim
  da fila e paga PoW de novo.
- **Por que demora**: o bmchat usa **PoW (prova de trabalho) conforme o
  protocolo demanda** — dificuldade mínima 1000/1000 por objeto,
  inegociável. Cada envio (pedido de chave, chave, mensagem, confirmação)
  custa de dezenas de segundos a minutos de CPU **nos dois lados**, e a
  retransmissão P2P entre nós voluntários soma mais minutos. Some a isso
  programa fechado, computador desligado ou rede ainda sincronizando, e o
  ciclo de ida-e-volta de uma pergunta/resposta facilmente passa de horas.
- **O que fazer enquanto espera**: deixe o programa aberto e conectado;
  acompanhe o estado pelos símbolos (`…`, `✓✓`, `✓✓`) e pelo *Ver log*.
  Se pedirem detalhes, envie o conteúdo de *Ver log* e do *Diagnóstico de
  rede* (ambos têm botão de copiar).

Abrindo a conversa do suporte aparece uma barra com **Enviar diagnóstico**
(também na janela do Suporte): ela monta um relatório de triagem (versão,
sistema, rede, contas, pendentes, config, PoW e log recente — **sem chaves
privadas nem conteúdo de mensagens**) e mostra tudo numa prévia. O botão
**Enviar ao suporte nasce desabilitado** e só libera marcando
"Li o relatório acima e autorizo o envio ao suporte" — **nada é enviado sem
esse consentimento explícito**; há também Copiar e Cancelar. O envio segue
cifrado pelo fluxo normal de mensagens.

## 10. Testes

```bash
python3 -m pytest tests/ -q
```

Cobrem ciclo de pubkey, envio com ACK, rede local entre dois clientes,
assinaturas DER, PoW contra a função extraída do PyBitmessage, derivação de
chans idêntica à referência, ECIES cruzado com o `pyelliptic` original,
persistência de inventário, backup/restore e exclusões. Os testes aceleram
o PoW; na rede real vale o 1000/1000. **Testes aumentam a confiança, não
provam ausência de bugs** (ver seção 11).

## 11. Limites e riscos conhecidos

Seja direto: este software **não é auditado** e foi escrito de forma
iterativa. Ao usá-lo, assuma que:

- **Pode haver bugs** que perdem mensagens, duplicam envios, corrompem o
  banco local ou travam a interface — e **vulnerabilidades** (incluindo
  execução remota via dados de rede, como em todo cliente de rede complexo).
- **Privacidade tem limites inerentes ao protocolo**: as mensagens são
  cifradas, mas todos os nós retransmitem todos os objetos — tamanho,
  horário e volume do seu tráfego são visíveis a quem observa a rede. Sem
  proxy Tor/I2P, seu IP fica exposto aos pares. Não há *forward secrecy*:
  se sua chave privada vazar no futuro, mensagens antigas gravadas podem
  ser lidas.
- **Anonimato não é garantido** por este programa; para ameaças sérias use
  ferramentas auditadas e aprenda o modelo de ameaças antes.
- **Chaves**: perda = perda permanente da identidade e do histórico
  associado; vazamento = outra pessoa se passa por você e lê o que chegar.
- **Rede**: lentidão de minutos a horas é normal (PoW + retransmissão);
  "rápido" aqui não significa seguro.
- **Compatibilidade**: o alvo é o protocolo Bitmessage v3/stream 1 e
  objetos v1/v4/v5; endereços antigos (v2/v3) para contato são recusados.

Se encontrar algo errado, relate com o conteúdo de *Ver log* e do
*Diagnóstico de rede* (botões de copiar embutidos) — sem esses dados quase
não há como investigar.

## Licença

**0BSD** (BSD Zero Clause) — a mais permissiva possível: pode usar, copiar,
modificar e distribuir para qualquer fim, com ou sem custo, sem nem precisar
manter crédito. Veja o arquivo `LICENSE` (o software é fornecido "como está",
sem garantias).

## 12. Versionamento

Rolling release no branch `rolling-release`: cada commit é uma versão, no
formato `AAAA.MM.DD+r<commits>.g<sha>[.dirty]`, exibida em *Sobre* e enviada
no user-agent do protocolo. Sem repositório git, mostra `0.0.0+unknown`.

## Atualizações (via `git pull`)

O programa atualiza pelo próprio git, sem baixar nada de outro lugar:

- Ao abrir, ele confere em segundo plano se há commits novos no remoto e
  **avisa com uma janela** quando houver, mostrando quantos são.
- Menu ☰ → **Verificar atualizações** faz a mesma checagem na hora (avisa
  se já está atualizado, se não há rede ou se a cópia não tem git).
- Aceitando, ele executa o equivalente a `git pull --ff-only`: só avança se
  for avanço direto — **nunca cria merge nem toca em alterações locais**; se
  você mexeu no código, ele recusa e explica.
- Aplicada a atualização, o programa **reinicia sozinho** na nova versão.

Comandos equivalentes no terminal, a partir da pasta do projeto:

```bash
git pull --ff-only   # atualiza (só avanço direto)
python3 run.py       # abre de novo
```

## Solução de problemas

Ordem para investigar qualquer coisa (do mais comum ao mais raro):

- **Mensagem presa no relógio**: abra a conversa e leia a legenda do
  contato. `aguardando chave pública…` = o outro lado ainda não respondeu
  ao pedido de chave (ele precisa estar online e sincronizado; o pedido é
  republicado sozinho a cada 10 min). `PoW: N` no rodapé com N > 0 = cálculo
  em andamento, aguarde.
- **Mensagem não chega ao destino**: confira se a sua saiu do relógio para
  `✓✓` (publicada) e depois `✓✓` azul (entregue ao programa dele). Sem
  `✓✓` azul, o problema está do seu lado (itens acima). Com `✓✓` azul e
  nada lá, o problema está no outro cliente.
- **Rede zerada (`Rede: 0/X`)**: sem internet, firewall bloqueando saída,
  proxy errado ou DNS indisponível (as sementes DNS precisam resolver).
  Teste alternar entre conexão direta e Tor.
- **Relógio divergente**: o diagnóstico acusa `DIVERGENTE` quando seu
  relógio difere mais de 1h — os nós derrubam a conexão. Acerte data e hora
  do sistema.
- **Primeira sincronização lenta**: dezenas de milhares de objetos;
  acompanhe `Objetos` crescendo no rodapé. Não use *Apagar objetos* no meio
  dela (recomeça os downloads).
- **Programa fechou no meio do envio**: o PoW em curso é cancelado, mas a
  mensagem pendente tenta de novo sozinha ao reabrir.
- **Nada resolveu**: copie *Ver log* e *Diagnóstico de rede* e envie ao
  suporte (menu ☰ → *Suporte…*), junto com o que você esperava que
  acontecesse.
