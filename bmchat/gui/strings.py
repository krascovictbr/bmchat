"""Strings centralizadas PT-BR (preparado para i18n).

Todas as frases da interface vivem aqui como templates com
placeholders nomeados — nada de concatenacao ``"a" + var + "b"``.
Trocar para EN = traduzir este arquivo; codigo usa .format().
"""

# -- Diagnostico -----------------------------------------------------------

DIAG_TITLE = "Diagnóstico de rede"
DIAG_GENERATED_AT = "Gerado em: {when}"
DIAG_APP_VERSION = "App: bmchat {version}"
DIAG_SYSTEM = "Sistema: {system} | Python: {py}"
DIAG_SECTION_RESUMO = "📊 Resumo"
DIAG_LABEL_ESTADO = "Estado: {state}"
DIAG_LABEL_ATIVO_HA = "Ativo há: {uptime}"
DIAG_LABEL_PROXY = "Proxy: {proxy}"
DIAG_LABEL_STREAMS = "Streams: {streams}"
DIAG_LABEL_VERSAO = "Versão: {version}"
DIAG_SECTION_REDE = "🌐 Rede"
DIAG_LABEL_CONEXOES = "Conexões: {established} estabelecidas de {total}"
DIAG_LABEL_CONEXOES_DETALHE = (
    "Conexões: {established} estabelecidas de {total} "
    "({negotiating} negociando, {silent} silenciosas)"
)
DIAG_LABEL_TRAFEGO = "Tráfego total: ↑ {up}  ↓ {down}"
DIAG_SECTION_INVENTARIO = "📦 Inventário & Sincronização"
DIAG_LABEL_OBJETOS = "Objetos guardados: {count}"
DIAG_LABEL_HASHES = "Hashes conhecidos: {count}"
DIAG_LABEL_INVENTARIO_MEM = "Inventário em memória: {count}"
DIAG_LABEL_PENDENTES = "Pendentes: {count}"
DIAG_LABEL_SESSAO = (
    "Sessão: {received} objetos recebidos, "
    "{announced} anunciados, {invs} invs, {getdatas} getdatas"
)
DIAG_PROGRESS_SINCRONIZANDO = (
    "Sincronizando: {done} de {total} ({pending} pendentes) — {pct}% {bar}"
)
DIAG_PROGRESS_SINCRONIZADO = "Sincronizado — {total} de {total} (0 pendentes) — 100% {bar}"
DIAG_PROGRESS_BAR_FULL = "█"
DIAG_PROGRESS_BAR_EMPTY = "░"
DIAG_SECTION_PARES = "👥 Pares"
DIAG_LABEL_PARES_CONHECIDOS = "Pares conhecidos: {count}"
DIAG_LABEL_PARES_BACKOFF = "Em pausa (backoff): {count}"
DIAG_LABEL_PARES_PRODUTIVOS = "Produtivos (já enviaram inv): {count}"
DIAG_SECTION_CONEXOES = "🔗 Conexões — detalhe"
DIAG_NO_CONNECTIONS = "Nenhuma conexão. Verifique a internet ou o proxy."
DIAG_TABLE_HEADER = (
    "Host:porta              Ver  Stream  Serv  Nota  Relógio          "
    "Inv  Idade  Estado"
)
DIAG_TABLE_SEPARATOR = (
    "────────────────────────────────────────────────────────────────────────"
)
DIAG_LEGEND = "Legenda: 🟢 ok · 🟡 negociando/silencioso · 🔴 divergente/erro"
DIAG_CONNECTION_ROW = (
    "{host_port:<19} {version:>4}  {streams:<6} {services:>4} "
    "{rating:>4}  {clock:<14} {inv:>4} {age:>5}s  {status}"
)
DIAG_CLOCK_DIVERGENT = "relógio {offset:+d}s (DIVERGENTE: ajuste o relógio!)"
DIAG_CLOCK_OK = "relógio {offset:+d}s"
DIAG_CLOCK_UNKNOWN = "relógio ?"

# -- Estado humano ---------------------------------------------------------

STATE_PARADO = "🔴 Rede parada — clique para reconectar ou verifique as configurações"
STATE_PROCURANDO = (
    "🟡 procurando pares… {total} tentando · {known} conhecidos "
    "({backoff} em pausa) — girando a lista e re-consultando sementes DNS"
)
STATE_NEGOCIANDO = "🟡 Negociando com {total} par(es)… estabelecendo criptografia"
STATE_AGUARDANDO_INV = (
    "🟡 Conectado ({established}) mas aguardando inventário há {uptime} "
    "(par mudo há ~{silent}s é desconectado)"
)
STATE_SINCRONIZANDO = (
    "🔵 Sincronizando: {done} de {total} ({pending} pendentes) — {pct}% {bar}"
)
STATE_CONECTADO = "🟢 Conectado — {established} de {total} ativas"
STATE_CONECTADO_DETALHE = (
    "🟢 Conectado — {established} de {total} ativas · "
    "{stored} objetos · {peers} pares"
)
STATE_NENHUM_INV = "🟡 Conectado, mas nenhum inventário chegou ainda (0 invs em {uptime})"
STATE_RESYNC = "🔵 Re-sync: {pending} pendentes (há {elapsed}; pode levar minutos)"

# -- Statusbar -------------------------------------------------------------

STATUS_TOOLTIP_TEMPLATE = (
    "Rede: {established}/{total} ativas · {silent} silenciosas · "
    "{stored} objetos guardados ({pending} pendentes) · "
    "{peers} pares conhecidos ({backoff} em pausa, {productive} produtivos) · "
    "Tráfego ↑ {up} ↓ {down} · Proxy: {proxy} · Streams: {streams} · "
    "Ativo há {uptime}\nClique para abrir diagnóstico completo."
)
STATUS_CONNECTED_SIMPLE = "🟢 Conectado"
STATUS_POW_SUFFIX = " · PoW: {count} ativo(s)"

# -- Welcome ---------------------------------------------------------------

WELCOME_TITLE = "Bem-vindo ao bmchat — mensageiro P2P privado"
WELCOME_SUBTITLE_IDENTITY = (
    "Sua identidade é seu endereço Bitmessage. "
    "Funciona como um e-mail descentralizado e cifrado:"
)
WELCOME_EXPLAIN_ID = (
    "Quem tem seu endereço (BM-…) pode te enviar mensagens que só você lê. "
    "Cada identidade tem um par de chaves privadas — sem elas você perde tudo."
)
WELCOME_ADDRESS_LABEL = "📋 Seu endereço (compartilhe com seus contatos):"
WELCOME_NO_IDENTITY = "(crie uma identidade no menu ☰ → Nova identidade)"
WELCOME_COPY_HINT = (
    "Copie e envie por e-mail, QR ou mensagem. "
    "O destinatário precisa adicionar seu endereço como contato."
)
WELCOME_BACKUP_WARN = (
    "🔒 Backup essencial: Menu ☰ → Backup. Guarde em papel ou gerenciador "
    "de senhas. Se perder as chaves e o dispositivo, é IMPOSSÍVEL recuperar."
)
WELCOME_START_HINT = (
    "💬 Comece: clique em ✎ para adicionar um contato ou canal (#). "
    "Canais são grupos por nome (ex: #geral)."
)
WELCOME_NETWORK_HINT = "🌐 Rede: {connections} conexões | Proxy: {proxy} | {state}"
WELCOME_HELP_FOOTER = "Dica: a barra inferior mostra o estado da rede. Clique nela para diagnóstico."

# -- Tooltips --------------------------------------------------------------

TOOLTIP_HAMBURGER = "Menu principal — identidades, rede, backup e configurações"
TOOLTIP_SEARCH = "Buscar conversas — filtre por nome ou endereço (Ctrl+F)"
TOOLTIP_FAB = "Nova conversa — adicionar contato ou canal (Ctrl+N)"
TOOLTIP_IDENTITY_MENU = "Identidade usada para enviar — clique para trocar"
TOOLTIP_NEW_IDENTITY = "Criar nova identidade (novo endereço BM-…)"
TOOLTIP_BACKUP = "Backup — exportar chaves privadas com segurança"
TOOLTIP_MANAGE_ID = "Gerenciar identidades — renomear, desativar ou excluir"
TOOLTIP_IDENTITY_AVATAR = "Seu avatar — clique para copiar o endereço"
TOOLTIP_IDENTITY_COPY = "Clique para copiar seu endereço (BM-…)"
TOOLTIP_BADGE = "Identidade atual — clique para copiar"
TOOLTIP_ATTACH = "Anexar arquivo — até 1 MB, será cifrado junto à mensagem"
TOOLTIP_EMOJI = "Inserir emoji"
TOOLTIP_SEND = "Enviar mensagem (Enter). Shift+Enter = nova linha"
TOOLTIP_SCHEDULE = "Agendar envio — escolher data e hora futura"
TOOLTIP_JUMP = "Ir para o fim — novas mensagens"
TOOLTIP_WELCOME_COPY = "Copiar meu endereço — compartilhe com quem vai te escrever"
TOOLTIP_STATUSBAR = "Estado da rede — clique para abrir diagnóstico completo"

# -- Chat header -----------------------------------------------------------

CHAT_STATUS_PUBKEY_KNOWN = "✔ Criptografia pronta — mensagens são cifradas ponto-a-ponto"
CHAT_STATUS_AWAITING_PUBKEY = "⏳ Buscando chave pública… mensagens ficam em espera até encontrar o par"
CHAT_STATUS_CHANNEL = "📢 Canal Bitmessage (broadcast) — todos os inscritos recebem"
CHAT_STATUS_GENERIC = "{address}"

# -- Message ticks / status texts -----------------------------------------

TICK_STATUS_ACKRECEIVED = "Entregue — confirmação (ACK) recebida do destinatário"
TICK_STATUS_SENT = "Publicada na rede — aguardando confirmação (ACK) do destinatário"
TICK_STATUS_AWAITING = (
    "Aguardando chave pública do destinatário — buscando na rede P2P (pode levar minutos)"
)
TICK_STATUS_SENDING = "Enviando — calculando prova de trabalho (PoW) e publicando na rede"
TICK_STATUS_ACKFAILED = (
    "Sem confirmação (ACK não recebido antes da expiração) — o destinatário "
    "pode não ter recebido. Clique com o botão direito → Reenviar (até 3 tentativas)."
)
TICK_STATUS_RECEIVED = "Recebida"
TICK_STATUS_RECEIVED_READ = "Recebida e lida"

# -- Flash messages --------------------------------------------------------

FLASH_MSG_RECEIVED = "📩 Nova mensagem recebida"
FLASH_BROADCAST = "📢 Nova postagem no canal"
FLASH_PUBKEY_RECEIVED = "🔑 Chave pública recebida e validada"
FLASH_ACK_RECEIVED = "✔ Mensagem entregue — confirmação (ACK) recebida"
FLASH_POW_PROGRESS = "⛏ PoW {token}: {rate:.0f} hashes/s"
FLASH_POW_CANCELLED = "⛏ PoW cancelado"
FLASH_COPY_ADDRESS = "Endereço copiado: {short}"
FLASH_COPY_TEXT = "Texto copiado"
FLASH_COPY = "Copiado"
FLASH_IDENTITY_SWITCH = "Enviando como {label} ({short})"
FLASH_IDENTITY_RENAMED = "Identidade renomeada para {label}"
FLASH_IDENTITY_ENABLED = "Identidade ativada: {label}"
FLASH_IDENTITY_DISABLED = "Identidade desativada; enviando como {label}"
FLASH_IDENTITY_DELETED = "Identidade excluída; enviando como {label}"
FLASH_RETRYING = "Reenviando mensagem…"
FLASH_REPLYING = "Respondendo… escolha o destinatário se for encaminhar"
FLASH_FORWARD_READY = "Mensagem pronta para encaminhar — selecione o destinatário"
FLASH_MESSAGE_DELETED = "Mensagem excluída"
FLASH_ATTACH_READY = "Anexo pronto ({name}) — digite uma mensagem opcional e envie."
FLASH_EMPTY_MESSAGE = "Digite uma mensagem antes de enviar."
FLASH_MSG_SENT = "✉ Mensagem enviada — publicada na rede, aguardando confirmação"
FLASH_CHANNEL_SENT = "📢 Mensagem enviada ao canal — será disseminada aos inscritos"
FLASH_SCHEDULED = "Mensagem agendada para {when}"
FLASH_THEME_CHANGED = "Tema alterado para {name}"
FLASH_DIAG_SENT = "Diagnóstico enviado ao suporte"
FLASH_FALLBACK_IDENTITY = "Identidade anterior não encontrada; usando {label} (sem popup)"
FLASH_SELECT_IDENTITY = "Selecione uma identidade"
FLASH_SELECT_POW = "Selecione um POW para cancelar"
FLASH_POW_CANCEL_ASK = "POW {token}: cancelamento pedido"
FLASH_POW_CANCEL_ALL = "Cancelando {count} POW(s)…"
FLASH_UPDATE_CHECKING = "Verificando atualizações…"
FLASH_UPDATE_DONE = "Atualizado! Reiniciando…"
FLASH_ADDRESS_COPIED_SIMPLE = "Endereço copiado"
