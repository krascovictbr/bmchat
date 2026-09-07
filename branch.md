# Changelog — branch `ui-optimization`

Registro das atualizações vindas do branch `ui-optimization`
(merge fast-forward `57a0d15` em `rolling-release`, 2026-09-07;
base `a247655`). Formato: Adicionado / Mudado / Corrigido.

## [ui-optimization] — 2026-09-07

### Adicionado
- Paginação do chat: últimas 200 mensagens + pílula "carregar mensagens
  anteriores" (+200 por clique).
- Cache de quebra de linha `(texto, largura)`, cap 500 FIFO.
- Debounce de 80 ms no hover e no redimensionar da lista de conversas.
- Coalescing de eventos de mensagem (200 ms) e limite de 1 atualização/s
  no progresso do PoW.
- Scrollbar visível na lista de conversas.
- `transient(parent)` nos 7 popups próprios.
- Foco no campo de texto ao abrir conversa; placeholder "Mensagem" com
  restauração ao perder o foco.
- Consentimento explícito no envio de diagnóstico ao suporte (checkbox
  destrava o Enviar).
- Singleton no popup de emoji.
- `messages_for_conversation(address, limit=None)` no banco (default
  preserva o comportamento antigo).
- Validação no envio: identidade obsoleta e contato removido avisam em vez
  de criar mensagem fantasma/órfã; rascunho limpo ao trocar de conversa.
- Menus dispensam em qualquer clique fora; removidos menubar nativo e botão
  `⋮` (só hambúrguer ☰); entrada "Verificar POW ativos" no hambúrguer.
- Diálogos com esqueleto comum, foco inicial, Enter/Escape, centralização,
  scrollbar e altura dinâmica no `choose`, abertura sem cintilação e grab
  sempre liberado.

### Mudado
- Redraw do chat: pula relayout se a largura não mudou; doodle só no
  viewport (era até 6000 px).
- `_fit_width` com busca binária; prévia da conversa e não-lidas com menos
  queries (1 `GROUP BY` + `LIMIT 1`).
- Placeholder em português; fonte do welcome reutilizada em vez de recriada.
- `_poll` mostra erro de handler conhecido e ignora evento malformado sem
  matar o loop.
- Diálogo de diagnóstico/backup/log/rede: rodapé de botões empacotado
  primeiro (botões sempre visíveis).
- Tela de suporte e backup com botão "Enviar diagnóstico".

### Corrigido
- Palavra gigante sem espaço congelava a interface (`_wrap_lines` O(n²) →
  ~4 medições por trecho).
- Índice de seleção obsoleto quebrava ao abrir conversa.
- Mensagem de checksum errado inalcançável (código real `'checksumfailed'`).
- "Verificar POW" contava conexões ainda negociando (agora só estabelecidas).
- Códigos de atualização em inglês cru traduzidos.
- `db.close()` duplo levantava exceção.

### Verificação
- `pytest tests/ -q`: **24 passed**.
- Smokes Tkinter: paginação (250 msgs → 1907 itens), hover, scrollbar,
  envio, 71 checks de diálogos, consentimento, menus, startup e fechamento
  sem erros de callback.
- Medido: redraw 500 msgs 1382 ms → 216 ms; lista 100 conversas 1062 ms →
  682 ms; preview 20 conversas ~99 ms → ~19 ms.
