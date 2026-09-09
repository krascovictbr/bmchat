## CVE-2024-23342
- ID: CVE-2024-23342
- Descrição: Ataque de temporização Minerva contra a curva P-256 no pacote ecdsa via `SigningKey.sign_digest()`; a medição do tempo de assinatura vaza o nonce interno e pode revelar a chave privada. Verificação de assinatura não é afetada; sem correção planejada (canais laterais fora do escopo do projeto).
- Impacto: Nenhum no bmchat: o app usa exclusivamente secp256k1 (`bmchat/crypto/ecc.py`), nunca P-256 nem `sign_digest()`; o NVD lista como vulneráveis apenas versões até 0.18.0 (instalado 0.19.2); o ataque exige medição de tempo local de alta precisão, impraticável contra assinaturas locais esporádicas. Risco residual documentado como aceito.
- Nota CVSS: 7.4 Alta — CVSS 3.1 `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N`

## CVE-2019-14859
- ID: CVE-2019-14859
- Descrição: O ecdsa antes de 0.13.3 aceitava assinaturas malformadas sem verificar a codificação DER, tornando a assinatura maleável e permitindo forjar transações.
- Impacto: Nenhum no bmchat: corrigido em 0.13.3; instalado 0.19.2.
- Nota CVSS: 9.1 Crítica — CVSS 3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`

## CVE-2019-14853
- ID: CVE-2019-14853
- Descrição: O ecdsa antes de 0.13.3 levantava exceções inesperadas (ou nenhuma) ao decodificar assinaturas DER malformadas, permitindo negação de serviço.
- Impacto: Nenhum no bmchat: corrigido em 0.13.3; instalado 0.19.2. O `verify_signature` próprio ainda captura `Exception` por decoder como defesa em profundidade.
- Nota CVSS: 7.5 Alta — CVSS 3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`

## CVE-2026-33936
- ID: CVE-2026-33936
- Descrição: O ecdsa antes de 0.19.2 aceitava DER truncado em `der.remove_octet_string()`; uma chave privada DER maliciosa fazia `SigningKey.from_der()` levantar exceção interna em vez de rejeitar de forma limpa, permitindo negação de serviço a quem processa chaves DER não confiáveis.
- Impacto: Nenhum no bmchat: corrigido em 0.19.2 (versão instalada e novo piso do `requirements.txt`); o app nunca chama `from_der` com entrada não confiável.
- Nota CVSS: 5.3 Média — CVSS 3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L`

## CVE-2023-52323
- ID: CVE-2023-52323
- Descrição: PyCryptodome e pycryptodomex antes de 3.19.1 permitiam vazamento por canal lateral na descriptografia OAEP, explorável para um ataque de Manger.
- Impacto: Nenhum no bmchat: instalado 3.23.0; o app nunca usa OAEP (usa ECIES próprio com AES-256-CBC via `Crypto.Cipher.AES`).
- Nota CVSS: 5.9 Média — CVSS 3.1 `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N`

## CVE-2018-15560
- ID: CVE-2018-15560
- Descrição: PyCryptodome antes de 3.6.6 tinha estouro de inteiro na variável `data_len` em AESNI.c, tratando mal mensagens menores que 16 bytes.
- Impacto: Nenhum no bmchat: instalado 3.23.0, fora da faixa afetada.
- Nota CVSS: 7.5 Alta — CVSS 3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`

## CVE-2025-48379
- ID: CVE-2025-48379
- Descrição: O Pillow de 11.2.0 até antes de 11.3.0 tinha estouro de buffer no heap ao salvar imagem grande em formato DDS comprimido, sem checar o espaço do buffer.
- Impacto: Nenhum no bmchat: instalado 11.3.0, que já contém a correção; o app nunca salva DDS.
- Nota CVSS: 7.1 Alta — CVSS 3.1 `AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H`

## CVE-2026-25990
- ID: CVE-2026-25990
- Descrição: O Pillow de 10.3.0 até antes de 12.1.1 permitia escrita fora dos limites ao carregar imagem PSD maliciosa.
- Impacto: Afetava o bmchat: decoder PSD alcançável via `Image.open().load()` em bytes de anexo vindos de peer. Corrigido com `Pillow>=12.3.0` no `requirements.txt` mais allowlist de formatos de prévia (`ALLOWED_PREVIEW_FORMATS`).
- Nota CVSS: 7.5 Alta — CVSS 3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`

## CVE-2026-40192
- ID: CVE-2026-40192
- Descrição: O Pillow de 10.3.0 até 12.1.1 não limitava dados GZIP ao decodificar imagem FITS, permitindo bomba de descompressão com consumo ilimitado de memória.
- Impacto: Afetava o bmchat: decoder FITS alcançável via `Image.open().load()` em bytes de anexo vindos de peer. Corrigido com `Pillow>=12.3.0` mais allowlist de formatos de prévia.
- Nota CVSS: 7.5 Alta — CVSS 3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`

## CVE-2026-42308
- ID: CVE-2026-42308
- Descrição: O Pillow antes de 12.2.0 podia sofrer estouro de inteiro ao acompanhar a posição corrente quando uma fonte avança por glifo em valor excessivo.
- Impacto: Nenhum direto no bmchat: APIs de fonte (`ImageFont`) nunca são chamadas; corrigido de qualquer forma pelo bump para `Pillow>=12.3.0`.
- Nota CVSS: 5.5 Média — CVSS 3.1 `AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H`

## CVE-2026-42309
- ID: CVE-2026-42309
- Descrição: O Pillow de 11.2.1 até antes de 12.2.0 aceitava listas aninhadas como coordenadas em APIs como `ImagePath.Path` e `ImageDraw.polygon`, com estouro de buffer.
- Impacto: Nenhum direto no bmchat: essas APIs nunca são chamadas; corrigido de qualquer forma pelo bump para `Pillow>=12.3.0`.
- Nota CVSS: 5.5 Média — CVSS 3.1 `AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H`

## CVE-2026-42310
- ID: CVE-2026-42310
- Descrição: O Pillow de 4.2.0 até antes de 12.2.0 travava o processo em 100% de CPU ao processar PDF malicioso.
- Impacto: Afetava o bmchat por precaução: o plugin PDF é registrado por padrão no `Image.open()`, que recebe bytes de peer. Corrigido com `Pillow>=12.3.0` mais allowlist de formatos de prévia.
- Nota CVSS: 5.5 Média — CVSS 3.1 `AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H`

## CVE-2026-42311
- ID: CVE-2026-42311
- Descrição: O Pillow de 10.3.0 até antes de 12.2.0 podia sofrer corrupção de memória (travamento ou execução arbitrária) ao processar arquivo PSD malicioso.
- Impacto: Afetava o bmchat: decoder PSD alcançável via `Image.open().load()` em bytes de anexo vindos de peer. Corrigido com `Pillow>=12.3.0` mais allowlist de formatos de prévia.
- Nota CVSS: 7.8 Alta — CVSS 3.1 `AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H`

## CVE-2026-54058
- ID: CVE-2026-54058
- Descrição: O Pillow antes de 12.3.0, ao carregar imagem McIdas AREA de um arquivo via mmap, aceitava stride menor que a largura real da linha, fazendo leituras além da região mapeada (vazamento de memória ou falha).
- Impacto: Nenhum direto no bmchat: o app abre imagens via `BytesIO`, sem nome de arquivo, de modo que o ramo mmap é inalcançável; corrigido de qualquer forma pelo bump para `Pillow>=12.3.0`.
- Nota CVSS: 9.1 Crítica — CVSS 3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H`

## CVE-2026-54059
- ID: CVE-2026-54059
- Descrição: O Pillow antes de 12.3.0 lia dimensões de glifo da seção METRICS de fonte PCF e alocava via `Image.frombytes()` sem checagem de bomba de descompressão (até 8,5 bilhões de pixels a partir de 148 bytes).
- Impacto: Nenhum direto no bmchat: `PcfFontFile` nunca é usado; corrigido de qualquer forma pelo bump para `Pillow>=12.3.0`.
- Nota CVSS: 7.5 Alta — CVSS 3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`

## CVE-2026-54060
- ID: CVE-2026-54060
- Descrição: O Pillow antes de 12.3.0 montava o bitmap combinado em `FontFile.compile()` com `Image.new()` sem checagem de bomba de descompressão.
- Impacto: Nenhum direto no bmchat: APIs de fonte nunca são usadas; corrigido de qualquer forma pelo bump para `Pillow>=12.3.0`.
- Nota CVSS: 7.5 Alta — CVSS 3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`

## CVE-2026-55379
- ID: CVE-2026-55379
- Descrição: O Pillow antes de 12.3.0 lia `BBX width height` de fonte BDF e passava as dimensões a `Image.new()` sem checagem de bomba de descompressão.
- Impacto: Nenhum direto no bmchat: `BdfFontFile` nunca é usado; corrigido de qualquer forma pelo bump para `Pillow>=12.3.0`.
- Nota CVSS: 7.5 Alta — CVSS 3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`

## CVE-2026-55380
- ID: CVE-2026-55380
- Descrição: O Pillow antes de 12.3.0 lia dimensões do cabeçalho GD 2.x em `GdImageFile._open()` sem checagem de bomba de descompressão (4,3 GB a partir de 1037 bytes).
- Impacto: Nenhum direto no bmchat: `GdImageFile` nunca é usado; corrigido de qualquer forma pelo bump para `Pillow>=12.3.0`.
- Nota CVSS: 7.5 Alta — CVSS 3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`

## CVE-2026-55798
- ID: CVE-2026-55798
- Descrição: O Pillow antes de 12.3.0 montava comando `cmd.exe` em `WindowsViewer.get_command()` com o caminho do arquivo sem escape e `shell=True`, permitindo injeção de comandos.
- Impacto: Nenhum no bmchat: visualizadores externos nunca são chamados e o app roda em Linux.
- Nota CVSS: 4.5 Média — CVSS 3.1 `AV:L/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:L`

## CVE-2026-59197
- ID: CVE-2026-59197
- Descrição: O Pillow antes de 12.3.0 permitia escrita fora dos limites no heap via `ImageFilter.RankFilter` com tamanho de filtro ímpar muito grande, por aritmética sem checagem em `ImagingExpand()`.
- Impacto: Nenhum direto no bmchat: `RankFilter` nunca é usado; corrigido de qualquer forma pelo bump para `Pillow>=12.3.0`.
- Nota CVSS: 8.2 Alta — CVSS 3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H`

## CVE-2026-59198
- ID: CVE-2026-59198
- Descrição: O Pillow de 5.2.0 até 12.3.0 lia além do buffer de linha ao salvar imagem modo `1` com compressão TGA RLE, copiando bytes do heap para o arquivo gerado.
- Impacto: Nenhum no bmchat: o app nunca salva TGA; corrigido de qualquer forma pelo bump para `Pillow>=12.3.0`.
- Nota CVSS: 6.5 Média — CVSS 3.1 `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:L`

## CVE-2026-59199
- ID: CVE-2026-59199
- Descrição: O Pillow antes de 12.3.0 permitia escrita fora dos limites no heap via `Image.paste()`, `Image.crop()` e `Image.alpha_composite()` com coordenadas próximas aos limites do int32.
- Impacto: Nenhum direto no bmchat: o app nunca chama essas APIs com coordenadas de peer (só `thumbnail`/`resize` com tamanhos calculados); corrigido de qualquer forma pelo bump para `Pillow>=12.3.0`.
- Nota CVSS: 7.5 Alta — CVSS 3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`

## CVE-2026-59200
- ID: CVE-2026-59200
- Descrição: O Pillow de 5.1.0 até 12.3.0 chamava `zlib.decompress()` em `PdfParser.PdfStream.decode()` sem teto de saída (o `bufsize` é só dica inicial), permitindo OOM com ~950 KB de PDF.
- Impacto: Nenhum direto no bmchat: `PdfParser` nunca é usado; corrigido de qualquer forma pelo bump para `Pillow>=12.3.0`.
- Nota CVSS: 7.5 Alta — CVSS 3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`

## CVE-2026-59204
- ID: CVE-2026-59204
- Descrição: O Pillow de 8.2.0 até 12.2.0 acumulava `total_component_width` entre tiles na decodificação JPEG2000, forçando realocações até o tamanho da imagem e permitindo exaustão de memória.
- Impacto: Afetava o bmchat: decoder JPEG2000 alcançável via `Image.open().load()` em bytes de anexo vindos de peer. Corrigido com `Pillow>=12.3.0` mais allowlist de formatos de prévia.
- Nota CVSS: 7.5 Alta — CVSS 3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`

## CVE-2026-59205
- ID: CVE-2026-59205
- Descrição: O Pillow antes de 12.3.0 permitia corrupção de heap em `ImageCmsTransform.apply()` quando a imagem de saída tinha modo diferente do declarado no transform (o LittleCMS escrevia linhas RGBA em linha de 1 byte por pixel).
- Impacto: Nenhum direto no bmchat: `ImageCms` nunca é usado; corrigido de qualquer forma pelo bump para `Pillow>=12.3.0`.
- Nota CVSS: 7.5 Alta — CVSS 3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`

## CVE-2025-4517
- ID: CVE-2025-4517
- Descrição: O módulo `tarfile` do CPython permitia escrita arbitrária fora do diretório de extração com `filter="data"` (padrão no 3.14+), via `extractall()`/`extract()` em tars não confiáveis.
- Impacto: Nenhum no bmchat: `tarfile` nunca é usado.
- Nota CVSS: 9.4 Crítica — CVSS 3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L`

## CVE-2026-7210
- ID: CVE-2026-7210
- Descrição: `xml.parsers.expat` e `xml.etree.ElementTree` usavam entropia insuficiente na proteção contra hash-flooding do Expat, permitindo DoS com XML malicioso (mitigação total exige libexpat 2.8.0+).
- Impacto: Nenhum no bmchat: instalado 3.14.7, fora da faixa afetada (3.14.0 até antes de 3.14.6); o app nunca processa XML.
- Nota CVSS: 7.5 Alta — CVSS 3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`

## CVE-2026-15308
- ID: CVE-2026-15308
- Descrição: O `html.parser.HTMLParser` incremental permitia DoS de CPU com declarações de markup não terminadas repetidas em dados não controlados.
- Impacto: Nenhum no bmchat: instalado 3.14.7, fora da faixa afetada (3.14.0 até antes de 3.14.7); `html.parser` nunca é usado.
- Nota CVSS: 7.5 Alta — CVSS 3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`

## CVE-2026-0865
- ID: CVE-2026-0865
- Descrição: Nomes e valores de cabeçalhos HTTP controlados pelo usuário com quebras de linha permitiam injetar cabeçalhos HTTP.
- Impacto: Nenhum no bmchat: o app não usa cliente HTTP nem monta cabeçalhos com entrada externa.
- Nota CVSS: 5.9 Média — CVSS 4.0 `AV:N/AC:L/AT:P/PR:H/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N`

## CVE-2026-1299
- ID: CVE-2026-1299
- Descrição: O `BytesGenerator` do módulo `email` não citava newlines de cabeçalhos ao serializar mensagens, permitindo injeção de cabeçalhos com `LiteralHeader` mal dobrados.
- Impacto: Nenhum no bmchat: o módulo `email` nunca é usado.
- Nota CVSS: 6.0 Média — CVSS 4.0 `AV:N/AC:L/AT:P/PR:L/UI:N/VC:L/VI:H/VA:N/SC:N/SI:N/SA:N`

## CVE-2026-3276
- ID: CVE-2026-3276
- Descrição: `unicodedata.normalize()` consumia CPU excessiva com entradas de combining characters longas e alternadas, em todas as formas de normalização.
- Impacto: Nenhum no bmchat: `unicodedata.normalize` nunca é chamado.
- Nota CVSS: 6.3 Média — CVSS 4.0 `AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N`

## CVE-2026-2297
- ID: CVE-2026-2297
- Descrição: O hook de importação de `.pyc` legados (`SourcelessFileLoader`) não usava `io.open_code()`, de modo que handlers de auditoria `sys.audit` não disparavam.
- Impacto: Nenhum no bmchat: o app não usa hooks `sys.audit`.
- Nota CVSS: 5.7 Média — CVSS 4.0 `AV:L/AC:L/AT:P/PR:L/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N`

## CVE-2021-35331
- ID: CVE-2021-35331
- Descrição: Vulnerabilidade de format string em `nmakehlp.c` do Tcl 8.6.11 via arquivo malicioso; significância disputada por terceiros.
- Impacto: Nenhum no bmchat: instalado Tcl 8.6.16, fora da única versão afetada (8.6.11); é helper de build Windows, não runtime do Tk.
- Nota CVSS: 7.8 Alta — CVSS 3.1 `AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H`
