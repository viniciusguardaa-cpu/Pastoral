# Audit Pastoral — revisão de código (sem compilar) — 2026-10-16

Legenda: [FUNCIONA] implementado e plausível de ponta a ponta · [PARCIAL] funciona com ressalva/escopo limitado · [STUB] existe mas inativo/usado só parcialmente · [BUG] defeito concreto ou provável

## 1. Proxy transparente

| Status | Item | Onde | Justificativa |
|---|---|---|---|
| [FUNCIONA] | pf rdr 80/443 → 127.0.0.1:8080 | `Sources/PastoralCore/ARPSpoofPlan.swift:168`; aplicado em `Sources/PastoralHelper/main.swift:369` | `rdr pass on <iface> inet proto tcp ... port {80,443} -> 127.0.0.1 port 8080` + âncora `pastoral-sheep`, aplicado/desaplicado via pfctl pelo helper root. |
| [FUNCIONA] | Listener NWConnection + delegate próprio | `Sources/PastoralProxy/TransparentProxy.swift:31-76` | `NWListener` em 127.0.0.1:8080; despacho por primeiros bytes: prefixo `CONNECT `, SNI direto (`looksLikeTLS`), senão HTTP puro. |
| [FUNCIONA] | Decisão por CONNECT / SNI / plaintext | `TransparentProxy.swift:60-76`, `527-538` | TLS redirecionado sem CONNECT detectado por bytes `16 03 xx`; SNI extraído com parser próprio de ClientHello (com extensão server_name ausente → nil). |
| [FUNCIONA] | CONNECT → 200 + MITM ou túnel | `TransparentProxy.swift:256-296` | Lê o ClientHello antes de decidir; com CA → intercepta (MITM); sem CA → túnel com SNI capturado só p/ diagnóstico. |
| [PARCIAL] | HTTP puro: captura completa | `TransparentProxy.swift:118-190` | Corpo de **request** só via Content-Length — POST `chunked` chega truncado; resposta capturada (sem rewrite) corta o corpo no ponto de decisão e chunked fica codificado. Aceitável p/ triagem, incompleto como HAR. |
| [PARCIAL] | HTTPS-via-SNI | `Sources/PastoralProxy/TLSInterceptor.swift:143-230` | Código real (listener TLS efêmero com leaf do SNI, túnel de volta ao origin espelhando versão/ciphers do hello, fallback p/ túnel em falha) **mas `caManager` é sempre nil** — ver §2. Na prática o sheep só faz túnel. |
| [RISCO] | Força TCP cegando QUIC | `ARPSpoofPlan.swift:174` | `block return out quick on <iface> proto udp ... port 443` para hosts desviados: quebra cliente QUIC-only e adiciona penalidade de retry por domínio mesmo nos que caem pra TCP. |

## 2. CA própria

| Status | Item | Onde | Justificativa |
|---|---|---|---|
| [STUB] | Gerar/assinar CA no app | `Sources/Pastoral/Support/AppState.swift:~1130` (proxy criado sem CA); grep `caManager=` em `Sources/Pastoral` → 0 hits | O motor MITM inteiro está adormecido: nenhum fluxo cria `CAManager`, nenhum botão instala a raiz, nenhum painel Trust. `MobileConfig.swift` gera perfil `.mobileconfig` mas ninguém o chama. |
| [FUNCIONA]* | Mecânica da CA em si | `Sources/PastoralCore/CAManager.swift:42-216` | *Se instanciada*: RSA-2048 via openssl + Keychain (`kSecAttrIsPermanent`), CA 3650 dias, leaf por SNI com SAN `DNS:<sni>` válido 365 dias, cache `.der/.key` em `~/Library/Application Support/Pastoral/leaves`, SecIdentity em memória via PKCS#12. `installTrust`/`removeTrust`/`isTrusted` via `security add-trusted-cert` no System.keychain. |
| [BUG] | Cabeçalho PEM errado | `CAManager.swift:200-215` (`leafIdentityFromFiles`) | `SecKeyCopyExternalRepresentation` devolve tipicamente **PKCS#8**, mas o código embuta em "BEGIN RSA PRIVATE KEY" (PKCS#1) — openssl rejeita; leaf então cai no caminho `generateLeaf` (sem erro visível?). Mesmo risco na importação da key da CA (`CAManager.swift:183`). |
| [BUG] | Cache de leaf sem checagem de expiração | `CAManager.swift:382-385` + uso em `secIdentity(for:)` | Cache considerado válido só pela existência dos arquivos; certificado expirado (>365d) continua servido. |
| [RISCO] | SNI interpolado em shell | `CAManager.swift:162,166` | SNI entra crú no comando openssl via `/bin/sh` — caractere estranho quebra ou injeta; `identityCache` sem limite (cresce com nº de SNIs distintos). |

## 3. HTTP/2

| Status | Item | Onde | Justificativa |
|---|---|---|---|
| [PARCIAL] | Implementação manual | `Sources/PastoralCore/HTTP2.swift` | Só **decode**: parser de frames (9-octet, todos os tipos) + HPACK-lite (tabela estática de 61, literal c/sem índice, size-update; strings Huffman viram `nil`). Sem encoder, sem estado de stream/janela. Suficiente p/ navegar porque o proxy força ALPN `http/1.1` nos dois sentidos (`TLSInterceptor.swift:206-207` e `originTLSParameters` em `TransparentProxy.swift:399`) — navegador degrada. Preface h2 em plaintext é logado como diag `h2_preface` e o stream é descartado (`TransparentProxy.swift:123-129`). |

## 4. Inject

| Status | Item | Onde | Justificativa |
|---|---|---|---|
| [FUNCIONA] | Substituição de imagens HTML | `Sources/PastoralCore/ContentRewriter.swift:44-150` | Regex `<img ...>` (inclui `srcset`), escopo global/sufixo-de-domínio/regex-de-path, dimensões esperadas via query `w=/h=/width=/height=` ou padrão `WxH` no path, re-escrita de headers (tira etag/cache/CL/TE, `Connection: close`), buffer máx. 25 MB com fallback passthrough. |
| [FUNCIONA] | Rotação + preservação de dimensão | `ContentRewriter.swift:152-190`, `Sources/PastoralProxy/InjectionEngine.swift:38-70` | `ImagePool` round-robin sob NSLock (troca quente via `configure/disable`), `resizer` opcional reencoda na dimensão esperada (SVG/GIF passam crus). |
| [PARCIAL] | Escopo efetivo | `InjectionEngine.swift` + `AppState.swift:~1130` | Injeção só acontece onde o proxy reescreve: **HTTP sempre; HTTPS apenas se o alvo confiar na CA** — e o app não cria nem instala a CA (§2). O texto no InjectTabView ("HTTPS só é reescrito em alvos que confiam na CA Pastoral") promete um fluxo que o usuário não consegue ativar. |
| [RISCO] | Regex de usuário sobre path | `ContentRewriter.swift` (scope `.pathPattern`) | ReDoS com padrão patológico — aceitável em contexto LAN pentest, vale documentar. |

## 5. Camera

| Status | Item | Onde | Justificativa |
|---|---|---|---|
| [FUNCIONA] | ONVIF discovery | `Sources/Pastoral/Services/OnvifProbe.swift:20-123` | WS-Discovery `Probe` em multicast 239.255.255.250:3702 + broadcast 255.255.255.255, timeout 150 ms, janela 2,5 s com segunda rodada genérica, dedupe por endpoint/xaddr. |
| [FUNCIONA] | ONVIF → URI do stream | `Sources/Pastoral/Services/OnvifClient.swift:36-190` | SOAP GetCapabilities → mediaXAddr → GetProfiles → GetStreamUri por perfil, com auth HTTP Digest (MD5) reusando `RTSPAuth`; bota fora no primeiro transporte falho dentro do loop de credenciais. |
| [FUNCIONA] | RTSP snapshot | `Sources/Pastoral/Services/RTSPSnapshotClient.swift:91-332` | DESCRIBE→401→retry de credenciais→SETUP interleaved→PLAY, RTP com resync por scan, JPEG-over-RTP com strip de restart markers RFC 2435 + fallback DQT com Q≥128; track H.264/H.265 cai em snapshot HTTP (6 caminhos: Axis/Dahua/Hikvision/ISAPI genérico); FFD8 check, teto 4 MB. |
| [FUNCIONA] | Stream H.264 live | `Sources/Pastoral/Services/RTSPStreamClient.swift:300-387`, `Sources/Pastoral/Services/H264Decoder.swift:187-263` | Reassembly RFC 6184 (single NAL 0-23, STAP-A 24, FU-A 28; STAP-B/FU-B ignorados) → VideoToolbox com format description a partir de SPS/PPS, pré-buf de 50 NALs. Loop JPEG live também funcional (RFC 2435 no RTP). |
| [STUB] | H.265/HEVC live | `RTSPStreamClient.swift:~290` | Erro explícito: "H.265/HEVC não suportado para live ainda" (snapshot ainda tenta via HTTP). |
| [FUNCIONA] | camera_passwords.txt | `Sources/Pastoral/Resources/camera_passwords.txt` (770 linhas), carregado em `Sources/Pastoral/Support/AppState.swift:120-131` | Wordlist usada pelo botão "Força" (brute force de credenciais), além de `defaultCameraCredentials` e `commonStreamPaths` hardcoded — coerente com o domínio. |
| [PARCIAL] | Brute force | `RTSPStreamClient.swift` / `RTSPSnapshotClient.swift` | Sério (1 credencial de cada vez — lento com 770 palavras × câmeras) e heurística de lockout após **3 erros de transporte consecutivos** desiste cedo demais em câmera instável/ocupada; sem backoff. |
| [BUG] | OUI cruzado câmera ↔ TV | `CameraDetector.swift` + `TVDetector.swift` | Keywords "sony", "panasonic", "flir" estão nas **duas** listas → TV da Sony aparece na aba Câmera (e vice-versa) pelo match de vendor via OUI. |

## 6. Bugs visíveis e riscos (fora das seções acima)

| Status | Item | Onde | Justificativa |
|---|---|---|---|
| [BUG] | Body chunked de request perdido | `TransparentProxy.swift:148-149` | `buffer.bodyBytes` decidido só por Content-Length → POST `Transfer-Encoding: chunked` é encaminhado sem corpo. |
| [BUG] | Replay corrompe corpo binário | `Sources/PastoralCore/ReplayBuilder.swift:32-34` | `String(data:encoding:.utf8)` e re-encode: imagem/PDF/replay binário vira lixo com replacements de ??. |
| [BUG] | 200 antes do upstream | `TransparentProxy.swift:258-261` | "Connection Established" vai pro cliente antes do resolve/conecta; DNS ruim = 200 seguido de reset. Cosmético p/ navegação, engana clientes rígidos. |
| [RISCO] | Listener MITM publicado em todas as interfaces | `TLSInterceptor.swift:~159` | `NWListener(using: tls, on: .any)` por intercepção: porta efêmera visível na LAN; qualquer host pode ligar ali e ver a leaf (e, se chegar antes da vítima, furar o `newConnectionLimit(1)`). Deveria ser 127.0.0.1/loopback local. |
| [RISCO] | Spin-loop na handshake probe | `TLSInterceptor.swift:37-45` | `while case .waiting = receive(...)` lendo 1 byte por iteração até o fim da handshake — busy-wait que segura a fila serial do proxy. |
| [RISCO] | Fila única serial no proxy | `TransparentProxy.swift:29` | Todos os callbacks de todas as conexões num `DispatchQueue` só; uma escrita que trava (buffer TCP cheio) estagna callbacks de todas as outras conexões. Ok p/ poucos hosts, gargalo em rede ocupada. |
| [BUG/perf] | CIContext por frame + sem pacing | `H264Decoder.swift:~266`, `243-247` | `CIContext()` novo a cada frame dentro do callback C; `CMSampleTimingInfo` todo `.invalid` → frames chegam na velocidade da rede, sem cadência CFR. |
| [RISCO] | Replay aceita qualquer certificado | `Sources/Pastoral/Services/ReplayClient.swift` (verify_block ~l.44) | `completion(true)` no replay TLS: fine p/ debug, mas faz o replay "passar" mesmo em mismatch de cert que seria sinal importante. |
| [RISCO] | ONVIF XML via regex | `Sources/PastoralCore/Onvif.swift` | Scanneres de regex sobre SOAP/XML quebram com namespaces incomuns/ordem de atributos — discovery já filtra responderes não-ONVIF, mas parsing frágil fica silenciosamente sem URI. |
| [NOTE] | Digest MD5 only | `Sources/PastoralCore/RTSPAuth.swift:77-139` | SHA-256 não suportado (documentado no comentário); câmera que exija `algorithm=SHA-256` não passa. |
| [FUNCIONA] | InterceptDecision (escopo por host) | `Sources/PastoralCore/InterceptDecision.swift:30-44` | Filtro limpo selectedIDs ∧ ¬excluded — coerente com o KillTab. |
| [FUNCIONA] | Helper IPC | `Sources/Pastoral/Services/HelperClient.swift:21-99` | Socket Unix + JSON por linha, conexão dedicada por stream (QUIC/mDNS), timeout 2 s; robusto. |
| [FUNCIONA] | Túnel WireGuard/Tailscale | `Sources/PastoralCore/TunnelConfig.swift:15-58` | Render de `wg-quick`/args Tailscale + validadores (CIDR, endpoint, key base64 44 chars). |

## Veredito curto

O núcleo que o app **efetivamente oferece hoje** funciona: pf rdr, proxy transparente, captura HTTP completo, túnel HTTPS com visibilidade de SNI, injeção em HTTP, e o pacote Camera (ONVIF+RTSP+H.264+wordlist) é o mais acabado do projeto. A camada MITM (CA + intercept TLS + rewrite HTTPS) está **escrita de verdade mas desligada**: falta um botão "Instalar CA" ligando `CAManager` → `proxy.caManager`, e esse é o maior gap entre o README/UX prometido e o que roda. Bugs concretos mais urgentes: PEM PKCS#8 rotulado de PKCS#1 na CA, cache de leaf sem expiração, POST chunked sem body no proxy, binary-corrupt no Replay, e CIContext-per-frame no decoder.

## 9. Correções aplicadas — 2026-10-16 (auditoria executada + build + 202 testes)

| # | Bug do relatório | Arquivo | Correção |
|---|---|---|---|
| 1 | §2 MITM adormecido (caManager sempre nil) | `Pastoral/Support/AppState.swift`, `Pastoral/Views/SheepTabView.swift` | Proxy agora criado com CAManager real; botão "CA" na toolbar da Ovelha instala/remove a raiz no System.keychain via novos verbos `ca.trust.install`/`ca.trust.remove` do helper (root). |
| 2 | §2 PEM PKCS#8 em header "RSA PRIVATE KEY" | `PastoralCore/CAManager.swift` | Headers viraram `BEGIN PRIVATE KEY` (4 sites); SNI validado antes de tocar openssl (`validateSNI`, hostnames de caractere simples, len ≤ 253). |
| 3 | §2 Cache de leaf sem expiração | `CAManager.swift` | Sidecar `<sni>.der.exp` com expiração ISO-8601; cache só aceito dentro da validade. |
| 4 | §1 CONNECT respondido antes do SNI | `PastoralProxy/TLSInterceptor.swift`, `TransparentProxy.swift` | Handler CONNECT lê ClientHello antes do 200; sem CA → túnel cego ao origin (SNI) mantendo a captura; 502 em falha. |
| 5 | §1 chunked truncado nos requests | `TransparentProxy.swift` | Parser de framing chunked; request só encaminhado quando o corpo termina (terminator 0 + CRLF). |
| 6 | §8 pf multi-alvo: âncora sobrescrita alvo a alvo | `PastoralHelper/PFManager.swift` | `addDropRule` reescreve um único conf canônico com **todos** os alvos ativos + um só `pfctl -f`; novo `removeDropRule(for:)` cirúrgico; alvos persistem em `/var/db/pastoral/kill.targets` e sobrevivem a restart do helper. |
| 7 | §8 restore com remove-before-copy | `PFManager.swift` | Copia para `/etc/pf.conf.pastoral.new` e só então move por cima; falha de copy não apaga o pf.conf vivo. |
| 8 | §8 spoof.stop: restore enviado na thread que está parando | `PastoralHelper/ARPSpoofer.swift` | `stopSpoof` cancela a thread, espera ela sair (bound 1s) e só então envia os frames de restore; restart do alvo usa o mesmo caminho sem esperar. |
| 9 | §8 spoof.stop derrubava regra de outro alvo / desligava forwarding no meio de outro alvo | `PastoralHelper/main.swift` | `killTargets` + `divertTargets` separados; stop remove só a regra do IP parado; forwarding fica ON enquanto houver divert, volta ao estado anterior só quando killTargets vazio. |
| 10 | §10 priorState de forwarding pisado | `PastoralHelper/ForwardingManager.swift` | Estado anterior gravado só no primeiro enable. |
| 11 | §6 socket 0666 root | `main.swift` `applySocketPerms` | Com grupo `access_bpf`: 0660 root:access_bpf (chmod depois de unlink → modo novo de fato aplicado). Sem grupo: 0666 (compat com instalador atual). |
| — | Listener TLS fixo em 127.0.0.1 (rdr entrega em iface) | `TLSInterceptor.swift` | Voltou para `.any` (wildcard aceita as conexões de 127.0.0.1 que o rdr entrega); comentado no código — `NWEndpoint.Port` não tem init host+port. |

### Artefatos gerados
- `dist/pastoral-helper.pkg` (novo) · `dist/Pastoral.app` (novo)
- `Scripts/update-installed.sh` — instala helper, troca o .app, reinicia o daemon e confere o socket, tudo num `sudo`.

### Pendências conhecidas (não corrigidas, por escopo)
- QUIC: hosts desviados têm UDP/443 bloqueado para forçar TCP-fallback (comportamento projetado, documentado em `QUICParser.swift`); se algum cliente só falar QUIC ele cai da rede até cair no fallback.
- Sem grupo `access_bpf` nesta máquina → socket continua 0666 até criar o grupo no Instalador.
- Perfil `.mobileconfig` (MobileConfig.swift) ainda sem caller — botão novo cobre instalação direta no System.keychain via helper root.

## 10. Camada Lobo — auditoria (2026-10-21)

Escopo: WiFi hound (scan/deauth/captura BPF), parser EAPOL + linhas hashcat, portal cativo + colheita de credenciais, armadilha de CA, Modo Criminoso e persistência harvest. Base: `swift build` limpo e `swift test` 263/263; refs atuais do código.

### 10.1 Scan Wi-Fi

| Status | Item | Onde | Justificativa |
|---|---|---|---|
| [FUNCIONA] | Scan primary airport, fallback CoreWLAN | `PastoralHelper/WiFiHound.swift:138-146` (`run()`), `49-56` | `airport -I -s` com parser próprio; CoreWLAN `scanForNetworks` como fallback. |
| [BUG] | Segurança vazia no caminho CoreWLAN | `WiFiHound.swift:52` | `let sec = "" // CWNetwork não expõe segurança nesta API` — **expõe**: `CWNetwork.securityType` (`CWSecurity`); a tabela `securityLabel(_:)` logo abaixo no mesmo arquivo existe mas só é usada pelo scanner principal. Vizinhos via CoreWLAN aparecem sem criptografia. |
| [RISCO] | pipe lido depois de `waitUntilExit` | `WiFiHound.swift:145` | `p.run(); p.waitUntilExit()` e só então lê o pipe — para muita saída o buffer do pipe enche e o airport bloqueia em write → deadlock potencial do scan inteiro. |
| [PARCIAL] | `wifiCurrent` quando desassociado | `Pastoral/Support/AppState.swift:1911-1912` | `wifiNets.first { $0.current } ?? wifiNets.max(by: signal)` — sem associação, escolhe o vizinho mais forte e a UI rotula de "Rede atual"; a guarda "Conecte-se ao Wi-Fi que deseja caçar" (`AppState.swift:1950`) raramente dispara. |

### 10.2 Deauth / caça-senha

| Status | Item | Onde | Justificativa |
|---|---|---|---|
| [PARCIAL] | Injeção best-effort | `WiFiHound.swift:152-200` | `DeauthInjector` monta o frame de 30 B e injeta por `pcap_inject` com fallback para BPF write; o próprio comentário admite que o driver Apple pode descartar frames de management — "injetado" não é "a estação foi expulsa". Sem confirmação de entrega. |
| [NOTE] | Canal ignorado na injeção | `PastoralHelper/main.swift:267` | `case .deauthSend(let targetMAC, let bssid, _)` — o `channel` enviado por `AppState.swift:2000` chega e é jogado fora; o frame sai no canal atual de en0. |
| [FUNCIONA] | Orquestração da caçada | `AppState.swift:1944-1990` | janela N s → settle 700 ms → burst de deauth (hosts observáveis + `ff:ff:ff:ff:ff:ff`) → auto-stop por deadline no helper com flush de pares parciais. |

### 10.3 Hound (captura BPF)

| Status | Item | Onde | Justificativa |
|---|---|---|---|
| [BUG] | `pastoral_set_promisc` lê flags zeradas | `PastoralBPFShim/include/bpf_shim.h:55-68` | `memset(&ifr,0)` e só então lê `ifr.ifr_flags` (sempre 0) — falta o `SIOCGIFFLAGS` antes. Com `on=1` escreve só `IFF_PROMISC` → zera `IFF_UP/IFF_RUNNING` de en0 (Wi-Fi cai instantaneamente); com `on=0` escreve `0xFFFFFFFE`. |
| [BUG] | Promisc desliga antes da captura rodar | `WiFiHound.swift:255-256` | `pastoral_set_promisc(interface, 1)` seguido de `defer { pastoral_set_promisc(interface, 0) }` — o defer dispara no fim da função `start()`, logo no segundo da captura a interface volta a **não** promíscua. A janela inteira é capturada sem promisc. |
| [RISCO] | Cap de pares descarta os abertos | `WiFiHound.swift:383` | `if pairs.count > 64 { pairs = pairs.filter { $0.value.done } }` — acima do limite elimina exatamente os pares esperando o segundo nonce (os únicos que ainda podem virar handshake). |
| [PARCIAL] | PMKID via mgmt espelhado 0x888B | `WpaCapture.swift:~62-67`, `parseAssociationResponse` :136+ | Depende do driver espelhar assoc/(re)auth response para a Ethernet — raro em Mac; mais aspiracional que efetivo. |
| [RISCO] | Sem 802.1Q no decode | `Sources/PastoralCore/ARPFrame.swift:231-246` | `EthernetFrame.decode` não desempacota `0x88A1` — EAPOL VLAN-tagged cai sem ser visto (comum em rede corporativa com VLAN de guests). |
| [FUNCIONA] | Loop de captura | `WiFiHound.swift:270-300` | `openBPF`/`readBPF`/`iterateBPF`, `SO_RCVTIMEO` 1 s, deadline no loop; `stop()` fecha o fd antes de `flushPartials()` (sem deadlock). |

### 10.4 Parser EAPOL + linha hashcat

| Status | Item | Onde | Justificativa |
|---|---|---|---|
| [BUG] | Cabeçalho não bate com RFC 3923/4202 | `WpaCapture.swift:101-129` | `payload[3]==0x01`: [3] é o byte baixo do **Length** EAP (code@0=0x02, id@1, len@2-3) — quase nunca 1. O byte de version real é [4] (0x02 v1 / 0x03 v2); a checagem `payload[4]==0x03` o lê como "type_code". Descriptor type exigido em [9]; o real está em [4]=0x00. Máscara RF-MIC `0x1F00` — os bits reais são `0x001F` → `hasRFMIC` quase sempre false. Corpo lido como replay(16)+nonce(32) a partir de off=11(+8): layout real é replay_counter(**8**)+nonce(32) → nonce real em [17..49), lido em [27..59). Resultado: handshake real é rejeitado nos checks; se passasse, o nonce viria defasado. |
| [BUG] | Testes codificam o bug | `Tests/PastoralTests/WpaCaptureTests.swift:17-45` | Vetores sintéticos montam `[0x02, len_hi, len_lo, 0x01, 0x03, flags(2), keylen(2), 0x00, 0x01, replay(16), nonce(32), …]` — consistentes com o parser acima, não com a RFC. Os 263 testes verdes validam um mundo que não existe no ar. |
| [BUG] | Formato da linha ≠ hashcat | `WpaCapture.swift:45-65` | Sai `ESSID BSSID STAMAC NONCE1 NONCE2 EKEYMIC HcxPMKID EAPOL` separado por espaço (MACs com dois-pontos). Hashcat `-m 22000/22001` aceita hccapx ou **texto hcnpcapng**: campos com `*`, hex puro — PMKID `WPA*01*<pmkid32>*<macAP12>*<macSTA12>*<essidhex>***`; EAPOL `WPA*02*<mic32>*<macAP>*<macSTA>*<essidhex>*<anonce64>*<snonce64>[*eapol][*keyver]` (confirmado em `hashcat` master: `module_22001.c::module_hash_binary_save` e `docs/hashcat-example-hashes.md`, ST_HASH `WPA*01*5ce7…***`). A promessa da UI — "linhas saem prontas para o hashcat: hashcat -m 22001 arquivo.txt rockyou.txt" (`LoboTabView.swift:329`) — é falsa; o hashcat rejeita as 8 colunas. |
| [RISCO] | ekeyMIC sempre zero | `WiFiHound.swift:242,314,389` (`Self.zero64`) | Em registro type-2 o hashcat valida o candidato contra o mic gravado; mic all-zero rejeita a senha certa salvo se a ferramenta tratar zero como "sem check" — teste de bancada recomendado. |
| [RISCO] | Frames EAPOL concatenados sem separador | `WiFiHound.swift:315,390` (`st.eapols.joined()`) | Mesmo com o layout do campo corrigido, cada frame do exchange precisa de fronteira definida (convenção ewlM2/hcxpcapngtool) — hoje são colados crus. |

### 10.5 Portal cativo + colheita

| Status | Item | Onde | Justificativa |
|---|---|---|---|
| [FUNCIONA] | Regras do portal (plaintext) | `PastoralProxy/TransparentProxy.swift:336-393` | Probes cativos (`captive.apple.com`, `generate_204`…) → 200 `pastoral-offline`; `/__pastoral__/portal.html` servido; perfil CA em match exato c/ `Content-Disposition: attachment`; resto de GET/HEAD → 302 para a página. |
| [PARCIAL] | Só pega HTTP puro | `TransparentProxy.swift:205-243` (chamada em plaintext), regra :241 | `handlePortal` só vê request que chegou sem TLS (`tlsOrigin==nil`). Android/iOS sondam `generate_204` em **HTTPS**: sem CA confiada nesses aparelhos o portal nem aparece (túnel cego). O perfil CA resolve para dispositivos macOS/iOS locais que instalem a raiz, não força portal no terceiro. |
| [BUG] | Colhe credencial vazia | `TransparentProxy.swift:416-426` | Se `CredentialPortal.parseFormBody(body)` retorna nil, ainda cria `CapturedCredential(user:"",pass:"")` e registra no harvest jsonl + log — entradas falsas que poluem a colheita. |
| [FUNCIONA] | Página falsa + parser do form | `PastoralCore/CredentialPortal.swift` (271 linhas) | Sabores icloud/google/generic, parse de body urlencoded, percentDecode/escape próprios, página de sucesso. |

### 10.6 Armadilha de CA

| Status | Item | Onde | Justificativa |
|---|---|---|---|
| [FUNCIONA] | Perfil mobileconfig servido pelo portal | `AppState.swift:961` (`caProfileData`), `TransparentProxy.swift:378-391` | Geração real do perfil; download dentro da página de login. |
| [FUNCIONA] | Instalar/remover raiz via helper root | `PastoralHelper/main.swift:1190-1230` | `security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain` com retry de remove antes; remoção idempotente + fallback `delete-certificate -c "Pastoral CA"`. |
| [NOTE] | criminalStrike avisa e segue | `AppState.swift:1892-1896` | Falha de instalação de CA vira `log.warn` — decisão correta: o portal funciona sem ela, o MITM local é bônus. |

### 10.7 Modo Criminoso / armas

| Status | Item | Onde | Justificativa |
|---|---|---|---|
| [FUNCIONA] | `criminalStrike` | `AppState.swift:1881-1905` | scanARP → `autoTarget` (:1714) → ensureCAManager + setCATrust(true) (warn-only) → style `.login`, armas `[.portal]` → `loboInvade`; retorna nil se a ovelha subiu, senão a última mensagem de erro. |
| [FUNCIONA] | invade/retreat reaproveitam ovelha | `AppState.swift:1631,1663` | Mesma base pf/ARP/proxy da Sheep; pulso/gargalo reagem a troca de alvo via `restartLoboPulseIfNeeded` (:1765). |
| [PARCIAL] | portalSSID herda o fallback de `wifiCurrent` | `AppState.swift:1740-1746` (idem :1530) | SSID exibido/recordado pode ser o do vizinho mais forte quando desassociado → credencial colhida com `ssid` errado. |

### 10.8 Colheita persistida / cérebro de creds

| Status | Item | Onde | Justificativa |
|---|---|---|---|
| [FUNCIONA] | Harvest JSONL | `AppState.swift:1832-1870` | Append em `~/Library/Application Support/Pastoral/harvest.jsonl`, cap 1000 em memória, `loadHarvest` no init, clear remove o arquivo. |
| [RISCO] | Cérebro hardcoded fora do app | `AppState.swift:317-319` | `~/TESTMONEY/CRACKER/creds.json` — caminho absoluto da checkout; leitores paralelos (scout/deepcrack em CRACKER/) dependem dele sem schema/version. |
| [BUG] | Credencial vazia persistida | ver §10.5 (`TransparentProxy.swift:416-426`) | Entradas vazias chegam ao jsonl e ao creds.json compartilhado — deepcrack vai queimar candidatos nulos. |

### Veredito curto — Lobo

A corrente **portal → login falso → colheita → persistência** funciona de ponta a ponta para tráfego HTTP puro (e a armadilha de CA fecha o ciclo em macOS/iOS locais). A corrente de **caça-senha** tem três bugs concretos que se somam e anulam o recurso hoje: (1) promisc desligado durante toda a captura (defer no fim de `start()`); (2) `pastoral_set_promisc` operando sobre flags zeradas (zera `IFF_UP` do en0 no on, escreve `0xFFFFFFFE` no off); (3) parser EAPOL que rejeita todo handshake real — com os testes validando o parser com o bug. E mesmo que algum par chegasse inteiro, a linha emitida não é um formato que o hashcat `-m 22000/22001` lê. Corrigir 10.3+10.4 (promisc de fato ligado, RFC 3923, vetores de teste reais, saída hcnpcapng `WPA*…`) é o que torna "Caçar senha" utilizável; o resto da camada está sólido para escopo LAN pentest.
