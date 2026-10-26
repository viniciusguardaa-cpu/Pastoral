# Pastoral

Aplicativo nativo para macOS 14+, escrito em Swift/SwiftUI, com um serviço administrativo separado e bibliotecas compartilhadas em Swift/C.

## Versão local 1.1.0 — 18/10/2026

Esta atualização concentra mudanças em recuperação da sessão, segurança do canal administrativo, transparência dos estados e identidade visual. A interface usa a logo original, verde-floresta e creme, com barra lateral fixa e visão geral.

Abrir a tela de tráfego não inicia uma captura. A página inicial consulta o serviço e apresenta o contexto local; a busca de dispositivos depende de ação explícita.

## Organização

- Sources/Pastoral: interface, serviços do aplicativo e estado.
- Sources/PastoralCore: modelos, persistência, parsers e protocolo compartilhado.
- Sources/PastoralHelper: processo administrativo e restauração.
- Sources/PastoralProxy: implementação de proxy existente.
- Sources/libpcap e Sources/PastoralBPFShim: integração nativa em C.
- Tests/PastoralTests: testes do núcleo.
- Tests/PastoralAppTests: regressões de recuperação e renderização sem rede.
- Tests/PastoralProxyTests: testes de integração do proxy.
- Installer e Scripts: instalador, distribuição e apoio de CI.

## Desenvolvimento

Requer Swift 6.2 ou superior (Xcode 26).

```sh
swift build
swift test --filter 'PastoralTests|PastoralAppTests'
make app
```

O último comando compila e gera dist/Pastoral.app e dist/pastoral-helper.pkg; não instala o serviço. DIST pode ser sobrescrito para gerar artefatos em outra pasta.

O aplicativo contém o instalador e os recursos do SwiftPM. A logo está versionada na pasta de recursos, sem depender de um arquivo fora do projeto.

Para uma prévia sem operações de rede:

```sh
open -n dist/Pastoral.app --args --design-preview
```

Os dispositivos da prévia são ilustrativos e os controles ficam desativados.

Para renderizar os quatro cenários de interface:

```sh
PASTORAL_RENDER_DIR=/tmp/pastoral-previews swift test --filter DesignPreviewTests
```

## Recuperação e permissões

O estado de recuperação é salvo atomicamente. Dispositivos que desaparecem de uma busca continuam registrados para restauração. O aplicativo só confirma a limpeza quando recebe respostas de sucesso; falhas permanecem visíveis.

O serviço cria o socket com modo 0600 e atribui seu acesso ao usuário da sessão gráfica. Sem uma sessão gráfica identificável, o acesso continua restrito a root. O serviço verifica o usuário do cliente, mas ainda não valida a identidade de código assinado do aplicativo.

Alterações no código do serviço só passam a valer no sistema após instalar o pacote atualizado. O build não instala nem reinicia o serviço.

## Validação desta atualização

225 testes passaram em execução local com renderização habilitada. O aplicativo de release abriu em modo de prévia e sua assinatura local foi verificada. Não foram executadas operações privilegiadas nem os testes de integração do proxy.

## Limitações

- A captura simultânea ainda é limitada pelo atendimento sequencial de conexões no serviço.
- O replay tem limitações de corpos binários e validação TLS.
- Sem medição ativa, a velocidade por dispositivo aparece como “Sem medição”.
- A limpeza de políticas seletivas existentes atua por âncora.
- HTTPS, câmeras, túneis e recuperação após morte forçada do serviço precisam de validação em laboratório.
- A compilação local é assinada ad hoc. Notarização e distribuição universal não foram verificadas nesta entrega.

Use as operações de rede somente em ambientes para os quais tenha autorização.
