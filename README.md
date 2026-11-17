# f5flow — Mapa interativo do fluxo de tráfego F5 BIG-IP

O `f5flow.py` lê a configuração de um BIG-IP (qkview, `bigip.conf` ou diretório extraído) e gera um **fluxograma HTML interativo** mostrando, para cada aplicação, o caminho completo do tráfego:

```
FQDN → [NAT/firewall | Internet direto] → Virtual Server → LTM Policy / iRule
     → condição → Pool / Node / Redirect / WAF → Membros
```

Opcionalmente, cruza a configuração do F5 com o **NAT de entrada do firewall** (FortiGate, Palo Alto, Cisco ASA ou CSV genérico) e com o **DNS** (CSV ou arquivo de zona BIND), para mostrar de onde vem o tráfego de cada VS. Também exporta um **CSV** com uma linha por caminho, útil para inventário e documentação.

---

## Sumário

1. [Requisitos](#1-requisitos)
2. [Início rápido](#2-início-rápido)
3. [Entradas](#3-entradas)
4. [Opções da linha de comando](#4-opções-da-linha-de-comando)
5. [Usando o HTML gerado](#5-usando-o-html-gerado)
6. [O CSV de caminhos](#6-o-csv-de-caminhos)
7. [Alertas](#7-alertas)
8. [Como a análise funciona](#8-como-a-análise-funciona)
9. [Limitações conhecidas](#9-limitações-conhecidas)
10. [Adicionando outro fabricante de firewall](#10-adicionando-outro-fabricante-de-firewall)
11. [Solução de problemas](#11-solução-de-problemas)
12. [Cuidados com dados de clientes](#12-cuidados-com-dados-de-clientes)

---

## 1. Requisitos

- **Python 3.7+** (Windows, Linux ou macOS).
- **Nenhuma dependência externa** — só a biblioteca padrão.
- Para **abrir** o HTML: um navegador moderno. Por padrão o HTML carrega a biblioteca de grafos (Cytoscape.js) via internet; para uso offline veja [`--libs`](#uso-offline---libs).

## 2. Início rápido

```bash
git clone https://github.com/mateuscampinho/f5flow.git
cd f5flow

# Só com o qkview (mínimo obrigatório)
python f5flow.py cliente.qkview -o fluxo.html --csv fluxos.csv
```

Abra `fluxo.html` no navegador.

Testando com os arquivos fictícios da pasta `exemplos/`:

```bash
python f5flow.py exemplos/bigip.conf \
    --nat-csv exemplos/nat.csv \
    --fqdns exemplos/fqdns.csv \
    -o fluxo.html --csv fluxos.csv
```

Saída esperada no terminal:

```
exemplos/nat.csv: 2 regra(s) de NAT de entrada (csv)
Fontes: exemplos/bigip.conf
2 virtual servers, 3 pools, 1 iRules, 1 LTM policies, 1 data-groups
2 regras de NAT de entrada no total
2 FQDNs lidos
0 alertas
HTML: fluxo.html
CSV:  fluxos.csv
```

### Cenários comuns

| Cenário | Comando |
|---|---|
| Só o F5 | `python f5flow.py cliente.qkview -o fluxo.html` |
| F5 + firewall na frente + DNS | `python f5flow.py cliente.qkview --nat backup_fw.conf --fqdns fqdns.csv -o fluxo.html --csv fluxos.csv` |
| VS com IP público, sem firewall (só DNS) | `python f5flow.py cliente.qkview --zone zona.txt --origin cliente.com.br -o fluxo.html` |
| Dois firewalls de fabricantes diferentes | `python f5flow.py cliente.qkview --nat fortigate:fw1.conf --nat asa:fw2.txt -o fluxo.html` |
| Par de BIG-IPs (ou vários arquivos) | `python f5flow.py bigip01.qkview bigip02.qkview -o fluxo.html` |

---

## 3. Entradas

Só a configuração do F5 é obrigatória. NAT e DNS são opcionais e independentes entre si.

### 3.1 Configuração do F5 (obrigatória)

Pode-se passar vários arquivos na mesma execução; tudo é combinado.

| Tipo | O que é lido |
|---|---|
| **qkview** (`.qkview`, `.tar.gz`) | `config/bigip.conf` e `config/partitions/*/bigip.conf` de dentro do pacote |
| **Diretório** | todos os arquivos `bigip.conf` encontrados recursivamente |
| **Arquivo `.conf`** | lido diretamente |

Objetos interpretados: `ltm virtual`, `pool`, `node`, `policy`, `rule` (iRules), `data-group`, `profile`, `monitor`, `persistence` e `snatpool`. Partições são respeitadas (`/Particao/objeto`); referências sem caminho são resolvidas na partição do VS e, se não existirem, em `/Common`.

> **Como obter:** gere o qkview pela GUI (*System › Support › New Support Snapshot*) ou via `tmsh`/`qkview`. Alternativamente, copie `/config/bigip.conf` e `/config/partitions/*/bigip.conf` do equipamento.

### 3.2 NAT de entrada — `--nat` (opcional)

Informe a configuração do firewall que fica na frente do F5. O tipo é **detectado automaticamente** pelo conteúdo, ou pode ser forçado no formato `tipo:arquivo`. A opção pode ser repetida (vários equipamentos). Aliases aceitos: `--firewall`, `--fortigate`.

| Tipo | Como exportar | O que é lido |
|---|---|---|
| `fortigate` | Backup de configuração do FortiGate | bloco `config firewall vip` (inclusive port forward e realservers) |
| `paloalto` | No CLI: `set cli config-output-format set` e depois `show` | regras de NAT com *destination translation* e NAT estático bidirecional |
| `asa` | `show running-config` do Cisco ASA / FTD (LINA) | object NAT, twice NAT e `static` legado (pré-8.3) |
| `csv` | Planilha montada manualmente | ver abaixo |

**CSV genérico** (`--nat-csv arquivo.csv` ou `--nat csv:arquivo.csv`) — para qualquer outro equipamento:

```csv
nome,ip_publico,porta_publica,ip_interno,porta_interna,dispositivo
vip_portal_https,200.100.50.10,443,10.10.10.50,443,FW-Borda
```

- Separador `,`, `;` ou tab (detectado automaticamente).
- Cabeçalhos aceitos (sem distinção de maiúsculas): `nome/name/vip/regra/rule`, `ip_publico/extip/public_ip/ip_externo`, `porta_publica/extport/public_port/porta_externa`, `ip_interno/mappedip/internal_ip/ip_destino`, `porta_interna/mappedport/internal_port/porta_destino`, `dispositivo/device/firewall/equipamento`.
- Porta vazia, `0`, `*` ou `any` = todas as portas (NAT estático 1:1).

**Como o NAT é ligado ao VS:** a regra casa com um VS quando o IP interno (ou um *realserver*) é igual ao IP do VS — ou o contém, se for range/sub-rede — e, em caso de port forward, a porta interna bate com a porta do VS.

### 3.3 DNS (opcional)

| Opção | Formato |
|---|---|
| `--fqdns arquivo.csv` | CSV `fqdn,ip`. O segundo campo pode ser um nome (tratado como CNAME). |
| `--zone zona.txt` | Arquivo de zona BIND (registros `A`, `AAAA`, `CNAME`). Use `--origin dominio.com.br` se o arquivo não tiver `$ORIGIN`. |

Exemplo de `fqdns.csv`:

```csv
fqdn,ip
portal.exemplo.com.br,200.100.50.10
www.exemplo.com.br,portal.exemplo.com.br
```

Os CNAMEs são resolvidos em cadeia (até 8 níveis). O FQDN é ligado:
- à **regra de NAT** cujo IP externo é o IP resolvido; ou
- **diretamente ao VS** cujo IP é o IP resolvido.

### 3.4 Exposição de cada VS

Com base no NAT e no IP do VS, cada virtual server é classificado:

| Exposição | Critério |
|---|---|
| **via NAT (dispositivo)** | uma regra de NAT aponta para o IP/porta do VS |
| **IP público direto** | VS com IP roteável na internet e sem NAT → aparece um nó "Internet" antes do VS |
| **interno** | IP privado sem NAT (só classificado assim quando há dados de NAT informados) |
| **IP privado (NAT não informado)** | IP privado e nenhum arquivo de NAT foi passado |

---

## 4. Opções da linha de comando

```
python f5flow.py ENTRADA [ENTRADA ...] [opções]
```

| Opção | Descrição | Padrão |
|---|---|---|
| `ENTRADA` | qkview, `bigip.conf` ou diretório (um ou mais) | — |
| `-o`, `--output` | arquivo HTML de saída | `f5_fluxo.html` |
| `--title` | título exibido no HTML | `Fluxo das aplicacoes F5` |
| `--nat` | config do firewall: `arquivo` ou `tipo:arquivo` (repetível) | — |
| `--nat-csv` | CSV genérico de NAT (repetível) | — |
| `--fqdns` | CSV `fqdn,ip` (repetível) | — |
| `--zone` | arquivo de zona BIND (repetível) | — |
| `--origin` | origem da zona, se o arquivo não tiver `$ORIGIN` | — |
| `--csv` | exporta os caminhos em CSV (separador `;`) | — |
| `--json` | exporta o grafo bruto (nós e arestas) em JSON | — |
| `--libs` | diretório com as bibliotecas JS para embutir no HTML (offline) | CDN |

### Uso offline (`--libs`)

Por padrão o HTML busca as bibliotecas em `unpkg.com`. Para gerar um HTML 100% autocontido (ex.: entregar a um cliente sem acesso à internet, ou abrir em rede isolada), baixe uma vez os três arquivos para uma pasta:

| Arquivo | URL |
|---|---|
| `cytoscape.min.js` | https://unpkg.com/cytoscape@3.28.1/dist/cytoscape.min.js |
| `dagre.min.js` | https://unpkg.com/dagre@0.8.5/dist/dagre.min.js |
| `cytoscape-dagre.js` | https://unpkg.com/cytoscape-dagre@2.5.0/cytoscape-dagre.js |

```bash
python f5flow.py cliente.qkview --libs ./libs -o fluxo.html
```

---

## 5. Usando o HTML gerado

A tela tem três colunas:

**Esquerda — lista de virtual servers**
- Clique em um VS para abrir o fluxo dele.
- **Filtro**: busca por nome, IP, FQDN, NAT ou exposição.
- **Membros**: mostra/oculta os membros dos pools.
- **Entrada (DNS/NAT)**: mostra/oculta FQDNs, regras de NAT e o nó Internet.
- **Direção**: layout da esquerda para a direita ou de cima para baixo.
- Abaixo da lista, o quadro de **Alertas** (ver seção 7).
- VSs desabilitados aparecem riscados.

**Centro — fluxograma**
- **Clique** em um nó: destaca o caminho dele (o resto fica esmaecido) e mostra os detalhes à direita.
- **Duplo clique** em um VS: abre o fluxo daquele VS (útil em encadeamentos `virtual → virtual`).
- **Clique no fundo**: remove o destaque.
- Roda do mouse para zoom; arraste para mover.
- **Ver todos**: desenha todos os VSs de uma vez (pede confirmação acima de 1.500 elementos).
- **Ajustar**: enquadra o desenho na tela.
- **Exportar PNG**: salva a imagem do fluxo atual em alta resolução.

**Direita — detalhes**
- Campos do objeto selecionado (perfis, certificados, persistência, SNAT, VLANs, monitor, balanceamento etc.).
- Para iRules e condições: o **código com as linhas relevantes destacadas**.
- "Configuração (bigip.conf)": o trecho bruto do objeto.
- Para pools, policies e iRules: lista de **quais VSs usam** aquele objeto, com link.

### Legenda

| Cor / forma | Significado |
|---|---|
| Roxo claro | FQDN |
| Cinza (elipse) | Internet (VS com IP público direto) |
| Laranja (hexágono) | NAT / firewall |
| Azul (negrito) | Virtual server |
| Verde-água | LTM policy |
| Lilás | iRule |
| Amarelo (losango) | Condição (regra da policy ou `if`/`switch` da iRule) |
| Verde (barril) | Pool |
| Verde claro | Membro do pool |
| Vermelho (pentágono) | Política WAF (ASM/AWAF) |
| Rosa | Redirect / HTTP::respond |
| Vermelho escuro (octógono) | Reject / drop |
| Cinza tracejado | Destino dinâmico ou objeto não encontrado |
| Linha verde tracejada | Default pool |
| Linha laranja | Entrada (DNS/NAT) |
| Linha lilás | Encaminhamento para outro virtual server |

---

## 6. O CSV de caminhos

Com `--csv`, é gerada **uma linha por caminho possível** (VS × mecanismo × condição × destino). Separador `;` e codificação UTF-8 com BOM (abre direto no Excel).

| Coluna | Conteúdo |
|---|---|
| `fqdns` | FQDNs que apontam para o VS |
| `nat_entrada` | regras de NAT que chegam ao VS |
| `exposicao` | via NAT / IP público direto / interno |
| `virtual_server` | nome completo do VS |
| `destino_vs` | IP:porta do VS |
| `estado` | habilitado / desabilitado |
| `mecanismo` | `1. LTM policy`, `2. iRule`, `default pool`… (número = ordem de avaliação) |
| `objeto` | nome da policy ou iRule |
| `evento` | evento da iRule (`HTTP_REQUEST`, `CLIENT_ACCEPTED`…) |
| `condicao` | condição que leva ao destino |
| `acao` | `pool`, `node`, `virtual`, `redirect`, `respond`, `reject`, `waf`… |
| `destino` | pool, node, VS ou URL de destino |
| `membros` | membros do pool (`ip:porta; ip:porta`) |
| `linha` | linha da iRule onde o destino aparece |

Exemplo (gerado a partir de `exemplos/`):

| virtual_server | mecanismo | condicao | acao | destino |
|---|---|---|---|---|
| vs_portal_https | 1. LTM policy | `api: http-uri path starts-with {/api}` | pool | pool_api |
| vs_portal_https | 2. iRule | `if { [HTTP::uri] starts_with "/manutencao" }` | pool | pool_manutencao |
| vs_portal_https | 2. iRule | `elseif { [HTTP::host] eq "antigo..." }` | redirect | `https://portal...` |
| vs_portal_https | default pool | nenhuma regra selecionou outro destino | pool | pool_portal_https |

---

## 7. Alertas

O painel de alertas (e o total no terminal) aponta possíveis problemas de configuração:

| Alerta | O que verificar |
|---|---|
| Pool / iRule / LTM policy referenciada mas não encontrada | objeto em outra partição não incluída, ou referência quebrada |
| Pool sem membros | pool vazio associado a um VS ou regra |
| VS sem default pool, policy ou iRule | VS que não encaminha para lugar nenhum |
| VS desabilitado | VS presente na config, mas desativado |
| iRule com pool dinâmico | destino calculado em tempo de execução (`pool $var`); confira a lógica |
| NAT *dispositivo* sem VS correspondente | regra de NAT que aponta para IP/porta que não é VS no F5 (sobra ou outro equipamento) |
| VS com IP privado sem NAT de entrada mapeado | VS possivelmente interno — ou NAT faltando no arquivo do firewall |
| N FQDN(s) não apontam para nenhum NAT/VS mapeado | registros DNS que não chegam a este F5 |

---

## 8. Como a análise funciona

**Ordem de avaliação no VS** (exibida também nos detalhes de cada VS):

1. **LTM policies**, na ordem em que estão no VS;
2. **iRules**, na ordem listada;
3. **default pool** — usado só se nada acima selecionou outro destino.

A última seleção de pool vence. No fluxograma, as arestas do VS são numeradas (`1º LTM policy`, `2º iRule`…).

**LTM policies:** cada regra vira um nó de condição (com o ordinal), e as ações são traduzidas: `forward select pool/node/virtual`, `http-reply redirect location`, `asm enable policy` (WAF), `asm disable`, `reset`/`shutdown` (reject). Ações sem destino de tráfego (ex.: inserir header) aparecem só no CSV como "outras".

**iRules:** o código TCL é lido linha a linha, acompanhando a estrutura de chaves para reconstruir o contexto (`when EVENTO` → `if`/`elseif`/`else` → `switch` → caso). São detectados:
`pool` (inclusive `pool X member IP porta`), `node`, `virtual`, `HTTP::redirect`, `HTTP::respond` (com `Location`, se houver) e `reject`/`drop`/`discard`. Linhas de `log` são ignoradas.

**Data-groups:** se uma iRule com `pool $variavel` referencia um data-group cujos registros (chave ou valor) são nomes de pools, esses pools são ligados ao nó dinâmico com o rótulo "via data-group".

---

## 9. Limitações conhecidas

- A análise de iRules é **heurística**: o TCL não é executado. Lógica muito dinâmica (procs, `eval`, variáveis montadas por concatenação) pode não ser reconhecida — o painel de detalhes sempre mostra o código para conferência.
- `else` aparece como "else"; a negação do `if` anterior não é expandida.
- Destinos dinâmicos (`pool $var`, `pool [class ...]`) aparecem como "dinâmico", exceto quando ligados via data-group (seção 8).
- iRules de sistema (`_sys_*`, ex.: `_sys_https_redirect`) não estão no `bigip.conf`; aparecem marcadas como "(sistema)", sem análise do conteúdo.
- Apenas o módulo **LTM** é interpretado. GTM/DNS, APM e políticas ASM aparecem só como referência (ex.: nome da política WAF ativada por uma LTM policy).
- No Palo Alto, objetos de endereço do tipo FQDN e grupos de serviço não são expandidos; no ASA, `object-group` não é expandido.

---

## 10. Adicionando outro fabricante de firewall

Toda regra de NAT, de qualquer fabricante, é normalizada pela função `nat_rule()`. Para suportar um novo equipamento:

1. Escreva uma função que recebe o texto do arquivo e devolve uma lista de `nat_rule(...)`:

   ```python
   def parse_meufw(text):
       out = []
       for linha in text.splitlines():
           # ... extrair os campos ...
           out.append(nat_rule("MeuFW", nome, extip=ip_pub, extport=porta_pub,
                               mappedip=ip_int, mappedport=porta_int))
       return out
   ```

2. Registre em `NAT_PARSERS`:

   ```python
   NAT_PARSERS = {..., "meufw": parse_meufw}
   ```

3. (Opcional) Para detecção automática, acrescente um teste em `NAT_DETECT`:

   ```python
   ("meufw", lambda t: re.search(r"^algo-tipico-do-arquivo", t, re.M)),
   ```

Enquanto isso não existir, o caminho mais rápido é exportar as regras para o [CSV genérico](#32-nat-de-entrada----nat-opcional).

---

## 11. Solução de problemas

| Sintoma | Causa provável / solução |
|---|---|
| `nenhum bigip.conf encontrado nas entradas informadas` | O qkview não contém `config/bigip.conf` no caminho esperado, ou o diretório está errado. Extraia o qkview e aponte para o diretório. |
| `nao reconheci o formato de ARQUIVO` | Formato de NAT não detectado. Use `tipo:arquivo` (ex.: `--nat paloalto:export.txt`) ou o CSV genérico. |
| HTML abre em branco / sem desenho | Sem acesso a `unpkg.com`. Gere com `--libs` (seção 4). |
| `aviso: falha ao interpretar '...'` | Um objeto específico não pôde ser lido; o restante da análise continua normalmente. |
| Palo Alto: 0 regras de NAT | O export precisa estar em formato `set` (`set cli config-output-format set` antes do `show`). |
| FQDN não aparece ligado | O IP do DNS precisa ser igual ao IP externo do NAT ou ao IP do VS. Confira o alerta de FQDNs não mapeados. |
| "Ver todos" fica lento | Ambientes grandes geram milhares de nós; use o filtro e navegue por VS, ou desmarque "Membros". |

---

## 12. Cuidados com dados de clientes

qkviews, backups de firewall e zonas DNS contêm informações sensíveis do cliente. **Não versione esses arquivos neste repositório.** O `.gitignore` já ignora `*.qkview`, `*.tar.gz`, `*.ucs`, as pastas `clientes/` e `dados/`, e as saídas geradas (`*.html`, CSV de fluxos, JSON).

O HTML gerado embute a configuração do cliente (incluindo o código das iRules) — trate-o com o mesmo cuidado ao compartilhar.

---

## Estrutura do repositório

```
f5flow/
├── f5flow.py          # o script (arquivo único)
├── README.md          # este manual
├── .gitignore
└── exemplos/          # dados fictícios para teste
    ├── bigip.conf
    ├── nat.csv
    └── fqdns.csv
```
