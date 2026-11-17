#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
f5flow.py - Mapa interativo do fluxo de trafego das aplicacoes F5 BIG-IP

Le a configuracao do BIG-IP (qkview, bigip.conf ou diretorio extraido),
analisa virtual servers, LTM policies, iRules, pools, nodes e data-groups,
e gera um HTML interativo (fluxograma) com o caminho de cada aplicacao:

    FQDN -> [NAT/firewall | Internet direto] -> Virtual Server -> LTM Policy / iRule
         -> condicao -> Pool / Node / Redirect / WAF -> Membros

So o qkview/bigip.conf e obrigatorio. DNS e NAT sao opcionais e independentes.

Uso basico:
    python f5flow.py cliente.qkview -o fluxo.html --csv fluxos.csv

Com firewall na frente (qualquer fabricante suportado) e DNS:
    python f5flow.py cliente.qkview \
        --nat backup_firewall.conf \
        --fqdns fqdns.csv \
        -o fluxo.html --csv fluxos.csv

VS com IP publico, sem firewall na frente (so DNS):
    python f5flow.py cliente.qkview --zone zona.txt --origin cliente.com.br -o fluxo.html

Entradas do F5 (podem ser combinadas, varios arquivos):
    - qkview (.qkview / .tar.gz)  -> extrai config/bigip.conf e config/partitions/*/bigip.conf
    - diretorio                   -> procura todos os bigip.conf recursivamente
    - arquivo .conf               -> lido diretamente

NAT de entrada (--nat, repetivel; o tipo e detectado pelo conteudo ou informado
como tipo:arquivo):
    fortigate  backup do FortiGate ("config firewall vip")
    paloalto   PAN-OS/Panorama em formato set ("set cli config-output-format set" + "show")
    asa        Cisco ASA/FTD ("show running-config"): object NAT, twice NAT, static legado
    csv        qualquer outro equipamento: nome,ip_publico,porta_publica,ip_interno,porta_interna[,dispositivo]
               (tambem via --nat-csv)
  Para outro fabricante, crie parse_<x>(text) devolvendo nat_rule(...) e registre em NAT_PARSERS.

Exposicao de cada VS (aparece no fluxo, na lista e no CSV):
    via NAT        uma regra de NAT aponta para o IP/porta do VS
    IP publico     VS com IP roteavel na internet e sem NAT -> no "Internet" antes do VS
    interno        IP privado sem NAT (so classificado assim quando ha dados de NAT)

DNS (opcional):
    --fqdns      CSV: fqdn,ip   (ip pode ser um nome para CNAME)
    --zone       arquivo de zona BIND (A/AAAA/CNAME); use --origin se nao houver $ORIGIN
    O FQDN e ligado a regra de NAT (IP externo) ou direto ao VS (IP do VS).

Outras opcoes:
    --csv        exporta uma linha por caminho (VS x mecanismo x condicao x destino)
    --json       exporta o grafo bruto
    --libs DIR   embute as bibliotecas JS no HTML (abre sem internet). DIR deve
                 conter cytoscape.min.js, dagre.min.js e cytoscape-dagre.js

Sem dependencias externas (apenas biblioteca padrao). Por padrao o HTML carrega
Cytoscape.js via CDN (unpkg); use --libs para gerar um HTML 100% offline.

Limitacoes conhecidas:
    - A analise de iRules e heuristica (TCL nao e executado). Condicoes de
      if/elseif/switch sao reconstruidas a partir da estrutura de chaves; o
      painel de detalhes mostra o codigo com as linhas relevantes destacadas.
    - "else" aparece como "else" (a negacao do if anterior nao e expandida).
    - Destinos dinamicos (pool $var, pool [class ...]) aparecem como "dinamico";
      quando o iRule usa um data-group cujos valores sao pools, eles sao ligados.
"""

import argparse
import csv
import datetime as _dt
import ipaddress
import json
import re
import socket
import sys
import tarfile
import textwrap
from pathlib import Path

# ---------------------------------------------------------------------------
# Parser do formato tmsh (bigip.conf)
# ---------------------------------------------------------------------------

TCL_HEADERS = ("ltm rule", "gtm rule", "rule ")
TOKEN_RE = re.compile(r'"(?:\\.|[^"\\])*"|[{}]|\n|[^\s{}"]+')
CONF_RE = re.compile(r'(?:^|/)config/(?:partitions/[^/]+/)?bigip\.conf$')


def _match_brace(text, start, tcl):
    """Retorna o indice da chave que fecha a que esta em text[start]."""
    depth, i, n, inq = 0, start, len(text), False
    while i < n:
        c = text[i]
        if c == "\\":
            i += 2
            continue
        if inq:
            if c == '"':
                inq = False
        elif c == '"' and not tcl:
            inq = True
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return n - 1


def split_objects(text):
    """Divide o arquivo em objetos de primeiro nivel: [(header, body)]."""
    objs, i, n = [], 0, len(text)
    while i < n:
        while i < n and text[i] in " \t\r\n":
            i += 1
        if i >= n:
            break
        if text[i] == "#":
            j = text.find("\n", i)
            i = n if j < 0 else j + 1
            continue
        j = i
        while j < n and text[j] not in "{\n":
            j += 1
        if j >= n or text[j] == "\n":
            i = j + 1
            continue
        header = text[i:j].strip()
        k = _match_brace(text, j, header.startswith(TCL_HEADERS))
        objs.append((header, text[j + 1:k]))
        i = k + 1
    return objs


def unquote(s):
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        return s[1:-1].replace('\\"', '"')
    return s


def header_tokens(header):
    return [unquote(t) for t in re.findall(r'"(?:\\.|[^"\\])*"|\S+', header)]


def parse_block(tokens, i=0):
    """Converte tokens em lista de (palavras, filho|None)."""
    items, cur = [], []
    while i < len(tokens):
        t = tokens[i]
        if t == "\n":
            if cur:
                items.append((cur, None))
                cur = []
            i += 1
        elif t == "{":
            child, i = parse_block(tokens, i + 1)
            items.append((cur, child))
            cur = []
        elif t == "}":
            if cur:
                items.append((cur, None))
            return items, i + 1
        else:
            cur.append(unquote(t))
            i += 1
    if cur:
        items.append((cur, None))
    return items, i


def parse_body(body):
    return parse_block(TOKEN_RE.findall(body))[0]


def kv(items, key):
    for words, ch in items or []:
        if words and words[0] == key and ch is None:
            return words[1:]
    return None


def kv1(items, key, default=None):
    v = kv(items, key)
    return " ".join(v) if v else default


def sub(items, key):
    for words, ch in items or []:
        if words and words[0] == key and ch is not None:
            return ch
    return None


def listed(items):
    out = []
    for words, ch in items or []:
        if ch is not None:
            out.append(" ".join(words))
        else:
            out.extend(words)
    return out


def flat_words(items):
    out = []
    for words, ch in items or []:
        if ch is None:
            out.extend(words)
        elif words and words[0] == "values":
            out.append("{" + " | ".join(listed(ch)) + "}")
        else:
            out.extend(words)
            out.extend(flat_words(ch))
    return out


def find_values(items, key):
    out = []
    for words, ch in items or []:
        if words and words[0] == key and ch is None and len(words) > 1:
            out.append(" ".join(words[1:]))
        if ch is not None:
            out.extend(find_values(ch, key))
    return out


# ---------------------------------------------------------------------------
# Utilitarios de nomes, enderecos e portas
# ---------------------------------------------------------------------------

SERVICES = {
    "any": "0", "http": "80", "https": "443", "ftp": "21", "ssh": "22",
    "telnet": "23", "smtp": "25", "domain": "53", "pop3": "110",
    "imap": "143", "snmp": "161", "ldap": "389", "ldaps": "636",
    "imaps": "993", "pop3s": "995", "ms-sql-s": "1433", "mysql": "3306",
    "rdp": "3389", "webcache": "8080", "http-alt": "8080", "www": "80",
}


def full(name, part="Common"):
    name = unquote(name or "")
    if not name or name == "none" or name.startswith("/"):
        return name
    return "/%s/%s" % (part, name)


def part_of(name):
    return name.split("/")[1] if name.startswith("/") and name.count("/") >= 2 else "Common"


def base(name):
    return (name or "").rstrip("/").split("/")[-1]


def short(name):
    """Nome curto: so o basename se estiver em /Common."""
    if name.startswith("/Common/"):
        return name[len("/Common/"):]
    return name.lstrip("/")


def resolve(table, name, part):
    f = full(name, part)
    if f in table:
        return f
    alt = "/Common/" + base(name)
    if alt in table:
        return alt
    return f


def port_num(p):
    p = str(p or "").strip()
    if p.isdigit():
        return p
    if p in SERVICES:
        return SERVICES[p]
    try:
        return str(socket.getservbyname(p))
    except (OSError, TypeError):
        return p


def split_addr_port(s):
    """'/Common/10.1.1.10%2:https' -> ('10.1.1.10%2', '443')"""
    s = (s or "").split("/")[-1]
    m = re.match(r"^([\d.]+(?:%\d+)?):(\S+)$", s)
    if m:
        return m.group(1), port_num(m.group(2))
    if s.count(":") == 1:
        a, p = s.split(":")
        return a, port_num(p)
    m = re.match(r"^(.+)\.(\w+)$", s)
    if m and ":" in m.group(1):
        return m.group(1), port_num(m.group(2))
    return s, ""


def strip_rd(ip):
    return (ip or "").split("%")[0]


def ip_in(ip, spec):
    """ip pertence a 'a.b.c.d', 'a-b' ou 'a.b.c.d/nn'."""
    ip = strip_rd(ip)
    spec = (spec or "").strip()
    if not ip or not spec:
        return False
    if ip == spec:
        return True
    try:
        addr = ipaddress.ip_address(ip)
        if "-" in spec:
            lo, hi = spec.split("-", 1)
            return ipaddress.ip_address(lo.strip()) <= addr <= ipaddress.ip_address(hi.strip())
        if "/" in spec:
            return addr in ipaddress.ip_network(spec, strict=False)
        if " " in spec:  # mascara estilo Fortigate "10.0.0.0 255.255.255.0"
            net, mask = spec.split()[:2]
            return addr in ipaddress.ip_network("%s/%s" % (net, mask), strict=False)
    except ValueError:
        return False
    return False


def port_match(vs_port, spec):
    if not spec or vs_port in ("", "0"):
        return True
    for part in spec.replace(",", " ").split():
        if "-" in part:
            a, b = part.split("-", 1)
            if a.isdigit() and b.isdigit() and vs_port.isdigit() and int(a) <= int(vs_port) <= int(b):
                return True
        elif part == vs_port:
            return True
    return False


def is_public(ip):
    try:
        return ipaddress.ip_address(strip_rd(ip)).is_global
    except ValueError:
        return False


def is_ip(s):
    try:
        ipaddress.ip_address(strip_rd(s))
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Modelo da configuracao F5
# ---------------------------------------------------------------------------


class F5Config:
    def __init__(self):
        self.virtuals, self.pools, self.nodes = {}, {}, {}
        self.policies, self.irules, self.datagroups = {}, {}, {}
        self.profiles, self.monitors, self.persist, self.snatpools = {}, {}, {}, {}
        self.sources = []

    # -- carga -------------------------------------------------------------
    def load(self, label, text):
        self.sources.append(label)
        for header, body in split_objects(text):
            toks = header_tokens(header)
            if len(toks) < 3 or toks[0] != "ltm":
                continue
            raw = "%s {%s}" % (header, body)
            kind = toks[1]
            try:
                if kind == "rule":
                    name = full(toks[2])
                    self.irules[name] = {"name": name, "code": body.strip("\n"), "raw": raw}
                    continue
                items = parse_body(body)
                if kind == "virtual":
                    self._virtual(full(toks[2]), items, raw)
                elif kind == "pool":
                    self._pool(full(toks[2]), items, raw)
                elif kind == "node":
                    name = full(toks[2])
                    self.nodes[name] = {
                        "address": kv1(items, "address") or kv1(sub(items, "fqdn"), "name") or base(name),
                        "raw": raw,
                    }
                elif kind == "policy":
                    self._policy(full(toks[2]), items, raw)
                elif kind == "data-group" and len(toks) >= 4:
                    self._datagroup(full(toks[3]), toks[2], items, raw)
                elif kind == "profile" and len(toks) >= 4:
                    name = full(toks[3])
                    self.profiles[name] = {
                        "type": toks[2], "raw": raw,
                        "certs": sorted(set(base(c) for c in find_values(items, "cert") if c != "none")),
                    }
                elif kind == "monitor" and len(toks) >= 4:
                    self.monitors[full(toks[3])] = {
                        "type": toks[2], "send": kv1(items, "send", ""), "recv": kv1(items, "recv", ""), "raw": raw,
                    }
                elif kind == "persistence" and len(toks) >= 4:
                    self.persist[full(toks[3])] = {"type": toks[2], "raw": raw}
                elif kind == "snatpool":
                    self.snatpools[full(toks[2])] = {"members": listed(sub(items, "members")), "raw": raw}
            except Exception as exc:  # nunca derruba a analise por um objeto
                print("aviso: falha ao interpretar '%s': %s" % (header, exc), file=sys.stderr)

    def _virtual(self, name, items, raw):
        part = part_of(name)
        ip, port = split_addr_port(kv1(items, "destination", ""))
        profiles = []
        for words, ch in sub(items, "profiles") or []:
            if words:
                profiles.append((full(words[0], part), kv1(ch, "context", "all") if ch else "all"))
        snat = sub(items, "source-address-translation")
        snat_type = kv1(snat, "type", "") if snat else ""
        snat_pool = kv1(snat, "pool", "") if snat else ""
        if not snat_type and kv1(items, "snat"):
            snat_type = kv1(items, "snat")
        if not snat_type and kv1(items, "snatpool"):
            snat_type, snat_pool = "snat", kv1(items, "snatpool")
        pool = kv1(items, "pool")
        self.virtuals[name] = {
            "name": name, "raw": raw, "ip": ip, "port": port,
            "protocol": kv1(items, "ip-protocol", ""),
            "pool": full(pool, part) if pool else None,
            "rules": [full(r, part) for r in listed(sub(items, "rules"))],
            "policies": [full(p, part) for p in listed(sub(items, "policies"))],
            "profiles": profiles,
            "persist": [full(p, part) for p in listed(sub(items, "persist"))],
            "fallback_persist": kv1(items, "fallback-persistence", ""),
            "snat": snat_type, "snat_pool": snat_pool,
            "disabled": any(w == ["disabled"] for w, c in items if c is None),
            "description": kv1(items, "description", ""),
            "vlans": listed(sub(items, "vlans")),
            "vlans_mode": "enabled" if any(w == ["vlans-enabled"] for w, c in items) else (
                "disabled" if any(w == ["vlans-disabled"] for w, c in items) else ""),
            "source": kv1(items, "source", ""),
        }

    def _pool(self, name, items, raw):
        part = part_of(name)
        members = []
        for words, ch in sub(items, "members") or []:
            if not words:
                continue
            mname = words[0]
            node, port = split_addr_port(mname)
            addr = kv1(ch, "address") if ch else None
            if not addr:
                n = self.nodes.get(full(node, part)) or self.nodes.get("/Common/" + node)
                addr = n["address"] if n else node
            state = []
            if ch:
                if kv1(ch, "session", "") == "user-disabled":
                    state.append("desabilitado")
                if kv1(ch, "state", "") == "user-down":
                    state.append("forced offline")
                if kv1(ch, "priority-group"):
                    state.append("prio %s" % kv1(ch, "priority-group"))
            members.append({
                "node": base(node), "addr": addr, "port": port,
                "monitor": kv1(ch, "monitor", "") if ch else "", "state": state,
            })
        self.pools[name] = {
            "name": name, "raw": raw, "members": members,
            "lb": kv1(items, "load-balancing-mode", "round-robin"),
            "monitor": kv1(items, "monitor", ""),
            "min_up": kv1(items, "min-active-members", ""),
        }

    def _policy(self, name, items, raw):
        rules = []
        for words, ch in sub(items, "rules") or []:
            if not words or ch is None:
                continue
            conds = []
            for _w, c in sub(ch, "conditions") or []:
                conds.append(" ".join(flat_words(c)))
            actions = []
            for _w, c in sub(ch, "actions") or []:
                actions.append(flat_words(c))
            rules.append({
                "name": words[0], "ordinal": kv1(ch, "ordinal", "0"),
                "conditions": conds, "actions": actions,
                "description": kv1(ch, "description", ""),
            })
        rules.sort(key=lambda r: int(r["ordinal"]) if r["ordinal"].isdigit() else 0)
        self.policies[name] = {
            "name": name, "raw": raw, "rules": rules,
            "strategy": base(kv1(items, "strategy", "first-match")),
            "requires": listed(sub(items, "requires")),
            "controls": listed(sub(items, "controls")),
        }

    def _datagroup(self, name, dgtype, items, raw):
        recs = []
        for words, ch in sub(items, "records") or []:
            if words:
                recs.append((words[0], kv1(ch, "data", "") if ch else ""))
        self.datagroups[name] = {"name": name, "kind": dgtype, "type": kv1(items, "type", ""), "records": recs, "raw": raw}


# ---------------------------------------------------------------------------
# Analise de iRules
# ---------------------------------------------------------------------------

RE_POOL = re.compile(r"(?<![\w:$.\-\[])(?<!LB::server )(?<!LB::status )pool\s+(\S+)(?:\s+member\s+(\S+)(?:\s+(\d+))?)?")
RE_NODE = re.compile(r"(?<![\w:$.\-\[])(?<!LB::server )(?<!LB::status )node\s+(\S+)(?:\s+(\d+))?")
RE_VIRTUAL = re.compile(r"(?<![\w:$.\-\[])virtual\s+(\S+)")
RE_REDIRECT = re.compile(r"HTTP::redirect\s+(.+)$")
RE_RESPOND = re.compile(r"HTTP::respond\s+(\d{3})(.*)$")
RE_REJECT = re.compile(r"(?:^|[{;]\s*)(reject|drop|discard)\s*(?:$|[;}])")
RE_EVENT = re.compile(r"^\s*when\s+(\w+)", re.M)
RE_LOCATION = re.compile(r'Location\s+"?([^"\s}]+)', re.I)


def _clean_target(t):
    t = t.strip()
    while t and t[-1] in "};":
        t = t[:-1].rstrip()
    if t.startswith('"') and t.endswith('"') and len(t) > 1:
        t = t[1:-1]
    return t


def _ctx_to_cond(stack):
    parts, sw = [], None
    for label in stack:
        if label.startswith("when "):
            continue
        if label.startswith("switch"):
            tail = re.sub(r"^switch\s+(?:-\w+\s+)*(?:--\s+)?", "", label).strip()
            sw = tail or "switch"
            continue
        if sw is not None:
            case = label.rstrip("-").strip()
            parts.append("%s = %s" % (sw, case) if case != "default" else "%s = (default)" % sw)
            sw = None
            continue
        lab = re.sub(r"^(if|elseif)\s*", lambda m: m.group(1) + " ", label).strip()
        parts.append(lab)
    return " E ".join(parts)


def analyze_irule(code):
    """Retorna destinos encontrados com evento e condicao."""
    findings, stack = [], []
    for ln, raw in enumerate(code.split("\n"), 1):
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        while s.startswith("}"):
            if stack:
                stack.pop()
            s = s[1:].lstrip()
        if not s:
            continue
        clean = s.replace("\\{", "").replace("\\}", "")
        opens, closes = clean.count("{"), clean.count("}")
        event = next((l[5:].split()[0] for l in stack if l.startswith("when ") and len(l.split()) > 1), "")
        cond = _ctx_to_cond(stack)
        inline = ""
        if opens and opens == closes and clean.rstrip().endswith("}"):
            # bloco de uma linha: 'if { cond } { pool x }' ou '"/manut*" { node ... }'
            depth, k = 0, len(clean.rstrip()) - 1
            while k >= 0:
                if clean[k] == "}":
                    depth += 1
                elif clean[k] == "{":
                    depth -= 1
                    if depth == 0:
                        break
                k -= 1
            head = clean[:k].strip() if k > 0 else ""
            if head:
                inline = _ctx_to_cond(stack + [head])
        if not s.startswith("log "):
            found = []
            for m in RE_POOL.finditer(s):
                found.append(("pool", _clean_target(m.group(1)), m.group(2) or ""))
            for m in RE_NODE.finditer(s):
                found.append(("node", _clean_target(m.group(1)) + ((":" + m.group(2)) if m.group(2) else ""), ""))
            for m in RE_VIRTUAL.finditer(s):
                t = _clean_target(m.group(1))
                if t != "name":
                    found.append(("virtual", t, ""))
            m = RE_REDIRECT.search(s)
            if m:
                found.append(("redirect", _clean_target(m.group(1)), ""))
            m = RE_RESPOND.search(s)
            if m:
                code_ = m.group(1)
                loc = RE_LOCATION.search(m.group(2))
                found.append(("respond", code_ + ((" -> " + loc.group(1)) if loc else ""), ""))
            m = RE_REJECT.search(s)
            if m:
                found.append(("reject", m.group(1), ""))
            for kind, target, member in found:
                c = inline or cond
                findings.append({
                    "kind": kind, "target": target, "member": member,
                    "event": event, "cond": c, "line": ln, "text": s,
                })
        net = opens - closes
        if net > 0:
            label = s[:-1].strip() if s.endswith("{") else s
            if label.startswith("when "):
                label = "when " + " ".join(label[5:].split()[:1])
            for _ in range(net):
                stack.append(label)
        elif net < 0:
            for _ in range(-net):
                if stack:
                    stack.pop()
    return findings


def policy_action(words):
    def after(k):
        if k in words:
            i = words.index(k)
            return words[i + 1] if i + 1 < len(words) else ""
        return ""
    if "asm" in words:
        if "enable" in words and "policy" in words:
            return "waf", after("policy")
        if "disable" in words:
            return "waf-off", ""
    if "forward" in words:
        for k in ("pool", "node", "virtual"):
            if k in words:
                return k, after(k)
        if "reset" in words:
            return "reject", "reset"
    if "http-reply" in words and "redirect" in words:
        return "redirect", after("location")
    if "shutdown" in words or ("tcp" in words and "reset" in words):
        return "reject", "reset"
    return "other", " ".join(words)


# ---------------------------------------------------------------------------
# NAT de entrada (firewalls de qualquer fabricante) e DNS
# ---------------------------------------------------------------------------
# Toda regra de NAT de entrada vira o mesmo formato, independente do fabricante:
#   {"device", "name", "extip", "extport", "mappedip", "mappedport",
#    "portforward", "protocol", "extintf", "comment", "realservers"}
# Para suportar outro fabricante: escreva parse_<x>(text) -> [nat_rule(...)],
# registre em NAT_PARSERS e, se quiser deteccao automatica, em NAT_DETECT.


def norm_port(p):
    p = str(p or "").strip()
    if p in ("", "any", "0", "*"):
        return ""
    return port_num(p)


def nat_rule(device, name, extip="", extport="", mappedip="", mappedport="", protocol="tcp",
             extintf="", comment="", realservers=None):
    extport, mappedport = norm_port(extport), norm_port(mappedport)
    clean = lambda ip: re.sub(r"/32$", "", (ip or "").strip())
    return {"device": device, "name": name, "extip": clean(extip), "extport": extport,
            "mappedip": clean(mappedip), "mappedport": mappedport or extport,
            "portforward": bool(extport or mappedport), "protocol": protocol or "tcp",
            "extintf": extintf, "comment": comment, "realservers": realservers or []}


def parse_fortigate(text):
    """'config firewall vip' de um backup do FortiGate."""
    out, inside, depth, cur = [], False, 0, None
    for raw in text.splitlines():
        s = raw.strip()
        if not inside:
            if s == "config firewall vip":
                inside, depth = True, 1
            continue
        if s.startswith("config "):
            depth += 1
            continue
        if s == "end":
            depth -= 1
            if depth == 0:
                inside = False
            continue
        if depth > 1:
            m = re.match(r"set ip\s+(\S+)", s)
            if m and cur is not None:
                cur["realservers"].append(m.group(1).strip('"'))
            continue
        if s.startswith("edit "):
            cur = {"name": s[5:].strip().strip('"'), "extip": "", "mappedip": "", "extport": "",
                   "mappedport": "", "portforward": False, "protocol": "tcp", "extintf": "",
                   "comment": "", "realservers": []}
        elif s == "next":
            if cur:
                pf = cur["portforward"]
                out.append(nat_rule("FortiGate", cur["name"], cur["extip"], cur["extport"] if pf else "",
                                    cur["mappedip"], cur["mappedport"] if pf else "", cur["protocol"],
                                    cur["extintf"], cur["comment"], cur["realservers"]))
            cur = None
        elif s.startswith("set ") and cur is not None:
            parts = s.split(None, 2)
            key, val = parts[1], (parts[2] if len(parts) > 2 else "")
            first = next((a or b for a, b in re.findall(r'"([^"]*)"|(\S+)', val)), "")
            if key == "portforward":
                cur["portforward"] = first == "enable"
            elif key in cur:
                cur[key] = first
    return out


def _pan_tokens(line):
    toks = []
    for m in re.finditer(r'"([^"]*)"|\[([^\]]*)\]|(\S+)', line):
        if m.group(1) is not None:
            toks.append(m.group(1))
        elif m.group(2) is not None:
            toks.append(m.group(2).split())
        else:
            toks.append(m.group(3))
    return toks


def _after(seq, key):
    for j in range(len(seq) - 1):
        if seq[j] == key:
            return seq[j + 1]
    return None


def parse_paloalto(text):
    """PAN-OS / Panorama em formato 'set' (set cli config-output-format set; show)."""
    addrs, svcs, rules, order = {}, {"service-http": "80", "service-https": "443", "any": ""}, {}, []
    for raw in text.splitlines():
        s = raw.strip()
        if not s.startswith("set "):
            continue
        t = _pan_tokens(s)
        for i in range(1, len(t) - 2):
            if t[i] == "rules" and t[i - 1] == "nat" and isinstance(t[i - 2], str) and t[i - 2].endswith("rulebase"):
                name, rest = t[i + 1], t[i + 2:]
                if name not in rules:
                    rules[name] = {}
                    order.append(name)
                r = rules[name]
                for key in ("destination", "service", "source", "to", "from", "description"):
                    v = _after(rest, key)
                    if v is not None:
                        r[key] = v
                for ctx in ("destination-translation", "dynamic-destination-translation"):
                    if ctx in rest:
                        sub_ = rest[rest.index(ctx):]
                        for key in ("translated-address", "translated-port"):
                            v = _after(sub_, key)
                            if v is not None:
                                r[key] = v
                if "source-translation" in rest:
                    sub_ = rest[rest.index("source-translation"):]
                    v = _after(sub_, "translated-address")
                    if v is not None:
                        r["src-translated"] = v
                    if _after(sub_, "bi-directional") == "yes":
                        r["bidir"] = True
                if _after(rest, "disabled") == "yes":
                    r["disabled"] = True
                break
            if t[i] == "address" and isinstance(t[i + 1], str) and i + 3 < len(t) and t[i + 2] in ("ip-netmask", "ip-range"):
                addrs[t[i + 1]] = t[i + 3] if isinstance(t[i + 3], str) else ""
                break
            if t[i] == "service" and isinstance(t[i + 1], str) and i + 2 < len(t) and t[i + 2] == "protocol":
                port = _after(t[i:], "port")
                if isinstance(port, str):
                    svcs[t[i + 1]] = port
                break

    def addr(v):
        if isinstance(v, list):
            v = v[0] if v else ""
        return addrs.get(v, v) or ""

    out = []
    for name in order:
        r = rules[name]
        if r.get("disabled"):
            continue
        svc = r.get("service", "any")
        svc = svc[0] if isinstance(svc, list) and svc else svc
        port = svcs.get(svc, svc if str(svc).isdigit() else "")
        zone = r.get("from", "")
        zone = ",".join(zone) if isinstance(zone, list) else zone
        if r.get("translated-address"):
            ext = addr(r.get("destination", ""))
            if ext and ext != "any":
                out.append(nat_rule("Palo Alto", name, ext, port, addr(r["translated-address"]),
                                    r.get("translated-port", "") or port, extintf=zone,
                                    comment=r.get("description", "")))
        elif r.get("bidir") and r.get("src-translated"):
            out.append(nat_rule("Palo Alto", name, addr(r["src-translated"]), "", addr(r.get("source", "")), "",
                                extintf=zone, comment="static-ip bidirecional"))
    return out


def parse_asa(text):
    """Cisco ASA / FTD (LINA): object NAT, twice NAT e 'static' legado (pre-8.3)."""
    objs, svcs, raw_nats = {}, {}, []
    cur, kind = None, None
    for line in text.splitlines():
        if not line.strip() or line.startswith("!"):
            cur = None
            continue
        s = line.strip()
        if not line[0].isspace():
            cur, kind = None, None
            m = re.match(r"object network (\S+)", s)
            if m:
                cur, kind = m.group(1), "net"
                continue
            m = re.match(r"object service (\S+)", s)
            if m:
                cur, kind = m.group(1), "svc"
                continue
            m = re.match(r"nat \(([^,]+),([^)]+)\)\s+(?:\d+\s+|after-auto\s+)?source static (\S+) (\S+)(.*)", s)
            if m:
                svc = re.search(r"service (\S+) (\S+)", m.group(5))
                raw_nats.append(("twice", m.group(2), m.group(3), m.group(4),
                                 svc.group(1) if svc else None, svc.group(2) if svc else None, None))
                continue
            m = re.match(r"static \(([^,]+),([^)]+)\)\s+(tcp|udp)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)", s)
            if m:
                raw_nats.append(("legacy", m.group(2), m.group(6), m.group(4), m.group(7), m.group(5), m.group(3)))
                continue
            m = re.match(r"static \(([^,]+),([^)]+)\)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)", s)
            if m:
                raw_nats.append(("legacy", m.group(2), m.group(4), m.group(3), None, None, None))
            continue
        if kind == "net":
            m = re.match(r"host (\S+)", s)
            if m:
                objs[cur] = m.group(1)
            m = re.match(r"subnet (\S+) (\S+)", s)
            if m:
                objs[cur] = "%s %s" % (m.group(1), m.group(2))
            m = re.match(r"range (\S+) (\S+)", s)
            if m:
                objs[cur] = "%s-%s" % (m.group(1), m.group(2))
            m = re.match(r"nat \(([^,]+),([^)]+)\) static (\S+)(?: service (tcp|udp) (\S+) (\S+))?", s)
            if m:
                raw_nats.append(("object", m.group(2), cur, m.group(3), m.group(5), m.group(6), m.group(4)))
        elif kind == "svc":
            m = re.search(r"(?:source|destination) eq (\S+)", s)
            if m:
                svcs[cur] = m.group(1)

    out = []
    for i, (typ, outif, real, mapped, rport, mport, proto) in enumerate(raw_nats):
        real_ip, ext_ip = objs.get(real, real), objs.get(mapped, mapped)
        if typ == "twice":
            rport, mport = svcs.get(rport, ""), svcs.get(mport, "")
        if ext_ip == "interface":
            ext_ip = "interface " + outif
        name = real if typ != "legacy" else "static-%d" % (i + 1)
        out.append(nat_rule("Cisco ASA", name, ext_ip, mport or "", real_ip, rport or "", proto or "tcp",
                            extintf=outif, comment="%s NAT" % typ))
    return out


def parse_nat_csv(text):
    """CSV generico: nome, ip_publico, porta_publica, ip_interno, porta_interna[, dispositivo]."""
    aliases = {
        "name": ("name", "nome", "vip", "regra", "rule"),
        "extip": ("extip", "ip_publico", "ip publico", "public_ip", "ip_externo", "externo"),
        "extport": ("extport", "porta_publica", "porta publica", "public_port", "porta_externa"),
        "mappedip": ("mappedip", "ip_interno", "ip interno", "internal_ip", "ip_destino"),
        "mappedport": ("mappedport", "porta_interna", "porta interna", "internal_port", "porta_destino"),
        "device": ("device", "dispositivo", "firewall", "equipamento"),
    }
    lines = text.lstrip("﻿")
    dialect = csv.Sniffer().sniff(lines[:2048], delimiters=",;\t") if lines.strip() else csv.excel
    out = []
    for n, row in enumerate(csv.DictReader(lines.splitlines(), dialect=dialect), 1):
        low = {(k or "").strip().lower(): (v or "").strip() for k, v in row.items()}
        get = lambda key: next((low[a] for a in aliases[key] if low.get(a)), "")
        if get("mappedip") or get("extip"):
            out.append(nat_rule(get("device") or "NAT", get("name") or "regra-%d" % n, get("extip"),
                                get("extport"), get("mappedip"), get("mappedport")))
    return out


NAT_PARSERS = {"fortigate": parse_fortigate, "paloalto": parse_paloalto, "asa": parse_asa, "csv": parse_nat_csv}
NAT_DETECT = [
    ("fortigate", lambda t: re.search(r"^\s*config firewall vip\b", t, re.M)),
    ("paloalto", lambda t: re.search(r"\brulebase nat rules\b", t)),
    ("asa", lambda t: re.search(r"^(object network |nat \(|static \()", t, re.M)),
]


def load_nat(spec):
    """'arquivo' (tipo detectado) ou 'tipo:arquivo' (fortigate, paloalto, asa, csv)."""
    kind, path = None, spec
    if ":" in spec and spec.split(":", 1)[0].lower() in NAT_PARSERS:
        kind, path = spec.split(":", 1)
        kind = kind.lower()
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    if not kind:
        if path.lower().endswith((".csv", ".tsv")):
            kind = "csv"
        else:
            kind = next((k for k, test in NAT_DETECT if test(text)), None)
    if not kind:
        sys.exit("nao reconheci o formato de %s. Use tipo:arquivo (%s) ou um CSV generico."
                 % (path, ", ".join(NAT_PARSERS)))
    rules = NAT_PARSERS[kind](text)
    print("%s: %d regra(s) de NAT de entrada (%s)" % (path, len(rules), kind))
    return rules


def load_fqdn_csv(path):
    recs = []
    with open(path, newline="", encoding="utf-8-sig") as fh:
        sample = fh.read(2048)
        fh.seek(0)
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t") if sample else csv.excel
        for row in csv.reader(fh, dialect=dialect):
            if len(row) < 2 or not row[0].strip():
                continue
            name, val = row[0].strip().rstrip(".").lower(), row[1].strip().rstrip(".")
            if name in ("fqdn", "nome", "name", "host"):
                continue
            recs.append((name, "A" if is_ip(val) else "CNAME", val.lower() if not is_ip(val) else val))
    return recs


def parse_zone(text, origin=None):
    recs, cur_origin, last = [], (origin or "").rstrip(".").lower(), None

    def qualify(n):
        n = n.lower()
        if n == "@":
            return cur_origin
        if n.endswith("."):
            return n[:-1]
        return "%s.%s" % (n, cur_origin) if cur_origin else n

    for raw in text.splitlines():
        line = raw.split(";", 1)[0].rstrip()
        if not line.strip():
            continue
        if line.upper().startswith("$ORIGIN"):
            cur_origin = line.split()[1].rstrip(".").lower()
            continue
        if line.startswith("$"):
            continue
        toks = line.split()
        if line[0] in " \t":
            name = last
        else:
            name = toks.pop(0)
            last = name
        while toks and (toks[0].isdigit() or toks[0].upper() in ("IN", "CH", "HS")
                        or re.match(r"^\d+[smhdw]$", toks[0], re.I)):
            toks.pop(0)
        if len(toks) < 2 or name is None:
            continue
        rtype, val = toks[0].upper(), toks[1]
        if rtype in ("A", "AAAA"):
            recs.append((qualify(name), "A", val))
        elif rtype == "CNAME":
            recs.append((qualify(name), "CNAME", qualify(val)))
    return recs


def resolve_fqdns(recs):
    """Retorna {fqdn: {'ips': set, 'cname': str|None, 'external': bool}}"""
    table = {}
    for name, rtype, val in recs:
        table.setdefault(name, []).append((rtype, val))

    def ips(name, depth=0):
        if depth > 8:
            return set(), None
        out, ext = set(), None
        for rtype, val in table.get(name, []):
            if rtype == "A":
                out.add(val)
            else:
                sub_ips, sub_ext = ips(val, depth + 1)
                out |= sub_ips
                if not sub_ips and val not in table:
                    ext = val
                ext = ext or sub_ext
        return out, ext

    result = {}
    for name in table:
        found, ext = ips(name)
        cname = next((v for t, v in table[name] if t == "CNAME"), None)
        result[name] = {"ips": found, "cname": cname, "external": ext}
    return result


# ---------------------------------------------------------------------------
# Grafo
# ---------------------------------------------------------------------------


def wrap(text, width=40, max_lines=5):
    out = []
    for part in str(text).split("\n"):
        out.extend(textwrap.wrap(part, width, break_long_words=True, break_on_hyphens=False) or [""])
    if len(out) > max_lines:
        out = out[:max_lines]
        out[-1] = out[-1][: width - 1] + "\u2026"
    return "\n".join(out)


def node_size(label, typ):
    lines = label.split("\n")
    w = max(len(l) for l in lines) * 6.6 + 28
    h = len(lines) * 14 + 20
    if typ == "cond":
        w, h = w * 1.45, h * 1.9
    elif typ in ("fw", "waf", "reject", "redirect"):
        w += 24
    elif typ == "pool":
        h += 6
    return round(max(w, 60)), round(h)


class Graph:
    def __init__(self):
        self.nodes, self.edges, self._ek = {}, [], set()

    def node(self, nid, typ, label, **info):
        if nid not in self.nodes:
            lab = wrap(label)
            w, h = node_size(lab, typ)
            self.nodes[nid] = {"id": nid, "type": typ, "label": lab, "w": w, "h": h, "info": info}
        return nid

    def edge(self, s, t, label="", kind=""):
        k = (s, t, label)
        if k not in self._ek:
            self._ek.add(k)
            self.edges.append({"source": s, "target": t, "label": label, "kind": kind})


BUILTIN_PROFILES = {
    "tcp": "tcp", "f5-tcp-progressive": "tcp", "f5-tcp-wan": "tcp", "f5-tcp-lan": "tcp",
    "f5-tcp-optimized": "tcp", "mptcp-mobile-optimized": "tcp", "udp": "udp", "fastL4": "fastl4",
    "http": "http", "http-explicit": "http", "http2": "http2", "clientssl": "client-ssl",
    "clientssl-secure": "client-ssl", "serverssl": "server-ssl", "serverssl-insecure-compatible": "server-ssl",
    "oneconnect": "one-connect", "websecurity": "web-security (ASM)", "httpcompression": "http-compression",
    "wan-optimized-compression": "http-compression", "optimize-caching": "web-acceleration",
    "webacceleration": "web-acceleration", "stream": "stream", "ftp": "ftp", "dns": "dns",
}


class Builder:
    def __init__(self, cfg, nats=None, fqdns=None):
        self.cfg, self.nats, self.fqdns = cfg, nats or [], fqdns or {}
        self.g = Graph()
        self.alerts, self.flows = [], []
        self.vs_up = {}  # vs -> {'nat': [...], 'fqdn': [...], 'exposure': str}

    # -- nos de destino ------------------------------------------------------
    def pool_node(self, pname):
        nid = "pool:" + pname
        if nid in self.g.nodes:
            return nid
        p = self.cfg.pools.get(pname)
        if not p:
            self.alerts.append("Pool referenciado mas nao encontrado: %s" % pname)
            return self.g.node(nid, "missing", "pool %s\n(nao encontrado)" % short(pname), fields=[["Referencia", pname]])
        mon = p["monitor"] or "nenhum"
        fields = [["Pool", pname], ["Balanceamento", p["lb"]], ["Monitor", mon],
                  ["Membros", str(len(p["members"]))]]
        if p["min_up"]:
            fields.append(["Min. membros ativos", p["min_up"]])
        mons = [m for m in re.findall(r"/[\w./-]+", mon) if m in self.cfg.monitors]
        for m in mons:
            mi = self.cfg.monitors[m]
            det = mi["type"]
            if mi["send"]:
                det += "\nsend: " + mi["send"]
            if mi["recv"]:
                det += "\nrecv: " + mi["recv"]
            fields.append(["Monitor " + short(m), det])
        self.g.node(nid, "pool", "%s\n%s \u00b7 %d membro(s)" % (short(pname), p["lb"], len(p["members"])),
                    fields=fields, raw=p["raw"])
        if not p["members"]:
            self.alerts.append("Pool sem membros: %s" % pname)
        for m in p["members"]:
            mid = "mem:%s:%s" % (m["addr"], m["port"])
            label = "%s:%s" % (strip_rd(m["addr"]), m["port"])
            if m["node"] and m["node"] != m["addr"]:
                label += "\n" + m["node"]
            if m["state"]:
                label += "\n(" + ", ".join(m["state"]) + ")"
            self.g.node(mid, "member", label, fields=[["Endereco", m["addr"]], ["Porta", m["port"]],
                                                      ["Node", m["node"]], ["Monitor proprio", m["monitor"] or "-"],
                                                      ["Estado", ", ".join(m["state"]) or "habilitado"]])
            self.g.edge(nid, mid)
        return nid

    def members_str(self, pname):
        p = self.cfg.pools.get(pname)
        if not p:
            return ""
        return "; ".join("%s:%s" % (strip_rd(m["addr"]), m["port"]) for m in p["members"])

    def target(self, kind, target, part, src, idx, member=""):
        """Cria o no de destino e retorna (id, descricao_para_csv)."""
        g = self.g
        dynamic = target.startswith("$") or target.startswith("[")
        if kind == "pool":
            if dynamic:
                return g.node("dyn:%s:%d" % (src, idx), "dynamic", "pool dinamico\n%s" % target,
                              fields=[["Expressao", target]]), "pool dinamico " + target
            pname = resolve(self.cfg.pools, target, part)
            pid = self.pool_node(pname)
            if member:
                mid = "node:" + member
                g.node(mid, "node", "member %s" % member, fields=[["Selecao direta de membro", member]])
                g.edge(pid, mid, "member")
            return pid, pname
        if kind == "node":
            if dynamic:
                return g.node("dyn:%s:%d" % (src, idx), "dynamic", "node dinamico\n%s" % target,
                              fields=[["Expressao", target]]), "node dinamico " + target
            return g.node("node:" + target, "node", "node %s" % target, fields=[["Node", target]]), "node " + target
        if kind == "virtual":
            if dynamic:
                return g.node("dyn:%s:%d" % (src, idx), "dynamic", "virtual dinamico\n%s" % target,
                              fields=[["Expressao", target]]), "virtual dinamico " + target
            vname = resolve(self.cfg.virtuals, target, part)
            vid = "vs:" + vname
            if vid not in g.nodes:
                g.node(vid, "missing", "VS %s\n(nao encontrado)" % short(vname), fields=[["Referencia", vname]])
            return vid, "virtual " + vname
        if kind == "redirect":
            return g.node("redir:%s:%d" % (src, idx), "redirect", "redirect\n%s" % target,
                          fields=[["Location", target]]), "redirect " + target
        if kind == "respond":
            return g.node("resp:%s:%d" % (src, idx), "redirect", "HTTP::respond %s" % target,
                          fields=[["Resposta", target]]), "respond " + target
        if kind == "reject":
            return g.node("rej:%s:%d" % (src, idx), "reject", target, fields=[["Acao", target]]), target
        if kind == "waf":
            wname = full(target, part)
            return g.node("waf:" + wname, "waf", "WAF (ASM)\n%s" % short(wname),
                          fields=[["Politica ASM/AWAF", wname]]), "WAF " + wname
        if kind == "waf-off":
            return g.node("wafoff:%s:%d" % (src, idx), "reject", "WAF desabilitado",
                          fields=[["Acao", "asm disable"]]), "WAF desabilitado"
        return g.node("other:%s:%d" % (src, idx), "dynamic", target, fields=[["Acao", target]]), target

    # -- objetos -------------------------------------------------------------
    def policy(self, vsname, pname, order, row_base):
        g, part = self.g, part_of(vsname)
        pid = "pol:" + pname
        pol = self.cfg.policies.get(pname)
        if not pol:
            g.node(pid, "missing", "policy %s\n(nao encontrada)" % short(pname), fields=[["Referencia", pname]])
            self.alerts.append("LTM policy referenciada mas nao encontrada: %s" % pname)
            return pid
        new = pid not in g.nodes
        g.node(pid, "policy", "LTM policy %s\n%s" % (short(pname), pol["strategy"]),
               fields=[["Policy", pname], ["Estrategia", pol["strategy"]],
                       ["Requires", ", ".join(pol["requires"]) or "-"],
                       ["Controls", ", ".join(pol["controls"]) or "-"],
                       ["Regras", str(len(pol["rules"]))]], raw=pol["raw"])
        for ri, rule in enumerate(pol["rules"]):
            rid = "polrule:%s/%s" % (pname, rule["name"])
            conds = rule["conditions"]
            cond_txt = " E ".join(conds) if conds else "sem condicao (sempre)"
            acts = [policy_action(a) for a in rule["actions"]]
            if new:
                g.node(rid, "cond", "%s\n%s" % (rule["name"], cond_txt),
                       fields=[["Policy", pname], ["Regra", rule["name"]], ["Ordinal", rule["ordinal"]],
                               ["Condicoes", "\n".join(conds) or "nenhuma"],
                               ["Acoes", "\n".join(" ".join(a) for a in rule["actions"]) or "nenhuma"],
                               ["Descricao", rule["description"] or "-"]])
                g.edge(pid, rid, "#%s" % rule["ordinal"])
            for ai, (kind, tgt) in enumerate(acts):
                if kind == "other":
                    continue
                tid, desc = self.target(kind, tgt, part, rid, ai)
                g.edge(rid, tid, {"waf": "asm enable", "waf-off": "asm disable"}.get(kind, kind),
                       "virtual" if kind == "virtual" else "")
                self.flows.append(dict(row_base, mecanismo="%d. LTM policy" % order, objeto=pname,
                                       evento="", condicao="%s: %s" % (rule["name"], cond_txt),
                                       acao=kind, destino=desc,
                                       membros=self.members_str(desc) if kind == "pool" else ""))
            others = [" ".join(a) for (k, _), a in zip(acts, rule["actions"]) if k == "other"]
            if others and not any(k != "other" for k, _ in acts):
                self.flows.append(dict(row_base, mecanismo="%d. LTM policy" % order, objeto=pname, evento="",
                                       condicao="%s: %s" % (rule["name"], cond_txt), acao="outras",
                                       destino="; ".join(others), membros=""))
        return pid

    def irule(self, vsname, rname, order, row_base):
        g, part = self.g, part_of(vsname)
        iid = "irule:" + rname
        ir = self.cfg.irules.get(rname)
        if not ir:
            if base(rname).startswith("_sys_"):
                g.node(iid, "irule", "iRule %s\n(sistema)" % short(rname), fields=[["iRule", rname]])
            else:
                g.node(iid, "missing", "iRule %s\n(nao encontrada)" % short(rname), fields=[["Referencia", rname]])
                self.alerts.append("iRule referenciada mas nao encontrada: %s" % rname)
            return iid
        if "findings" not in ir:
            ir["findings"] = analyze_irule(ir["code"])
        findings = ir["findings"]
        events = sorted(set(RE_EVENT.findall(ir["code"])))
        new = iid not in g.nodes
        g.node(iid, "irule", "iRule %s\n%s" % (short(rname), ", ".join(events) or "-"),
               fields=[["iRule", rname], ["Eventos", ", ".join(events) or "-"],
                       ["Destinos detectados", str(len(findings))]], code=ir["code"], raw="")
        # data-groups com valores que sao pools (selecao dinamica)
        dg_pools = []
        for dname, dg in self.cfg.datagroups.items():
            if re.search(r"(?<![\w/-])%s(?![\w-])" % re.escape(base(dname)), ir["code"]):
                pools = [v for _k, v in dg["records"] if v and resolve(self.cfg.pools, v, part) in self.cfg.pools]
                pools += [k for k, _v in dg["records"] if resolve(self.cfg.pools, k, part) in self.cfg.pools]
                if pools:
                    dg_pools.append((dname, sorted(set(pools))))
        cond_ids = {}
        for idx, f in enumerate(findings):
            src = iid
            if f["cond"]:
                key = (f["event"], f["cond"])
                if key not in cond_ids:
                    cid = "ircond:%s:%d" % (rname, len(cond_ids))
                    cond_ids[key] = cid
                    g.node(cid, "cond", "%s\n%s" % (f["event"], f["cond"]),
                           fields=[["iRule", rname], ["Evento", f["event"]], ["Condicao", f["cond"]]],
                           code=ir["code"], lines=[])
                    g.edge(iid, cid)
                src = cond_ids[key]
                lines = g.nodes[src]["info"].setdefault("lines", [])
                if f["line"] not in lines:
                    lines.append(f["line"])
            tid, desc = self.target(f["kind"], f["target"], part, "%s#%d" % (rname, idx), idx, f["member"])
            lab = "%s \u00b7 L%d" % (f["kind"], f["line"]) if f["cond"] else "%s \u00b7 %s \u00b7 L%d" % (f["event"], f["kind"], f["line"])
            g.edge(src, tid, lab, "virtual" if f["kind"] == "virtual" else "")
            if g.nodes[tid]["type"] in ("redirect", "reject", "dynamic", "node"):
                g.nodes[tid]["info"].setdefault("code", ir["code"])
                g.nodes[tid]["info"].setdefault("lines", [f["line"]])
            dyn = f["target"].startswith("$") or f["target"].startswith("[")
            if dyn and f["kind"] == "pool":
                self.alerts.append("iRule com pool dinamico: %s (linha %d)" % (rname, f["line"]))
                for dname, pools in dg_pools:
                    for pn in pools:
                        pid = self.pool_node(resolve(self.cfg.pools, pn, part))
                        g.edge(tid, pid, "via data-group %s" % short(dname))
                        self.flows.append(dict(row_base, mecanismo="%d. iRule" % order, objeto=rname, evento=f["event"],
                                               condicao="%s (via data-group %s)" % (f["cond"] or "-", short(dname)),
                                               acao="pool", destino=resolve(self.cfg.pools, pn, part),
                                               membros=self.members_str(resolve(self.cfg.pools, pn, part))))
            self.flows.append(dict(row_base, mecanismo="%d. iRule" % order, objeto=rname, evento=f["event"],
                                   condicao=f["cond"] or "-", acao=f["kind"], destino=desc,
                                   membros=self.members_str(desc) if f["kind"] == "pool" else "",
                                   linha=f["line"]))
        return iid

    # -- montagem ------------------------------------------------------------
    def build(self):
        cfg, g = self.cfg, self.g
        # cria todos os VS primeiro (para links virtual -> virtual)
        for vname, v in sorted(cfg.virtuals.items()):
            dest = "%s:%s" % (v["ip"], v["port"] or "*")
            g.node("vs:" + vname, "vs", "VS %s\n%s%s" % (short(vname), dest, " (desabilitado)" if v["disabled"] else ""))
        self.map_upstream()
        for vname, v in sorted(cfg.virtuals.items()):
            vid = "vs:" + vname
            dest = "%s:%s" % (v["ip"], v["port"] or "*")
            up = self.vs_up.get(vname, {"nat": [], "fqdn": [], "exposure": ""})
            row_base = {"virtual_server": vname, "destino_vs": dest, "estado": "desabilitado" if v["disabled"] else "habilitado",
                        "fqdns": "; ".join(sorted(set(up["fqdn"]))), "nat_entrada": "; ".join(sorted(set(up["nat"]))),
                        "exposicao": up["exposure"],
                        "linha": ""}
            order = 1
            for pname in v["policies"]:
                self.policy(vname, pname, order, row_base)
                g.edge(vid, "pol:" + pname, "%d\u00ba LTM policy" % order)
                order += 1
            for rname in v["rules"]:
                self.irule(vname, rname, order, row_base)
                g.edge(vid, "irule:" + rname, "%d\u00ba iRule" % order)
                order += 1
            if v["pool"]:
                pid = self.pool_node(v["pool"])
                g.edge(vid, pid, "default pool", "default")
                self.flows.append(dict(row_base, mecanismo="default pool", objeto="", evento="",
                                       condicao="nenhuma regra selecionou outro destino" if order > 1 else "sempre",
                                       acao="pool", destino=v["pool"], membros=self.members_str(v["pool"])))
            if not v["pool"] and order == 1:
                self.alerts.append("VS sem default pool, policy ou iRule: %s" % vname)
                self.flows.append(dict(row_base, mecanismo="-", objeto="", evento="", condicao="-",
                                       acao="nenhuma", destino="", membros=""))
            if v["disabled"]:
                self.alerts.append("VS desabilitado: %s" % vname)
            g.nodes[vid]["info"] = {"fields": self.vs_fields(vname, v, up), "raw": v["raw"]}
        return self

    def vs_fields(self, vname, v, up):
        cfg = self.cfg
        profs, certs = [], []
        for p, ctx in v["profiles"]:
            pi = cfg.profiles.get(p)
            ptype = pi["type"] if pi else BUILTIN_PROFILES.get(base(p), "padrao do sistema")
            profs.append("%s (%s%s)" % (short(p), ptype, "" if ctx == "all" else ", " + ctx))
            if pi and pi["type"] in ("client-ssl", "server-ssl"):
                for c in pi["certs"]:
                    certs.append("%s: %s" % (pi["type"], c))
        persist = []
        for p in v["persist"]:
            pi = cfg.persist.get(p)
            persist.append("%s (%s)" % (short(p), pi["type"] if pi else base(p)))
        snat = v["snat"] or "nenhum"
        if v["snat_pool"]:
            snat += " " + v["snat_pool"]
        fields = [["Virtual server", vname], ["Destino", "%s:%s" % (v["ip"], v["port"] or "*")],
                  ["Protocolo", v["protocol"] or "-"], ["Estado", "desabilitado" if v["disabled"] else "habilitado"],
                  ["Default pool", v["pool"] or "nenhum"],
                  ["LTM policies", "\n".join(v["policies"]) or "nenhuma"],
                  ["iRules (ordem)", "\n".join(v["rules"]) or "nenhuma"],
                  ["Perfis", "\n".join(profs) or "-"],
                  ["Certificados", "\n".join(certs) or "-"],
                  ["Persistencia", "\n".join(persist) or "nenhuma"],
                  ["Fallback persist.", short(v["fallback_persist"]) if v["fallback_persist"] else "-"],
                  ["SNAT", snat],
                  ["VLANs", ("%s: %s" % (v["vlans_mode"], ", ".join(v["vlans"]))) if v["vlans"] else "todas"]]
        if v["source"] and v["source"] not in ("0.0.0.0/0", "::/0"):
            fields.append(["Origem permitida", v["source"]])
        if v["description"]:
            fields.append(["Descricao", v["description"]])
        fields.insert(4, ["Exposicao", up["exposure"] or "-"])
        if up["nat"]:
            fields.append(["NAT de entrada", "\n".join(sorted(set(up["nat"])))])
        if up["fqdn"]:
            fields.append(["FQDNs", "\n".join(sorted(set(up["fqdn"])))])
        fields.append(["Ordem de avaliacao",
                       "LTM policies -> iRules (na ordem listada) -> default pool. "
                       "A ultima selecao de pool vence; o default pool so e usado se nada selecionar outro destino."])
        return fields

    def map_upstream(self):
        g, cfg = self.g, self.cfg
        up = lambda vname: self.vs_up.setdefault(vname, {"nat": [], "fqdn": [], "exposure": ""})
        nat_hits = {}
        for i, r in enumerate(self.nats):
            mapped = [r["mappedip"]] + r.get("realservers", [])
            ext = "%s:%s" % (r["extip"] or "?", r["extport"] or "*")
            intn = "%s:%s" % (r["mappedip"] or "?", r["mappedport"] or "*")
            matched = []
            for vname, v in cfg.virtuals.items():
                if not any(ip_in(v["ip"], m) for m in mapped if m):
                    continue
                if r["portforward"] and not port_match(v["port"], r["mappedport"] or r["extport"]):
                    continue
                matched.append(vname)
            if not matched:
                self.alerts.append("NAT %s sem VS correspondente: %s (%s -> %s)" % (r["device"], r["name"], ext, intn))
                continue
            fid = "fw:%s:%s:%d" % (r["device"], r["name"], i)
            g.node(fid, "fw", "NAT %s · %s\n%s → %s" % (r["device"], r["name"], ext, intn),
                   fields=[["Dispositivo", r["device"]], ["Regra / objeto", r["name"]],
                           ["IP/porta externa", ext], ["IP/porta interna", intn],
                           ["Tipo", "port forward" if r["portforward"] else "NAT estatico (todas as portas)"],
                           ["Interface / zona", r.get("extintf") or "-"],
                           ["Comentario", r.get("comment") or "-"]])
            nat_hits[fid] = r
            for vname in matched:
                g.edge(fid, "vs:" + vname, "NAT %s→%s" % (r["extport"] or "*", r["mappedport"] or "*"), "up")
                up(vname)["nat"].append("%s %s (%s)" % (r["device"], r["name"], ext))
                up(vname).setdefault("devices", set()).add(r["device"])

        # exposicao de cada VS
        for vname, v in cfg.virtuals.items():
            u = up(vname)
            if u["nat"]:
                u["exposure"] = "via NAT (%s)" % ", ".join(sorted(u.get("devices", ())))
            elif is_public(v["ip"]):
                u["exposure"] = "IP publico direto"
                g.node("internet", "internet", "Internet", fields=[["Exposicao", "VS com IP publico, sem NAT na frente"]])
                g.edge("internet", "vs:" + vname, "IP publico direto", "up")
            else:
                u["exposure"] = "interno" if self.nats else "IP privado (NAT nao informado)"
                if self.nats and not v["disabled"]:
                    self.alerts.append("VS com IP privado sem NAT de entrada mapeado (interno?): %s" % vname)

        unmatched = 0
        for fqdn, info in sorted(self.fqdns.items()):
            hit = False
            for fid, r in nat_hits.items():
                if any(ip_in(ip, r["extip"]) for ip in info["ips"]):
                    hit = True
                    self._fqdn_node(fqdn, info)
                    g.edge("fqdn:" + fqdn, fid, "DNS", "up")
                    for e in g.edges:
                        if e["source"] == fid and e["target"].startswith("vs:"):
                            up(e["target"][3:])["fqdn"].append(fqdn)
            for vname, v in cfg.virtuals.items():
                if any(ip == strip_rd(v["ip"]) for ip in info["ips"]):
                    hit = True
                    self._fqdn_node(fqdn, info)
                    g.edge("fqdn:" + fqdn, "vs:" + vname, "DNS direto", "up")
                    up(vname)["fqdn"].append(fqdn)
            if not hit:
                unmatched += 1
        if self.fqdns and unmatched:
            self.alerts.append("%d FQDN(s) nao apontam para nenhum NAT/VS mapeado" % unmatched)

    def _fqdn_node(self, fqdn, info):
        fields = [["FQDN", fqdn], ["IPs", ", ".join(sorted(info["ips"])) or "-"]]
        if info.get("cname"):
            fields.append(["CNAME", info["cname"]])
        if info.get("external"):
            fields.append(["CNAME externo", info["external"]])
        self.g.node("fqdn:" + fqdn, "fqdn", fqdn, fields=fields)


# ---------------------------------------------------------------------------
# Saidas
# ---------------------------------------------------------------------------

CDN_LIBS = [
    ("cytoscape.min.js", "https://unpkg.com/cytoscape@3.28.1/dist/cytoscape.min.js"),
    ("dagre.min.js", "https://unpkg.com/dagre@0.8.5/dist/dagre.min.js"),
    ("cytoscape-dagre.js", "https://unpkg.com/cytoscape-dagre@2.5.0/cytoscape-dagre.js"),
]


def libs_html(libs_dir=None):
    """Tags <script>: via CDN ou embutidas a partir de um diretorio local."""
    if not libs_dir:
        return "\n".join('<script src="%s"></script>' % url for _f, url in CDN_LIBS)
    parts = []
    for fname, url in CDN_LIBS:
        f = Path(libs_dir) / fname
        if not f.exists():
            sys.exit("--libs: arquivo %s nao encontrado (baixe de %s)" % (f, url))
        parts.append("<script>%s</script>" % f.read_text(encoding="utf-8").replace("</script", "<\\/script"))
    return "\n".join(parts)


HTML_TEMPLATE = r"""<!doctype html>
<html lang="pt-br">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__</title>
__LIBS__
<style>
*{box-sizing:border-box}
body{margin:0;font:13px/1.4 system-ui,"Segoe UI",Roboto,sans-serif;color:#1f2328;background:#fff;display:grid;grid-template-columns:300px 1fr 400px;height:100vh;overflow:hidden}
#side{border-right:1px solid #ddd;display:flex;flex-direction:column;min-height:0}
#side header{padding:12px;border-bottom:1px solid #eee}
h1{font-size:15px;margin:0 0 4px}
.meta{color:#666;font-size:12px}
#search{width:100%;padding:6px 8px;margin-top:8px;border:1px solid #ccc;border-radius:6px;font:inherit}
.opts{display:flex;flex-wrap:wrap;gap:6px 12px;margin-top:8px;font-size:12px;align-items:center}
#list{overflow:auto;flex:1;padding:4px 0;min-height:0}
.vs{padding:6px 12px;cursor:pointer;border-left:3px solid transparent}
.vs:hover{background:#f5f7fa}
.vs.active{background:#e8f0fe;border-left-color:#1a73e8}
.vs .n{font-weight:600;word-break:break-all}
.vs .d{color:#666;font-size:11.5px;word-break:break-all}
.vs.off .n{color:#999;text-decoration:line-through}
#alerts{border-top:1px solid #eee;max-height:32%;overflow:auto;padding:8px 12px;font-size:12px}
#alerts ul{margin:0;padding-left:16px}
#alerts li{margin-bottom:3px;word-break:break-all}
h2{font-size:13px;margin:4px 0 6px}
#main{position:relative;min-width:0}
#cy{position:absolute;inset:0}
#toolbar{position:absolute;top:8px;left:8px;z-index:5;display:flex;gap:6px;flex-wrap:wrap}
button{font:inherit;padding:5px 10px;border:1px solid #ccc;background:#fff;border-radius:6px;cursor:pointer}
button:hover{background:#f2f2f2}
#legend{position:absolute;bottom:8px;left:8px;z-index:5;background:rgba(255,255,255,.92);border:1px solid #ddd;border-radius:6px;padding:6px 8px;font-size:11px;display:flex;flex-wrap:wrap;gap:4px 10px;max-width:75%}
#legend i{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:4px;vertical-align:-1px;border:1px solid}
#det{border-left:1px solid #ddd;overflow:auto;padding:12px}
#det table{border-collapse:collapse;width:100%;font-size:12px;margin:8px 0}
#det td{border-bottom:1px solid #eee;padding:4px;vertical-align:top;word-break:break-word}
#det td:first-child{color:#666;white-space:nowrap;width:1%;padding-right:10px}
pre{background:#f6f8fa;border:1px solid #e5e7eb;border-radius:6px;padding:8px 0;font:11.5px/1.45 ui-monospace,Consolas,monospace;overflow:auto;margin:6px 0}
pre .L{display:block;white-space:pre;padding:0 8px;min-height:1.45em}
pre .L.hl{background:#fff3b0}
pre .ln{color:#999;user-select:none;display:inline-block;width:3em}
pre.raw{padding:8px;white-space:pre}
summary{cursor:pointer;color:#1a73e8;margin-top:8px}
#empty{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;color:#888;pointer-events:none}
a{color:#1a73e8}
</style>
</head>
<body>
<aside id="side">
  <header>
    <h1>__TITLE__</h1>
    <div class="meta" id="meta"></div>
    <input id="search" placeholder="Filtrar por nome, IP, FQDN ou NAT">
    <div class="opts">
      <label><input type="checkbox" id="optMembers" checked> Membros</label>
      <label><input type="checkbox" id="optUp" checked> Entrada (DNS/NAT)</label>
      <label>Direcao <select id="optDir"><option value="LR">esq. &rarr; dir.</option><option value="TB">cima &darr; baixo</option></select></label>
    </div>
  </header>
  <div id="list"></div>
  <div id="alerts"></div>
</aside>
<main id="main">
  <div id="toolbar">
    <button id="btnAll" title="Mostra todos os virtual servers de uma vez">Ver todos</button>
    <button id="btnFit">Ajustar</button>
    <button id="btnPng">Exportar PNG</button>
  </div>
  <div id="cy"></div>
  <div id="empty">Selecione um virtual server a esquerda</div>
  <div id="legend"></div>
</main>
<aside id="det"><h2>Detalhes</h2><p class="meta">Clique em um elemento do fluxo para ver a configuracao.</p></aside>
<script>const DATA = __DATA__;</script>
<script>
(function () {
  if (window.cytoscapeDagre) cytoscape.use(cytoscapeDagre);
  const $ = s => document.querySelector(s);
  const esc = s => String(s == null ? '' : s).replace(/[&<>"]/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;'}[c]));
  const N = new Map(DATA.nodes.map(n => [n.id, n]));
  const OUT = new Map(), IN = new Map();
  DATA.edges.forEach((e, i) => {
    e.id = 'e' + i;
    if (!OUT.has(e.source)) OUT.set(e.source, []);
    if (!IN.has(e.target)) IN.set(e.target, []);
    OUT.get(e.source).push(e);
    IN.get(e.target).push(e);
  });
  const TYPES = {
    fqdn: ['FQDN', '#efe7ff', '#7c4dff', 'round-rectangle'],
    internet: ['Internet', '#eceff1', '#455a64', 'ellipse'],
    fw: ['NAT / firewall', '#fff1e0', '#ef6c00', 'round-hexagon'],
    vs: ['Virtual server', '#e3efff', '#1a73e8', 'round-rectangle'],
    policy: ['LTM policy', '#e0f5f1', '#00897b', 'round-rectangle'],
    irule: ['iRule', '#f1e8fb', '#8e24aa', 'round-rectangle'],
    cond: ['Condicao', '#fff8d6', '#c9a400', 'round-diamond'],
    pool: ['Pool', '#e5f6e6', '#2e7d32', 'barrel'],
    member: ['Membro', '#f4fbf4', '#66bb6a', 'round-rectangle'],
    node: ['Node direto', '#eef7ee', '#43a047', 'ellipse'],
    waf: ['Politica WAF', '#fde7e7', '#c62828', 'round-pentagon'],
    redirect: ['Redirect / resposta', '#fdecef', '#d81b60', 'round-tag'],
    reject: ['Reject / drop', '#fbe9e7', '#b71c1c', 'round-octagon'],
    dynamic: ['Destino dinamico', '#f5f5f5', '#757575', 'round-rectangle'],
    missing: ['Nao encontrado', '#fafafa', '#9e9e9e', 'round-rectangle']
  };
  const style = [
    {selector: 'node', style: {
      'label': 'data(label)', 'text-wrap': 'wrap', 'text-valign': 'center', 'text-halign': 'center',
      'font-size': 11, 'font-family': 'system-ui, Segoe UI, sans-serif', 'color': '#1f2328',
      'width': 'data(w)', 'height': 'data(h)', 'border-width': 1.5, 'shape': 'round-rectangle',
      'background-color': '#fff', 'border-color': '#999'}},
    ...Object.entries(TYPES).map(([t, v]) => ({selector: 'node[type = "' + t + '"]', style: {'background-color': v[1], 'border-color': v[2], 'shape': v[3]}})),
    {selector: 'node[type = "vs"]', style: {'font-weight': 'bold', 'border-width': 2.5}},
    {selector: 'node[type = "missing"], node[type = "dynamic"]', style: {'border-style': 'dashed'}},
    {selector: 'edge', style: {
      'curve-style': 'bezier', 'target-arrow-shape': 'triangle', 'width': 1.4,
      'line-color': '#9aa4ae', 'target-arrow-color': '#9aa4ae', 'label': 'data(label)',
      'font-size': 9.5, 'color': '#333', 'text-background-color': '#fff',
      'text-background-opacity': 0.92, 'text-background-padding': 2}},
    {selector: 'edge[kind = "default"]', style: {'line-style': 'dashed', 'line-color': '#2e7d32', 'target-arrow-color': '#2e7d32'}},
    {selector: 'edge[kind = "virtual"]', style: {'line-color': '#8e24aa', 'target-arrow-color': '#8e24aa'}},
    {selector: 'edge[kind = "up"]', style: {'line-color': '#ef6c00', 'target-arrow-color': '#ef6c00'}},
    {selector: 'node:selected', style: {'border-color': '#ff6d00', 'border-width': 3.5}},
    {selector: '.faded', style: {'opacity': 0.18}}
  ];
  const cy = cytoscape({container: $('#cy'), style: style, wheelSensitivity: 0.25, minZoom: 0.03, maxZoom: 3});
  let current = null;
  const isUp = t => t === 'fw' || t === 'fqdn' || t === 'internet';
  const opts = () => ({members: $('#optMembers').checked, up: $('#optUp').checked, dir: $('#optDir').value});

  function collect(starts, o) {
    const startSet = new Set(starts), keep = new Set(starts), edges = new Map(), q = starts.slice();
    const allowed = id => {
      const t = N.get(id).type;
      if (!o.members && t === 'member') return false;
      if (!o.up && isUp(t)) return false;
      return true;
    };
    while (q.length) {
      const id = q.shift();
      if (N.get(id).type === 'vs' && !startSet.has(id)) continue;
      for (const e of OUT.get(id) || []) {
        if (!allowed(e.target)) continue;
        edges.set(e.id, e);
        if (!keep.has(e.target)) { keep.add(e.target); q.push(e.target); }
      }
    }
    if (o.up) for (const id of starts) {
      for (const e of IN.get(id) || []) {
        const s = N.get(e.source);
        if (!isUp(s.type)) continue;
        edges.set(e.id, e); keep.add(e.source);
        for (const e2 of IN.get(e.source) || []) {
          if (N.get(e2.source).type === 'fqdn') { edges.set(e2.id, e2); keep.add(e2.source); }
        }
      }
    }
    return {nodes: Array.from(keep, id => N.get(id)), edges: Array.from(edges.values())};
  }

  function render(starts) {
    const o = opts(), g = collect(starts, o);
    cy.elements().remove();
    cy.add(g.nodes.map(n => ({group: 'nodes', data: {id: n.id, label: n.label, type: n.type, w: n.w, h: n.h}})));
    cy.add(g.edges.map(e => ({group: 'edges', data: {id: e.id, source: e.source, target: e.target, label: e.label || '', kind: e.kind || ''}})));
    $('#empty').style.display = g.nodes.length ? 'none' : 'flex';
    const layout = window.cytoscapeDagre
      ? {name: 'dagre', rankDir: o.dir, nodeSep: 22, rankSep: 70, edgeSep: 10, padding: 30}
      : {name: 'breadthfirst', directed: true, padding: 30, spacingFactor: 1.1};
    cy.layout(layout).run();
  }

  function openVs(id) {
    current = id;
    render([id]);
    renderList();
    showDetails(id);
  }

  function showAll() {
    current = '__all__';
    render(DATA.nodes.filter(n => n.type === 'vs' || isUp(n.type)).map(n => n.id));
    renderList();
  }

  function ancestorsVs(id) {
    const seen = new Set([id]), out = new Set(), q = [id];
    while (q.length) {
      const cur = q.shift();
      for (const e of IN.get(cur) || []) {
        if (seen.has(e.source)) continue;
        seen.add(e.source);
        const t = N.get(e.source).type;
        if (t === 'vs') out.add(e.source);
        else if (!isUp(t)) q.push(e.source);
      }
    }
    return Array.from(out);
  }

  function showDetails(id) {
    const n = N.get(id);
    if (!n) return;
    const info = n.info || {};
    let h = '<h2>' + esc(n.label.replace(/\n/g, ' \u00b7 ')) + '</h2><div class="meta">' + esc((TYPES[n.type] || [n.type])[0]) + '</div>';
    if (info.fields && info.fields.length) {
      h += '<table>' + info.fields.map(f => '<tr><td>' + esc(f[0]) + '</td><td>' + esc(f[1]).replace(/\n/g, '<br>') + '</td></tr>').join('') + '</table>';
    }
    if (n.type === 'vs' && id !== current) h += '<p><button data-open="' + esc(id) + '">Abrir fluxo deste VS</button></p>';
    if (n.type !== 'vs') {
      const users = ancestorsVs(id);
      if (users.length) h += '<div class="meta">Usado pelos virtual servers:</div><ul>' + users.map(s => '<li><a href="#" data-open="' + esc(s) + '">' + esc(N.get(s).label.split('\n')[0]) + '</a></li>').join('') + '</ul>';
    }
    if (info.code) {
      const hl = new Set(info.lines || []);
      h += '<div class="meta">Codigo' + (hl.size ? ' (linhas relevantes destacadas)' : '') + '</div><pre>' +
        info.code.split('\n').map((l, i) => '<span class="L' + (hl.has(i + 1) ? ' hl' : '') + '"><span class="ln">' + (i + 1) + '</span>' + esc(l) + '</span>').join('') + '</pre>';
    }
    if (info.raw) h += '<details' + (info.code ? '' : ' open') + '><summary>Configuracao (bigip.conf)</summary><pre class="raw">' + esc(info.raw) + '</pre></details>';
    $('#det').innerHTML = h;
    const first = $('#det .hl');
    if (first) first.scrollIntoView({block: 'center'});
  }

  function renderList() {
    const f = $('#search').value.trim().toLowerCase();
    const items = DATA.vsList.filter(v => !f || [v.name, v.dest, v.exposure].concat(v.fqdns, v.nat).join(' ').toLowerCase().includes(f));
    $('#list').innerHTML = items.map(v =>
      '<div class="vs' + (v.id === current ? ' active' : '') + (v.disabled ? ' off' : '') + '" data-id="' + esc(v.id) + '">' +
      '<div class="n">' + esc(v.name) + '</div><div class="d">' + esc(v.dest) + (v.exposure ? ' \u00b7 ' + esc(v.exposure) : '') +
      (v.fqdns.length ? ' \u00b7 ' + esc(v.fqdns.join(', ')) : '') + '</div></div>').join('') ||
      '<p class="meta" style="padding:0 12px">Nenhum VS encontrado.</p>';
  }

  $('#list').addEventListener('click', ev => { const el = ev.target.closest('.vs'); if (el) openVs(el.dataset.id); });
  $('#det').addEventListener('click', ev => { const a = ev.target.closest('[data-open]'); if (a) { ev.preventDefault(); openVs(a.dataset.open); } });
  $('#search').addEventListener('input', renderList);
  ['#optMembers', '#optUp', '#optDir'].forEach(s => $(s).addEventListener('change', () => {
    if (current === '__all__') showAll(); else if (current) openVs(current);
  }));
  $('#btnAll').onclick = () => {
    if (DATA.nodes.length > 1500 && !confirm('Sao ' + DATA.nodes.length + ' elementos. O desenho pode ficar lento. Continuar?')) return;
    showAll();
  };
  $('#btnFit').onclick = () => cy.fit(undefined, 30);
  $('#btnPng').onclick = () => {
    const a = document.createElement('a');
    a.href = cy.png({full: true, scale: 2, bg: '#ffffff'});
    const nm = current === '__all__' ? 'todos' : (N.get(current) ? N.get(current).label.split('\n')[0] : 'fluxo');
    a.download = nm.replace(/[^\w.-]+/g, '_') + '.png';
    a.click();
  };
  cy.on('tap', 'node', ev => {
    const t = ev.target;
    showDetails(t.id());
    cy.elements().removeClass('faded');
    const keep = t.union(t.predecessors()).union(t.successors());
    cy.elements().not(keep).addClass('faded');
  });
  cy.on('tap', 'edge', ev => {
    const e = ev.target;
    cy.elements().removeClass('faded');
    showDetails(e.source().id());
  });
  cy.on('tap', ev => { if (ev.target === cy) cy.elements().removeClass('faded'); });
  cy.on('dbltap', 'node[type = "vs"]', ev => openVs(ev.target.id()));

  $('#legend').innerHTML = Object.values(TYPES).map(v => '<span><i style="background:' + v[1] + ';border-color:' + v[2] + '"></i>' + esc(v[0]) + '</span>').join('') +
    '<span>&#9473; default pool (tracejado)</span>';
  const m = DATA.meta;
  $('#meta').innerHTML = esc(m.counts) + '<br>Gerado em ' + esc(m.generated);
  $('#alerts').innerHTML = DATA.alerts.length
    ? '<h2>Alertas (' + DATA.alerts.length + ')</h2><ul>' + DATA.alerts.map(a => '<li>' + esc(a) + '</li>').join('') + '</ul>'
    : '<h2>Alertas</h2><p class="meta">Nenhum.</p>';
  renderList();
  if (DATA.vsList.length) openVs(DATA.vsList[0].id);
})();
</script>
</body>
</html>
"""


def write_html(builder, path, title, libs_dir=None):
    g, cfg = builder.g, builder.cfg
    vs_list = []
    for vname, v in sorted(cfg.virtuals.items()):
        up = builder.vs_up.get(vname, {"nat": [], "fqdn": [], "exposure": ""})
        vs_list.append({"id": "vs:" + vname, "name": short(vname), "dest": "%s:%s" % (v["ip"], v["port"] or "*"),
                        "disabled": v["disabled"], "fqdns": sorted(set(up["fqdn"])), "nat": sorted(set(up["nat"])),
                        "exposure": up["exposure"]})
    counts = "%d VS \u00b7 %d pools \u00b7 %d iRules \u00b7 %d policies" % (
        len(cfg.virtuals), len(cfg.pools), len(cfg.irules), len(cfg.policies))
    if builder.nats:
        counts += " \u00b7 %d regras NAT" % len(builder.nats)
    if builder.fqdns:
        counts += " \u00b7 %d FQDNs" % len(builder.fqdns)
    data = {
        "nodes": list(g.nodes.values()), "edges": g.edges, "vsList": vs_list,
        "alerts": sorted(set(builder.alerts)),
        "meta": {"counts": counts, "generated": _dt.datetime.now().strftime("%d/%m/%Y %H:%M"),
                 "sources": cfg.sources},
    }
    blob = json.dumps(data, ensure_ascii=False).replace("</", "<\\/")
    html = (HTML_TEMPLATE.replace("__LIBS__", libs_html(libs_dir))
            .replace("__TITLE__", title.replace("<", "&lt;")).replace("__DATA__", blob))
    Path(path).write_text(html, encoding="utf-8")


CSV_COLS = ["fqdns", "nat_entrada", "exposicao", "virtual_server", "destino_vs", "estado", "mecanismo", "objeto",
            "evento", "condicao", "acao", "destino", "membros", "linha"]


def write_csv(builder, path):
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.DictWriter(fh, fieldnames=CSV_COLS, delimiter=";", extrasaction="ignore")
        w.writeheader()
        for row in builder.flows:
            w.writerow({k: row.get(k, "") for k in CSV_COLS})


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def load_inputs(paths):
    texts = []
    for p in paths:
        P = Path(p)
        if not P.exists():
            sys.exit("arquivo nao encontrado: %s" % p)
        if P.is_dir():
            for f in sorted(P.rglob("bigip.conf")):
                texts.append((str(f), f.read_text(encoding="utf-8", errors="replace")))
        elif tarfile.is_tarfile(str(P)):
            with tarfile.open(str(P)) as tf:
                for m in tf.getmembers():
                    if m.isfile() and CONF_RE.search(m.name):
                        texts.append(("%s:%s" % (P.name, m.name), tf.extractfile(m).read().decode("utf-8", "replace")))
        else:
            texts.append((str(P), P.read_text(encoding="utf-8", errors="replace")))
    if not texts:
        sys.exit("nenhum bigip.conf encontrado nas entradas informadas")
    return texts


def main(argv=None):
    ap = argparse.ArgumentParser(description="Gera fluxograma interativo das aplicacoes F5 BIG-IP.")
    ap.add_argument("inputs", nargs="+", help="qkview, bigip.conf ou diretorio")
    ap.add_argument("-o", "--output", default="f5_fluxo.html", help="arquivo HTML de saida")
    ap.add_argument("--title", default="Fluxo das aplicacoes F5")
    ap.add_argument("--nat", "--firewall", "--fortigate", dest="nat", action="append", default=[],
                    help="config do firewall/NAT de entrada: 'arquivo' (tipo detectado) ou 'tipo:arquivo'. "
                         "Tipos: %s. Pode repetir para varios equipamentos." % ", ".join(NAT_PARSERS))
    ap.add_argument("--nat-csv", "--fw-csv", dest="nat_csv", action="append", default=[],
                    help="CSV generico de NAT: nome,ip_publico,porta_publica,ip_interno,porta_interna[,dispositivo]")
    ap.add_argument("--fqdns", action="append", default=[], help="CSV fqdn,ip")
    ap.add_argument("--zone", action="append", default=[], help="arquivo de zona BIND")
    ap.add_argument("--origin", default=None, help="origem da zona, se o arquivo nao tiver $ORIGIN")
    ap.add_argument("--csv", help="exporta os caminhos em CSV (separador ;)")
    ap.add_argument("--json", help="exporta o grafo em JSON")
    ap.add_argument("--libs", help="diretorio com cytoscape.min.js, dagre.min.js e cytoscape-dagre.js "
                                   "para embutir no HTML (uso offline)")
    a = ap.parse_args(argv)

    cfg = F5Config()
    for label, text in load_inputs(a.inputs):
        cfg.load(label, text)

    vips = []
    for f in a.nat:
        vips += load_nat(f)
    for f in a.nat_csv:
        vips += load_nat("csv:" + f)

    recs = []
    for f in a.fqdns:
        recs += load_fqdn_csv(f)
    for f in a.zone:
        recs += parse_zone(Path(f).read_text(encoding="utf-8", errors="replace"), a.origin)
    fqdns = resolve_fqdns(recs) if recs else {}

    b = Builder(cfg, vips, fqdns).build()
    write_html(b, a.output, a.title, a.libs)
    if a.csv:
        write_csv(b, a.csv)
    if a.json:
        Path(a.json).write_text(json.dumps({"nodes": list(b.g.nodes.values()), "edges": b.g.edges},
                                           ensure_ascii=False, indent=1), encoding="utf-8")

    print("Fontes: %s" % ", ".join(cfg.sources))
    print("%d virtual servers, %d pools, %d iRules, %d LTM policies, %d data-groups"
          % (len(cfg.virtuals), len(cfg.pools), len(cfg.irules), len(cfg.policies), len(cfg.datagroups)))
    if vips:
        print("%d regras de NAT de entrada no total" % len(vips))
    if fqdns:
        print("%d FQDNs lidos" % len(fqdns))
    print("%d alertas" % len(set(b.alerts)))
    print("HTML: %s" % a.output)
    if a.csv:
        print("CSV:  %s" % a.csv)


if __name__ == "__main__":
    main()
