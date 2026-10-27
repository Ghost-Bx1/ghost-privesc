# Ghost-Privesc

> By Gh0st-Bx1 | [github.com/Ghost-Bx1](https://github.com/Ghost-Bx1)

Ferramenta de verificacao de escalada de privilegios no Linux para pentest e CTF. Verifica automaticamente 17 vetores de privesc e gera um score de risco.

---

## Funcionalidades

| Modulo | Descricao |
|---|---|
| `--sistema` | Informacoes do host (kernel, OS, usuario, grupos perigosos) |
| `--kernel` | CVEs conhecidos (DirtyCow, DirtyPipe, eBPF, Netfilter...) |
| `--sudo` | Analise de `sudo -l` com lookup GTFOBins automatico |
| `--suid` | Binarios SUID/SGID com lookup GTFOBins automatico |
| `--caps` | Linux capabilities perigosas (cap_setuid, cap_sys_admin...) |
| `--cron` | Cron jobs com scripts inexistentes ou gravieis |
| `--servicos` | Unit files e binarios de servicos gravieis |
| `--path` | PATH hijacking (diretorios relativos ou gravieis) |
| `--nfs` | NFS exports com `no_root_squash` |
| `--senhas` | Credenciais em /etc/shadow, historico, .env, configs |
| `--containers` | Docker socket, container privilegiado, LXD escape |
| `--graveis` | /etc/passwd, /etc/sudoers, crontab e outros criticos |
| `--env` | Variaveis de ambiente sensiveis (LD_PRELOAD, tokens...) |
| `--processos` | Processos rodando como root |
| `--portas` | Servicos em localhost (MySQL, Redis, MongoDB...) |
| `--usuarios` | UIDs suspeitos (UID=0, home acessiveis) |

---

## Nivel de risco

Cada achado recebe pontuacao:
- **CRITICO** — 10 pts
- **ALTO** — 5 pts
- **MEDIO** — 3 pts
- **BAIXO** — 1 pt

Score total define o risco geral do host.

---

## Requisitos

```bash
# Sem dependencias externas — apenas stdlib Python 3
python3 --version  # 3.6+

# O script deve rodar no alvo Linux (nao funciona no Windows)
```

---

## Uso

```bash
# Verificacao completa (todos os modulos)
python3 ghost-privesc.py --completo

# Modulos especificos
python3 ghost-privesc.py --sudo --suid --caps

# Apenas senhas e credenciais
python3 ghost-privesc.py --senhas

# Verificacao rapida de escalada direta
python3 ghost-privesc.py --sudo --suid --caps --graveis

# Verificacao de containers (Docker/LXD)
python3 ghost-privesc.py --containers

# Executar sem argumento = completo automatico
python3 ghost-privesc.py

# Salvar relatorio JSON
python3 ghost-privesc.py --completo --output relatorio.json
```

---

## Saida exemplo

```
  Ghost-Privesc v1.0.0  |  Linux Privilege Escalation Checker

  [=] INFORMACOES DO SISTEMA
  [INFO   ] Hostname  : ubuntu-victim
  [INFO   ] Kernel    : 5.8.0-53-generic
  [INFO   ] OS        : Ubuntu 20.04.3 LTS
  [CRITICO] Usuario no grupo 'docker' - escape de container possivel

  [=] KERNEL / CVEs CONHECIDOS
  [CRITICO] Kernel 5.8.0-53-generic pode ser vulneravel: DirtyPipe (CVE-2022-0847)

  [=] SUDO
  [CRITICO] NOPASSWD: (ALL) NOPASSWD: /usr/bin/find
  [CRITICO] GTFOBins: find com NOPASSWD => privesc direto
             Ref: https://gtfobins.github.io/gtfobins/find/#sudo

  [=] SUID / SGID
  [CRITICO] SUID GTFOBins: /usr/bin/python3.8
             Ref: https://gtfobins.github.io/gtfobins/python3/#suid

  [=] RESUMO
  CRITICOS: 3  ALTOS: 2  MEDIOS: 1
  Score de risco: 38 pontos

  [!] RISCO CRITICO — Multiplos vetores de privesc identificados
```

---

## Opcoes completas

```
opcoes:
  --completo            Executar todos os modulos
  --sistema             Informacoes do sistema e grupos
  --kernel              CVEs de kernel conhecidos
  --sudo                Analise de sudo -l + GTFOBins
  --suid                Binarios SUID/SGID + GTFOBins
  --caps                Linux capabilities
  --cron                Cron jobs suspeitos
  --servicos            Unit files e binarios de servicos
  --path                PATH hijacking
  --nfs                 NFS no_root_squash
  --senhas              Credenciais em arquivos
  --containers          Docker/LXD escape
  --graveis             Arquivos criticos gravieis
  --env                 Variaveis de ambiente
  --processos           Processos como root
  --portas              Portas internas/localhost
  --usuarios            UIDs e homes suspeitos
  --output FILE         Salvar relatorio em JSON
```

---

## CVEs verificados

| CVE | Kernel | Severidade |
|---|---|---|
| CVE-2016-5195 | 3.x, 4.4 | CRITICO (DirtyCow) |
| CVE-2017-16995 | 4.8 | CRITICO (eBPF) |
| CVE-2022-0847 | 5.7–5.12 | CRITICO (DirtyPipe) |
| CVE-2022-25636 | 5.10 | ALTO (Netfilter) |
| CVE-2022-32250 | 5.15 | ALTO (nftables UAF) |
| CVE-2022-34918 | 5.16 | ALTO (nftables) |

---

## GTFOBins cobertos

**SUID/SGID:** bash, sh, find, vim, awk, perl, python, python3, ruby, env, nmap, curl, wget, tar, openssl, base64...

**Sudo NOPASSWD:** todos acima + docker, systemctl, journalctl, apt, pip, npm, node, php, mysql, psql, git, socat, nc...

---

## Aviso Legal

Uso exclusivo para pesquisa de seguranca, pentest autorizado e CTF. Execute somente em sistemas onde voce tem autorizacao explicita. Os autores nao se responsabilizam pelo uso indevido.
