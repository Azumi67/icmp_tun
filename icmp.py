#!/usr/bin/env python3
#Author: https://github.com/Azumi67
import os
import sys
import subprocess
import configparser
import random
import shutil
import readline
import io
import shlex

sys.stdout = io.TextIOWrapper(sys.stdout.detach(), encoding="utf-8", errors="replace")


def logo():
    logo_path = "/etc/logo2.sh"
    try:
        subprocess.run(["bash", "-c", logo_path], check=True)
    except subprocess.CalledProcessError as e:
        return e

    return None

RESET     = "\033[0m"
WHITE     = "\033[97m"
GREEN     = "\033[92m"
YELLOW    = "\033[93m"
CYAN      = "\033[96m"
MAGENTA   = "\033[95m"
RED       = "\033[91m"
BLUE      = "\033[96m"


SERVICE_MAIN  = "/etc/systemd/system/icmp_tun.service"
SERVICE_RESET = "/etc/systemd/system/icmp_tun_reset.service"
SCRIPT_RESET  = "/usr/local/bin/icmp_tun_reset.sh"
CONFIG_FILE   = "/etc/icmp_tun.conf"
GIT_REPO      = "https://github.com/Azumi67/icmp_tun.git"
DEFAULT_REPO  = "/usr/local/bin/icmp_tun"

def notify(title, message):
    if shutil.which("notify-send"):
        subprocess.call(["notify-send", title, message])

def run(cmd, exit_on_fail=True):
    print(f"{CYAN}$ {cmd}{RESET}")
    ret = subprocess.call(cmd, shell=True)
    if ret != 0 and exit_on_fail:
        print(f"{RED}Error: command failed:{RESET} {cmd}")
        sys.exit(1)

def root():
    if os.geteuid() != 0:
        print(f"{RED}Error: this script must be run as root!{RESET}")
        sys.exit(1)

cfg = configparser.ConfigParser()
default_repo = "/usr/local/bin/icmp_tun"
if os.path.exists(CONFIG_FILE):
    cfg.read(CONFIG_FILE)
if "paths" not in cfg:
    cfg["paths"] = {"repo_dir": default_repo}
    with open(CONFIG_FILE, "w") as f:
        cfg.write(f)

def save_config():
    with open(CONFIG_FILE, "w") as f:
        cfg.write(f)

def build_repo():
    repo = cfg["paths"]["repo_dir"]
    src = os.path.join(repo, "icmp_tun.cpp")
    if not os.path.isfile(src):
        print(f"{RED}Source not found: {src}{RESET}")
        return
    out = os.path.join(repo, "icmp_tun")
    run(f"g++ -O2 -std=c++17 {src} -o {out} -lsodium -pthread")

def install_n_build():
    run("apt update && apt install -y g++ build-essential libsodium-dev iproute2 git systemd sshpass")
    default = cfg["paths"]["repo_dir"]
    dest = input(f"{YELLOW}Clone directory {WHITE}[{default}]{RESET}: ").strip() or default
    abs_dest = os.path.abspath(dest)
    cfg["paths"]["repo_dir"] = abs_dest
    save_config()
    if not os.path.isdir(abs_dest):
        run(f"git clone {GIT_REPO} {abs_dest}")
    build_repo()
    input(f"{YELLOW}Press ENTER to return to main menu...{RESET}")

def generate_psk():
    os.system("clear")
    print("\033[92m ^ ^\033[0m")
    print("\033[92m(\033[91mO,O\033[92m)\033[0m")
    print("\033[92m(   ) \033[93mGenerate PSK \033[93mMenu\033[0m")
    print(
        '\033[92m "-"\033[93m═══════════════════════════════════════════════════\033[0m'
    )
    repo = cfg["paths"]["repo_dir"]
    if not os.path.isdir(repo):
        print(f"{RED}Repo missing; run option 1 first{RESET}")
        input(f"{YELLOW}Press ENTER to return to menu...{RESET}")
        return
    default_key = "psk.key"
    keyfile = input(f"{YELLOW}PSK filename inside {WHITE}{repo}{RESET} {WHITE}[{default_key}]{RESET}: ").strip() or default_key
    local = os.path.join(repo, keyfile)
    run(f"head -c 32 /dev/urandom > {local}")
    run(f"chmod 600 {local}")
    cfg["paths"]["psk_path"] = local
    save_config()
    print(f"{GREEN}✓ PSK generated at {local}{RESET}")
    notify("ICMP Tunnel", f"PSK written to {local}")
    if input(f"{YELLOW}SCP to remote?{RESET} ({GREEN}y{RESET}/{RED}n{RESET}): ").lower()=="y":
        user = input(f"{GREEN}Remote user:{RESET} ").strip()
        ip   = input(f"{GREEN}Remote IP:{RESET} ").strip()
        port = input(f"{YELLOW}SSH port{WHITE}[22]{RESET}: ").strip() or "22"
        remote_repo = input(f"{YELLOW}Remote repo dir{WHITE}[{repo}]{RESET}: ").strip() or repo
        pw = input(f"{GREEN}Remote password:{RESET} ")
        run(f"sshpass -p '{pw}' scp -o StrictHostKeyChecking=no -P {port} {local} {user}@{ip}:{remote_repo}/{keyfile}")
        print(f"{GREEN}✓ PSK copied to {ip}{RESET}")
        notify("ICMP Tunnel", f"PSK SCP to {ip} succeeded")
    input(f"{YELLOW}Press ENTER to return to menu...{RESET}")

def existing_inputs():
    if not os.path.isfile(SERVICE_MAIN):
        return
    lines = open(SERVICE_MAIN).read().splitlines()
    exec_line = next((l for l in lines if l.startswith("ExecStart=")), None)
    if not exec_line:
        return
    cmd = exec_line.split("=", 1)[1].strip()
    parts = shlex.split(cmd)
    t = cfg.setdefault("tunnel", {})
    t["bindir"] = os.path.dirname(parts[0])
    idx = 1
    while idx < len(parts) and parts[idx].startswith("--"):
        flag = parts[idx]
        if flag in ("--drop-root", "--color", "--verbose"):
            key = flag[2:].replace("-", "_")
            t[key] = "True"
            idx += 1
        else:
            key = flag[2:].replace("-", "_")
            if idx+1 < len(parts):
                t[key] = parts[idx+1]
            idx += 2
    rem = parts[idx:]
    names = ["tun", "local_pub", "remote_pub", "local_tun", "remote_tun"]
    for name, val in zip(names, rem[:5]):
        t[name] = val
    save_config()

def edit_tunnel():

    existing_inputs()    
    t = cfg.setdefault("tunnel", {})

    items = [
        ("1",  "Binary directory",   "bindir"),
        ("2",  "TUN name",           "tun"),
        ("3",  "Local public IP",    "local_pub"),
        ("4",  "Remote public IP",   "remote_pub"),
        ("5",  "Local TUN IP",       "local_tun"),
        ("6",  "Remote TUN IP",      "remote_tun"),
        ("7",  "MTU",                "mtu"),
        ("8",  "Batch size",         "batch"),
        ("9",  "Tunnel ID hex",      "id"),
        ("10", "Threads",            "threads"),
        ("11", "Drop root",          "drop"),
        ("12", "Color output",       "color"),
        ("13", "Verbose",            "verbose"),
        ("14", "Generate random ID", None),
        ("15", "Save & Exit",        None),
    ]

    while True:
        print(f"{MAGENTA}+{'-'*40}+{RESET}")
        print(f"{MAGENTA}|{' Edit Tunnel Parameters ':^40}|{RESET}")
        print(f"{MAGENTA}+{'-'*40}+{RESET}")

        for num, label, key in items:
            if key:
                val = t.get(key, "")
                if key in ("drop","color","verbose"):
                    val = "Y" if val.lower() in ("true","1","y","yes") else "N"
                print(f"{CYAN}| {num:>2}) {label:<18} [{WHITE}{val:^5}{RESET}{CYAN}] |{RESET}")
            else:
                print(f"{CYAN}| {num:>2}) {label:<27} |{RESET}")

        print(f"{MAGENTA}+{'-'*40}+{RESET}")
        choice = input(f"{YELLOW}Select [1-15]: {RESET}").strip()

        if choice == "15":
            break

        if choice == "14":
            new_id = f"0x{random.randint(0,0xFFFF):04x}"
            t["id"] = new_id
            print(f"{GREEN}✓ New ID: {WHITE}{new_id}{RESET}")

        else:
            lookup = {n:(lbl,k) for n,lbl,k in items if k}
            if choice in lookup:
                label, key = lookup[choice]
                curr = t.get(key, "")
                if key in ("drop","color","verbose"):
                    ans = input(
                        f"{YELLOW}{label}? ({GREEN}y{YELLOW}/{RED}n{YELLOW}) "
                        f"[{WHITE}{'Y' if curr.lower() in ('true','1','y') else 'N'}{RESET}{YELLOW}]: "
                    ).lower()
                    if ans == "y":
                        t[key] = "True"
                    elif ans == "n":
                        t[key] = "False"
                else:
                    ans = input(f"{YELLOW}{label} {WHITE}[{curr}]{RESET}: ").strip()
                    if ans:
                        t[key] = ans
                print(f"{GREEN}✓ {label} set to {WHITE}{t[key]}{RESET}")
            else:
                print(f"{RED}Invalid choice{RESET}")

        save_config()

    print(f"{GREEN}✓ All changes saved{RESET}")
    input(f"{YELLOW}Press ENTER to return to main menu...{RESET}")

def serviceFile():
    t   = cfg["tunnel"]
    psk = cfg["paths"].get("psk_path","")
    flags = []
    for flag in ("drop","color","verbose"):
        if t[flag].lower() in ("true","1","y","yes"):
            flags.append(f"--{flag}")
    flags += [
        f"--mtu {t['mtu']}", f"--batch {t['batch']}",
        f"--id {t['id']}", f"--threads {t['threads']}"
    ]
    psk_arg = f"--pskkey {psk}" if psk else ""
    cmd = " ".join([
        f"{t['bindir']}/icmp_tun", *flags,
        t["tun"], t["local_pub"], t["remote_pub"],
        t["local_tun"], t["remote_tun"], psk_arg
    ]).strip()
    with open(SERVICE_MAIN,"w") as f:
        f.write(f"""\
[Unit]
Description=ICMP Tunnel Service
After=network.target

[Service]
Type=simple
ExecStart={cmd}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
""")

def tunnelCreate():
    os.system("clear")
    print("\033[92m ^ ^\033[0m")
    print("\033[92m(\033[91mO,O\033[92m)\033[0m")
    print("\033[92m(   ) \033[93mCreate tunnel \033[93mMenu\033[0m")
    print(
        '\033[92m "-"\033[93m═══════════════════════════════════════════════════\033[0m'
    )

    bindir = input(
        f"{YELLOW}Installation directory (binary) {WHITE}[{cfg['paths']['repo_dir']}]{RESET}: "
    ).strip() or cfg['paths']['repo_dir']

    tun = input(f"{YELLOW}TUN interface name {GREEN}(e.g. icmptun){RESET}: ").strip()

    local_pub = input(f"{YELLOW}Local public IP {GREEN}(e.g. 192.0.2.1){RESET}: ").strip()
    remote_pub = input(f"{YELLOW}Remote public IP {GREEN}(e.g. 198.51.100.1){RESET}: ").strip()

    local_tun = input(f"{YELLOW}Local TUN IP {GREEN}(e.g. 172.0.0.1){RESET}: ").strip()
    remote_tun = input(f"{YELLOW}Remote TUN IP {GREEN}(e.g. 172.0.0.2){RESET}: ").strip()

    use_key = input(f"{YELLOW}Use PSK?{RESET} ({GREEN}y{RESET}/{RED}n{RESET}): ").lower() == 'y'
    psk_arg = ""
    if use_key:
        default_psk = cfg['paths'].get('psk_path', '')
        psk = input(
            f"{YELLOW}Path to PSK file {WHITE}[{default_psk}]{RESET}: "
        ).strip() or default_psk
        psk_arg = f"--pskkey {psk}"

    mtu = input(f"{YELLOW}MTU {WHITE}[1000]{RESET}: ").strip() or "1000"
    batch = input(f"{YELLOW}Batch size {WHITE}[16]{RESET}: ").strip() or "16"

    gen_id = f"0x{random.randint(0, 0xFFFF):04x}"
    tid = input(f"{YELLOW}Tunnel ID hex {WHITE}[{gen_id}]{RESET}: ").strip() or gen_id

    threads = input(f"{YELLOW}Threads {WHITE}[1]{RESET}: ").strip() or "1"

    drop = input(f"{YELLOW}Drop root after setup?{RESET} ({GREEN}y{RESET}/{RED}n{RESET}): ").lower() == 'y'
    color = input(f"{YELLOW}Enable color output?{RESET} ({GREEN}Y{RESET}/{RED}n{RESET}): ").lower() != 'n'
    verbose = input(f"{YELLOW}Enable verbose?{RESET} ({GREEN}y{RESET}/{RED}N{RESET}): ").lower() == 'y'

    flags = []
    if drop:    flags.append("--drop-root")
    if color:   flags.append("--color")
    if verbose: flags.append("--verbose")
    flags += [f"--mtu {mtu}", f"--batch {batch}", f"--id {tid}", f"--threads {threads}"]

    cmd = " ".join([
        f"{bindir}/icmp_tun",
        *flags,
        tun, local_pub, remote_pub, local_tun, remote_tun, psk_arg
    ]).strip()

    with open(SERVICE_MAIN, "w") as f:
        f.write(f"""\
[Unit]
Description=ICMP Tunnel Service
After=network.target

[Service]
Type=simple
ExecStart={cmd}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
""")

    run("systemctl daemon-reload")
    run("systemctl enable --now icmp_tun.service")

    print(f"{GREEN}✓ Tunnel service configured and running{RESET}")
    notify("ICMP Tunnel", "Service configured and started")
    print(f"{YELLOW}" + "―" * 50 + f"{RESET}")
    input(f"{YELLOW}Press ENTER to return to the main menu...{RESET}")


def resetTimer():
    iv = input(f"{YELLOW}Reset interval (number){WHITE}[e.g. 30]{RESET}: ").strip()
    iu = input(f"{YELLOW}Unit - minutes(m) or hours(h){WHITE}[m/h]{RESET}: ").strip().lower()
    with open(SCRIPT_RESET,"w") as f:
        f.write(f"""#!/bin/bash
while true; do
  sleep {iv}{iu}
  systemctl restart icmp_tun.service
done
""")
    os.chmod(SCRIPT_RESET,0o755)
    with open(SERVICE_RESET,"w") as f:
        f.write(f"""\
[Unit]
Description=ICMP Tunnel Auto-Reset

[Service]
Type=simple
ExecStart={SCRIPT_RESET}
Restart=always

[Install]
WantedBy=multi-user.target
""")
    run("systemctl daemon-reload")
    run("systemctl enable --now icmp_tun_reset.service")
    print(f"{GREEN}Reset timer configured.{RESET}")
    input(f"{YELLOW}Press ENTER to return to main menu...{RESET}")

def statusnlogs():
    print("\033[93m───────────────────────────────────────\033[0m")
    print(f"{CYAN}=== Service Status ==={RESET}")
    subprocess.call("systemctl status icmp_tun.service --no-pager", shell=True)
    print(f"{CYAN}=== Last 20 Logs ==={RESET}")
    subprocess.call("journalctl -u icmp_tun.service -n 20 --no-pager", shell=True)
    print("\033[93m───────────────────────────────────────\033[0m")
    input(f"{YELLOW}Press ENTER to return to main menu...{RESET}")

def uninstall_tun():
    print("\033[93m───────────────────────────────────────\033[0m")
    print(f"{YELLOW}Uninstalling ICMP Tunnel...{RESET}")
    print("\033[93m───────────────────────────────────────\033[0m")
    def safe(cmd):
        print(f"{CYAN}$ {cmd}{RESET}")
        subprocess.call(cmd, shell=True)
    safe("systemctl stop icmp_tun_reset.service")
    safe("systemctl stop icmp_tun.service")
    safe("systemctl disable icmp_tun_reset.service")
    safe("systemctl disable icmp_tun.service")
    for path in (SERVICE_MAIN, SERVICE_RESET):
        if os.path.exists(path):
            os.remove(path)
            print(f"{GREEN}✓ Removed {path}{RESET}")
    for path in (SCRIPT_RESET, CONFIG_FILE):
        if os.path.exists(path):
            os.remove(path)
            print(f"{GREEN}✓ Removed {path}{RESET}")
    safe("systemctl daemon-reload")
    repo = cfg["paths"]["repo_dir"]
    if os.path.isdir(repo) and input(f"{BLUE}Delete project dir {repo}? ({RED}y{BLUE}/{GREEN}n{BLUE}): {RESET}").lower()=="y":
        shutil.rmtree(repo)
        print(f"{GREEN}✓ Deleted project dir{RESET}")
    notify("ICMP Tunnel", "Uninstallation complete")
    input(f"{YELLOW}Press ENTER to return to menu...{RESET}")

def main():
    root()
    os.system("clear")
    logo()
    print("\033[92m ^ ^\033[0m")
    print("\033[92m(\033[91mO,O\033[92m)\033[0m")
    print("\033[92m(   ) \033[93mICMP Tunnel Setup Menu\033[0m")
    print(
        '\033[92m "-"\033[93m═══════════════════════════════════════════════════\033[0m'
    )
    while True:
        print("\033[93m╭───────────────────────────────────────╮\033[0m")
        print("1.\033[97m Install & Build Repo\033[0m")
        print("2.\033[93m Generate PSK & optional SCP\033[0m")
        print("3.\033[96m Create Tunnel\033[0m")
        print("4.\033[92m Edit parameters\033[0m")
        print("5.\033[93m Setup/edit reset timer\033[0m")
        print("6.\033[97m Show status & logs\033[0m")
        print("7.\033[91m Uninstall\033[0m")
        print("q.\033[97m Quit\033[0m")
        print("\033[93m───────────────────────────────────────\033[0m")

        choice = input(f"{GREEN}Choose [1-7, q]: {RESET}").strip()
        if   choice == "1": install_n_build()
        elif choice == "2": generate_psk()
        elif choice == "3": tunnelCreate()
        elif choice == "4": edit_tunnel()
        elif choice == "5": resetTimer()
        elif choice == "6": statusnlogs()
        elif choice == "7": uninstall_tun()
        elif choice == "q": sys.exit(0)
        else: print(f"{RED}Invalid choice.{RESET}")

main()
