#IP OVER ICMP Tunnel
-

- اپدیت جدید انجام شد که سرعت بهتری برای گیم در شرایط محدودیت بدهد. چندین کامند تغییر کرد
- بعدا اسکریپت اپدیت میشود.فعلا اسکریپت جواب نمیدهد


![6348248](https://github.com/Azumi67/PrivateIP-Tunnel/assets/119934376/398f8b07-65be-472e-9821-631f7b70f783)
**آموزش نصب با اسکریپت**
 <div align="right">
  <details>
    <summary><strong><img src="https://github.com/Azumi67/Rathole_reverseTunnel/assets/119934376/fcbbdc62-2de5-48aa-bbdd-e323e96a62b5" alt="Image"> </strong>نصب icmp_tun</summary>

------------------------------------ 
<p align="right">

  - اگر بر روی سرور شما محدودیت icmp نباشد، این تانل باید کار کند و فقط برای شرایطی هست که دسترسی محدود میباشد
- گزینه ها را به ترتیب نصب کنید
- - اگر نیاز به encryption دارید یک psk با اسکریپت بسازید و همین کلید را در سرور بعدی هم کپی کنید. به طور مثال اگر برنامه در /usr/local/bin/icmp_tun است در سرور مقابل هم همین مسیر باید داده شود. برای فرستادن فایل از طریق scp باید ان مسیر در سرور مقایل موجود باشد. پس برای همین اول این اسکریپت را در هر دو طرف اجرا کنید و install & build کنید تا پوشه مورد نظر در هر دو طرف سرور ساخته شود و سپس فایل psk و انتقال ان را انجام دهید
- اگر نیازی به encryption ندارید از این مورد عبور کنید
- سپس تانل را کانفیگ میکنیم. مسیر مورد نظری که فایل را دانلود کردیم به صورت پیش فرص در مسیر usr/local/bin/icmp_tun است. گزینه enter میزنید تا سوال بعدی پرسیده شود
- نام دیوایس را میدهیم و سپس ایپی پابلیک هر دو سرور به ترتیب لوکال و ریموت
- سپس ایپی پرایوت 4 خود را برای سرور لوکال و ریموت مشخص میکنیم
- اگر مایل به encryption بودید کلید psk را میسازید و در هر دو سرور کپی میکنید و سپس y میزنید
- مقدار mtu را 1000 میدهم و batch size را 16 یا 32 وارد میکنم
- ایدی تانل هر دو طرف باید یکسان باشد. مقدار thread بین 1 تا 3( من 3 قرار دادم)
- اگر میخواهید root پس از نصب به nobody نغییر یابد، این گزینه را فعال کنید
- رنگ لاگ را هم فعال میکنم و verbose را غیرفعال میکنم
- همین کار را در سرور روبرو انجام میدهم.

**- نصب پیش نیاز ها**
```
apt install python3 -y && sudo apt install python3-pip &&  pip install colorama && pip install netifaces && apt install curl -y
pip3 install colorama
sudo apt-get install python-pip -y  &&  apt-get install python3 -y && alias python=python3 && python -m pip install colorama && python -m pip install netifaces
sudo apt update -y && sudo apt install -y python3 python3-pip curl && pip3 install --upgrade pip && pip3 install netifaces colorama requests

```
- اجرای اسکریپت
```
apt install curl -y && bash -c "$(curl -fsSL https://raw.githubusercontent.com/Azumi67/icmp_tun/refs/heads/main/icmp.sh)"
```
------------------

  </details>
</div>  

---------------

A lightweight ICMP-based tunnel over a TUN interface, written in C++17 and optional ChaCha20-Poly1305 encryption. This tool encapsulates IP traffic in ICMP echo packets, allowing you to bypass certain network restrictions(IF ICMP in your server is not restricted ofc)

## Features

- **TUN interface:** Creates a Linux TUN device and forwards IP packets through it.
- **ICMP encapsulation (ECHO/ECHOREPLY):** Tunnels traffic inside ICMP echo payloads.
- **poll/reply model:** Client sends ICMP **ECHO** polls; server returns **ECHOREPLY** (server sends data only when polled).
- **Burst replies:** Server can flush multiple queued frames per poll using `--burst` (better throughput, fewer stalls).
- **Frame packing:** Pack multiple IP frames into a single ICMP payload using `--pack` (lower overhead, better performance on bursty traffic).
- **Optional encryption:** ChaCha20-Poly1305 (libsodium) authenticated encryption via `--pskkey`.
- **Daemon mode:** Run in the background using `--daemon` / `-d`.
- **Logging:** Verbose mode (`--verbose` / `-v`) and optional colored output (`--color` / `-c`).
- **Privilege drop:** Optionally drop privileges after setup using `--drop-root`.


## Prerequisites

* **Linux** (kernel ≥ 3.9) with support for TUN/TAP (`/dev/net/tun`).
* **g++** (C++17)
* **libsodium** (for optional encryption)
* **iproute2** (for `ip` command)

On Debian/Ubuntu systems, install dependencies with:

```bash
sudo apt update
sudo apt install -y g++ build-essential libsodium-dev iproute2
```

## Building

Clone the repository and compile:

```bash
git clone https://github.com/Azumi67/icmp_tun.git
cd icmp-tun
#Single - file compile
g++ -O2 -std=c++17 icmp_tun.cpp -o icmp_tun -lsodium -pthread
```

## Generating a Pre-Shared Key (PSK)

If you plan to use encryption, generate a 32-byte random key:

```bash
#Create a 32 - byte key file
head -c 32 /dev/urandom > psk.key
chmod 600 psk.key
```

> **Note**: You must use the *same* `psk.key` on both endpoints. To copy the key securely:
>
> * **With SCP**:
>
>   ```bash
>   scp psk.key user@remote:/path/to/psk.key
>   ```
>
> * **Without SCP**: Transfer via another secure channel (e.g., encrypted email, USB drive, or other secure file transfer), ensuring the file’s integrity and confidentiality.

## Usage

```bash
sudo ./icmp_tun [OPTIONS] <tun> <local_public_ip> <remote_public_ip> <local_private_ip> <remote_private_ip>
```
<tun>: Name of the TUN interface (e.g., tun0)
<local_public_ip>: Public IP of this machine
<remote_public_ip>: Public IP of the peer
<local_private_ip>: IP to assign to the local TUN device (recommended /30 pair)
<remote_private_ip>: IP of the remote TUN endpoint

## Generating a Random Tunnel ID

You can generate a 16-bit random tunnel ID (in hex) using common CLI tools:

* **Using OpenSSL**:

  ```bash
  ID="0x$(openssl rand -hex 2)"
  ```
* **Using /dev/urandom and od**:

  ```bash
  ID="0x$(head -c2 /dev/urandom | od -An -tu2 | awk '{printf "%04x", $1}')"
  ```

Then pass `--id $ID` to `icmp_tun`:

```bash
sudo ./icmp_tun --id $ID tun0 192.0.2.1 198.51.100.1 10.0.0.1 10.0.0.2
```

## Full CLI Reference

```
Usage:
  sudo ./icmp_tun
    [--mode client|server]
    [--poll-ms MS] [--burst N] [--pack N]
    [--mtu MTU|-b MTU] [--id ID|-i ID]
    [--pskkey <file>] [--drop-root]
    [--daemon|-d] [--color|-c] [--verbose|-v]
    [--rt] [--cpu N]
    <tun> <local_pub_ip> <remote_pub_ip> <local_tun_ip> <remote_tun_ip>
```

### Options

--mode client|server

Select role:

client sends ICMP ECHO polls

server replies with ICMP ECHOREPLY (server traffic is carried only inside replies)

--poll-ms MS (client only)
Client poll interval. Lower values = lower latency, but more ICMP traffic.
Typical range: 5..15

--burst N (server only)
Number of replies per poll (flush more queued frames).
Typical range: 2..8

--pack N (both server & client)
Pack up to N frames into one ICMP payload (reduces overhead and helps bursty traffic).
Recommended: 2

--mtu MTU, -b MTU
Set TUN MTU (default: 1000).

--id ID, -i ID
Tunnel identifier (ICMP echo ID). Must match on both ends (default: 0x1234).

--pskkey <file>
Enable encryption with a 32-byte PSK file (same file on both ends).

--drop-root
Drop root privileges to nobody after setup.

--daemon, -d
Run in the background (daemon).

--color, -c
Enable colored output.

--verbose, -v
Increase log verbosity.

--rt (Linux)
Try realtime scheduling (advanced).

--cpu N (Linux)
Pin networking thread to CPU N (advanced).


## Example

On **Server** (`192.0.2.1`) and **Client** (`198.51.100.1`), create a tunnel:

```bash
#Server
sudo ./icmp_tun --mode server -c -v --id 0x1234 --burst 4 --pack 2 \
  tun0 192.0.2.1 198.51.100.1 10.0.0.1 10.0.0.2

#Client
sudo ./icmp_tun --mode client -c -v --id 0x1234 --poll-ms 8 --pack 2 \
  tun0 198.51.100.1 192.0.2.1 10.0.0.2 10.0.0.1
```

With encryption (identical `psk.key` on both sides):

```bash
# server
sudo ./icmp_tun --mode server -c -v --id 0x1234 --burst 4 --pack 2 \
  --pskkey psk.key \
  tun0 192.0.2.1 198.51.100.1 10.0.0.1 10.0.0.2

#client
sudo ./icmp_tun --mode client -c -v --id 0x1234 --poll-ms 8 --pack 2 \
  --pskkey psk.key \
  tun0 198.51.100.1 192.0.2.1 10.0.0.2 10.0.0.1
```

## Gaming Recommended Profile (low-latency)

Why this helps:

--poll-ms 5 reduces the maximum “wait until next poll” delay → better ping/jitter.

--burst 6 lets the server flush more queued frames per poll → fewer micro-stalls under bursty game traffic.

--pack 2 reduces per-packet ICMP overhead and helps when packets come in bursts (common in games/voice).

If CPU usage rises too much, increase --poll-ms to 8 or reduce --burst to 4.

```bash
#Server
sudo ./icmp_tun --mode server -c -v --id 0x1234 --burst 6 --pack 2 \
  tun0 <SERVER_PUBLIC_IP> <CLIENT_PUBLIC_IP> 10.0.0.1 10.0.0.2

#Client
sudo ./icmp_tun --mode client -c -v --id 0x1234 --poll-ms 5 --pack 2 \
  tun0 <CLIENT_PUBLIC_IP> <SERVER_PUBLIC_IP> 10.0.0.2 10.0.0.1

```

## Daemonizing

To run in the background, add `-d`:

```bash
sudo ./icmp_tun --mode server -d -c --id 0x1234 --burst 4 --pack 2 \
  tun0 <SERVER_PUBLIC_IP> <CLIENT_PUBLIC_IP> 10.0.0.1 10.0.0.2
```

Logs will go to stdout (redirect or configure your service manager as needed).

## Logging

* **ERROR** and **WARN** always print.
* **INFO** prints when `--verbose` is enabled.
* **DEBUG** prints when both `--verbose` and `--color` are enabled.

## Dropping Privileges

Use `--drop-root` to switch to `nobody` after setup:

```bash
sudo ./icmp_tun --drop-root icmptun ...
```

## Firewall & ICMP Settings

By default, the kernel accepts and replies to ICMP ECHO packets. Unless you have custom firewall or sysctl settings, no additional configuration is needed. However, if you’ve hardened your system or are running a restrictive firewall, ensure the following:

* **Allow ICMP echo requests and replies**:

```
#IPv4
  sudo iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT
  sudo iptables -A OUTPUT -p icmp --icmp-type echo-reply -j ACCEPT

```

* **Verify sysctl ICMP settings**:

```
#Ensure echo requests are not ignored
  sysctl -w net.ipv4.icmp_echo_ignore_all=0
  sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1 
  ```

If neither firewall rules nor sysctl blocks ICMP, you can run without special ICMP configuration.

## Troubleshooting

* **Permission denied**: Ensure `/dev/net/tun` is accessible and you have root.
* **IP assignment failed**: Check `iproute2` and IP syntax.
* **No traffic**: Verify ICMP connectivity (e.g: `ping`).

