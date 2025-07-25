#IP OVER ICMP Tunnel
-

![6348248](https://github.com/Azumi67/PrivateIP-Tunnel/assets/119934376/398f8b07-65be-472e-9821-631f7b70f783)
**آموزش نصب با اسکریپت**
 <div align="right">
  <details>
    <summary><strong><img src="https://github.com/Azumi67/Rathole_reverseTunnel/assets/119934376/fcbbdc62-2de5-48aa-bbdd-e323e96a62b5" alt="Image"> </strong>نصب icmp_tun</summary>

------------------------------------ 
<p align="right">

  - این تانل اگر بر روی سرور شما اجازه icmp داده شود و محدود نشده باشد، باید کار کند و فقط برای شرایطی هست که دسترسی محدود میباشد
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

* **TUN interface**: Creates a virtual TUN device to forward IP packets.
* **ICMP encapsulation**: Sends and receives data in ICMP ECHO/ECHOREPLY messages.
* **Optional encryption**: ChaCha20-Poly1305 for authenticated encryption.
* **Multi-threaded**: Worker threads for parallel handling of packets.
* **Daemon mode**: Run in the background as a system daemon.
* **Logging**: Configurable verbosity and optional colored output.
* **Root drop**: Optionally drop privileges after setup for improved security.

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
  sudo ./icmp_tun [--daemon|-d] [--color|-c] [--mtu|-b MTU]
                  [--verbose|-v] [--batch|-n BATCH] [--id|-i ID]
                  [--pskkey <file>] [--drop-root]
                  [--threads|-m THREADS]
                  <tun> <local_pub_ip> <remote_pub_ip>
                  <local_tun_ip> <remote_tun_ip>
```

### Options

* `--daemon`, `-d`
  : Run as a background daemon.
* `--color`, `-c`
  : Enable colored log output.
* `--mtu <MTU>`, `-b <MTU>`
  : Set the TUN device MTU (default: 1000).
* `--verbose`, `-v`
  : Increase log verbosity (INFO level).
* `--batch <BATCH>`, `-n <BATCH>`
  : Number of packets to batch (default: 16).
* `--id <ID>`, `-i <ID>`
  : Tunnel identifier (ICMP echo ID, default: 0x1234).
* `--pskkey <file>`
  : Path to 32-byte PSK file to enable encryption.
* `--drop-root`
  : Drop root privileges after setup (to `nobody`).
* `--threads <THREADS>`, `-m <THREADS>`
  : Number of worker threads (default: 1).

### Positional Arguments

1. `<tun>`: Name of the TUN interface (e.g., `azumi`).
2. `<local_pub_ip>`: Public IP of the Local
3. `<remote_pub_ip>`: Public IP of the remote peer.
4. `<local_tun_ip>`: IP address to assign to the local TUN device (in `/30`).
5. `<remote_tun_ip>`: IP address for the remote TUN endpoint.

## Example

On **Machine A** (`192.0.2.1`) and **Machine B** (`198.51.100.1`), create a tunnel:

```bash
#Machine A
sudo ./icmp_tun icmptun 192.0.2.1 198.51.100.1 10.0.0.1 10.0.0.2

#Machine B
sudo ./icmp_tun icmptun 198.51.100.1 192.0.2.1 10.0.0.2 10.0.0.1
```

With encryption (identical `psk.key` on both sides):

```bash
sudo ./icmp_tun -c -v --pskkey psk.key icmptun 192.0.2.1 198.51.100.1 10.0.0.1 10.0.0.2
```

## Daemonizing

To run in the background, add `-d`:

```bash
sudo ./icmp_tun -d --color --pskkey psk.key tun0 A_pub B_pub A_tun B_tun
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

## Multi thread + Batch + MTU + Colorized logs
```
sudo ./icmp_tun -c -b 1000 -n 32 --pskkey psk.key icmptun 192.0.2.1 198.51.100.1 10.0.0.1 10.0.0.2 -m 3 --drop-root
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

