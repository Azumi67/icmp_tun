#IP OVER ICMP Tunnel
-

- پس از نوشتن اسکریپت و تست کامل در گیم، قرار داده خواهد شد

A lightweight ICMP-based tunnel over a TUN interface, written in C++17 and optional ChaCha20-Poly1305 encryption. This tool encapsulates IP traffic in ICMP echo packets, allowing you to bypass certain network restrictions.

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
git clone بعدا اضافه میشود
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
```bash
sudo ./icmp_tun -c -b 1000 -n 32 --pskkey psk.key icmptun 192.0.2.1 198.51.100.1 10.0.0.1 10.0.0.2 -m 3 --drop-root
```

## Troubleshooting

* **Permission denied**: Ensure `/dev/net/tun` is accessible and you have root.
* **IP assignment failed**: Check `iproute2` and IP syntax.
* **No traffic**: Verify ICMP connectivity (e.g: `ping`).

