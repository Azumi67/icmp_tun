// Author: github.com/Azumi67
// icmp_tun.cpp — ICMP TUN tunnel (poll/request-reply)
//
// Build:
//   apt install -y g++ build-essential libsodium-dev iproute2
//   g++ -O2 -std=c++17 icmp_tun.cpp -o icmp_tun -lsodium -pthread
//
// Recommended sysctl (both ends) for max reliability:
//   sudo sysctl -w net.ipv4.icmp_echo_ignore_all=1
//
// Usage:
//   sudo ./icmp_tun [options] <tun> <local_pub> <remote_pub> <local_private> <remote_private>
//
// Notes:
// - "pack" packs multiple frames into a single ICMP payload to reduce overhead.

#include <arpa/inet.h>
#include <fcntl.h>
#include <getopt.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <pwd.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <cstdarg>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iostream>
#include <mutex>
#include <queue>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <sodium.h>

#ifdef __linux__
#include <pthread.h>
#include <sched.h>
#endif

static constexpr int DEFAULT_MTU        = 1000;
static constexpr int DEFAULT_POLL_MS    = 10;
static constexpr int DEFAULT_BURST      = 1;
static constexpr int DEFAULT_PACK       = 1;
static constexpr int STATS_INTERVAL_SEC = 20;

static constexpr size_t QUEUE_MAX = 128; 

static constexpr size_t KEY_BYTES   = crypto_aead_chacha20poly1305_ietf_KEYBYTES;
static constexpr size_t NONCE_BYTES = crypto_aead_chacha20poly1305_ietf_NPUBBYTES;
static constexpr size_t TAG_BYTES   = crypto_aead_chacha20poly1305_ietf_ABYTES;

static const char *C_RESET   = "\033[0m";
static const char *C_RED     = "\033[31m";
static const char *C_YELLOW  = "\033[33m";
static const char *C_GREEN   = "\033[32m";
static const char *C_CYAN    = "\033[36m";
static const char *C_MAGENTA = "\033[35m";

enum LogLevel { LOG_ERROR=0, LOG_WARN, LOG_INFO, LOG_DEBUG };
static LogLevel g_log_level = LOG_WARN;
static bool g_use_color = false;
static bool g_verbose = false;

static void log_msg(LogLevel level, const char *fmt, ...)
{
    if (level > g_log_level) return;

    const char *lvl =
        (level == LOG_ERROR) ? "ERROR" :
        (level == LOG_WARN)  ? "WARN"  :
        (level == LOG_INFO)  ? "INFO"  : "DEBUG";

    const char *col = "";
    if (g_use_color) {
        switch (level) {
            case LOG_ERROR: col = C_RED; break;
            case LOG_WARN:  col = C_YELLOW; break;
            case LOG_INFO:  col = C_GREEN; break;
            case LOG_DEBUG: col = C_CYAN; break;
        }
    }

    char msgbuf[1600];
    va_list args;
    va_start(args, fmt);
    vsnprintf(msgbuf, sizeof(msgbuf), fmt, args);
    va_end(args);

    time_t now = time(nullptr);
    struct tm tm{};
    localtime_r(&now, &tm);
    char ts[64];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tm);

    std::ostringstream oss;
    oss << "[" << ts << "] ";
    if (g_use_color) oss << col;
    oss << "[" << lvl << "]";
    if (g_use_color) oss << C_RESET;
    oss << " " << msgbuf;

    std::cout << oss.str() << "\n";
}

static volatile sig_atomic_t g_keep_running = 1;

static std::atomic<uint64_t> g_total_sent{0};
static std::atomic<uint64_t> g_total_recv{0};
static std::atomic<uint64_t> g_ctr{0};
static std::atomic<uint16_t> g_seq{1};

static const uint8_t DUMMY_BYTE = 0;

static void on_signal(int sig)
{
    log_msg(LOG_WARN, "Signal %d received, stopping...", sig);
    g_keep_running = 0;
}

static void run_cmd(const std::string &cmd)
{
    int rc = system(cmd.c_str());
    if (rc != 0) {
        log_msg(LOG_ERROR, "Command failed (%d): %s", rc, cmd.c_str());
        exit(1);
    }
}

static void daemonize()
{
    if (fork() > 0) exit(0);
    setsid();
    if (fork() > 0) exit(0);
    if (chdir("/") < 0) perror("daemonize: chdir");
    for (int fd = 0; fd < 3; fd++) close(fd);
}

static void drop_privs()
{
    passwd *pw = getpwnam("nobody");
    if (!pw) {
        log_msg(LOG_ERROR, "getpwnam(nobody) failed");
        exit(1);
    }
    if (setgid(pw->pw_gid) || setuid(pw->pw_uid)) {
        log_msg(LOG_ERROR, "Failed to drop privileges");
        exit(1);
    }
    log_msg(LOG_INFO, "Dropped privileges to nobody (uid=%d gid=%d)", pw->pw_uid, pw->pw_gid);
}

static uint16_t icmp_checksum(const uint8_t *data, size_t len)
{
    uint32_t sum = 0;
    while (len >= 2) {
        uint16_t w;
        memcpy(&w, data, 2);
        sum += w;
        data += 2;
        len  -= 2;
    }
    if (len) sum += (uint16_t)(*data);

    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

enum Mode { MODE_CLIENT, MODE_SERVER };

struct Config
{
    bool daemon = false;
    bool drop_root = false;

    int mtu = DEFAULT_MTU;
    uint16_t tunnel_id = 0x1234;

    Mode mode = MODE_CLIENT;
    int poll_ms = DEFAULT_POLL_MS;
    int burst = DEFAULT_BURST;
    int pack = DEFAULT_PACK;

    bool crypto = false;
    std::string psk_path;

    bool rt = false;
    int cpu = -1;

    std::string tun, local_pub, remote_pub, local_pr, remote_pr;
};

struct Packet { std::vector<uint8_t> data; };

static std::mutex g_q_mtx;
static std::queue<Packet> g_q;

static void q_push(Packet &&p)
{
    std::lock_guard<std::mutex> lk(g_q_mtx);
    if (g_q.size() >= QUEUE_MAX) {
        
        return;
    }
    g_q.emplace(std::move(p));
}

static bool q_pop(Packet &p)
{
    std::lock_guard<std::mutex> lk(g_q_mtx);
    if (g_q.empty()) return false;
    p = std::move(g_q.front());
    g_q.pop();
    return true;
}

static size_t q_size()
{
    std::lock_guard<std::mutex> lk(g_q_mtx);
    return g_q.size();
}

static int tun_create(const std::string &name, int mtu)
{
    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) { perror("open /dev/net/tun"); exit(1); }

    ifreq ifr{};
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, name.c_str(), IFNAMSIZ);

    if (ioctl(fd, TUNSETIFF, &ifr) < 0) { perror("TUNSETIFF"); exit(1); }

    run_cmd("ip link set dev " + name + " up");
    run_cmd("ip link set dev " + name + " mtu " + std::to_string(mtu));

    log_msg(LOG_INFO, "Created TUN %s (MTU=%d)", name.c_str(), mtu);
    return fd;
}

static void tun_thread(int tun_fd, const Config &cfg)
{
    std::vector<uint8_t> buf((size_t)cfg.mtu + 128);
    while (g_keep_running) {
        ssize_t r = read(tun_fd, buf.data(), buf.size());
        if (r > 0) {
            Packet p;
            p.data.assign(buf.begin(), buf.begin() + r);
            q_push(std::move(p));
        } else if (r < 0 && errno == EINTR) {
            continue;
        } else if (r < 0) {
            log_msg(LOG_WARN, "TUN read error: %s", strerror(errno));
        }
    }
}

static bool load_psk(const std::string &path, std::vector<uint8_t> &key)
{
    key.assign(KEY_BYTES, 0);
    std::ifstream f(path, std::ios::binary);
    if (!f.good()) {
        log_msg(LOG_ERROR, "Could not open PSK file: %s", path.c_str());
        return false;
    }
    if (!f.read((char*)key.data(), KEY_BYTES)) {
        log_msg(LOG_ERROR, "Could not read %zu bytes from PSK: %s", KEY_BYTES, path.c_str());
        return false;
    }
    log_msg(LOG_INFO, "Loaded PSK from %s", path.c_str());
    return true;
}

static void pack_frames(const std::vector<Packet> &frames, std::vector<uint8_t> &out)
{
    out.clear();
    uint16_t count = (uint16_t)frames.size();
    out.resize(2);
    memcpy(out.data(), &count, 2);

    for (const auto &p : frames) {
        uint16_t l = (uint16_t)p.data.size();
        size_t old = out.size();
        out.resize(old + 2 + l);
        memcpy(out.data() + old, &l, 2);
        if (l) memcpy(out.data() + old + 2, p.data.data(), l);
    }
}

static bool unpack_frames(const uint8_t *data, size_t len,
                              std::vector<std::vector<uint8_t>> &frames)
{
    frames.clear();
    if (len < 2) return false;

    uint16_t count;
    memcpy(&count, data, 2);

    
    if (count > 64) return false;

    size_t off = 2;
    frames.reserve(count);

    for (uint16_t i = 0; i < count; i++) {
        if (off + 2 > len) return false;
        uint16_t l;
        memcpy(&l, data + off, 2);
        off += 2;
        if (off + l > len) return false;
        frames.emplace_back(data + off, data + off + l);
        off += l;
    }

    return off == len;
}

static bool maybe_encrypt(const uint8_t *plain, size_t plain_len,
                          const std::vector<uint8_t> &psk,
                          std::vector<uint8_t> &out)
{
    out.clear();
    if (psk.empty()) {
        if (plain_len) out.assign(plain, plain + plain_len);
        return true;
    }

    uint64_t ctr = g_ctr.fetch_add(1) + 1;
    uint8_t nonce[NONCE_BYTES];
    memcpy(nonce, &ctr, 8);
    memset(nonce + 8, 0, NONCE_BYTES - 8);

    out.resize(NONCE_BYTES + plain_len + TAG_BYTES);
    memcpy(out.data(), nonce, NONCE_BYTES);

    unsigned long long clen = 0;
    if (crypto_aead_chacha20poly1305_ietf_encrypt(
            out.data() + NONCE_BYTES, &clen,
            plain, plain_len,
            nullptr, 0, nullptr,
            nonce, psk.data()) != 0)
    {
        return false;
    }

    out.resize(NONCE_BYTES + (size_t)clen);
    return true;
}

static bool maybe_decrypt(const uint8_t *enc, size_t enc_len,
                          const std::vector<uint8_t> &psk,
                          std::vector<uint8_t> &out)
{
    out.clear();
    if (psk.empty()) {
        if (enc_len) out.assign(enc, enc + enc_len);
        return true;
    }

    if (enc_len < NONCE_BYTES + TAG_BYTES) return false;

    const uint8_t *nonce = enc;
    const uint8_t *ct = enc + NONCE_BYTES;
    size_t ctlen = enc_len - NONCE_BYTES;

    out.resize(ctlen);
    unsigned long long mlen = 0;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            out.data(), &mlen, nullptr,
            ct, ctlen,
            nullptr, 0,
            nonce, psk.data()) != 0)
    {
        return false;
    }

    out.resize((size_t)mlen);
    return true;
}

static bool ip_to_inaddr(const std::string &ip, in_addr &out)
{
    return inet_pton(AF_INET, ip.c_str(), &out) == 1;
}

static ssize_t icmp_send(int sock, const sockaddr_in &dst,
                         const Config &cfg, uint8_t type,
                         const uint8_t *payload, size_t payload_len)
{
    std::vector<uint8_t> buf(sizeof(icmphdr) + payload_len);

    icmphdr ic{};
    ic.type = type;
    ic.code = 0;
    ic.un.echo.id = htons(cfg.tunnel_id);
    ic.un.echo.sequence = htons(g_seq.fetch_add(1));
    ic.checksum = 0;

    memcpy(buf.data(), &ic, sizeof(ic));
    if (payload_len) memcpy(buf.data() + sizeof(ic), payload, payload_len);

    uint16_t csum = icmp_checksum(buf.data(), buf.size());
    memcpy(buf.data() + offsetof(icmphdr, checksum), &csum, sizeof(csum));

    iovec iov{ buf.data(), buf.size() };
    msghdr mh{};
    mh.msg_name = (void*)&dst;
    mh.msg_namelen = sizeof(dst);
    mh.msg_iov = &iov;
    mh.msg_iovlen = 1;

    ssize_t s = sendmsg(sock, &mh, 0);
    if (s > (ssize_t)sizeof(icmphdr)) {
        g_total_sent += (uint64_t)(s - (ssize_t)sizeof(icmphdr));
    }
    return s;
}

struct IcmpParsed {
    sockaddr_in src{};
    uint8_t type = 0;
    uint16_t id = 0;
    const uint8_t *payload = nullptr;
    size_t payload_len = 0;
};

static bool icmp_recv(int sock, IcmpParsed &out)
{
    static thread_local std::vector<uint8_t> buf(65536);

    sockaddr_in src{};
    socklen_t sl = sizeof(src);
    ssize_t l = recvfrom(sock, buf.data(), buf.size(), 0, (sockaddr*)&src, &sl);
    if (l < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return false;
        return false;
    }

    if (l < (ssize_t)(sizeof(iphdr) + sizeof(icmphdr))) return false;

    iphdr *ip = (iphdr*)buf.data();
    int ihl = ip->ihl * 4;
    if (ihl < (int)sizeof(iphdr)) return false;
    if (l < ihl + (int)sizeof(icmphdr)) return false;

    icmphdr *ic = (icmphdr*)(buf.data() + ihl);

    out.src = src;
    out.type = ic->type;
    out.id = ntohs(ic->un.echo.id);
    out.payload = buf.data() + ihl + sizeof(icmphdr);
    out.payload_len = (size_t)l - (size_t)ihl - sizeof(icmphdr);
    return true;
}

static void apply_affinity(const Config &cfg)
{
#ifdef __linux__
    if (cfg.cpu >= 0) {
        cpu_set_t set;
        CPU_ZERO(&set);
        CPU_SET(cfg.cpu, &set);
        pthread_setaffinity_np(pthread_self(), sizeof(set), &set);
    }
    if (cfg.rt) {
        sched_param sp{};
        sp.sched_priority = 40;
        pthread_setschedparam(pthread_self(), SCHED_FIFO, &sp);
    }
#else
    (void)cfg;
#endif
}

static void incoming_to_tun(int tun_fd, const std::vector<uint8_t> &plain)
{
    if (plain.empty()) return;

    std::vector<std::vector<uint8_t>> frames;
    if (unpack_frames(plain.data(), plain.size(), frames)) {
        for (auto &f : frames) {
            if (f.empty()) continue;
            ssize_t w = write(tun_fd, f.data(), f.size());
            if (w > 0) g_total_recv += (uint64_t)w;
        }
        return;
    }

    ssize_t w = write(tun_fd, plain.data(), plain.size());
    if (w > 0) g_total_recv += (uint64_t)w;
}

static void outgoing_frames(std::vector<Packet> &frames, int max_frames)
{
    frames.clear();
    frames.reserve((size_t)max_frames);
    for (int i = 0; i < max_frames; i++) {
        Packet p;
        if (!q_pop(p)) break;
        frames.emplace_back(std::move(p));
    }
}

static void stats_line()
{
    if (g_use_color) {
        std::cout << "\r" << C_MAGENTA << "[Stats]" << C_RESET
                  << " S:" << C_YELLOW << g_total_sent.load() << C_RESET
                  << " R:" << C_YELLOW << g_total_recv.load() << C_RESET
                  << " Q:" << C_YELLOW << q_size() << C_RESET
                  << "   " << std::flush;
    } else {
        std::cout << "\r[Stats] S:" << g_total_sent.load()
                  << " R:" << g_total_recv.load()
                  << " Q:" << q_size()
                  << "   " << std::flush;
    }
}

static void client_loop(int sock, int tun_fd, const Config &cfg,
                        const in_addr &expected_peer,
                        const std::vector<uint8_t> &psk)
{
    apply_affinity(cfg);

    auto next_stats = std::chrono::steady_clock::now() + std::chrono::seconds(STATS_INTERVAL_SEC);

    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_addr = expected_peer;

    while (g_keep_running) {
        std::vector<Packet> frames;
        outgoing_frames(frames, std::max(1, cfg.pack));

        std::vector<uint8_t> plain_payload;
        if (frames.empty()) {
            plain_payload.clear();
        } else if (cfg.pack > 1) {
            pack_frames(frames, plain_payload);
        } else {
            plain_payload = std::move(frames[0].data);
        }

        std::vector<uint8_t> enc_payload;
        const uint8_t *pp = &DUMMY_BYTE;
        size_t ppl = 0;

        if (!plain_payload.empty()) {
            if (!maybe_encrypt(plain_payload.data(), plain_payload.size(), psk, enc_payload)) {
                log_msg(LOG_WARN, "Encryption failed");
                enc_payload.clear();
            }
        }

        if (!enc_payload.empty()) { pp = enc_payload.data(); ppl = enc_payload.size(); }

        (void)icmp_send(sock, dst, cfg, ICMP_ECHO, pp, ppl);

        
        for (;;) {
            IcmpParsed ip{};
            if (!icmp_recv(sock, ip)) break;

            if (ip.src.sin_addr.s_addr != expected_peer.s_addr) continue;
            if (ip.type != ICMP_ECHOREPLY) continue;
            if (ip.id != cfg.tunnel_id) continue;

            std::vector<uint8_t> plain;
            if (!maybe_decrypt(ip.payload, ip.payload_len, psk, plain)) continue;

            incoming_to_tun(tun_fd, plain);
        }

        auto now = std::chrono::steady_clock::now();
        if (now >= next_stats) {
            stats_line();
            next_stats = now + std::chrono::seconds(STATS_INTERVAL_SEC);
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(cfg.poll_ms));
    }
}

static void server_loop(int sock, int tun_fd, const Config &cfg,
                        const in_addr &expected_peer,
                        const std::vector<uint8_t> &psk)
{
    apply_affinity(cfg);

    auto next_stats = std::chrono::steady_clock::now() + std::chrono::seconds(STATS_INTERVAL_SEC);

    while (g_keep_running) {
        IcmpParsed ip{};
        if (!icmp_recv(sock, ip)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            continue;
        }

        if (ip.src.sin_addr.s_addr != expected_peer.s_addr) continue;
        if (ip.type != ICMP_ECHO) continue;
        if (ip.id != cfg.tunnel_id) continue;

        // client->server
        if (ip.payload_len > 0) {
            std::vector<uint8_t> plain;
            if (maybe_decrypt(ip.payload, ip.payload_len, psk, plain)) {
                incoming_to_tun(tun_fd, plain);
            }
        }

        sockaddr_in reply_dst = ip.src;

        for (int b = 0; b < std::max(1, cfg.burst); b++) {
            std::vector<Packet> frames;
            outgoing_frames(frames, std::max(1, cfg.pack));

            if (frames.empty() && b > 0) break;

            std::vector<uint8_t> plain_payload;
            if (frames.empty()) {
                plain_payload.clear();
            } else if (cfg.pack > 1) {
                pack_frames(frames, plain_payload);
            } else {
                plain_payload = std::move(frames[0].data);
            }

            std::vector<uint8_t> enc_payload;
            const uint8_t *pp = &DUMMY_BYTE;
            size_t ppl = 0;

            if (!plain_payload.empty()) {
                if (!maybe_encrypt(plain_payload.data(), plain_payload.size(), psk, enc_payload)) {
                    log_msg(LOG_WARN, "Encryption failed");
                    enc_payload.clear();
                }
            }

            if (!enc_payload.empty()) { pp = enc_payload.data(); ppl = enc_payload.size(); }

            (void)icmp_send(sock, reply_dst, cfg, ICMP_ECHOREPLY, pp, ppl);
        }

        auto now = std::chrono::steady_clock::now();
        if (now >= next_stats) {
            stats_line();
            next_stats = now + std::chrono::seconds(STATS_INTERVAL_SEC);
        }
    }
}

static void print_help(const char *prog)
{
    std::cerr
      << "Usage:\n"
      << "  sudo " << prog << " [options] <tun> <local_pub> <remote_pub> <local_private> <remote_private>\n\n"
      << "Options:\n"
      << "  -d, --daemon              Run as daemon\n"
      << "  -c, --color               Colored output\n"
      << "  -v, --verbose             Verbose logs\n"
      << "  -b, --mtu MTU             TUN MTU (default " << DEFAULT_MTU << ")\n"
      << "  -i, --id ID               Tunnel ICMP id (hex or dec)\n"
      << "      --pskkey FILE         Enable crypto and read PSK from FILE (" << KEY_BYTES << " bytes)\n"
      << "      --drop-root           Drop privileges to nobody after setup\n"
      << "      --mode client|server  Mode (default client)\n"
      << "      --poll-ms MS          Client poll interval (default " << DEFAULT_POLL_MS << ")\n"
      << "      --burst N             Server replies per poll (default " << DEFAULT_BURST << ")\n"
      << "      --pack N              Pack up to N frames per payload (default " << DEFAULT_PACK << ")\n"
      << "      --rt                  Try RT scheduling (Linux)\n"
      << "      --cpu N               Pin net loop thread to CPU N (Linux)\n\n"
      << "Tip:\n"
      << "  sudo sysctl -w net.ipv4.icmp_echo_ignore_all=1\n";
    exit(1);
}

int main(int argc, char **argv)
{
    Config cfg;

    static option long_opts[] = {
        {"daemon",     no_argument,       0, 'd'},
        {"color",      no_argument,       0, 'c'},
        {"verbose",    no_argument,       0, 'v'},
        {"mtu",        required_argument, 0, 'b'},
        {"id",         required_argument, 0, 'i'},
        {"pskkey",     required_argument, 0,  0 },
        {"drop-root",  no_argument,       0,  0 },
        {"mode",       required_argument, 0,  0 },
        {"poll-ms",    required_argument, 0,  0 },
        {"burst",      required_argument, 0,  0 },
        {"pack",       required_argument, 0,  0 },
        {"rt",         no_argument,       0,  0 },
        {"cpu",        required_argument, 0,  0 },
        {0,0,0,0}
    };

    int opt, idx = 0;
    while ((opt = getopt_long(argc, argv, "dcvb:i:", long_opts, &idx)) != -1) {
        switch (opt) {
            case 'd': cfg.daemon = true; break;
            case 'c': g_use_color = true; break;
            case 'v': g_verbose = true; break;
            case 'b': cfg.mtu = atoi(optarg); break;
            case 'i': cfg.tunnel_id = (uint16_t)strtoul(optarg, nullptr, 0); break;
            case 0:
                if (!strcmp(long_opts[idx].name, "pskkey")) {
                    cfg.crypto = true;
                    cfg.psk_path = optarg;
                } else if (!strcmp(long_opts[idx].name, "drop-root")) {
                    cfg.drop_root = true;
                } else if (!strcmp(long_opts[idx].name, "mode")) {
                    std::string m = optarg;
                    if (m == "client") cfg.mode = MODE_CLIENT;
                    else if (m == "server") cfg.mode = MODE_SERVER;
                    else print_help(argv[0]);
                } else if (!strcmp(long_opts[idx].name, "poll-ms")) {
                    cfg.poll_ms = atoi(optarg);
                    if (cfg.poll_ms < 3) cfg.poll_ms = 3;
                } else if (!strcmp(long_opts[idx].name, "burst")) {
                    cfg.burst = atoi(optarg);
                    if (cfg.burst < 1) cfg.burst = 1;
                    if (cfg.burst > 32) cfg.burst = 32;
                } else if (!strcmp(long_opts[idx].name, "pack")) {
                    cfg.pack = atoi(optarg);
                    if (cfg.pack < 1) cfg.pack = 1;
                    if (cfg.pack > 16) cfg.pack = 16;
                } else if (!strcmp(long_opts[idx].name, "rt")) {
                    cfg.rt = true;
                } else if (!strcmp(long_opts[idx].name, "cpu")) {
                    cfg.cpu = atoi(optarg);
                }
                break;
            default:
                print_help(argv[0]);
        }
    }

    if (optind + 5 != argc) print_help(argv[0]);

    cfg.tun       = argv[optind++];
    cfg.local_pub = argv[optind++];
    cfg.remote_pub= argv[optind++];
    cfg.local_pr  = argv[optind++];
    cfg.remote_pr = argv[optind++];

    g_log_level = g_verbose ? LOG_INFO : LOG_WARN;

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    if (cfg.daemon) daemonize();

    if (sodium_init() < 0) {
        log_msg(LOG_ERROR, "sodium_init failed");
        return 1;
    }

    std::vector<uint8_t> psk;
    if (cfg.crypto) {
        if (!load_psk(cfg.psk_path, psk)) return 1;
    }

    in_addr expected_peer{};
    if (!ip_to_inaddr(cfg.remote_pub, expected_peer)) {
        log_msg(LOG_ERROR, "Invalid remote_pub IP: %s", cfg.remote_pub.c_str());
        return 1;
    }

    int tun_fd = tun_create(cfg.tun, cfg.mtu);
    run_cmd("ip addr add " + cfg.local_pr + "/30 dev " + cfg.tun);

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) { perror("socket"); return 1; }
    fcntl(sock, F_SETFL, fcntl(sock, F_GETFL, 0) | O_NONBLOCK);

    sockaddr_in any{};
    any.sin_family = AF_INET;
    any.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(sock, (sockaddr*)&any, sizeof(any)) < 0) {
        perror("bind");
        return 1;
    }

    if (cfg.drop_root) drop_privs();

    if (g_use_color) {
        std::cout << C_CYAN << "[Tunnel]" << C_RESET << " "
                  << C_GREEN << cfg.local_pr << C_RESET << " ↔ "
                  << C_GREEN << cfg.remote_pr << C_RESET << "\n"
                  << "  " << C_CYAN << "[Mode]" << C_RESET << " "
                  << (cfg.mode == MODE_CLIENT ? "client" : "server")
                  << "  " << C_CYAN << "[MTU]" << C_RESET << " " << cfg.mtu
                  << "  " << C_CYAN << "[ID]" << C_RESET << " 0x" << std::hex << cfg.tunnel_id << std::dec
                  << "  " << C_CYAN << "[Poll]" << C_RESET << " " << cfg.poll_ms << "ms"
                  << "  " << C_CYAN << "[Burst]" << C_RESET << " " << cfg.burst
                  << "  " << C_CYAN << "[Pack]" << C_RESET << " " << cfg.pack
                  << (cfg.crypto ? "  [Crypto]" : "")
                  << "\n"
                  << C_YELLOW << "Tip: sudo sysctl -w net.ipv4.icmp_echo_ignore_all=1" << C_RESET << "\n";
    } else {
        std::cout << "[Tunnel] " << cfg.local_pr << " ↔ " << cfg.remote_pr
                  << "  [Mode] " << (cfg.mode == MODE_CLIENT ? "client" : "server")
                  << "  [MTU] " << cfg.mtu
                  << "  [ID] 0x" << std::hex << cfg.tunnel_id << std::dec
                  << "  [Poll] " << cfg.poll_ms << "ms"
                  << "  [Burst] " << cfg.burst
                  << "  [Pack] " << cfg.pack
                  << (cfg.crypto ? "  [Crypto]" : "")
                  << "\nTip: sudo sysctl -w net.ipv4.icmp_echo_ignore_all=1\n";
    }

    std::thread tr(tun_thread, tun_fd, std::ref(cfg));

    std::thread net;
    if (cfg.mode == MODE_CLIENT) {
        net = std::thread(client_loop, sock, tun_fd, std::ref(cfg), expected_peer, std::ref(psk));
    } else {
        net = std::thread(server_loop, sock, tun_fd, std::ref(cfg), expected_peer, std::ref(psk));
    }

    tr.join();
    net.join();

    std::cout << "\nShutting down...\n";
    return 0;
}
