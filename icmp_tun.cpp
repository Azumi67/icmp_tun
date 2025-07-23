// Author : github.com/Azumi67
//  icmp_tun.cpp [ use when certain ways are blocked but icmp is allowed.
// I mostly tested it in my online game and i was happy with it.
//i hope you find it useful as well.
//  Build with:
//    apt install -y g++ build-essential libsodium-dev iproute2
//    g++ -O2 -std=c++17 icmp_tun.cpp -o icmp_tun -lsodium -pthread
//
//  Usage Help:
//    sudo ./icmp_tun     [--daemon|-d] [--color|-c] [--mtu|-b MTU]
//                        [--verbose|-v] [--batch|-n BATCH] [--id|-i ID]
//                        [--pskkey <file>] [--drop-root]
//                        [--threads|-m THREADS]
//                        <tun> <local_pub> <remote_pub>
//                        <local_private> <remote_private>

#include <arpa/inet.h>
#include <fcntl.h>
#include <getopt.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <pwd.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <cstring>
#include <cstdlib>
#include <iostream>
#include <fstream>
#include <vector>
#include <ctime>
#include <cstdarg>
#include <sstream>
#include <thread>
#include <mutex>
#include <atomic>
#include <sodium.h>

static const int DEFAULT_MTU = 1000;
static const int DEFAULT_BATCH = 16;
static const int STATS_INTERVAL = 20; // sec

// ChaCha20
static const size_t KEY_BYTES = crypto_aead_chacha20poly1305_ietf_KEYBYTES;
static const size_t NONCE_BYTES = crypto_aead_chacha20poly1305_ietf_NPUBBYTES;
static const size_t TAG_BYTES = crypto_aead_chacha20poly1305_ietf_ABYTES;

// Color
static const char *C_RESET = "\033[0m";
static const char *C_RED = "\033[31m";
static const char *C_YELLOW = "\033[33m";
static const char *C_GREEN = "\033[32m";
static const char *C_CYAN = "\033[36m";
static const char *C_MAGENTA = "\033[35m";

enum LogLevel
{
    LOG_ERROR = 0,
    LOG_WARN,
    LOG_INFO,
    LOG_DEBUG
};
static LogLevel log_level = LOG_WARN;
static bool use_color = false;
static bool verbose = false;
static bool drop_root = false;

static std::vector<std::string> logs;
static std::mutex log_mutex;

static volatile sig_atomic_t keep_running = 1;

static std::atomic<uint64_t> total_s{0}, total_r{0};
static std::atomic<uint64_t> global_ctr{0};

void log_msg(LogLevel level, const char *fmt, ...)
{
    if (level > log_level)
        return;
    const char *level_str = level == LOG_ERROR ? "ERROR" : level == LOG_WARN ? "WARN"
                                                       : level == LOG_INFO   ? "INFO"
                                                                             : "DEBUG";
    const char *color_code = "";
    if (use_color)
    {
        switch (level)
        {
        case LOG_ERROR:
            color_code = C_RED;
            break;
        case LOG_WARN:
            color_code = C_YELLOW;
            break;
        case LOG_INFO:
            color_code = C_GREEN;
            break;
        case LOG_DEBUG:
            color_code = C_CYAN;
            break;
        }
    }

    char msgbuf[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(msgbuf, sizeof(msgbuf), fmt, args);
    va_end(args);

    time_t now = time(nullptr);
    struct tm tm;
    localtime_r(&now, &tm);
    char timestr[64];
    strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", &tm);

    std::ostringstream oss;
    oss << "[" << timestr << "] ";
    if (use_color)
        oss << color_code;
    oss << "[" << level_str << "]";
    if (use_color)
        oss << C_RESET;
    oss << " " << msgbuf;

    {
        std::lock_guard<std::mutex> lk(log_mutex);
        logs.push_back(oss.str());
    }
    if (level <= LOG_WARN || (level == LOG_INFO && verbose))
    {
        std::cout << oss.str() << "\n";
    }
}

void help(const char *prog)
{
    std::cerr << "Usage: sudo " << prog
              << " [--daemon|-d] [--color|-c] [--mtu|-b MTU]\n"
              << "             [--verbose|-v] [--batch|-n BATCH]\n"
              << "             [--id|-i ID] [--pskkey <file>] [--drop-root]\n"
              << "             [--threads|-m THREADS]\n"
              << "             <tun> <local_pub> <remote_pub>\n"
              << "             <local_private> <remote_private>\n";
    exit(1);
}

void runCommand(const std::string &cmd)
{
    if (system(cmd.c_str()) != 0)
    {
        log_msg(LOG_ERROR, "Command failed: %s", cmd.c_str());
        exit(1);
    }
    log_msg(LOG_DEBUG, "Ran command: %s", cmd.c_str());
}

uint16_t icmp_checksum(uint16_t *buf, int len)
{
    uint32_t sum = 0;
    while (len > 1)
    {
        sum += *buf++;
        len -= 2;
    }
    if (len)
        sum += *(uint8_t *)buf;
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return ~sum;
}

void daemonize()
{
    if (fork() > 0)
        exit(0);
    setsid();
    if (fork() > 0)
        exit(0);
    if (chdir("/") < 0)
        perror("daemonize: chdir");
    for (int fd = 0; fd < 3; fd++)
        close(fd);
    log_msg(LOG_INFO, "Daemonized");
}

int createTun(const std::string &name, int mtu)
{
    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0)
    {
        perror("open /dev/net/tun");
        exit(1);
    }
    struct ifreq ifr{};
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, name.c_str(), IFNAMSIZ);
    if (ioctl(fd, TUNSETIFF, &ifr) < 0)
    {
        perror("TUNSETIFF");
        exit(1);
    }
    runCommand("ip link set dev " + name + " up");
    runCommand("ip link set dev " + name + " mtu " + std::to_string(mtu));
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
    log_msg(LOG_INFO, "Created TUN %s (MTU=%d)", name.c_str(), mtu);
    return fd;
}

bool load_psk(const std::string &path, std::vector<uint8_t> &key)
{
    std::ifstream f(path, std::ios::binary);
    if (!f.read((char *)key.data(), KEY_BYTES))
    {
        log_msg(LOG_ERROR, "Couldn't load PSK from %s", path.c_str());
        return false;
    }
    log_msg(LOG_INFO, "Loaded PSK from %s", path.c_str());
    return true;
}

void give_signal(int sig)
{
    log_msg(LOG_WARN, "Signal %d received, shutting down...", sig);
    keep_running = 0;
}

void drop_privs()
{
    struct passwd *pw = getpwnam("nobody");
    if (!pw)
    {
        log_msg(LOG_ERROR, "getpwnam failed");
        exit(1);
    }
    if (setgid(pw->pw_gid) || setuid(pw->pw_uid))
    {
        log_msg(LOG_ERROR, "Couldn't drop root");
        exit(1);
    }
    log_msg(LOG_INFO, "Dropped to nobody (uid=%d gid=%d)",
            pw->pw_uid, pw->pw_gid);
}

struct Config
{
    bool do_daemon = false;
    int mtu = DEFAULT_MTU;
    int batch = DEFAULT_BATCH;
    uint16_t tunnel_id = 0x1234;
    std::string psk_path;
    bool use_crypto = false;
    int threads = 1;
    std::string tun_name, local_pub, remote_pub, local_pr, remote_pr;
};

void worker_loop(int epfd, int tun_fd, int sock,
                 const sockaddr_in &peer,
                 const std::vector<uint8_t> &psk)
{
    size_t bufsize = Config().mtu + NONCE_BYTES + TAG_BYTES + 128;
    std::vector<uint8_t> tunbuf(bufsize), paybuf(bufsize);
    epoll_event evs[2];

    while (keep_running)
    {
        int ne = epoll_wait(epfd, evs, 2, STATS_INTERVAL * 1000);
        if (ne < 0 && errno != EINTR)
            break;
        for (int i = 0; i < ne; i++)
        {
            if (evs[i].data.fd == tun_fd)
            {
                ssize_t r = read(tun_fd, tunbuf.data(), bufsize);
                if (r > 0)
                {
                    log_msg(LOG_DEBUG, "Read %zd B from TUN", r);

                    uint8_t *payload = paybuf.data() + sizeof(icmphdr);
                    unsigned long long clen = r;
                    if (!psk.empty())
                    {
                        uint64_t ctr = global_ctr.fetch_add(1) + 1;
                        uint8_t nonce[NONCE_BYTES];
                        memcpy(nonce, &ctr, 8);
                        memset(nonce + 8, 0, NONCE_BYTES - 8);
                        if (crypto_aead_chacha20poly1305_ietf_encrypt(
                                payload + NONCE_BYTES, &clen,
                                tunbuf.data(), r,
                                nullptr, 0, nullptr, nonce, psk.data()) != 0)
                        {
                            log_msg(LOG_ERROR, "Encryption failed");
                            continue;
                        }
                        memcpy(payload, nonce, NONCE_BYTES);
                        log_msg(LOG_DEBUG, "Encrypted pkt #%llu (%llu ct)", ctr, clen);
                    }
                    else
                    {
                        memcpy(payload, tunbuf.data(), r);
                    }
                    size_t payload_len = psk.empty() ? r : NONCE_BYTES + clen;
                    icmphdr ic{ICMP_ECHO, 0, 0, htons(Config().tunnel_id), 0};
                    memcpy(paybuf.data() + sizeof(ic), payload, payload_len);
                    ic.checksum = icmp_checksum((uint16_t *)paybuf.data(),
                                                sizeof(ic) + payload_len);
                    memcpy(paybuf.data(), &ic, sizeof(ic));

                    iovec iov{paybuf.data(), sizeof(ic) + payload_len};
                    msghdr mh{(void *)&peer, sizeof(peer), &iov, 1, nullptr, 0, 0};
                    ssize_t s = sendmsg(sock, &mh, 0);
                    if (s > (ssize_t)sizeof(ic))
                    {
                        total_s += s - sizeof(ic);
                        log_msg(LOG_DEBUG, "Sent %zd B ICMP", s - sizeof(ic));
                    }
                }
            }
            else if (evs[i].data.fd == sock)
            {
                uint8_t buf[65536];
                sockaddr_in src;
                socklen_t sl = sizeof(src);
                ssize_t l = recvfrom(sock, buf, sizeof(buf), 0,
                                     (sockaddr *)&src, &sl);
                if (l >= (ssize_t)(sizeof(iphdr) + sizeof(icmphdr)))
                {
                    iphdr *ip = (iphdr *)buf;
                    int ihl = ip->ihl * 4;
                    icmphdr *ic = (icmphdr *)(buf + ihl);
                    if ((ic->type == ICMP_ECHO || ic->type == ICMP_ECHOREPLY) && ntohs(ic->un.echo.id) == Config().tunnel_id)
                    {
                        uint8_t *enc = buf + ihl + sizeof(*ic);
                        int enclen = l - ihl - sizeof(*ic);
                        if (!psk.empty())
                        {
                            uint8_t *nonce = enc;
                            uint8_t *ct = enc + NONCE_BYTES;
                            int ctlen = enclen - NONCE_BYTES;
                            std::vector<uint8_t> pt(ctlen);
                            unsigned long long mlen;
                            if (crypto_aead_chacha20poly1305_ietf_decrypt(
                                    pt.data(), &mlen, nullptr,
                                    ct, ctlen, nullptr, 0, nonce, psk.data()) == 0)
                            {
                                ssize_t w = write(tun_fd, pt.data(), mlen);
                                if (w > 0)
                                {
                                    total_r += w;
                                    log_msg(LOG_DEBUG, "Wrote %zd B to TUN", w);
                                }
                            }
                            else
                            {
                                log_msg(LOG_ERROR, "Decryption failed");
                            }
                        }
                        else
                        {
                            ssize_t w = write(tun_fd, enc, enclen);
                            if (w > 0)
                            {
                                total_r += w;
                                log_msg(LOG_DEBUG, "Wrote %zd B to TUN", w);
                            }
                        }
                    }
                }
            }
        }

        static time_t last_ts = time(nullptr);
        time_t now = time(nullptr);
        if (now - last_ts >= STATS_INTERVAL)
        {
            if (use_color)
            {
                std::cout << "\r" << C_MAGENTA << "[Stats]" << C_RESET
                          << " S:" << C_YELLOW << total_s << C_RESET
                          << " R:" << C_YELLOW << total_r << C_RESET << "   ";
            }
            else
            {
                std::cout << "\r[Stats] S:" << total_s << " R:" << total_r << "   ";
            }
            std::cout.flush();
            last_ts = now;
            log_msg(LOG_INFO, "Stats: sent=%lu recv=%lu",
                    total_s.load(), total_r.load());
        }
    }
}

int main(int argc, char *argv[])
{
    Config cfg;
    static struct option opts[] = {
        {"daemon", no_argument, 0, 'd'},
        {"color", no_argument, 0, 'c'},
        {"mtu", required_argument, 0, 'b'},
        {"verbose", no_argument, 0, 'v'},
        {"batch", required_argument, 0, 'n'},
        {"id", required_argument, 0, 'i'},
        {"pskkey", required_argument, 0, 0},
        {"drop-root", no_argument, 0, 0},
        {"threads", required_argument, 0, 'm'},
        {0, 0, 0, 0}};
    int idx = 0, opt;
    while ((opt = getopt_long(argc, argv, "dcb:vn:i:m:", opts, &idx)) != -1)
    {
        switch (opt)
        {
        case 'd':
            cfg.do_daemon = true;
            break;
        case 'c':
            use_color = true;
            break;
        case 'b':
            cfg.mtu = atoi(optarg);
            break;
        case 'v':
            verbose = true;
            break;
        case 'n':
            cfg.batch = atoi(optarg);
            break;
        case 'i':
            cfg.tunnel_id = strtoul(optarg, nullptr, 0);
            break;
        case 'm':
            cfg.threads = atoi(optarg);
            break;
        case 0:
            if (!strcmp(opts[idx].name, "pskkey"))
            {
                cfg.psk_path = optarg;
                cfg.use_crypto = true;
            }
            else if (!strcmp(opts[idx].name, "drop-root"))
            {
                drop_root = true;
            }
            break;
        default:
            help(argv[0]);
        }
    }
    if (optind + 5 != argc)
        help(argv[0]);
    cfg.tun_name = argv[optind++];
    cfg.local_pub = argv[optind++];
    cfg.remote_pub = argv[optind++];
    cfg.local_pr = argv[optind++];
    cfg.remote_pr = argv[optind++];

    log_level = verbose ? LOG_INFO : LOG_WARN;
    signal(SIGINT, give_signal);
    signal(SIGTERM, give_signal);

    if (cfg.do_daemon)
        daemonize();
    if (sodium_init() < 0)
    {
        log_msg(LOG_ERROR, "sodium_init failed");
        exit(1);
    }

    std::vector<uint8_t> psk(KEY_BYTES);
    if (cfg.use_crypto && !load_psk(cfg.psk_path, psk))
        exit(1);

    int tun_fd = createTun(cfg.tun_name, cfg.mtu);
    runCommand("ip addr add " + cfg.local_pr + "/30 dev " + cfg.tun_name);
    log_msg(LOG_INFO, "Assigned IP %s/30 to %s",
            cfg.local_pr.c_str(), cfg.tun_name.c_str());

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0)
    {
        perror("socket");
        exit(1);
    }
    fcntl(sock, F_SETFL, fcntl(sock, F_GETFL, 0) | O_NONBLOCK);
    sockaddr_in anyaddr{};
    anyaddr.sin_family = AF_INET;
    anyaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(sock, (sockaddr *)&anyaddr, sizeof(anyaddr)) < 0)
    {
        perror("bind");
        exit(1);
    }
    sockaddr_in peer{};
    peer.sin_family = AF_INET;
    inet_pton(AF_INET, cfg.remote_pub.c_str(), &peer.sin_addr);

    if (drop_root)
        drop_privs();

    int epfd = epoll_create1(0);
    epoll_event ev{.events = EPOLLIN};
    ev.data.fd = tun_fd;
    epoll_ctl(epfd, EPOLL_CTL_ADD, tun_fd, &ev);
    ev.data.fd = sock;
    epoll_ctl(epfd, EPOLL_CTL_ADD, sock, &ev);

    if (use_color)
    {
        std::cout << C_CYAN << "[Tunnel]" << C_RESET << " "
                  << C_GREEN << cfg.local_pr << C_RESET << " ↔ "
                  << C_GREEN << cfg.remote_pr << C_RESET << "\n"
                  << "  " << C_CYAN << "[MTU]" << C_RESET << " " << cfg.mtu
                  << "  " << C_CYAN << "[BATCH]" << C_RESET << " " << cfg.batch
                  << "  " << C_CYAN << "[ID]" << C_RESET << " 0x" << std::hex
                  << cfg.tunnel_id << std::dec
                  << "  " << C_CYAN << "[Threads]" << C_RESET << " " << cfg.threads
                  << (cfg.use_crypto ? "  [Crypto]\n" : "\n");
    }
    else
    {
        std::cout << "[Tunnel] " << cfg.local_pr << " ↔ " << cfg.remote_pr << "\n"
                  << "[MTU] " << cfg.mtu << "  [BATCH] " << cfg.batch
                  << "  [ID] 0x" << std::hex << cfg.tunnel_id << std::dec
                  << "  [Threads] " << cfg.threads
                  << (cfg.use_crypto ? "  [Crypto]\n" : "\n");
    }

    std::vector<std::thread> workers;
    for (int i = 0; i < cfg.threads; i++)
    {
        workers.emplace_back(worker_loop,
                             epfd, tun_fd, sock, peer, psk);
    }

    for (auto &t : workers)
        t.join();

    std::cout << "\nShutting down...\n";
    log_msg(LOG_INFO, "Shutdown complete");
    return 0;
}
