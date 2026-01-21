#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define TD_NETFORWARD_DEFAULT_SOCKET "/tmp/netforward_sidecar.sock"

struct sockaddr_vlan {
    uint8_t dest_mac[ETH_ALEN];
    uint8_t src_mac[ETH_ALEN];
    uint32_t port;
    uint16_t vlanid;
    uint16_t svlanid;
    uint32_t length;
    uint16_t eth_type;
};

struct stub_opts {
    char socket_path[108];
    uint32_t port;
    uint16_t vlan;
    int count;
    int interval_ms;
    bool gratuitous;
    bool idle;
};

static volatile sig_atomic_t g_stop = 0;

static void on_signal(int signo) {
    (void)signo;
    g_stop = 1;
}

static void write_mac(uint8_t mac[ETH_ALEN], uint8_t base, uint8_t step) {
    mac[0] = 0x02;
    mac[1] = 0x00;
    mac[2] = 0x00;
    mac[3] = 0x00;
    mac[4] = base;
    mac[5] = step;
}

static size_t build_arp_frame(uint8_t *buf, size_t cap, uint32_t sender_host, uint32_t target_host, bool gratuitous, uint8_t src_mac[ETH_ALEN]) {
    if (cap < sizeof(struct ethhdr) + sizeof(struct ether_arp)) {
        return 0;
    }

    struct ethhdr *eth = (struct ethhdr *)buf;
    memset(eth->h_dest, 0xFF, ETH_ALEN);
    memcpy(eth->h_source, src_mac, ETH_ALEN);
    eth->h_proto = htons(ETH_P_ARP);

    struct ether_arp *arp = (struct ether_arp *)(buf + sizeof(struct ethhdr));
    memset(arp, 0, sizeof(*arp));
    arp->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp->ea_hdr.ar_pro = htons(ETH_P_IP);
    arp->ea_hdr.ar_hln = ETH_ALEN;
    arp->ea_hdr.ar_pln = 4;
    arp->ea_hdr.ar_op = htons(gratuitous ? ARPOP_REPLY : ARPOP_REQUEST);

    uint32_t sender_ip = htonl(sender_host);
    uint32_t target_ip = htonl(target_host);
    memcpy(&arp->arp_sha, src_mac, ETH_ALEN);
    memcpy(&arp->arp_spa, &sender_ip, sizeof(sender_ip));
    memcpy(&arp->arp_tha, src_mac, ETH_ALEN);
    memcpy(&arp->arp_tpa, gratuitous ? &sender_ip : &target_ip, sizeof(target_ip));

    return sizeof(struct ethhdr) + sizeof(struct ether_arp);
}

static int write_full(int fd, const void *buf, size_t len) {
    const uint8_t *p = buf;
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, p + off, len - off);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

static void parse_args(int argc, char **argv, struct stub_opts *opts) {
    if (!opts) {
        return;
    }
    memset(opts, 0, sizeof(*opts));
    snprintf(opts->socket_path, sizeof(opts->socket_path), "%s", TD_NETFORWARD_DEFAULT_SOCKET);
    opts->port = 3;
    opts->vlan = 1;
    opts->count = 10;
    opts->interval_ms = 500;
    opts->gratuitous = false;
    opts->idle = false;

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--socket") == 0 && i + 1 < argc) {
            snprintf(opts->socket_path, sizeof(opts->socket_path), "%s", argv[++i]);
        } else if (strcmp(argv[i], "--count") == 0 && i + 1 < argc) {
            opts->count = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--interval-ms") == 0 && i + 1 < argc) {
            opts->interval_ms = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--vlan") == 0 && i + 1 < argc) {
            opts->vlan = (uint16_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--ifindex") == 0 && i + 1 < argc) {
            opts->port = (uint32_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--gratuitous") == 0) {
            opts->gratuitous = true;
        } else if (strcmp(argv[i], "--idle") == 0) {
            opts->idle = true;
        }
    }
}

static int setup_listener(const char *path) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);

    unlink(path);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("bind");
        close(fd);
        return -1;
    }

    if (listen(fd, 1) != 0) {
        perror("listen");
        close(fd);
        return -1;
    }

    return fd;
}

int main(int argc, char **argv) {
    struct stub_opts opts;
    parse_args(argc, argv, &opts);

    const char *env_sock = getenv("TD_NETFORWARD_SIDECAR_SOCK");
    if (env_sock && env_sock[0]) {
        snprintf(opts.socket_path, sizeof(opts.socket_path), "%s", env_sock);
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    int listen_fd = setup_listener(opts.socket_path);
    if (listen_fd < 0) {
        return EXIT_FAILURE;
    }

    printf("[netforward-sidecar-stub] listening on %s vlan=%u ifindex=%u count=%d interval_ms=%d gratuitous=%d idle=%d\n",
           opts.socket_path,
           opts.vlan,
           opts.port,
           opts.count,
           opts.interval_ms,
           opts.gratuitous ? 1 : 0,
           opts.idle ? 1 : 0);
    fflush(stdout);

    int conn_fd = accept(listen_fd, NULL, NULL);
    if (conn_fd < 0) {
        perror("accept");
        close(listen_fd);
        return EXIT_FAILURE;
    }

    if (opts.idle) {
        pause();
        close(conn_fd);
        close(listen_fd);
        return EXIT_SUCCESS;
    }

    uint8_t frame[sizeof(struct ethhdr) + sizeof(struct ether_arp)];
    uint8_t src_mac[ETH_ALEN];

    int to_send = opts.count <= 0 ? 1 : opts.count;
    for (int i = 0; (opts.count <= 0) || i < to_send; ++i) {
        if (g_stop) {
            break;
        }

        write_mac(src_mac, 0x10, (uint8_t)i);
        size_t frame_len = build_arp_frame(frame, sizeof(frame), 0x0A000000 | (uint32_t)(10 + i), 0x0A000064, opts.gratuitous, src_mac);
        if (frame_len == 0) {
            fprintf(stderr, "failed to build ARP frame\n");
            break;
        }

        struct sockaddr_vlan header;
        memset(&header, 0, sizeof(header));
        memcpy(header.dest_mac, frame, ETH_ALEN);
        memcpy(header.src_mac, frame + ETH_ALEN, ETH_ALEN);
        header.port = opts.port;
        header.vlanid = opts.vlan;
        header.length = (uint32_t)frame_len;
        header.eth_type = ETH_P_ARP;

        if (write_full(conn_fd, &header, sizeof(header)) != 0 || write_full(conn_fd, frame, frame_len) != 0) {
            perror("write");
            break;
        }

        if (opts.interval_ms > 0) {
            struct timespec ts = {
                .tv_sec = opts.interval_ms / 1000,
                .tv_nsec = (opts.interval_ms % 1000) * 1000000L,
            };
            nanosleep(&ts, NULL);
        }

        if (opts.count <= 0) {
            continue;
        }
    }

    close(conn_fd);
    close(listen_fd);
    unlink(opts.socket_path);
    printf("[netforward-sidecar-stub] completed\n");
    return EXIT_SUCCESS;
}
