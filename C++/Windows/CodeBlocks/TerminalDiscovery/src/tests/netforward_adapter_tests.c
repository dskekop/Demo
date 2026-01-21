#define _GNU_SOURCE

#include "td_adapter_registry.h"

#include "adapter_api.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/if_ether.h>
#include <pthread.h>
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

struct sockaddr_vlan {
    uint8_t dest_mac[ETH_ALEN];
    uint8_t src_mac[ETH_ALEN];
    uint32_t port;
    uint16_t vlanid;
    uint16_t svlanid;
    uint32_t length;
    uint16_t eth_type;
};

struct server_args {
    char sock_path[108];
    bool send_arp;
    bool short_length;
    uint16_t vlan;
    uint32_t port;
    bool ready;
    pthread_mutex_t lock;
    pthread_cond_t cond;
};

struct packet_capture {
    struct td_adapter_packet_view view;
    bool received;
};

static void write_full_or_fail(int fd, const void *buf, size_t len) {
    const uint8_t *p = buf;
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, p + off, len - off);
        if (n <= 0) {
            break;
        }
        off += (size_t)n;
    }
}

static void notify_ready(struct server_args *args) {
    pthread_mutex_lock(&args->lock);
    args->ready = true;
    pthread_cond_broadcast(&args->cond);
    pthread_mutex_unlock(&args->lock);
}

static void wait_ready(struct server_args *args) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += 2;
    pthread_mutex_lock(&args->lock);
    while (!args->ready) {
        if (pthread_cond_timedwait(&args->cond, &args->lock, &ts) != 0) {
            break;
        }
    }
    pthread_mutex_unlock(&args->lock);
}

static size_t build_frame(bool arp, uint8_t *buf, size_t cap, uint16_t ether_type) {
    if (cap < sizeof(struct ethhdr)) {
        return 0;
    }
    struct ethhdr *eth = (struct ethhdr *)buf;
    memset(eth->h_dest, 0xFF, ETH_ALEN);
    eth->h_dest[0] = 0xFF;
    eth->h_dest[1] = 0xFF;
    eth->h_dest[2] = 0xFF;
    eth->h_dest[3] = 0xFF;
    eth->h_dest[4] = 0xFF;
    eth->h_dest[5] = 0xFF;
    eth->h_source[0] = 0x00;
    eth->h_source[1] = 0x11;
    eth->h_source[2] = 0x22;
    eth->h_source[3] = 0x33;
    eth->h_source[4] = 0x44;
    eth->h_source[5] = 0x55;
    eth->h_proto = htons(ether_type);

    if (!arp) {
        memset(buf + sizeof(struct ethhdr), 0xAA, 32);
        return sizeof(struct ethhdr) + 32;
    }

    if (cap < sizeof(struct ethhdr) + sizeof(struct ether_arp)) {
        return 0;
    }

    struct ether_arp *arp_hdr = (struct ether_arp *)(buf + sizeof(struct ethhdr));
    memset(arp_hdr, 0, sizeof(*arp_hdr));
    arp_hdr->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp_hdr->ea_hdr.ar_pro = htons(ETH_P_IP);
    arp_hdr->ea_hdr.ar_hln = ETH_ALEN;
    arp_hdr->ea_hdr.ar_pln = 4;
    arp_hdr->ea_hdr.ar_op = htons(ARPOP_REQUEST);

    uint32_t spa = inet_addr("192.0.2.10");
    uint32_t tpa = inet_addr("192.0.2.1");
    memcpy(&arp_hdr->arp_sha, eth->h_source, ETH_ALEN);
    memcpy(&arp_hdr->arp_spa, &spa, sizeof(spa));
    memcpy(&arp_hdr->arp_tpa, &tpa, sizeof(tpa));
    memset(&arp_hdr->arp_tha, 0, ETH_ALEN);

    return sizeof(struct ethhdr) + sizeof(struct ether_arp);
}

static void *sidecar_server(void *arg) {
    struct server_args *args = arg;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        notify_ready(args);
        return NULL;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", args->sock_path);

    unlink(args->sock_path);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("bind");
        notify_ready(args);
        close(fd);
        return NULL;
    }

    if (listen(fd, 1) != 0) {
        perror("listen");
        notify_ready(args);
        close(fd);
        return NULL;
    }

    notify_ready(args);

    int conn = accept(fd, NULL, NULL);
    if (conn < 0) {
        perror("accept");
        close(fd);
        return NULL;
    }

    uint8_t frame[128];
    size_t frame_len = build_frame(args->send_arp, frame, sizeof(frame), args->send_arp ? ETH_P_ARP : ETH_P_IP);
    if (args->short_length && frame_len > 8) {
        frame_len = 8;
    }

    struct sockaddr_vlan header;
    memset(&header, 0, sizeof(header));
    memcpy(header.dest_mac, frame, ETH_ALEN);
    memcpy(header.src_mac, frame + ETH_ALEN, ETH_ALEN);
    header.port = args->port;
    header.vlanid = args->vlan;
    header.length = (uint32_t)frame_len;
    header.eth_type = args->send_arp ? ETH_P_ARP : ETH_P_IP;

    write_full_or_fail(conn, &header, sizeof(header));
    write_full_or_fail(conn, frame, frame_len);

    close(conn);
    close(fd);
    return NULL;
}

static void packet_cb(const struct td_adapter_packet_view *packet, void *ctx) {
    struct packet_capture *cap = ctx;
    cap->view = *packet;
    cap->received = true;
}

static bool wait_for_packet(struct packet_capture *cap) {
    for (int i = 0; i < 20; ++i) {
        if (cap->received) {
            return true;
        }
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 50 * 1000000L};
        nanosleep(&ts, NULL);
    }
    return cap->received;
}

static bool test_netforward_receives_arp(void) {
    char tmpdir[] = "/tmp/nfsidecar.XXXXXX";
    if (!mkdtemp(tmpdir)) {
        perror("mkdtemp");
        return false;
    }

    char sock_path[108];
    snprintf(sock_path, sizeof(sock_path), "%s/socket", tmpdir);
    setenv("TD_NETFORWARD_SIDECAR_SOCK", sock_path, 1);

    struct server_args args = {.send_arp = true, .short_length = false, .vlan = 100, .port = 5};
    snprintf(args.sock_path, sizeof(args.sock_path), "%s", sock_path);
    pthread_mutex_init(&args.lock, NULL);
    pthread_cond_init(&args.cond, NULL);

    pthread_t server_thread;
    pthread_create(&server_thread, NULL, sidecar_server, &args);
    wait_ready(&args);

    struct td_adapter_env env = {0};
    struct td_adapter_config cfg = {.tx_interval_ms = 0};
    td_adapter_t *adapter = NULL;
    const struct td_adapter_descriptor *desc = td_adapter_registry_find("netforward");
    if (!desc || !desc->ops || desc->ops->init(&cfg, &env, &adapter) != TD_ADAPTER_OK) {
        fprintf(stderr, "adapter init failed\n");
        return false;
    }

    struct packet_capture cap = {0};
    struct td_adapter_packet_subscription sub = {.callback = packet_cb, .user_ctx = &cap};
    desc->ops->register_packet_rx(adapter, &sub);
    desc->ops->start(adapter);

    bool ok = wait_for_packet(&cap);

    desc->ops->stop(adapter);
    desc->ops->shutdown(adapter);
    pthread_join(server_thread, NULL);

    unlink(sock_path);
    rmdir(tmpdir);

    if (!ok) {
        fprintf(stderr, "no packet received\n");
        return false;
    }

    if (cap.view.ether_type != ETH_P_ARP || cap.view.vlan_id != 100 || cap.view.ifindex != 5) {
        fprintf(stderr, "unexpected packet fields ether=%u vlan=%d ifindex=%u\n",
                cap.view.ether_type,
                cap.view.vlan_id,
                cap.view.ifindex);
        return false;
    }

    return true;
}

static bool test_netforward_ignores_non_arp(void) {
    char tmpdir[] = "/tmp/nfsidecar.XXXXXX";
    if (!mkdtemp(tmpdir)) {
        perror("mkdtemp");
        return false;
    }

    char sock_path[108];
    snprintf(sock_path, sizeof(sock_path), "%s/socket", tmpdir);
    setenv("TD_NETFORWARD_SIDECAR_SOCK", sock_path, 1);

    struct server_args args = {.send_arp = false, .short_length = false, .vlan = 20, .port = 7};
    snprintf(args.sock_path, sizeof(args.sock_path), "%s", sock_path);
    pthread_mutex_init(&args.lock, NULL);
    pthread_cond_init(&args.cond, NULL);

    pthread_t server_thread;
    pthread_create(&server_thread, NULL, sidecar_server, &args);
    wait_ready(&args);

    struct td_adapter_env env = {0};
    struct td_adapter_config cfg = {.tx_interval_ms = 0};
    td_adapter_t *adapter = NULL;
    const struct td_adapter_descriptor *desc = td_adapter_registry_find("netforward");
    if (!desc || !desc->ops || desc->ops->init(&cfg, &env, &adapter) != TD_ADAPTER_OK) {
        fprintf(stderr, "adapter init failed\n");
        return false;
    }

    struct packet_capture cap = {0};
    struct td_adapter_packet_subscription sub = {.callback = packet_cb, .user_ctx = &cap};
    desc->ops->register_packet_rx(adapter, &sub);
    desc->ops->start(adapter);

    bool got_packet = wait_for_packet(&cap);

    desc->ops->stop(adapter);
    desc->ops->shutdown(adapter);
    pthread_join(server_thread, NULL);

    unlink(sock_path);
    rmdir(tmpdir);

    if (got_packet) {
        fprintf(stderr, "unexpected packet delivered\n");
        return false;
    }

    return true;
}

int main(void) {
    struct {
        const char *name;
        bool (*fn)(void);
    } tests[] = {
        {"netforward_receives_arp", test_netforward_receives_arp},
        {"netforward_ignores_non_arp", test_netforward_ignores_non_arp},
    };

    size_t total = sizeof(tests) / sizeof(tests[0]);
    size_t failures = 0;

    for (size_t i = 0; i < total; ++i) {
        if (tests[i].fn && tests[i].fn()) {
            printf("[PASS] %s\n", tests[i].name);
        } else {
            printf("[FAIL] %s\n", tests[i].name);
            failures += 1;
        }
    }

    if (failures > 0) {
        printf("%zu/%zu tests failed\n", failures, total);
        return 1;
    }

    printf("all %zu tests passed\n", total);
    return 0;
}
