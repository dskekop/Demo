#define _GNU_SOURCE

#include "netforward_adapter.h"

#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <stdarg.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "td_logging.h"

#define TD_NETFORWARD_DEFAULT_SOCKET "/tmp/netforward_sidecar.sock"
#define TD_NETFORWARD_LOG_COMPONENT "netforward"
#define TD_NETFORWARD_MAX_FRAME 2048U

struct sockaddr_vlan {
    uint8_t dest_mac[ETH_ALEN];
    uint8_t src_mac[ETH_ALEN];
    uint32_t port;
    uint16_t vlanid;
    uint16_t svlanid;
    uint32_t length;    /* Length of Ethernet frame (excluding this header) */
    uint16_t eth_type;
};

struct vlan_header {
    uint16_t tci;
    uint16_t encapsulated_proto;
} __attribute__((packed));

struct td_adapter {
    struct td_adapter_config cfg;
    struct td_adapter_env env;
    char sock_path[108];

    atomic_bool running;
    int sock_fd;
    pthread_t rx_thread;
    bool rx_thread_started;

    pthread_mutex_t state_lock;
    struct td_adapter_packet_subscription packet_sub;
    bool packet_subscribed;

    pthread_mutex_t send_lock;
    struct timespec last_send;
};

static void nf_logf(struct td_adapter *adapter, td_log_level_t level, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

static void nf_logf(struct td_adapter *adapter, td_log_level_t level, const char *fmt, ...) {
    char buffer[256];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);

    if (adapter && adapter->env.log_fn) {
        adapter->env.log_fn(adapter->env.log_user_data, level, TD_NETFORWARD_LOG_COMPONENT, buffer);
    } else {
        td_log_writef(level, TD_NETFORWARD_LOG_COMPONENT, "%s", buffer);
    }
}

static int normalize_vlan(int vlan) {
    if (vlan >= 1 && vlan <= 4094) {
        return vlan;
    }
    return -1;
}

static const char *resolve_socket_path(char buf[108]) {
    const char *env_path = getenv("TD_NETFORWARD_SIDECAR_SOCK");
    const char *path = (env_path && env_path[0]) ? env_path : TD_NETFORWARD_DEFAULT_SOCKET;
    size_t len = strlen(path);
    if (len >= 108) {
        return NULL;
    }
    memcpy(buf, path, len + 1);
    return buf;
}

static ssize_t read_full(int fd, void *buf, size_t len) {
    uint8_t *p = buf;
    size_t off = 0;
    while (off < len) {
        ssize_t n = read(fd, p + off, len - off);
        if (n == 0) {
            return (ssize_t)off;
        }
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        off += (size_t)n;
    }
    return (ssize_t)off;
}

static bool query_iface_details(const char *iface,
                                int *kernel_ifindex_out,
                                uint8_t mac_out[ETH_ALEN],
                                struct in_addr *ip_out) {
    if (!iface || !iface[0]) {
        return false;
    }

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return false;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", iface);

    bool ok = true;

    if (ioctl(fd, SIOCGIFINDEX, &ifr) == 0) {
        if (kernel_ifindex_out) {
            *kernel_ifindex_out = ifr.ifr_ifindex;
        }
    } else {
        ok = false;
    }

    if (ok && ioctl(fd, SIOCGIFHWADDR, &ifr) == 0) {
        if (mac_out) {
            memcpy(mac_out, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
        }
    } else if (mac_out) {
        memset(mac_out, 0, ETH_ALEN);
    }

    if (ok && ioctl(fd, SIOCGIFADDR, &ifr) == 0) {
        if (ip_out) {
            *ip_out = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;
        }
    } else if (ip_out) {
        ip_out->s_addr = 0;
    }

    close(fd);
    return ok;
}

static bool all_zero_mac(const uint8_t mac[ETH_ALEN]) {
    for (size_t i = 0; i < ETH_ALEN; ++i) {
        if (mac[i] != 0) {
            return false;
        }
    }
    return true;
}

static td_adapter_result_t build_tx_frame(const struct td_adapter_arp_request *req,
                                          const char *tx_iface,
                                          int tx_ifindex,
                                          const uint8_t iface_mac[ETH_ALEN],
                                          const struct in_addr iface_ip,
                                          uint8_t *frame,
                                          size_t frame_capacity,
                                          size_t *frame_len_out) {
    if (!req || !tx_iface || !tx_iface[0] || !frame || !frame_len_out) {
        return TD_ADAPTER_ERR_INVALID_ARG;
    }

    if (frame_capacity < sizeof(struct ethhdr) + sizeof(struct ether_arp)) {
        return TD_ADAPTER_ERR_INVALID_ARG;
    }

    uint8_t sender_mac[ETH_ALEN];
    if (all_zero_mac(req->sender_mac)) {
        memcpy(sender_mac, iface_mac, ETH_ALEN);
    } else {
        memcpy(sender_mac, req->sender_mac, ETH_ALEN);
    }

    struct in_addr sender_ip = req->sender_ip;
    if (sender_ip.s_addr == 0) {
        sender_ip = iface_ip;
    }

    if (sender_ip.s_addr == 0) {
        return TD_ADAPTER_ERR_NOT_READY;
    }

    uint8_t target_mac[ETH_ALEN];
    if (all_zero_mac(req->target_mac)) {
        memset(target_mac, 0xFF, ETH_ALEN);
    } else {
        memcpy(target_mac, req->target_mac, ETH_ALEN);
    }

    struct ethhdr *eth = (struct ethhdr *)frame;
    memcpy(eth->h_dest, target_mac, ETH_ALEN);
    memcpy(eth->h_source, sender_mac, ETH_ALEN);
    eth->h_proto = htons(ETH_P_ARP);

    struct ether_arp *arp = (struct ether_arp *)(frame + sizeof(struct ethhdr));
    memset(arp, 0, sizeof(*arp));
    arp->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp->ea_hdr.ar_pro = htons(ETH_P_IP);
    arp->ea_hdr.ar_hln = ETH_ALEN;
    arp->ea_hdr.ar_pln = 4;
    arp->ea_hdr.ar_op = htons(ARPOP_REQUEST);
    memcpy(&arp->arp_sha, sender_mac, ETH_ALEN);
    memcpy(&arp->arp_spa, &sender_ip.s_addr, sizeof(arp->arp_spa));
    memcpy(&arp->arp_tha, target_mac, ETH_ALEN);
    memcpy(&arp->arp_tpa, &req->target_ip.s_addr, sizeof(arp->arp_tpa));

    *frame_len_out = sizeof(struct ethhdr) + sizeof(struct ether_arp);
    (void)tx_ifindex; /* tx_ifindex kept for clarity; ARP frame not tagged here */
    return TD_ADAPTER_OK;
}

static td_adapter_result_t connect_sidecar(struct td_adapter *adapter) {
    if (!adapter) {
        return TD_ADAPTER_ERR_INVALID_ARG;
    }

    if (!resolve_socket_path(adapter->sock_path)) {
        nf_logf(adapter, TD_LOG_ERROR, "sidecar socket path too long");
        return TD_ADAPTER_ERR_INVALID_ARG;
    }

    if (adapter->sock_fd >= 0) {
        close(adapter->sock_fd);
        adapter->sock_fd = -1;
    }

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        nf_logf(adapter, TD_LOG_ERROR, "socket(AF_UNIX) failed: %s", strerror(errno));
        return TD_ADAPTER_ERR_SYS;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", adapter->sock_path);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        nf_logf(adapter, TD_LOG_ERROR, "connect(%s) failed: %s", adapter->sock_path, strerror(errno));
        close(fd);
        return TD_ADAPTER_ERR_SYS;
    }

    adapter->sock_fd = fd;
    nf_logf(adapter, TD_LOG_INFO, "connected to sidecar socket %s", adapter->sock_path);
    return TD_ADAPTER_OK;
}

static void discard_bytes(int fd, size_t len) {
    uint8_t tmp[256];
    size_t remaining = len;
    while (remaining > 0) {
        size_t chunk = remaining < sizeof(tmp) ? remaining : sizeof(tmp);
        ssize_t n = read_full(fd, tmp, chunk);
        if (n <= 0) {
            break;
        }
        remaining -= (size_t)n;
    }
}

static void deliver_packet(struct td_adapter *adapter,
                           const uint8_t *frame,
                           size_t frame_len,
                           uint32_t ifindex,
                           int vlan_id) {
    if (!adapter || !frame || frame_len < sizeof(struct ethhdr)) {
        return;
    }

    struct ethhdr eth;
    memcpy(&eth, frame, sizeof(eth));

    uint16_t ether_type = ntohs(eth.h_proto);
    size_t offset = sizeof(struct ethhdr);

    if (ether_type == ETH_P_8021Q || ether_type == ETH_P_8021AD) {
        if (frame_len < offset + sizeof(struct vlan_header)) {
            return;
        }
        struct vlan_header vlan;
        memcpy(&vlan, frame + offset, sizeof(vlan));
        ether_type = ntohs(vlan.encapsulated_proto);
        offset += sizeof(vlan);
    }

    if (ether_type != ETH_P_ARP) {
        return;
    }

    size_t payload_len = frame_len > offset ? (frame_len - offset) : 0U;

    struct td_adapter_packet_subscription sub;
    bool subscribed = false;
    pthread_mutex_lock(&adapter->state_lock);
    if (adapter->packet_subscribed) {
        sub = adapter->packet_sub;
        subscribed = true;
    }
    pthread_mutex_unlock(&adapter->state_lock);

    if (!subscribed || !sub.callback) {
        return;
    }

    struct td_adapter_packet_view view;
    memset(&view, 0, sizeof(view));
    view.frame = frame;
    view.frame_len = frame_len;
    view.payload = frame + offset;
    view.payload_len = payload_len;
    view.ether_type = ether_type;
    view.vlan_id = normalize_vlan(vlan_id);
    clock_gettime(CLOCK_REALTIME, &view.ts);
    view.ifindex = ifindex;
    memcpy(view.src_mac, eth.h_source, ETH_ALEN);
    memcpy(view.dst_mac, eth.h_dest, ETH_ALEN);

    sub.callback(&view, sub.user_ctx);
}

static void *rx_thread_main(void *arg) {
    struct td_adapter *adapter = arg;
    uint8_t buffer[TD_NETFORWARD_MAX_FRAME + sizeof(struct sockaddr_vlan)];

    while (atomic_load(&adapter->running)) {
        if (adapter->sock_fd < 0) {
            if (connect_sidecar(adapter) != TD_ADAPTER_OK) {
                struct timespec ts = {.tv_sec = 0, .tv_nsec = 100 * 1000000L};
                nanosleep(&ts, NULL);
                continue;
            }
        }

        struct sockaddr_vlan header;
        ssize_t peeked = recv(adapter->sock_fd, &header, sizeof(header), MSG_PEEK);
        if (peeked == 0) {
            nf_logf(adapter, TD_LOG_WARN, "sidecar socket closed");
            close(adapter->sock_fd);
            adapter->sock_fd = -1;
            continue;
        }
        if (peeked < 0) {
            if (errno == EINTR || errno == EAGAIN) {
                continue;
            }
            nf_logf(adapter, TD_LOG_ERROR, "sidecar recv peek failed: %s", strerror(errno));
            close(adapter->sock_fd);
            adapter->sock_fd = -1;
            continue;
        }
        if ((size_t)peeked < sizeof(header)) {
            /* partial header; drain available bytes to realign */
            discard_bytes(adapter->sock_fd, (size_t)peeked);
            continue;
        }

        size_t frame_len = header.length;
        size_t total_len = sizeof(header) + frame_len;
        if (frame_len == 0 || frame_len > TD_NETFORWARD_MAX_FRAME || total_len > sizeof(buffer)) {
            nf_logf(adapter, TD_LOG_WARN, "dropping frame len=%zu (max %u)", frame_len, TD_NETFORWARD_MAX_FRAME);
            discard_bytes(adapter->sock_fd, total_len);
            continue;
        }

        ssize_t n = read_full(adapter->sock_fd, buffer, total_len);
        if (n <= 0) {
            nf_logf(adapter, TD_LOG_WARN, "sidecar read failed/closed");
            close(adapter->sock_fd);
            adapter->sock_fd = -1;
            continue;
        }
        if ((size_t)n < total_len) {
            nf_logf(adapter, TD_LOG_WARN, "short read: expected %zu got %zd", total_len, n);
            continue;
        }

        memcpy(&header, buffer, sizeof(header));
        const uint8_t *frame = buffer + sizeof(header);
        deliver_packet(adapter, frame, frame_len, header.port, header.vlanid);
    }

    nf_logf(adapter, TD_LOG_INFO, "RX thread stopping");
    return NULL;
}

static td_adapter_result_t ensure_rx_thread(struct td_adapter *adapter) {
    if (!adapter) {
        return TD_ADAPTER_ERR_INVALID_ARG;
    }
    if (adapter->rx_thread_started) {
        return TD_ADAPTER_OK;
    }
    int rc = pthread_create(&adapter->rx_thread, NULL, rx_thread_main, adapter);
    if (rc != 0) {
        nf_logf(adapter, TD_LOG_ERROR, "pthread_create failed: %s", strerror(rc));
        return TD_ADAPTER_ERR_SYS;
    }
    adapter->rx_thread_started = true;
    return TD_ADAPTER_OK;
}

static td_adapter_result_t nf_init(const struct td_adapter_config *cfg,
                                   const struct td_adapter_env *env,
                                   td_adapter_t **handle) {
    if (!handle) {
        return TD_ADAPTER_ERR_INVALID_ARG;
    }

    struct td_adapter *adapter = calloc(1, sizeof(*adapter));
    if (!adapter) {
        return TD_ADAPTER_ERR_NO_MEMORY;
    }

    adapter->cfg = cfg ? *cfg : (struct td_adapter_config){0};
    if (env) {
        adapter->env = *env;
    }
    adapter->sock_fd = -1;
    pthread_mutex_init(&adapter->state_lock, NULL);
    pthread_mutex_init(&adapter->send_lock, NULL);
    atomic_store(&adapter->running, false);

    *handle = adapter;
    nf_logf(adapter, TD_LOG_INFO, "netforward adapter initialized");
    return TD_ADAPTER_OK;
}

static void nf_shutdown(td_adapter_t *handle) {
    if (!handle) {
        return;
    }
    struct td_adapter *adapter = handle;
    nf_logf(adapter, TD_LOG_INFO, "netforward adapter shutdown");
    free(adapter);
}

static td_adapter_result_t nf_start(td_adapter_t *handle) {
    if (!handle) {
        return TD_ADAPTER_ERR_INVALID_ARG;
    }
    struct td_adapter *adapter = handle;
    if (atomic_load(&adapter->running)) {
        return TD_ADAPTER_ERR_ALREADY;
    }

    atomic_store(&adapter->running, true);
    td_adapter_result_t rc = ensure_rx_thread(adapter);
    if (rc != TD_ADAPTER_OK) {
        atomic_store(&adapter->running, false);
        return rc;
    }
    return TD_ADAPTER_OK;
}

static void nf_stop(td_adapter_t *handle) {
    if (!handle) {
        return;
    }
    struct td_adapter *adapter = handle;
    atomic_store(&adapter->running, false);
    if (adapter->rx_thread_started) {
        pthread_join(adapter->rx_thread, NULL);
        adapter->rx_thread_started = false;
    }
    if (adapter->sock_fd >= 0) {
        close(adapter->sock_fd);
        adapter->sock_fd = -1;
    }
    nf_logf(adapter, TD_LOG_INFO, "netforward adapter stopped");
}

static td_adapter_result_t nf_register_packet_rx(td_adapter_t *handle,
                                                 const struct td_adapter_packet_subscription *sub) {
    if (!handle || !sub || !sub->callback) {
        return TD_ADAPTER_ERR_INVALID_ARG;
    }
    struct td_adapter *adapter = handle;
    pthread_mutex_lock(&adapter->state_lock);
    adapter->packet_sub = *sub;
    adapter->packet_subscribed = true;
    pthread_mutex_unlock(&adapter->state_lock);

    if (atomic_load(&adapter->running)) {
        return ensure_rx_thread(adapter);
    }
    return TD_ADAPTER_OK;
}

static td_adapter_result_t nf_send_arp(td_adapter_t *handle,
                                       const struct td_adapter_arp_request *req) {
    if (!handle || !req) {
        return TD_ADAPTER_ERR_INVALID_ARG;
    }

    struct td_adapter *adapter = handle;

    const char *tx_iface = NULL;
    int tx_ifindex = -1;
    uint8_t iface_mac[ETH_ALEN];
    struct in_addr iface_ip = {0};

    if (req->tx_iface_valid && req->tx_iface[0]) {
        tx_iface = req->tx_iface;
        tx_ifindex = req->tx_kernel_ifindex;
    } else if (req->vlan_id >= 1 && req->vlan_id <= 4094) {
        static char vlan_name[IFNAMSIZ];
        snprintf(vlan_name, sizeof(vlan_name), "Vlan%d", req->vlan_id);
        tx_iface = vlan_name;
    } else if (adapter->cfg.tx_iface && adapter->cfg.tx_iface[0]) {
        tx_iface = adapter->cfg.tx_iface;
    }

    if (!tx_iface || !tx_iface[0]) {
        return TD_ADAPTER_ERR_INVALID_ARG;
    }

    if (!query_iface_details(tx_iface, &tx_ifindex, iface_mac, &iface_ip)) {
        nf_logf(adapter, TD_LOG_WARN, "query_iface_details(%s) failed", tx_iface);
        return TD_ADAPTER_ERR_NOT_READY;
    }

    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (fd < 0) {
        nf_logf(adapter, TD_LOG_WARN, "socket(AF_PACKET) failed: %s", strerror(errno));
        return TD_ADAPTER_ERR_SYS;
    }

    pthread_mutex_lock(&adapter->send_lock);
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    if (adapter->cfg.tx_interval_ms > 0 && adapter->last_send.tv_sec != 0) {
        long diff_ms = (now.tv_sec - adapter->last_send.tv_sec) * 1000L;
        diff_ms += (now.tv_nsec - adapter->last_send.tv_nsec) / 1000000L;
        if (diff_ms < (long)adapter->cfg.tx_interval_ms) {
            long sleep_ms = (long)adapter->cfg.tx_interval_ms - diff_ms;
            if (sleep_ms > 0) {
                struct timespec ts = {.tv_sec = sleep_ms / 1000, .tv_nsec = (sleep_ms % 1000) * 1000000L};
                nanosleep(&ts, NULL);
            }
        }
        clock_gettime(CLOCK_MONOTONIC, &now);
    }

    uint8_t frame[sizeof(struct ethhdr) + sizeof(struct ether_arp)];
    size_t frame_len = 0;
    td_adapter_result_t rc = build_tx_frame(req, tx_iface, tx_ifindex, iface_mac, iface_ip, frame, sizeof(frame), &frame_len);
    if (rc != TD_ADAPTER_OK) {
        pthread_mutex_unlock(&adapter->send_lock);
        close(fd);
        return rc;
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = tx_ifindex;
    sll.sll_halen = ETH_ALEN;
    memcpy(sll.sll_addr, frame, ETH_ALEN);

    ssize_t sent = sendto(fd, frame, frame_len, 0, (struct sockaddr *)&sll, sizeof(sll));
    if (sent < 0 || (size_t)sent != frame_len) {
        nf_logf(adapter, TD_LOG_WARN, "sendto(%s) failed: %s", tx_iface, strerror(errno));
        rc = TD_ADAPTER_ERR_SYS;
    } else {
        adapter->last_send = now;
    }

    pthread_mutex_unlock(&adapter->send_lock);
    close(fd);
    return rc;
}

static td_adapter_result_t nf_query_iface(td_adapter_t *handle,
                                          const char *ifname,
                                          struct td_adapter_iface_info *info_out) {
    if (!handle || !ifname || !info_out) {
        return TD_ADAPTER_ERR_INVALID_ARG;
    }

    memset(info_out, 0, sizeof(*info_out));
    int ifindex = -1;
    struct in_addr ip = {0};
    if (!query_iface_details(ifname, &ifindex, info_out->mac, &ip)) {
        return TD_ADAPTER_ERR_NOT_FOUND;
    }
    snprintf(info_out->ifname, sizeof(info_out->ifname), "%s", ifname);
    info_out->ipv4 = ip;
    info_out->flags = 0;
    return TD_ADAPTER_OK;
}

static void nf_log_write(td_adapter_t *handle,
                         td_log_level_t level,
                         const char *component,
                         const char *message) {
    struct td_adapter *adapter = handle;
    if (!adapter || !component || !message) {
        return;
    }
    if (adapter->env.log_fn) {
        adapter->env.log_fn(adapter->env.log_user_data, level, component, message);
    } else {
        td_log_writef(level, component, "%s", message);
    }
}

static const struct td_adapter_ops g_netforward_ops = {
    .init = nf_init,
    .shutdown = nf_shutdown,
    .start = nf_start,
    .stop = nf_stop,
    .register_packet_rx = nf_register_packet_rx,
    .send_arp = nf_send_arp,
    .query_iface = nf_query_iface,
    .log_write = nf_log_write,
    .mac_locator_ops = NULL,
};

const struct td_adapter_descriptor *td_netforward_adapter_descriptor(void) {
    static const struct td_adapter_descriptor desc = {
        .name = "netforward",
        .ops = &g_netforward_ops,
    };
    return &desc;
}