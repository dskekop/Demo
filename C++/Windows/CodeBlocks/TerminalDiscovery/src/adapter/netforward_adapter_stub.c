#include "netforward_adapter_stub.h"

#include <stdlib.h>
#include <string.h>

struct td_adapter {
    struct td_adapter_env env;
};

static void stub_log(struct td_adapter *handle,
                     td_log_level_t level,
                     const char *component,
                     const char *message) {
    if (!handle || !handle->env.log_fn) {
        return;
    }
    handle->env.log_fn(handle->env.log_user_data, level, component, message);
}

static td_adapter_result_t nf_init(const struct td_adapter_config *cfg,
                                   const struct td_adapter_env *env,
                                   td_adapter_t **handle) {
    (void)cfg;
    if (!handle) {
        return TD_ADAPTER_ERR_INVALID_ARG;
    }

    struct td_adapter *adapter = calloc(1, sizeof(*adapter));
    if (!adapter) {
        return TD_ADAPTER_ERR_NO_MEMORY;
    }
    if (env) {
        adapter->env = *env;
    }
    stub_log(adapter, TD_LOG_WARN, "netforward", "netforward adapter stub initialized; functionality not implemented");
    *handle = adapter;
    return TD_ADAPTER_OK;
}

static void nf_shutdown(td_adapter_t *handle) {
    free(handle);
}

static td_adapter_result_t nf_start(td_adapter_t *handle) {
    stub_log(handle, TD_LOG_INFO, "netforward", "netforward adapter stub start");
    return TD_ADAPTER_OK;
}

static void nf_stop(td_adapter_t *handle) {
    stub_log(handle, TD_LOG_INFO, "netforward", "netforward adapter stub stop");
}

static td_adapter_result_t nf_register_packet_rx(td_adapter_t *handle,
                                                 const struct td_adapter_packet_subscription *sub) {
    (void)handle;
    (void)sub;
    return TD_ADAPTER_ERR_UNSUPPORTED;
}

static td_adapter_result_t nf_send_arp(td_adapter_t *handle,
                                       const struct td_adapter_arp_request *req) {
    (void)handle;
    (void)req;
    return TD_ADAPTER_ERR_UNSUPPORTED;
}

static td_adapter_result_t nf_query_iface(td_adapter_t *handle,
                                          const char *ifname,
                                          struct td_adapter_iface_info *info_out) {
    (void)handle;
    (void)ifname;
    if (info_out) {
        memset(info_out, 0, sizeof(*info_out));
    }
    return TD_ADAPTER_ERR_UNSUPPORTED;
}

static void nf_log_write(td_adapter_t *handle,
                         td_log_level_t level,
                         const char *component,
                         const char *message) {
    stub_log(handle, level, component, message);
}

static td_adapter_result_t nf_lookup(td_adapter_t *handle,
                                     const uint8_t mac[ETH_ALEN],
                                     uint16_t vlan_id,
                                     uint32_t *ifindex_out,
                                     uint64_t *version_out) {
    (void)handle;
    (void)mac;
    (void)vlan_id;
    if (ifindex_out) {
        *ifindex_out = 0;
    }
    if (version_out) {
        *version_out = 0;
    }
    return TD_ADAPTER_ERR_UNSUPPORTED;
}

static td_adapter_result_t nf_lookup_by_vid(td_adapter_t *handle,
                                            const uint8_t mac[ETH_ALEN],
                                            uint16_t vlan_id,
                                            uint32_t *ifindex_out) {
    (void)handle;
    (void)mac;
    (void)vlan_id;
    if (ifindex_out) {
        *ifindex_out = 0;
    }
    return TD_ADAPTER_ERR_UNSUPPORTED;
}

static td_adapter_result_t nf_subscribe(td_adapter_t *handle,
                                        td_adapter_mac_locator_refresh_cb cb,
                                        void *ctx) {
    (void)handle;
    (void)cb;
    (void)ctx;
    return TD_ADAPTER_ERR_UNSUPPORTED;
}

static td_adapter_result_t nf_get_version(td_adapter_t *handle, uint64_t *version_out) {
    (void)handle;
    if (version_out) {
        *version_out = 0;
    }
    return TD_ADAPTER_ERR_UNSUPPORTED;
}

static const struct td_adapter_mac_locator_ops g_mac_locator_ops = {
    .lookup = nf_lookup,
    .lookup_by_vid = nf_lookup_by_vid,
    .subscribe = nf_subscribe,
    .get_version = nf_get_version,
};

static const struct td_adapter_ops g_netforward_ops = {
    .init = nf_init,
    .shutdown = nf_shutdown,
    .start = nf_start,
    .stop = nf_stop,
    .register_packet_rx = nf_register_packet_rx,
    .send_arp = nf_send_arp,
    .query_iface = nf_query_iface,
    .log_write = nf_log_write,
    .mac_locator_ops = &g_mac_locator_ops,
};

const struct td_adapter_descriptor *td_netforward_adapter_descriptor(void) {
    static const struct td_adapter_descriptor desc = {
        .name = "netforward",
        .ops = &g_netforward_ops,
    };
    return &desc;
}
