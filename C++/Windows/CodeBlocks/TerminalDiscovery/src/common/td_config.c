#include "td_config.h"

#include <errno.h>
#include <string.h>
#include <stdio.h>

#include "terminal_manager.h"

#include "td_logging.h"

#ifndef TD_DEFAULT_ADAPTER
#define TD_DEFAULT_ADAPTER "realtek"
#endif
#define TD_DEFAULT_RX_IFACE "eth0"
#define TD_DEFAULT_TX_IFACE "eth0"
#define TD_DEFAULT_TX_INTERVAL_MS 100U

int td_config_load_defaults(struct td_runtime_config *cfg) {
    if (!cfg) {
        return -1;
    }

    memset(cfg, 0, sizeof(*cfg));

    snprintf(cfg->adapter_name, sizeof(cfg->adapter_name), "%s", TD_DEFAULT_ADAPTER);
    snprintf(cfg->rx_iface, sizeof(cfg->rx_iface), "%s", TD_DEFAULT_RX_IFACE);
    snprintf(cfg->tx_iface, sizeof(cfg->tx_iface), "%s", TD_DEFAULT_TX_IFACE);
    cfg->tx_interval_ms = TD_DEFAULT_TX_INTERVAL_MS;
    cfg->keepalive_interval_sec = TD_DEFAULT_KEEPALIVE_INTERVAL_SEC;
    cfg->keepalive_miss_threshold = TD_DEFAULT_KEEPALIVE_MISS_THRESHOLD;
    cfg->iface_invalid_holdoff_sec = TD_DEFAULT_IFACE_INVALID_HOLDOFF_SEC;
    cfg->max_terminals = TD_DEFAULT_MAX_TERMINALS;
    cfg->stats_log_interval_sec = TD_DEFAULT_STATS_LOG_INTERVAL_SEC;
    cfg->log_level = TD_LOG_INFO;

    return 0;
}

int td_config_to_manager_config(const struct td_runtime_config *runtime,
                                struct terminal_manager_config *out) {
    if (!runtime || !out) {
        return -1;
    }

    memset(out, 0, sizeof(*out));
    out->keepalive_interval_sec = runtime->keepalive_interval_sec;
    out->keepalive_miss_threshold = runtime->keepalive_miss_threshold;
    out->iface_invalid_holdoff_sec = runtime->iface_invalid_holdoff_sec;
    out->scan_interval_ms = 0U;
    out->vlan_iface_format = NULL;
    out->max_terminals = runtime->max_terminals;

    if (runtime->ignored_vlan_count > TD_MAX_IGNORED_VLANS) {
        return -1;
    }

    for (size_t i = 0; i < runtime->ignored_vlan_count; ++i) {
        uint16_t vlan = runtime->ignored_vlans[i];
        if (vlan == 0 || vlan > 4094U) {
            return -1;
        }
    }

    out->ignored_vlan_count = runtime->ignored_vlan_count;
    if (runtime->ignored_vlan_count > 0) {
        memcpy(out->ignored_vlans,
               runtime->ignored_vlans,
               runtime->ignored_vlan_count * sizeof(out->ignored_vlans[0]));
    }

    return 0;
}

int td_config_add_ignored_vlan(struct td_runtime_config *cfg, unsigned int vlan_id) {
    if (!cfg) {
        return -EINVAL;
    }
    if (vlan_id == 0 || vlan_id > 4094U) {
        return -ERANGE;
    }

    for (size_t i = 0; i < cfg->ignored_vlan_count; ++i) {
        if (cfg->ignored_vlans[i] == vlan_id) {
            return 0;
        }
    }

    if (cfg->ignored_vlan_count >= TD_MAX_IGNORED_VLANS) {
        return -ENOSPC;
    }

    cfg->ignored_vlans[cfg->ignored_vlan_count++] = (uint16_t)vlan_id;
    return 0;
}

int td_config_remove_ignored_vlan(struct td_runtime_config *cfg, unsigned int vlan_id) {
    if (!cfg) {
        return -EINVAL;
    }
    if (vlan_id == 0 || vlan_id > 4094U) {
        return -ERANGE;
    }

    for (size_t i = 0; i < cfg->ignored_vlan_count; ++i) {
        if (cfg->ignored_vlans[i] == vlan_id) {
            size_t remaining = cfg->ignored_vlan_count - i - 1;
            if (remaining > 0) {
                memmove(&cfg->ignored_vlans[i],
                        &cfg->ignored_vlans[i + 1],
                        remaining * sizeof(cfg->ignored_vlans[0]));
            }
            cfg->ignored_vlan_count -= 1;
            cfg->ignored_vlans[cfg->ignored_vlan_count] = 0U;
            return 0;
        }
    }

    return -ENOENT;
}

void td_config_clear_ignored_vlans(struct td_runtime_config *cfg) {
    if (!cfg) {
        return;
    }

    if (cfg->ignored_vlan_count > 0) {
        memset(cfg->ignored_vlans, 0, sizeof(cfg->ignored_vlans));
        cfg->ignored_vlan_count = 0;
    }
}
