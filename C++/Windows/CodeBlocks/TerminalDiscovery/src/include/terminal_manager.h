#ifndef TERMINAL_MANAGER_H
#define TERMINAL_MANAGER_H

#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#include "adapter_api.h"

#ifndef TD_MAX_IGNORED_VLANS
#define TD_MAX_IGNORED_VLANS 32U
#endif

#ifndef TD_PENDING_VLAN_DEBUG
#define TD_PENDING_VLAN_DEBUG 1
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    TERMINAL_STATE_ACTIVE = 0,
    TERMINAL_STATE_PROBING,
    TERMINAL_STATE_IFACE_INVALID,
} terminal_state_t;

struct terminal_key {
    uint8_t mac[ETH_ALEN];
    struct in_addr ip;
};

struct terminal_metadata {
    int vlan_id;            /* -1 if unknown */
    uint32_t ifindex;       /* 0 when unavailable; logical port identifier (not tx_kernel_ifindex) */
    uint64_t mac_view_version; /* 0 when unresolved; snapshot version for last bridge lookup */
};

struct terminal_entry {
    struct terminal_key key;
    terminal_state_t state;
    struct timespec last_seen;
    struct timespec last_probe;
    uint32_t failed_probes;
    struct terminal_metadata meta;
    char tx_iface[IFNAMSIZ];
    int tx_kernel_ifindex;
    struct in_addr tx_source_ip;
    int pending_vlan_id;
    int vid_lookup_vlan;
    bool mac_refresh_enqueued;
    bool mac_verify_enqueued;
    bool vid_lookup_attempted;
    struct terminal_entry *next;
};

typedef struct terminal_probe_request {
    struct terminal_key key;
    char tx_iface[IFNAMSIZ];
    int tx_kernel_ifindex;
    struct in_addr source_ip;
    int vlan_id;
    terminal_state_t state_before_probe;
} terminal_probe_request_t;

typedef void (*terminal_probe_fn)(const terminal_probe_request_t *request, void *user_ctx);

typedef struct terminal_snapshot {
    struct terminal_key key;
    struct terminal_metadata meta;
} terminal_snapshot_t;

typedef enum {
    TERMINAL_EVENT_TAG_DEL = 0,
    TERMINAL_EVENT_TAG_ADD,
    TERMINAL_EVENT_TAG_MOD,
} terminal_event_tag_t;

typedef struct terminal_event_record {
    struct terminal_key key;
    uint32_t ifindex; /* 0 when unknown; logical port identifier */
    uint32_t prev_ifindex; /* 0 when unavailable; previous logical port for MOD events */
    terminal_event_tag_t tag;
} terminal_event_record_t;

typedef void (*terminal_event_callback_fn)(const terminal_event_record_t *records,
                                           size_t count,
                                           void *user_ctx);

typedef bool (*terminal_query_callback_fn)(const terminal_event_record_t *record, void *user_ctx);

struct terminal_manager_stats {
    uint64_t terminals_discovered;
    uint64_t terminals_removed;
    uint64_t capacity_drops;
    uint64_t probes_scheduled;
    uint64_t probe_failures;
    uint64_t address_update_events;
    uint64_t events_dispatched;
    uint64_t event_dispatch_failures;
    uint64_t current_terminals;
};

typedef void (*td_debug_writer_t)(void *ctx, const char *line);

typedef struct td_debug_dump_opts {
    bool filter_by_state;
    terminal_state_t state;
    bool filter_by_vlan;
    int vlan_id;
    bool filter_by_ifindex;
    uint32_t ifindex;
    bool filter_by_mac_prefix;
    uint8_t mac_prefix[ETH_ALEN];
    size_t mac_prefix_len;
    bool verbose_metrics;
    bool expand_terminals;
    bool expand_pending_vlans;
} td_debug_dump_opts_t;

typedef struct td_debug_dump_context {
    const td_debug_dump_opts_t *opts;
    size_t lines_emitted;
    bool had_error;
} td_debug_dump_context_t;

static inline void td_debug_context_reset(td_debug_dump_context_t *ctx,
                                          const td_debug_dump_opts_t *opts) {
    if (!ctx) {
        return;
    }
    ctx->opts = opts;
    ctx->lines_emitted = 0U;
    ctx->had_error = false;
}

struct td_debug_file_writer_ctx {
    FILE *stream;
    td_debug_dump_context_t *debug_ctx;
};

static inline void td_debug_file_writer_ctx_init(struct td_debug_file_writer_ctx *ctx,
                                                 FILE *stream,
                                                 td_debug_dump_context_t *debug_ctx) {
    if (!ctx) {
        return;
    }
    ctx->stream = stream;
    ctx->debug_ctx = debug_ctx;
}

void td_debug_writer_file(void *ctx, const char *line);

struct terminal_manager;

typedef struct terminal_address_update {
    int kernel_ifindex;
    struct in_addr address;
    uint8_t prefix_len; /* 0-32 */
    bool is_add;        /* true = add/update, false = remove */
} terminal_address_update_t;

typedef int (*terminal_address_sync_fn)(void *ctx);

struct terminal_manager_config {
    unsigned int keepalive_interval_sec;
    unsigned int keepalive_miss_threshold;
    unsigned int iface_invalid_holdoff_sec;
    unsigned int scan_interval_ms;
    const char *vlan_iface_format; /* e.g. "vlan%u"; leave NULL to reuse ingress name */
    size_t max_terminals;
    uint16_t ignored_vlans[TD_MAX_IGNORED_VLANS];
    size_t ignored_vlan_count;
};

struct terminal_manager *terminal_manager_create(const struct terminal_manager_config *cfg,
                                                  td_adapter_t *adapter,
                                                  const struct td_adapter_ops *adapter_ops,
                                                  terminal_probe_fn probe_cb,
                                                  void *probe_ctx);

void terminal_manager_destroy(struct terminal_manager *mgr);

void terminal_manager_on_packet(struct terminal_manager *mgr,
                                const struct td_adapter_packet_view *packet);

void terminal_manager_on_timer(struct terminal_manager *mgr);

void terminal_manager_on_address_update(struct terminal_manager *mgr,
                                        const terminal_address_update_t *update);

void terminal_manager_set_address_sync_handler(struct terminal_manager *mgr,
                                               terminal_address_sync_fn handler,
                                               void *handler_ctx);

void terminal_manager_request_address_sync(struct terminal_manager *mgr);

int terminal_manager_set_event_sink(struct terminal_manager *mgr,
                                    terminal_event_callback_fn callback,
                                    void *callback_ctx);

int terminal_manager_query_all(struct terminal_manager *mgr,
                               terminal_query_callback_fn callback,
                               void *callback_ctx);

void terminal_manager_flush_events(struct terminal_manager *mgr);

struct terminal_manager *terminal_manager_get_active(void);

void terminal_manager_get_stats(struct terminal_manager *mgr,
                                struct terminal_manager_stats *out);

int terminal_manager_set_keepalive_interval(struct terminal_manager *mgr,
                                            unsigned int interval_sec);

int terminal_manager_set_keepalive_miss_threshold(struct terminal_manager *mgr,
                                                  unsigned int miss_threshold);

int terminal_manager_set_iface_invalid_holdoff(struct terminal_manager *mgr,
                                               unsigned int holdoff_sec);

int terminal_manager_set_max_terminals(struct terminal_manager *mgr,
                                       size_t max_terminals);

int terminal_manager_add_ignored_vlan(struct terminal_manager *mgr,
                                      uint16_t vlan_id);

int terminal_manager_remove_ignored_vlan(struct terminal_manager *mgr,
                                         uint16_t vlan_id);

void terminal_manager_clear_ignored_vlans(struct terminal_manager *mgr);

void terminal_manager_log_config(struct terminal_manager *mgr);

void terminal_manager_log_stats(struct terminal_manager *mgr);

int td_debug_dump_terminal_table(struct terminal_manager *mgr,
                                 const td_debug_dump_opts_t *opts,
                                 td_debug_writer_t writer,
                                 void *writer_ctx,
                                 td_debug_dump_context_t *ctx);

int td_debug_dump_iface_prefix_table(struct terminal_manager *mgr,
                                     td_debug_writer_t writer,
                                     void *writer_ctx,
                                     td_debug_dump_context_t *ctx);

int td_debug_dump_iface_binding_table(struct terminal_manager *mgr,
                                      const td_debug_dump_opts_t *opts,
                                      td_debug_writer_t writer,
                                      void *writer_ctx,
                                      td_debug_dump_context_t *ctx);

int td_debug_dump_mac_lookup_queue(struct terminal_manager *mgr,
                                   td_debug_writer_t writer,
                                   void *writer_ctx,
                                   td_debug_dump_context_t *ctx);

int td_debug_dump_pending_vlan_table(struct terminal_manager *mgr,
                                     const td_debug_dump_opts_t *opts,
                                     td_debug_writer_t writer,
                                     void *writer_ctx,
                                     td_debug_dump_context_t *ctx);

int td_debug_dump_mac_locator_state(struct terminal_manager *mgr,
                                    td_debug_writer_t writer,
                                    void *writer_ctx,
                                    td_debug_dump_context_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* TERMINAL_MANAGER_H */
