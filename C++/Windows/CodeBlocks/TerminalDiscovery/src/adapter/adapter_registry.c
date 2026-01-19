#include "td_adapter_registry.h"

#include <stdbool.h>
#include <string.h>

#ifdef TD_ENABLE_ADAPTER_REALTEK
#include "realtek_adapter.h"
#endif
#ifdef TD_ENABLE_ADAPTER_NETFORWARD
#include "netforward_adapter_stub.h"
#endif

static const struct td_adapter_descriptor *g_adapters[2];
static size_t g_adapter_count = 0;
static bool g_initialized = false;

static void ensure_initialized(void) {
    if (g_initialized) {
        return;
    }

#ifdef TD_ENABLE_ADAPTER_REALTEK
    g_adapters[g_adapter_count++] = td_realtek_adapter_descriptor();
#endif
#ifdef TD_ENABLE_ADAPTER_NETFORWARD
    g_adapters[g_adapter_count++] = td_netforward_adapter_descriptor();
#endif

    g_initialized = true;
}

const struct td_adapter_descriptor *td_adapter_registry_find(const char *name) {
    ensure_initialized();
    if (!name) {
        return NULL;
    }

    for (size_t i = 0; i < g_adapter_count; ++i) {
        const struct td_adapter_descriptor *desc = g_adapters[i];
        if (desc && desc->name && strcmp(desc->name, name) == 0) {
            return desc;
        }
    }
    return NULL;
}

const struct td_adapter_descriptor *td_adapter_registry_get(size_t index) {
    ensure_initialized();
    if (index >= g_adapter_count) {
        return NULL;
    }
    return g_adapters[index];
}

size_t td_adapter_registry_count(void) {
    ensure_initialized();
    return g_adapter_count;
}
