#ifndef TD_LOGGING_H
#define TD_LOGGING_H

#include <stdbool.h>
#include <stddef.h>

#include "adapter_api.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*td_log_sink_fn)(void *ctx,
                               td_log_level_t level,
                               const char *component,
                               const char *message);

void td_log_set_level(td_log_level_t level);

td_log_level_t td_log_get_level(void);

void td_log_set_sink(td_log_sink_fn sink, void *ctx);

td_log_sink_fn td_log_get_sink(void **ctx_out);

void td_log_writef(td_log_level_t level,
                   const char *component,
                   const char *fmt,
                   ...)
    __attribute__((format(printf, 3, 4)));

void td_log_writef_force(td_log_level_t level,
                         const char *component,
                         const char *fmt,
                         ...)
    __attribute__((format(printf, 3, 4)));

const char *td_log_level_to_string(td_log_level_t level);

td_log_level_t td_log_level_from_string(const char *text,
                                         bool *ok_out);

#ifdef __cplusplus
}
#endif

#endif /* TD_LOGGING_H */
