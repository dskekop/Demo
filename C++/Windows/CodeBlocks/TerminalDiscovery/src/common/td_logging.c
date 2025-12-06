#include "td_logging.h"

#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#ifndef TD_LOG_BUFFER_SIZE
#define TD_LOG_BUFFER_SIZE 512
#endif

static void default_sink(void *ctx, td_log_level_t level, const char *component, const char *message);

static pthread_mutex_t g_log_lock = PTHREAD_MUTEX_INITIALIZER;
static td_log_level_t g_log_level = TD_LOG_INFO;
static td_log_sink_fn g_log_sink = NULL;
static void *g_log_sink_ctx = NULL;

static void td_log_vwritef(td_log_level_t level,
                           const char *component,
                           const char *fmt,
                           va_list args) {
    char buffer[TD_LOG_BUFFER_SIZE];
    vsnprintf(buffer, sizeof(buffer), fmt, args);

    pthread_mutex_lock(&g_log_lock);
    td_log_sink_fn sink = g_log_sink ? g_log_sink : default_sink;
    void *ctx = g_log_sink_ctx;
    pthread_mutex_unlock(&g_log_lock);

    sink(ctx, level, component, buffer);
}

static void default_sink(void *ctx, td_log_level_t level, const char *component, const char *message) {
    (void)ctx;
    const char *level_str = td_log_level_to_string(level);

    char timestamp[20];
    timestamp[0] = '\0';

    time_t now = time(NULL);
    if (now != (time_t)-1) {
        struct tm tm_snapshot;
        struct tm *tm_result = NULL;
#if defined(_POSIX_VERSION)
        tm_result = localtime_r(&now, &tm_snapshot);
#else
        struct tm *non_thread_safe = localtime(&now);
        if (non_thread_safe != NULL) {
            tm_snapshot = *non_thread_safe;
            tm_result = &tm_snapshot;
        }
#endif
        if (tm_result != NULL) {
            if (strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_result) == 0) {
                timestamp[0] = '\0';
            }
        }
    }

    const char *ts_display = timestamp[0] != '\0' ? timestamp : "0000-00-00 00:00:00";
    fprintf(stderr,
            "%s [%s] %s: %s\n",
            ts_display,
            level_str ? level_str : "UNK",
            component ? component : "core",
            message);
}

void td_log_set_level(td_log_level_t level) {
    pthread_mutex_lock(&g_log_lock);
    g_log_level = level;
    pthread_mutex_unlock(&g_log_lock);
}

td_log_level_t td_log_get_level(void) {
    pthread_mutex_lock(&g_log_lock);
    td_log_level_t level = g_log_level;
    pthread_mutex_unlock(&g_log_lock);
    return level;
}

void td_log_set_sink(td_log_sink_fn sink, void *ctx) {
    pthread_mutex_lock(&g_log_lock);
    g_log_sink = sink;
    g_log_sink_ctx = ctx;
    pthread_mutex_unlock(&g_log_lock);
}

td_log_sink_fn td_log_get_sink(void **ctx_out) {
    pthread_mutex_lock(&g_log_lock);
    td_log_sink_fn sink = g_log_sink;
    if (ctx_out) {
        *ctx_out = g_log_sink_ctx;
    }
    pthread_mutex_unlock(&g_log_lock);
    return sink;
}

void td_log_writef(td_log_level_t level, const char *component, const char *fmt, ...) {
    if (level < td_log_get_level()) {
        return;
    }

    va_list args;
    va_start(args, fmt);
    td_log_vwritef(level, component, fmt, args);
    va_end(args);
}

void td_log_writef_force(td_log_level_t level, const char *component, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    td_log_vwritef(level, component, fmt, args);
    va_end(args);
}

const char *td_log_level_to_string(td_log_level_t level) {
    switch (level) {
    case TD_LOG_TRACE:
        return "TRACE";
    case TD_LOG_DEBUG:
        return "DEBUG";
    case TD_LOG_INFO:
        return "INFO";
    case TD_LOG_WARN:
        return "WARN";
    case TD_LOG_ERROR:
        return "ERROR";
    case TD_LOG_NONE:
        return "NONE";
    default:
        return "UNKNOWN";
    }
}

td_log_level_t td_log_level_from_string(const char *text, bool *ok_out) {
    if (!text) {
        if (ok_out) {
            *ok_out = false;
        }
        return TD_LOG_INFO;
    }

    if (ok_out) {
        *ok_out = true;
    }

    if (strcasecmp(text, "trace") == 0) {
        return TD_LOG_TRACE;
    }
    if (strcasecmp(text, "debug") == 0) {
        return TD_LOG_DEBUG;
    }
    if (strcasecmp(text, "info") == 0) {
        return TD_LOG_INFO;
    }
    if (strcasecmp(text, "warn") == 0 || strcasecmp(text, "warning") == 0) {
        return TD_LOG_WARN;
    }
    if (strcasecmp(text, "error") == 0) {
        return TD_LOG_ERROR;
    }
    if (strcasecmp(text, "none") == 0 || strcasecmp(text, "off") == 0) {
        return TD_LOG_NONE;
    }

    if (ok_out) {
        *ok_out = false;
    }
    return TD_LOG_INFO;
}
