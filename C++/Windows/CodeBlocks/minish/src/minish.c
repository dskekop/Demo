#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <ctype.h>
#include <dirent.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <limits.h>
#include <time.h>

#include "linenoise.h"

/* 获取当前终端路径 */
static const char* get_tty_name() {
    static char buf[PATH_MAX];

    char *p = ttyname(STDIN_FILENO);
    if (p) return p;

    ssize_t n = readlink("/proc/self/fd/0", buf, sizeof(buf)-1);
    if (n > 0) {
        buf[n] = 0;
        return buf;
    }
    return "unknown";
}

static char *trim_inplace(char *s) {
    if (!s) return s;

    char *start = s;
    while (*start && isspace((unsigned char)*start)) start++;
    if (start != s)
        memmove(s, start, strlen(start) + 1);

    char *end = s + strlen(s);
    while (end > s && isspace((unsigned char)end[-1]))
        *--end = '\0';

    return s;
}

struct strlist {
    char **items;
    size_t len;
    size_t cap;
};

static void strlist_clear(struct strlist *list) {
    if (!list) return;
    for (size_t i = 0; i < list->len; ++i)
        free(list->items[i]);
    free(list->items);
    list->items = NULL;
    list->len = list->cap = 0;
}

static bool strlist_contains(const struct strlist *list, const char *value) {
    if (!list || !value) return false;
    for (size_t i = 0; i < list->len; ++i)
        if (!strcmp(list->items[i], value))
            return true;
    return false;
}

static int strlist_append(struct strlist *list, const char *value) {
    if (!list || !value) return -1;
    if (strlist_contains(list, value))
        return 0;

    if (list->len == list->cap) {
        size_t newcap = list->cap ? list->cap * 2 : 64;
        char **tmp = realloc(list->items, newcap * sizeof(*tmp));
        if (!tmp)
            return -1;
        list->items = tmp;
        list->cap = newcap;
    }

    list->items[list->len] = strdup(value);
    if (!list->items[list->len])
        return -1;
    list->len++;
    return 0;
}

struct completion_cache {
    char *path_snapshot;
    time_t refreshed_at;
    struct strlist names;
};

static struct completion_cache g_cache;

static void free_cache(void) {
    strlist_clear(&g_cache.names);
    free(g_cache.path_snapshot);
    g_cache.path_snapshot = NULL;
    g_cache.refreshed_at = 0;
}

static void scan_dir_for_exec(const char *dir) {
    DIR *dp = opendir(dir);
    if (!dp) return;

    struct dirent *de;
    while ((de = readdir(dp))) {
        const char *name = de->d_name;
        if (!strcmp(name, ".") || !strcmp(name, ".."))
            continue;

        char pathbuf[PATH_MAX];
        if (snprintf(pathbuf, sizeof(pathbuf), "%s/%s", dir, name) >= (int)sizeof(pathbuf))
            continue;

        if (access(pathbuf, X_OK) == 0)
            strlist_append(&g_cache.names, name);
    }

    closedir(dp);
}

static void refresh_path_cache(void) {
    const time_t now = time(NULL);
    const char *path_env = getenv("PATH");
    if (!path_env)
        path_env = "";

    if (g_cache.path_snapshot && !strcmp(g_cache.path_snapshot, path_env)) {
        if (now - g_cache.refreshed_at < 1)
            return;
    }

    free_cache();

    char *path_copy = strdup(path_env);
    if (!path_copy)
        return;

    char *saveptr = NULL;
    for (char *dir = strtok_r(path_copy, ":", &saveptr);
         dir;
         dir = strtok_r(NULL, ":", &saveptr)) {
        if (*dir == '\0')
            dir = ".";
        scan_dir_for_exec(dir);
    }

    free(path_copy);
    g_cache.path_snapshot = strdup(path_env);
    g_cache.refreshed_at = now;
}

static void add_completion_line(const char *buf,
                                size_t token_start,
                                const char *replacement,
                                linenoiseCompletions *lc) {
    size_t prefix_len = token_start;
    size_t repl_len = strlen(replacement);
    char *line = malloc(prefix_len + repl_len + 1);
    if (!line)
        return;

    memcpy(line, buf, prefix_len);
    memcpy(line + prefix_len, replacement, repl_len + 1);
    linenoiseAddCompletion(lc, line);
    free(line);
}

static void complete_command_token(const char *buf,
                                   size_t token_start,
                                   const char *token,
                                   linenoiseCompletions *lc) {
    static const char *builtins[] = {"exit", "quit", NULL};
    size_t token_len = strlen(token);

    for (size_t i = 0; builtins[i]; ++i) {
        if (token_len == 0 || strncmp(builtins[i], token, token_len) == 0)
            add_completion_line(buf, token_start, builtins[i], lc);
    }

    refresh_path_cache();
    for (size_t i = 0; i < g_cache.names.len; ++i) {
        const char *name = g_cache.names.items[i];
        if (token_len == 0 || strncmp(name, token, token_len) == 0)
            add_completion_line(buf, token_start, name, lc);
    }
}

static bool is_dir(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0)
        return false;
    return S_ISDIR(st.st_mode);
}

static void complete_path_token(const char *buf,
                                size_t token_start,
                                const char *token,
                                linenoiseCompletions *lc) {
    const char *slash = strrchr(token, '/');
    char dirprefix[PATH_MAX];
    char dirpath[PATH_MAX];
    const char *partial = token;

    if (slash) {
        size_t prefix_len = (size_t)(slash - token + 1);
        if (prefix_len >= sizeof(dirprefix))
            return;
        memcpy(dirprefix, token, prefix_len);
        dirprefix[prefix_len] = '\0';

        size_t dir_len = (size_t)(slash - token);
        if (dir_len == 0) {
            strcpy(dirpath, "/");
        } else if (dir_len < sizeof(dirpath)) {
            memcpy(dirpath, token, dir_len);
            dirpath[dir_len] = '\0';
        } else {
            return;
        }

        partial = slash + 1;
    } else {
        dirprefix[0] = '\0';
        strcpy(dirpath, ".");
    }

    DIR *dp = opendir(dirpath);
    if (!dp)
        return;

    struct dirent *de;
    const size_t partial_len = strlen(partial);
    while ((de = readdir(dp))) {
        const char *name = de->d_name;
        if (!strcmp(name, ".") || !strcmp(name, ".."))
            continue;
        if (partial_len && strncmp(name, partial, partial_len) != 0)
            continue;

        char candidate[PATH_MAX];
        size_t prefix_len = strlen(dirprefix);
        size_t name_len = strlen(name);
        if (prefix_len + name_len + 2 > sizeof(candidate))
            continue;

        if (prefix_len) {
            memcpy(candidate, dirprefix, prefix_len);
            memcpy(candidate + prefix_len, name, name_len + 1);
        } else {
            memcpy(candidate, name, name_len + 1);
        }

        char fullpath[PATH_MAX];
        if (snprintf(fullpath, sizeof(fullpath), "%s/%s", dirpath, name) >= (int)sizeof(fullpath))
            continue;
        if (is_dir(fullpath)) {
            size_t clen = strlen(candidate);
            if (clen + 1 < sizeof(candidate)) {
                candidate[clen] = '/';
                candidate[clen + 1] = '\0';
            }
        }

        add_completion_line(buf, token_start, candidate, lc);
    }

    closedir(dp);
}

static void completion_cb(const char *buf, linenoiseCompletions *lc) {
    size_t len = strlen(buf);
    size_t token_start = len;
    while (token_start > 0) {
        unsigned char c = (unsigned char)buf[token_start - 1];
        if (c == ' ' || c == '\t')
            break;
        token_start--;
    }

    const char *token = buf + token_start;
    if (strchr(token, '/'))
        complete_path_token(buf, token_start, token, lc);
    else
        complete_command_token(buf, token_start, token, lc);
}

static void save_history(const char *cmd) {
    if (cmd && *cmd)
        linenoiseHistoryAdd(cmd);
}

static void load_history(void) {
    linenoiseHistorySetMaxLen(128);
}

int main(void) {
    /* 父进程忽略 SIGINT，避免 Ctrl-C 杀死 mini-shell */
    signal(SIGINT, SIG_IGN);
    signal(SIGQUIT, SIG_IGN);

        /* 启动时打印一次关键信息 */
        printf("mini-shell ready: PID=%d PGID=%d SID=%d TTY=%s\n\n",
            getpid(), getpgrp(), getsid(0), get_tty_name());

    linenoiseSetCompletionCallback(completion_cb);
    load_history();
    atexit(free_cache);

    const char *prompt = "mini$ ";
    for (;;) {
        errno = 0;
        char *line = linenoise(prompt);
        if (!line) {
            if (errno == EAGAIN) {
                putchar('\n');
                continue;
            }
            putchar('\n');
            break;
        }

        char *cmd = trim_inplace(line);
        if (*cmd == '\0') {
            free(line);
            continue;
        }

        if (!strcmp(cmd, "exit") || !strcmp(cmd, "quit")) {
            save_history(cmd);
            free(line);
            break;
        }

        pid_t pid = fork();
        if (pid < 0) {
            perror("fork");
            free(line);
            continue;
        }

        if (pid == 0) {
            /* 子进程恢复默认信号行为：能被 Ctrl-C 杀死 */
            signal(SIGINT, SIG_DFL);
            signal(SIGQUIT, SIG_DFL);

            execlp("/bin/sh", "sh", "-c", cmd, (char*)NULL);
            perror("exec");
            _exit(127);
        }

        /* 父等待子 */
        int st;
        waitpid(pid, &st, 0);

        save_history(cmd);
        free(line);
    }

    printf("bye.\n");
    return 0;
}