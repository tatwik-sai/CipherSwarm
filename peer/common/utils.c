#include "utils.h"
#include <stdarg.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pthread.h>

static FILE *g_log_file = NULL;
static int g_console_enabled = 1;
static pthread_mutex_t g_log_lock = PTHREAD_MUTEX_INITIALIZER;

int log_init_file_session(const char *log_path)
{
    pthread_mutex_lock(&g_log_lock);

    g_log_file = fopen(log_path, "a");
    if (!g_log_file) {
        pthread_mutex_unlock(&g_log_lock);
        return -1;
    }

    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    char stamp[64];
    if (tm) {
        strftime(stamp, sizeof(stamp), "%Y-%m-%d %H:%M:%S", tm);
    } else {
        safe_strncpy(stamp, "unknown-time", sizeof(stamp));
    }

    fprintf(g_log_file,
            "\n============================================================\n"
            "Peer session started: %s\n"
            "============================================================\n",
            stamp);
    fflush(g_log_file);

    pthread_mutex_unlock(&g_log_lock);
    return 0;
}

void log_close_file(void)
{
    pthread_mutex_lock(&g_log_lock);
    if (g_log_file) {
        fclose(g_log_file);
        g_log_file = NULL;
    }
    pthread_mutex_unlock(&g_log_lock);
}

void log_set_console_output(int enabled)
{
    pthread_mutex_lock(&g_log_lock);
    g_console_enabled = enabled ? 1 : 0;
    pthread_mutex_unlock(&g_log_lock);
}

/* ══════════════════════════════════════════════════════════════
 *  Logging
 * ══════════════════════════════════════════════════════════════ */

void log_msg(const char *level, const char *color,
             const char *file, int line,
             const char *fmt, ...)
{
    char timebuf[32];
    time_now_str(timebuf, sizeof(timebuf));

    /* Extract just the filename from full path */
    const char *basename = strrchr(file, '/');
    basename = basename ? basename + 1 : file;

    va_list args;

    pthread_mutex_lock(&g_log_lock);

    if (g_console_enabled) {
        fprintf(stderr, "%s[%s %s %s:%d]%s ",
                color, timebuf, level, basename, line, CLR_RESET);

        va_start(args, fmt);
        vfprintf(stderr, fmt, args);
        va_end(args);

        fprintf(stderr, "\n");
        fflush(stderr);
    }

    if (g_log_file) {
        fprintf(g_log_file, "[%s %s %s:%d] ",
                timebuf, level, basename, line);
        va_start(args, fmt);
        vfprintf(g_log_file, fmt, args);
        va_end(args);
        fprintf(g_log_file, "\n");
        fflush(g_log_file);
    }

    pthread_mutex_unlock(&g_log_lock);
}

void die(const char *msg)
{
    fprintf(stderr, "%s[FATAL]%s %s: %s\n",
            CLR_RED, CLR_RESET, msg, strerror(errno));
    exit(EXIT_FAILURE);
}

/* ══════════════════════════════════════════════════════════════
 *  String / Time Helpers
 * ══════════════════════════════════════════════════════════════ */

void time_now_str(char *buf, size_t len)
{
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    strftime(buf, len, "%H:%M:%S", tm);
}

void safe_strncpy(char *dst, const char *src, size_t n)
{
    strncpy(dst, src, n - 1);
    dst[n - 1] = '\0';
}

/* ══════════════════════════════════════════════════════════════
 *  Hex Conversion
 * ══════════════════════════════════════════════════════════════ */

void bytes_to_hex(const unsigned char *data, size_t len, char *hex_out)
{
    for (size_t i = 0; i < len; i++) {
        sprintf(hex_out + (i * 2), "%02x", data[i]);
    }
    hex_out[len * 2] = '\0';
}

void hex_to_bytes(const char *hex, unsigned char *out, size_t out_len)
{
    for (size_t i = 0; i < out_len; i++) {
        unsigned int byte;
        sscanf(hex + (i * 2), "%02x", &byte);
        out[i] = (unsigned char)byte;
    }
}

/* ══════════════════════════════════════════════════════════════
 *  Filesystem
 * ══════════════════════════════════════════════════════════════ */

int mkdirs(const char *path)
{
    char tmp[512];
    safe_strncpy(tmp, path, sizeof(tmp));
    size_t len = strlen(tmp);

    if (tmp[len - 1] == '/')
        tmp[len - 1] = '\0';

    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(tmp, 0755);
            *p = '/';
        }
    }
    return mkdir(tmp, 0755);
}
