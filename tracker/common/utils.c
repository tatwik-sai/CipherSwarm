#include "utils.h"
#include <stdarg.h>
#include <sys/stat.h>
#include <sys/types.h>

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

    fprintf(stderr, "%s[%s %s %s:%d]%s ",
            color, timebuf, level, basename, line, CLR_RESET);

    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);

    fprintf(stderr, "\n");
    fflush(stderr);
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
