#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

/* ── Color codes ──────────────────────────────────────────── */
#define CLR_RESET   "\033[0m"
#define CLR_RED     "\033[1;31m"
#define CLR_GREEN   "\033[1;32m"
#define CLR_YELLOW  "\033[1;33m"
#define CLR_BLUE    "\033[1;34m"
#define CLR_CYAN    "\033[1;36m"
#define CLR_GRAY    "\033[0;37m"

/* ── Logging macros ───────────────────────────────────────── */
#define LOG_INFO(fmt, ...) \
    log_msg("INFO",  CLR_GREEN,  __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#define LOG_WARN(fmt, ...) \
    log_msg("WARN",  CLR_YELLOW, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#define LOG_ERR(fmt, ...) \
    log_msg("ERROR", CLR_RED,    __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#define LOG_DEBUG(fmt, ...) \
    log_msg("DEBUG", CLR_GRAY,   __FILE__, __LINE__, fmt, ##__VA_ARGS__)

/* ── Utility functions ────────────────────────────────────── */

void log_msg(const char *level, const char *color,
             const char *file, int line,
             const char *fmt, ...);

/* Peer logging controls */
int  log_init_file_session(const char *log_path);
void log_close_file(void);
void log_set_console_output(int enabled);

void die(const char *msg);

/* Get current time as a formatted string */
void time_now_str(char *buf, size_t len);

/* Safe string copy with null termination */
void safe_strncpy(char *dst, const char *src, size_t n);

/* Convert binary data to hex string */
void bytes_to_hex(const unsigned char *data, size_t len, char *hex_out);

/* Convert hex string back to binary */
void hex_to_bytes(const char *hex, unsigned char *out, size_t out_len);

/* Create directory if it doesn't exist (recursive) */
int mkdirs(const char *path);

#endif /* UTILS_H */
