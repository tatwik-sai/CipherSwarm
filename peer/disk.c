/*
 * ═══════════════════════════════════════════════════════════════
 *  CipherSwarm — Disk Manager
 *
 *  Handles all file I/O operations with flock()-based locking
 *  to ensure data consistency under concurrent access.
 *
 *  OS Concepts: file locking (flock), seek + read/write
 * ═══════════════════════════════════════════════════════════════
 */

#include "peer.h"
#include "common/utils.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <errno.h>

/* ══════════════════════════════════════════════════════════════
 *  Write a piece to disk (download path)
 *
 *  Uses LOCK_EX (exclusive lock) to prevent concurrent writes
 *  to the same file region.
 * ══════════════════════════════════════════════════════════════ */

int write_piece(const char *filepath, int piece_index, int piece_size,
                const void *data, int data_len)
{
    int fd = open(filepath, O_WRONLY | O_CREAT, 0644);
    if (fd < 0) {
        LOG_ERR("Cannot open file for writing: %s (%s)", filepath, strerror(errno));
        return -1;
    }

    /* Exclusive lock for writing */
    if (flock(fd, LOCK_EX) < 0) {
        LOG_ERR("flock(LOCK_EX) failed: %s", strerror(errno));
        close(fd);
        return -1;
    }

    off_t offset = (off_t)piece_index * piece_size;
    if (lseek(fd, offset, SEEK_SET) < 0) {
        LOG_ERR("lseek failed at piece %d: %s", piece_index, strerror(errno));
        flock(fd, LOCK_UN);
        close(fd);
        return -1;
    }

    ssize_t written = write(fd, data, (size_t)data_len);
    if (written != data_len) {
        LOG_ERR("Short write at piece %d: %zd/%d", piece_index, written, data_len);
        flock(fd, LOCK_UN);
        close(fd);
        return -1;
    }

    /* Unlock */
    flock(fd, LOCK_UN);
    close(fd);

    LOG_DEBUG("Wrote piece %d (%d bytes) to %s", piece_index, data_len, filepath);
    return 0;
}

/* ══════════════════════════════════════════════════════════════
 *  Read a piece from disk (upload path)
 *
 *  Uses LOCK_SH (shared lock) to allow concurrent reads.
 * ══════════════════════════════════════════════════════════════ */

int read_piece(const char *filepath, int piece_index, int piece_size,
               void *buf, int buf_size)
{
    int fd = open(filepath, O_RDONLY);
    if (fd < 0) {
        LOG_ERR("Cannot open file for reading: %s (%s)", filepath, strerror(errno));
        return -1;
    }

    /* Shared lock for reading */
    if (flock(fd, LOCK_SH) < 0) {
        LOG_ERR("flock(LOCK_SH) failed: %s", strerror(errno));
        close(fd);
        return -1;
    }

    off_t offset = (off_t)piece_index * piece_size;
    if (lseek(fd, offset, SEEK_SET) < 0) {
        LOG_ERR("lseek failed at piece %d: %s", piece_index, strerror(errno));
        flock(fd, LOCK_UN);
        close(fd);
        return -1;
    }

    ssize_t nread = read(fd, buf, (size_t)buf_size);
    if (nread < 0) {
        LOG_ERR("Read failed at piece %d: %s", piece_index, strerror(errno));
        flock(fd, LOCK_UN);
        close(fd);
        return -1;
    }

    /* Unlock */
    flock(fd, LOCK_UN);
    close(fd);

    LOG_DEBUG("Read piece %d (%zd bytes) from %s", piece_index, nread, filepath);
    return (int)nread;
}

/* ══════════════════════════════════════════════════════════════
 *  Create an empty file of the given size (for download prep)
 * ══════════════════════════════════════════════════════════════ */

int create_empty_file(const char *filepath, long file_size)
{
    int fd = open(filepath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        LOG_ERR("Cannot create file: %s (%s)", filepath, strerror(errno));
        return -1;
    }

    /* Extend file to desired size */
    if (ftruncate(fd, file_size) < 0) {
        LOG_ERR("ftruncate failed: %s", strerror(errno));
        close(fd);
        return -1;
    }

    close(fd);
    LOG_INFO("Created empty file: %s (%ld bytes)", filepath, file_size);
    return 0;
}
