/*
 * ═══════════════════════════════════════════════════════════════
 *  CipherSwarm — Torrent Creator / Loader
 *
 *  Splits a file into pieces, computes SHA1 hash per piece,
 *  and builds a Torrent metadata struct.
 * ═══════════════════════════════════════════════════════════════
 */

#include "peer.h"
#include "common/crypto.h"
#include "common/utils.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <libgen.h>

int create_torrent_from_file(const char *filepath, struct Torrent *t,
                              const char *tracker_ip, int tracker_port,
                              const char *auth_ip, int auth_port)
{
    memset(t, 0, sizeof(struct Torrent));

    /* Get file size */
    struct stat st;
    if (stat(filepath, &st) != 0) {
        LOG_ERR("Cannot stat file: %s", filepath);
        return -1;
    }

    t->file_size  = st.st_size;
    t->piece_size = PIECE_SIZE;
    t->total_pieces = (int)((t->file_size + PIECE_SIZE - 1) / PIECE_SIZE);

    if (t->total_pieces > MAX_FILES) {
        LOG_ERR("File too large: %d pieces (max %d)", t->total_pieces, MAX_FILES);
        return -1;
    }

    /* Extract filename */
    char tmp[MAX_FILENAME];
    safe_strncpy(tmp, filepath, MAX_FILENAME);
    char *fname = basename(tmp);
    safe_strncpy(t->file_name, fname, MAX_FILENAME);

    /* Server info */
    safe_strncpy(t->tracker_ip, tracker_ip, MAX_IP_LEN);
    t->tracker_port = tracker_port;
    safe_strncpy(t->auth_server_ip, auth_ip, MAX_IP_LEN);
    t->auth_server_port = auth_port;

    /* Compute SHA1 for each piece */
    FILE *fp = fopen(filepath, "rb");
    if (!fp) {
        LOG_ERR("Cannot open file: %s", filepath);
        return -1;
    }

    unsigned char piece_buf[PIECE_SIZE];
    char all_hashes[MAX_FILES * SHA1_HEX_LEN];
    int hash_offset = 0;

    for (int i = 0; i < t->total_pieces; i++) {
        size_t to_read = PIECE_SIZE;
        /* Last piece may be smaller */
        if (i == t->total_pieces - 1) {
            long remaining = t->file_size - (long)i * PIECE_SIZE;
            if (remaining < (long)PIECE_SIZE) to_read = (size_t)remaining;
        }

        size_t nread = fread(piece_buf, 1, to_read, fp);
        if (nread != to_read) {
            LOG_ERR("Short read at piece %d: expected %zu, got %zu", i, to_read, nread);
            fclose(fp);
            return -1;
        }

        sha1_hash_hex(piece_buf, nread, t->piece_hashes[i]);

        /* Accumulate hashes for file_id computation */
        memcpy(all_hashes + hash_offset, t->piece_hashes[i], SHA1_HEX_LEN - 1);
        hash_offset += SHA1_HEX_LEN - 1;
    }
    fclose(fp);

    /* Compute file_id = SHA1 of all concatenated piece hashes */
    sha1_hash_hex(all_hashes, hash_offset, t->file_id);

    LOG_INFO("Created torrent: %s", t->file_name);
    LOG_INFO("  file_id:      %s", t->file_id);
    LOG_INFO("  file_size:    %ld bytes", t->file_size);
    LOG_INFO("  pieces:       %d × %d bytes", t->total_pieces, t->piece_size);

    return 0;
}
