/*
 * ═══════════════════════════════════════════════════════════════
 *  CipherSwarm — Torrent Metadata Management
 *
 *  Stores, loads, and lists .torrent metadata files on the
 *  auth server side.
 * ═══════════════════════════════════════════════════════════════
 */

#include "auth_server.h"
#include "common/utils.h"

#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

/* ── Store Torrent ────────────────────────────────────────── */

int store_torrent(const struct Torrent *t)
{
    mkdirs(TORRENTS_DIR);

    /* Keep only the latest torrent per filename to avoid stale entries
     * that can appear in list/download flows after repeated test runs. */
    DIR *dir = opendir(TORRENTS_DIR);
    if (dir) {
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            const char *ext = strrchr(entry->d_name, '.');
            if (!ext || strcmp(ext, ".torrent") != 0) continue;

            char existing_id[MAX_ID_LEN];
            size_t id_len = (size_t)(ext - entry->d_name);
            if (id_len >= MAX_ID_LEN) continue;
            memcpy(existing_id, entry->d_name, id_len);
            existing_id[id_len] = '\0';

            if (strcmp(existing_id, t->file_id) == 0) continue;

            struct Torrent existing;
            if (load_torrent(existing_id, &existing) == 0 &&
                strcmp(existing.file_name, t->file_name) == 0) {
                char old_path[512];
                snprintf(old_path, sizeof(old_path), "%s/%s.torrent",
                         TORRENTS_DIR, existing_id);
                if (unlink(old_path) == 0) {
                    LOG_INFO("Removed stale torrent: %s (%s)",
                             existing.file_name, existing_id);
                }
            }
        }
        closedir(dir);
    }

    char path[512];
    snprintf(path, sizeof(path), "%s/%s.torrent", TORRENTS_DIR, t->file_id);

    FILE *fp = fopen(path, "wb");
    if (!fp) {
        LOG_ERR("Cannot create torrent file: %s", path);
        return -1;
    }

    /* Write as binary struct for simplicity */
    size_t written = fwrite(t, sizeof(struct Torrent), 1, fp);
    fclose(fp);

    if (written != 1) {
        LOG_ERR("Failed to write torrent: %s", path);
        return -1;
    }

    LOG_INFO("Stored torrent: %s (%s)", t->file_name, t->file_id);
    return 0;
}

/* ── Load Torrent ─────────────────────────────────────────── */

int load_torrent(const char *file_id, struct Torrent *t_out)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/%s.torrent", TORRENTS_DIR, file_id);

    FILE *fp = fopen(path, "rb");
    if (!fp) {
        LOG_ERR("Torrent not found: %s", file_id);
        return -1;
    }

    size_t nread = fread(t_out, sizeof(struct Torrent), 1, fp);
    fclose(fp);

    if (nread != 1) {
        LOG_ERR("Failed to read torrent: %s", path);
        return -1;
    }

    return 0;
}

/* ── List Torrents ────────────────────────────────────────── */

int list_torrents(struct Torrent *out_list, int max_count)
{
    mkdirs(TORRENTS_DIR);

    DIR *dir = opendir(TORRENTS_DIR);
    if (!dir) {
        LOG_WARN("Cannot open torrents directory");
        return 0;
    }

    int count = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL && count < max_count) {
        /* Skip non-.torrent files */
        const char *ext = strrchr(entry->d_name, '.');
        if (!ext || strcmp(ext, ".torrent") != 0) continue;

        /* Extract file_id from filename */
        char file_id[MAX_ID_LEN];
        size_t id_len = ext - entry->d_name;
        if (id_len >= MAX_ID_LEN) continue;
        memcpy(file_id, entry->d_name, id_len);
        file_id[id_len] = '\0';

        if (load_torrent(file_id, &out_list[count]) == 0) {
            count++;
        }
    }

    closedir(dir);
    return count;
}
