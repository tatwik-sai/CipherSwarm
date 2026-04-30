/*
 * CipherSwarm — Peer Node Entry Point
 * Terminal menu-driven interface for login, upload, download.
 * OS Concepts: fork(), threads, sockets, IPC
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <sys/stat.h>

#include "peer.h"
#include "ipc.h"
#include "common/network.h"
#include "common/crypto.h"
#include "common/utils.h"

static struct PeerState g_state;
static struct IpcResources g_ipc;
static char g_peer_log_path[512];
static struct PeerIdentity g_identity;

/* ══════════════════════════════════════════════════════════════
 *  Peer Identity Management — persistent local identity
 *
 *  Stored at: <peer_dir>/.data/peer_identity (binary format)
 * ══════════════════════════════════════════════════════════════ */

static char g_identity_path[512];     /* <peer_dir>/.data/peer_identity */

static int identity_load(void)
{
    FILE *fp = fopen(g_identity_path, "rb");
    if (!fp) return -1;

    size_t nread = fread(&g_identity, sizeof(struct PeerIdentity), 1, fp);
    fclose(fp);

    if (nread != 1) {
        LOG_ERR("Failed to read peer identity");
        return -1;
    }

    LOG_INFO("Identity loaded: peer_id=%s username=%s", g_identity.peer_id, g_identity.username);
    return 0;
}

static int identity_save(void)
{
    char data_dir[512];
    snprintf(data_dir, sizeof(data_dir), "%s/.data", g_state.peer_dir);
    mkdirs(data_dir);

    FILE *fp = fopen(g_identity_path, "wb");
    if (!fp) {
        LOG_ERR("Cannot create peer identity file");
        return -1;
    }

    size_t written = fwrite(&g_identity, sizeof(struct PeerIdentity), 1, fp);
    fclose(fp);

    if (written != 1) {
        LOG_ERR("Failed to write peer identity");
        return -1;
    }

    LOG_INFO("Identity saved: peer_id=%s username=%s", g_identity.peer_id, g_identity.username);
    return 0;
}

static int do_first_time_register(void)
{
    printf("\n  " CLR_CYAN "╔══════════════════════════════════════════╗" CLR_RESET "\n");
    printf("  " CLR_CYAN "║   First Time Setup                        ║" CLR_RESET "\n");
    printf("  " CLR_CYAN "╚══════════════════════════════════════════╝" CLR_RESET "\n\n");

    printf("  Username: ");
    fflush(stdout);
    scanf("%31s", g_identity.username);

    char password[MAX_PASS_LEN];
    printf("  Password: ");
    fflush(stdout);
    scanf("%63s", password);

    /* Connect to auth server and register */
    int sockfd = connect_to(g_state.auth_ip, g_state.auth_port);
    if (sockfd < 0) {
        LOG_ERR("Cannot connect to auth server");
        return -1;
    }

    struct RegisterRequest req;
    memset(&req, 0, sizeof(req));
    safe_strncpy(req.username, g_identity.username, MAX_USER_LEN);
    safe_strncpy(req.password, password, MAX_PASS_LEN);

    send_msg(sockfd, MSG_REGISTER_PEER, &req, sizeof(req));

    char buf[MAX_PAYLOAD_SIZE];
    uint8_t type;
    uint32_t len;

    if (recv_msg(sockfd, &type, buf, sizeof(buf), &len) < 0) {
        close(sockfd);
        LOG_ERR("Failed to receive response from auth server");
        return -1;
    }
    close(sockfd);

    if (type == MSG_REGISTER_FAIL) {
        printf("  " CLR_RED "✗ Registration failed" CLR_RESET "\n");
        return -1;
    }

    if (type != MSG_REGISTER_OK || len < MAX_ID_LEN) {
        printf("  " CLR_RED "✗ Invalid response from auth server" CLR_RESET "\n");
        return -1;
    }

    struct RegisterResponse *resp = (struct RegisterResponse *)buf;
    safe_strncpy(g_identity.peer_id, resp->peer_id, MAX_ID_LEN);

    if (identity_save() < 0) {
        printf("  " CLR_RED "✗ Failed to save identity" CLR_RESET "\n");
        return -1;
    }

    printf("\n  " CLR_GREEN "✓ Registration successful!" CLR_RESET "\n");
    printf("  " CLR_GREEN "  Peer ID: %s" CLR_RESET "\n", g_identity.peer_id);
    printf("  " CLR_GREEN "  Username: %s" CLR_RESET "\n\n", g_identity.username);

    return 0;
}

/* ══════════════════════════════════════════════════════════════
 *  Seeding Registry — persistent per-peer file list
 *
 *  Stored at: <peer_dir>/.data/.seeding (one file_id per line)
 * ══════════════════════════════════════════════════════════════ */

#define MAX_SEEDING_FILES 32

static char  g_registry_path[512];   /* <peer_dir>/.data/.seeding */
static char  g_seeding_ids[MAX_SEEDING_FILES][MAX_ID_LEN];
static int   g_seeding_count = 0;

static int check_upload_permission(void);
static const char *role_str(int role);

/* Load registry from disk */
static void registry_load(void)
{
    g_seeding_count = 0;
    FILE *fp = fopen(g_registry_path, "r");
    if (!fp) return;

    char line[MAX_ID_LEN + 2];
    while (fgets(line, sizeof(line), fp) && g_seeding_count < MAX_SEEDING_FILES) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';
        if (strlen(line) > 0) {
            safe_strncpy(g_seeding_ids[g_seeding_count], line, MAX_ID_LEN);
            g_seeding_count++;
        }
    }
    fclose(fp);
    LOG_INFO("Registry: loaded %d seeding file(s) from %s", g_seeding_count, g_registry_path);
}

/* Save registry to disk */
static void registry_save(void)
{
    mkdirs(g_state.peer_dir);
    FILE *fp = fopen(g_registry_path, "w");
    if (!fp) { LOG_ERR("Cannot save seeding registry"); return; }

    for (int i = 0; i < g_seeding_count; i++)
        fprintf(fp, "%s\n", g_seeding_ids[i]);
    fclose(fp);
}

/* Add a file_id to the registry (deduplicates) */
static void registry_add(const char *file_id)
{
    for (int i = 0; i < g_seeding_count; i++) {
        if (strcmp(g_seeding_ids[i], file_id) == 0) return;
    }
    if (g_seeding_count >= MAX_SEEDING_FILES) {
        LOG_WARN("Seeding registry full (%d files)", MAX_SEEDING_FILES);
        return;
    }
    safe_strncpy(g_seeding_ids[g_seeding_count], file_id, MAX_ID_LEN);
    g_seeding_count++;
    registry_save();
    LOG_INFO("Registry: added %s (total: %d)", file_id, g_seeding_count);
}

/* ══════════════════════════════════════════════════════════════
 *  Tracker Announce — announces ALL registered files
 * ══════════════════════════════════════════════════════════════ */

static void announce_all_to_tracker(void)
{
    if (g_seeding_count == 0) return;

    char announce_id[MAX_ID_LEN];
    if (g_state.logged_in && strlen(g_state.peer_id) > 0) {
        safe_strncpy(announce_id, g_state.peer_id, sizeof(announce_id));
    } else {
        snprintf(announce_id, sizeof(announce_id), "peer_%d", g_state.listen_port);
    }

    for (int i = 0; i < g_seeding_count; i++) {
        int sockfd = connect_to(g_state.tracker_ip, g_state.tracker_port);
        if (sockfd < 0) continue;

        struct AnnounceRequest ann;
        memset(&ann, 0, sizeof(ann));
        safe_strncpy(ann.peer_id, announce_id, sizeof(ann.peer_id));
        safe_strncpy(ann.file_id, g_seeding_ids[i], MAX_ID_LEN);
        safe_strncpy(ann.ip, "127.0.0.1", MAX_IP_LEN);
        ann.port = g_state.listen_port;
        send_msg(sockfd, MSG_ANNOUNCE, &ann, sizeof(ann));

        char buf[RECV_BUF_SIZE]; uint8_t type; uint32_t len;
        recv_msg(sockfd, &type, buf, sizeof(buf), &len);
        close(sockfd);
    }
    LOG_INFO("Announced %d file(s) to tracker as %s", g_seeding_count, announce_id);
}

/* Re-announce thread */
static void *reannounce_thread(void *arg)
{
    (void)arg;
    while (g_state.is_seeding) {
        sleep(60);
        announce_all_to_tracker();
        LOG_DEBUG("Re-announced %d file(s) to tracker", g_seeding_count);
    }
    return NULL;
}

static int g_reannounce_running = 0;
static void start_reannounce_thread(void)
{
    if (g_reannounce_running) return;
    g_reannounce_running = 1;
    pthread_t tid;
    pthread_create(&tid, NULL, reannounce_thread, NULL);
    pthread_detach(tid);
}

/* ══════════════════════════════════════════════════════════════
 *  Auto-seed from registry on login
 * ══════════════════════════════════════════════════════════════ */

static void auto_seed_from_registry(void)
{
    if (g_seeding_count == 0) return;

    for (int i = 0; i < g_seeding_count; i++) {
        int sockfd = connect_to(g_state.auth_ip, g_state.auth_port);
        if (sockfd < 0) continue;

        send_msg(sockfd, MSG_DOWNLOAD_TORRENT, g_seeding_ids[i],
                 (uint32_t)strlen(g_seeding_ids[i]));

        char buf[MAX_PAYLOAD_SIZE]; uint8_t type; uint32_t len;
        if (recv_msg(sockfd, &type, buf, sizeof(buf), &len) < 0) {
            close(sockfd); continue;
        }
        close(sockfd);

        if (type != MSG_TORRENT_DATA || len < sizeof(struct Torrent)) continue;

        struct Torrent t;
        memcpy(&t, buf, sizeof(struct Torrent));

        /* Check if the file exists in our downloads dir */
        char filepath[512];
        snprintf(filepath, sizeof(filepath), "%s/%s", g_state.downloads_dir, t.file_name);
        struct stat st;
        if (stat(filepath, &st) != 0 || st.st_size != t.file_size) continue;

        /* Set as active torrent for serving */
        if (!g_state.is_seeding) {
            memcpy(&g_state.torrent, &t, sizeof(struct Torrent));
            for (int j = 0; j < t.total_pieces; j++)
                g_state.piece_status[j] = PIECE_DONE;
            g_state.is_seeding = 1;
            LOG_INFO("Auto-seeding: %s [%s]", t.file_name, t.file_id);
        }
    }

    announce_all_to_tracker();

    if (g_state.is_seeding)
        start_reannounce_thread();
}

/* ══════════════════════════════════════════════════════════════
 *  Login — authenticate with stored peer identity
 * ══════════════════════════════════════════════════════════════ */

static int do_login(void)
{
    printf("\n  " CLR_CYAN "Welcome, %s!" CLR_RESET "\n", g_identity.username);
    printf("  Password: ");
    fflush(stdout);

    char password[MAX_PASS_LEN];
    scanf("%63s", password);

    int sockfd = connect_to(g_state.auth_ip, g_state.auth_port);
    if (sockfd < 0) { LOG_ERR("Cannot connect to auth server"); return -1; }

    struct LoginRequest req;
    memset(&req, 0, sizeof(req));
    safe_strncpy(req.peer_id, g_identity.peer_id, MAX_ID_LEN);
    safe_strncpy(req.password, password, MAX_PASS_LEN);

    send_msg(sockfd, MSG_LOGIN, &req, sizeof(req));

    char buf[MAX_PAYLOAD_SIZE];
    uint8_t type; uint32_t len;
    if (recv_msg(sockfd, &type, buf, sizeof(buf), &len) < 0) {
        close(sockfd); return -1;
    }
    close(sockfd);

    if (type == MSG_LOGIN_OK && len >= sizeof(struct LoginResponse)) {
        struct LoginResponse resp;
        memcpy(&resp, buf, sizeof(resp));

        memcpy(&g_state.token, &resp.token, sizeof(struct Token));
        safe_strncpy(g_state.peer_id, g_identity.peer_id, sizeof(g_state.peer_id));
        g_state.role = resp.role;
        g_state.logged_in = 1;
        const char *role_name = role_str(g_state.role);
        printf("\n  " CLR_GREEN "✓ Login Successful" CLR_RESET "\n");
        printf("  User: %s\n", g_identity.username);
        printf("  Role: %s\n", role_name);
        printf("\n  " CLR_CYAN "================================================================" CLR_RESET "\n\n");

        /* On login: load registry and auto-seed */
        registry_load();
        if (g_seeding_count > 0) {
            printf("  " CLR_CYAN "ℹ Auto-seeding %d file(s) from registry..." CLR_RESET "\n",
                   g_seeding_count);
            auto_seed_from_registry();
        }

        return 0;
    }
    printf("  " CLR_RED "✗ Login failed" CLR_RESET "\n");
    return -1;
}

/* ══════════════════════════════════════════════════════════════
 *  Upload File
 * ══════════════════════════════════════════════════════════════ */

static int do_upload_file(void)
{
    if (!g_state.logged_in) { printf("  Please login first.\n"); return -1; }
    if (check_upload_permission() < 0) {
        printf("  " CLR_RED "✗ Upload is disabled for your current role (%s). Request admin to grant upload access." CLR_RESET "\n",
               role_str(g_state.role));
        return -1;
    }

    char filepath[512];
    printf("  File path: "); fflush(stdout);
    scanf("%511s", filepath);

    /* Create torrent */
    if (create_torrent_from_file(filepath, &g_state.torrent,
            g_state.tracker_ip, g_state.tracker_port,
            g_state.auth_ip, g_state.auth_port) < 0) {
        printf("  " CLR_RED "✗ Failed to create torrent from %s" CLR_RESET "\n", filepath);
        return -1;
    }

    /* Upload torrent metadata to auth server */
    int sockfd = connect_to(g_state.auth_ip, g_state.auth_port);
    if (sockfd < 0) {
        printf("  " CLR_RED "✗ Cannot connect to auth server" CLR_RESET "\n");
        return -1;
    }

    struct UploadTorrentRequest req;
    memset(&req, 0, sizeof(req));
    memcpy(&req.token, &g_state.token, sizeof(struct Token));
    memcpy(&req.torrent, &g_state.torrent, sizeof(struct Torrent));

    send_msg(sockfd, MSG_UPLOAD_TORRENT, &req, sizeof(req));

    char buf[RECV_BUF_SIZE]; uint8_t type; uint32_t len;
    recv_msg(sockfd, &type, buf, sizeof(buf), &len);
    close(sockfd);

    if (type != MSG_ACK) {
        buf[len < RECV_BUF_SIZE ? len : RECV_BUF_SIZE - 1] = '\0';
        printf("  " CLR_RED "✗ Torrent upload rejected by auth server: %s" CLR_RESET "\n", buf);
        return -1;
    }

    /* Persist local torrent metadata in this peer directory */
    mkdirs(g_state.torrents_dir);
    char torrent_path[512];
    snprintf(torrent_path, sizeof(torrent_path), "%s/%s.torrent",
             g_state.torrents_dir, g_state.torrent.file_id);
    FILE *tfp = fopen(torrent_path, "wb");
    if (tfp) {
        fwrite(&g_state.torrent, sizeof(struct Torrent), 1, tfp);
        fclose(tfp);
        LOG_INFO("Stored local torrent: %s", torrent_path);
    } else {
        LOG_WARN("Could not store local torrent: %s", torrent_path);
    }

    /* Copy file to this peer's downloads directory */
    mkdirs(g_state.downloads_dir);
    char dst[512];
    snprintf(dst, sizeof(dst), "%s/%s", g_state.downloads_dir, g_state.torrent.file_name);
    char cmd[1100];
    snprintf(cmd, sizeof(cmd), "cp '%s' '%s'", filepath, dst);
    system(cmd);

    /* Mark all pieces as done (we're the seeder) */
    for (int i = 0; i < g_state.torrent.total_pieces; i++)
        g_state.piece_status[i] = PIECE_DONE;
    g_state.is_seeding = 1;

    /* Add to persistent seeding registry */
    registry_add(g_state.torrent.file_id);

    /* Announce all files to tracker */
    announce_all_to_tracker();
    start_reannounce_thread();

    printf("  " CLR_GREEN "✓ File shared: %s" CLR_RESET "\n", g_state.torrent.file_name);
    printf("  " CLR_CYAN "  File ID: %s" CLR_RESET "\n", g_state.torrent.file_id);
    printf("  " CLR_CYAN "  Stored in: %s" CLR_RESET "\n", g_state.downloads_dir);
    printf("\n  " CLR_RED "================================================================" CLR_RESET "\n\n");
    return 0;
}

/* ══════════════════════════════════════════════════════════════
 *  List Files
 * ══════════════════════════════════════════════════════════════ */

static int do_list_files(void)
{
    int sockfd = connect_to(g_state.auth_ip, g_state.auth_port);
    if (sockfd < 0) return -1;

    send_msg(sockfd, MSG_LIST_TORRENTS, NULL, 0);

    char *buf = malloc(MAX_PAYLOAD_SIZE);
    uint8_t type; uint32_t len;
    if (recv_msg(sockfd, &type, buf, MAX_PAYLOAD_SIZE, &len) < 0) {
        close(sockfd); free(buf); return -1;
    }
    close(sockfd);

    if (type != MSG_TORRENT_LIST) { free(buf); return -1; }

    int count;
    memcpy(&count, buf, sizeof(int));
    struct Torrent *torrents = (struct Torrent *)(buf + sizeof(int));

    printf("\n  " CLR_CYAN "+-----+--------------------------------+------------------------------------------+----------+---------+" CLR_RESET "\n");
    printf("  " CLR_CYAN "| #   | File Name                      | File ID                                  | Size     | Status  |" CLR_RESET "\n");
    printf("  " CLR_CYAN "+-----+--------------------------------+------------------------------------------+----------+---------+" CLR_RESET "\n");
    if (count == 0) { printf("  No files available.\n"); }
    for (int i = 0; i < count; i++) {
        /* Check if we have this file locally in our downloads dir */
        char filepath[512];
        snprintf(filepath, sizeof(filepath), "%s/%s", g_state.downloads_dir, torrents[i].file_name);
        struct stat st;
        int have_local = (stat(filepath, &st) == 0 && st.st_size == torrents[i].file_size);
        
        char fname[31];
        strncpy(fname, torrents[i].file_name, sizeof(fname) - 1);
        fname[30] = '\0';
        
         printf("  | %-3d | %-30s | %-40s | %8ld | %-7s |\n",
             i + 1, fname, torrents[i].file_id, torrents[i].file_size,
             have_local ? CLR_GREEN "[LOCAL]" CLR_RESET : "");
    }
        printf("  " CLR_CYAN "+-----+--------------------------------+------------------------------------------+----------+---------+" CLR_RESET "\n");
    printf("\n  " CLR_CYAN "================================================================" CLR_RESET "\n\n");
    free(buf);
    return 0;
}

/* ══════════════════════════════════════════════════════════════
 *  Download File
 * ══════════════════════════════════════════════════════════════ */

static int do_download_file(void)
{
    if (!g_state.logged_in) { printf("  Please login first.\n"); return -1; }

    char file_id[MAX_ID_LEN];
    printf("  File ID: "); fflush(stdout);
    scanf("%40s", file_id);

    printf("\n  " CLR_CYAN "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" CLR_RESET "\n");
    printf("  " CLR_CYAN "  Download Initiated" CLR_RESET "\n");
    printf("  " CLR_CYAN "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" CLR_RESET "\n\n");

    /* Phase 1: Fetch torrent metadata */
    printf("  " CLR_YELLOW "▸ Phase 1:" CLR_RESET " Fetching torrent metadata from auth server...\n");
    int sockfd = connect_to(g_state.auth_ip, g_state.auth_port);
    if (sockfd < 0) {
        printf("  " CLR_RED "  ✗ Cannot reach auth server at %s:%d" CLR_RESET "\n",
               g_state.auth_ip, g_state.auth_port);
        return -1;
    }
    send_msg(sockfd, MSG_DOWNLOAD_TORRENT, file_id, (uint32_t)strlen(file_id));

    char buf[MAX_PAYLOAD_SIZE]; uint8_t type; uint32_t len;
    if (recv_msg(sockfd, &type, buf, sizeof(buf), &len) < 0) {
        close(sockfd);
        printf("  " CLR_RED "  ✗ Auth server connection lost" CLR_RESET "\n");
        return -1;
    }
    close(sockfd);

    if (type != MSG_TORRENT_DATA || len < sizeof(struct Torrent)) {
        printf("  " CLR_RED "  ✗ File not found (ID: %s)" CLR_RESET "\n", file_id);
        return -1;
    }
    memcpy(&g_state.torrent, buf, sizeof(struct Torrent));

    printf("  " CLR_GREEN "  ✓ Torrent loaded" CLR_RESET "\n");
    printf("    ├─ File:    %s\n", g_state.torrent.file_name);
    printf("    ├─ Size:    %ld bytes\n", g_state.torrent.file_size);
    printf("    ├─ Pieces:  %d × %d bytes\n",
           g_state.torrent.total_pieces, g_state.torrent.piece_size);
    printf("    └─ ID:      %s\n\n", g_state.torrent.file_id);

    /* Persist downloaded metadata */
    mkdirs(g_state.torrents_dir);
    char torrent_path[512];
    snprintf(torrent_path, sizeof(torrent_path), "%s/%s.torrent",
             g_state.torrents_dir, g_state.torrent.file_id);
    FILE *tfp = fopen(torrent_path, "wb");
    if (tfp) {
        fwrite(&g_state.torrent, sizeof(struct Torrent), 1, tfp);
        fclose(tfp);
    }

    /* Phase 2: Peer discovery */
    printf("  " CLR_YELLOW "▸ Phase 2:" CLR_RESET " Querying tracker for active peers...\n");
    sockfd = connect_to(g_state.tracker_ip, g_state.tracker_port);
    if (sockfd < 0) {
        printf("  " CLR_RED "  ✗ Cannot reach tracker at %s:%d" CLR_RESET "\n",
               g_state.tracker_ip, g_state.tracker_port);
        return -1;
    }
    send_msg(sockfd, MSG_GET_PEERS, file_id, (uint32_t)strlen(file_id));

    if (recv_msg(sockfd, &type, buf, sizeof(buf), &len) < 0) {
        close(sockfd);
        printf("  " CLR_RED "  ✗ Tracker connection lost" CLR_RESET "\n");
        return -1;
    }
    close(sockfd);

    if (type != MSG_PEER_LIST) {
        printf("  " CLR_RED "  ✗ Invalid response from tracker" CLR_RESET "\n");
        return -1;
    }

    int peer_count;
    memcpy(&peer_count, buf, sizeof(int));
    struct PeerListEntry *entries = (struct PeerListEntry *)(buf + sizeof(int));

    if (peer_count == 0) {
        printf("  " CLR_RED "  ✗ No peers available in swarm" CLR_RESET "\n");
        return -1;
    }
    printf("  " CLR_GREEN "  ✓ Swarm discovered: %d peer(s) available" CLR_RESET "\n\n", peer_count);

    /* Phase 3: Connecting to peers */
    printf("  " CLR_YELLOW "▸ Phase 3:" CLR_RESET " Establishing peer connections...\n");
    int connected = 0;
    for (int i = 0; i < peer_count; i++) {
        if (entries[i].port == g_state.listen_port) {
            printf("    ├─ " CLR_GRAY "Skipping self (%s:%d)" CLR_RESET "\n",
                   entries[i].ip, entries[i].port);
            continue;
        }
        printf("    ├─ Connecting to %s:%d... ", entries[i].ip, entries[i].port);
        fflush(stdout);
        int idx = connect_to_peer_and_handshake(&g_state, entries[i].ip, entries[i].port);
        if (idx >= 0) {
            printf(CLR_GREEN "✓ handshake OK" CLR_RESET "\n");
            connected++;
        } else {
            printf(CLR_RED "✗ failed" CLR_RESET "\n");
        }
    }

    if (connected == 0) {
        printf("  " CLR_RED "  ✗ Could not connect to any peers" CLR_RESET "\n");
        return -1;
    }
    printf("  " CLR_GREEN "  ✓ Connected to %d peer(s), bitfield exchange complete" CLR_RESET "\n\n", connected);

    announce_all_to_tracker();

    /* Phase 4: Transfer */
    printf("  " CLR_YELLOW "▸ Phase 4:" CLR_RESET " Starting piece transfer (%d pieces, %d worker threads)...\n\n",
           g_state.torrent.total_pieces, connected);

    int result = start_download(&g_state);

    /* If download completed, add to our seeding registry */
    if (result == 0) {
        registry_add(g_state.torrent.file_id);
        g_state.is_seeding = 1;
        announce_all_to_tracker();
        start_reannounce_thread();
        printf("  " CLR_GREEN "  ✓ Now seeding — registered with tracker" CLR_RESET "\n");
    }
    printf("  " CLR_CYAN "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" CLR_RESET "\n\n");

    return result;
}

static const char *role_str(int role)
{
    switch (role) {
        case ROLE_DOWNLOADER: return "downloader";
        case ROLE_REGULAR:    return "regular";
        case ROLE_ADMIN:      return "admin";
        default:              return "unknown";
    }
}

static int check_upload_permission(void)
{
    int sockfd = connect_to(g_state.auth_ip, g_state.auth_port);
    if (sockfd < 0) return -1;

    struct AuthzCheckRequest req;
    memset(&req, 0, sizeof(req));
    memcpy(&req.token, &g_state.token, sizeof(req.token));
    send_msg(sockfd, MSG_CHECK_UPLOAD, &req, sizeof(req));

    char buf[RECV_BUF_SIZE];
    uint8_t type; uint32_t len;
    int ok = (recv_msg(sockfd, &type, buf, sizeof(buf), &len) == 0 && type == MSG_ACK);
    close(sockfd);
    return ok ? 0 : -1;
}

static int do_admin_list_users(void)
{
    if (!g_state.logged_in || g_state.role != ROLE_ADMIN) {
        printf("  " CLR_RED "✗ Admin login required" CLR_RESET "\n");
        return -1;
    }

    int sockfd = connect_to(g_state.auth_ip, g_state.auth_port);
    if (sockfd < 0) {
        printf("  " CLR_RED "✗ Connection to auth server failed" CLR_RESET "\n");
        return -1;
    }

    struct AdminAuthRequest req;
    memset(&req, 0, sizeof(req));
    memcpy(&req.token, &g_state.token, sizeof(req.token));
    send_msg(sockfd, MSG_ADMIN_LIST_USERS, &req, sizeof(req));

    char buf[MAX_PAYLOAD_SIZE];
    uint8_t type; uint32_t len;
    if (recv_msg(sockfd, &type, buf, sizeof(buf), &len) < 0) {
        close(sockfd);
        printf("  " CLR_RED "✗ Failed to fetch users" CLR_RESET "\n");
        return -1;
    }
    close(sockfd);

    if (type != MSG_ADMIN_LIST_USERS || len < sizeof(int)) {
        printf("  " CLR_RED "✗ Invalid response from auth server" CLR_RESET "\n");
        return -1;
    }

    int count = 0;
    memcpy(&count, buf, sizeof(int));
    struct UserRoleEntry *users = (struct UserRoleEntry *)(buf + sizeof(int));

    printf("\n  " CLR_CYAN "+-------------------+----------------+" CLR_RESET "\n");
    printf("  " CLR_CYAN "| Username          | Role           |" CLR_RESET "\n");
    printf("  " CLR_CYAN "+-------------------+----------------+" CLR_RESET "\n");
    for (int i = 0; i < count; i++) {
        const char *role_name = role_str(users[i].role);
        printf("  | %-17s | %-14s |\n", users[i].username, role_name);
    }
    printf("  " CLR_CYAN "+-------------------+----------------+" CLR_RESET "\n");
    printf("\n  " CLR_GREEN "================================================================" CLR_RESET "\n\n");
    return 0;
}

static int do_admin_set_role(void)
{
    if (!g_state.logged_in || g_state.role != ROLE_ADMIN) {
        printf("  Admin login required.\n");
        return -1;
    }

    char target[MAX_USER_LEN];
    int role;
    printf("  Target username: "); fflush(stdout);
    scanf("%31s", target);
    printf("  New role (0=downloader, 1=regular): "); fflush(stdout);
    scanf("%d", &role);

    int sockfd = connect_to(g_state.auth_ip, g_state.auth_port);
    if (sockfd < 0) return -1;

    struct AdminSetRoleRequest req;
    memset(&req, 0, sizeof(req));
    memcpy(&req.token, &g_state.token, sizeof(req.token));
    safe_strncpy(req.target_user, target, sizeof(req.target_user));
    req.role = role;
    send_msg(sockfd, MSG_ADMIN_SET_ROLE, &req, sizeof(req));

    char buf[RECV_BUF_SIZE]; uint8_t type; uint32_t len;
    if (recv_msg(sockfd, &type, buf, sizeof(buf), &len) < 0) {
        close(sockfd);
        return -1;
    }
    close(sockfd);

    if (type == MSG_ACK) {
        printf("  " CLR_GREEN "✓ Role updated" CLR_RESET "\n");
        printf("\n  " CLR_GREEN "================================================================" CLR_RESET "\n\n");
        return 0;
    }

    printf("  " CLR_RED "✗ Failed to update role" CLR_RESET "\n");
    printf("\n  " CLR_RED "================================================================" CLR_RESET "\n\n");
    return -1;
}

static int tracker_swarm_count(const char *file_id)
{
    int sockfd = connect_to(g_state.tracker_ip, g_state.tracker_port);
    if (sockfd < 0) return -1;

    send_msg(sockfd, MSG_SWARM_COUNT_REQ, file_id, (uint32_t)strlen(file_id));

    char buf[RECV_BUF_SIZE]; uint8_t type; uint32_t len;
    if (recv_msg(sockfd, &type, buf, sizeof(buf), &len) < 0) {
        close(sockfd);
        return -1;
    }
    close(sockfd);

    if (type != MSG_SWARM_COUNT_RESP || len < sizeof(int)) return -1;

    int count = 0;
    memcpy(&count, buf, sizeof(int));
    return count;
}

static int do_admin_file_stats(void)
{
    if (!g_state.logged_in || g_state.role != ROLE_ADMIN) {
        printf("  " CLR_RED "✗ Admin login required" CLR_RESET "\n");
        return -1;
    }

    int sockfd = connect_to(g_state.auth_ip, g_state.auth_port);
    if (sockfd < 0) {
        printf("  " CLR_RED "✗ Connection to auth server failed" CLR_RESET "\n");
        return -1;
    }

    struct AdminAuthRequest req;
    memset(&req, 0, sizeof(req));
    memcpy(&req.token, &g_state.token, sizeof(req.token));
    send_msg(sockfd, MSG_ADMIN_FILE_STATS, &req, sizeof(req));

    char *buf = malloc(MAX_PAYLOAD_SIZE);
    if (!buf) {
        close(sockfd);
        printf("  " CLR_RED "✗ Memory allocation failed" CLR_RESET "\n");
        return -1;
    }

    uint8_t type; uint32_t len;
    if (recv_msg(sockfd, &type, buf, MAX_PAYLOAD_SIZE, &len) < 0) {
        close(sockfd);
        free(buf);
        printf("  " CLR_RED "✗ Failed to fetch file statistics" CLR_RESET "\n");
        return -1;
    }
    close(sockfd);

    if (type != MSG_ADMIN_FILE_STATS || len < sizeof(int)) {
        free(buf);
        printf("  " CLR_RED "✗ Invalid response from auth server" CLR_RESET "\n");
        return -1;
    }

    int count = 0;
    memcpy(&count, buf, sizeof(int));
    struct FileStatsEntry *stats = (struct FileStatsEntry *)(buf + sizeof(int));

    printf("\n  " CLR_CYAN "+--------------------+---------------+----------+--------+" CLR_RESET "\n");
    printf("  " CLR_CYAN "| File Name          | Uploader      | Downloads| Peers  |" CLR_RESET "\n");
    printf("  " CLR_CYAN "+--------------------+---------------+----------+--------+" CLR_RESET "\n");
    
    for (int i = 0; i < count; i++) {
        int swarm = tracker_swarm_count(stats[i].file_id);
        if (swarm < 0) swarm = 0;
        
        char fname[19];
        strncpy(fname, stats[i].file_name, sizeof(fname) - 1);
        fname[18] = '\0';
        
        char uploader[14];
        strncpy(uploader, stats[i].uploader, sizeof(uploader) - 1);
        uploader[13] = '\0';
        
        printf("  | %-18s | %-13s | %8d | %6d |\n",
               fname,
               uploader,
               stats[i].download_count,
               swarm);
    }
    printf("  " CLR_CYAN "+--------------------+---------------+----------+--------+" CLR_RESET "\n");
    printf("\n  " CLR_GREEN "================================================================" CLR_RESET "\n\n");

    free(buf);
    return 0;
}

/* ══════════════════════════════════════════════════════════════
 *  Status
 * ══════════════════════════════════════════════════════════════ */

static void show_status(void)
{
    printf("\n  " CLR_CYAN "Peer Status" CLR_RESET "\n");
    printf("  " CLR_CYAN "─────────────────────────────────────────────────" CLR_RESET "\n");
    printf("  %-30s %s\n", "Peer ID", g_state.logged_in ? g_state.peer_id : "(not logged in)");
    printf("  %-30s %s\n", "Role", role_str(g_state.role));
    printf("  %-30s %d\n", "Listen Port", g_state.listen_port);
    printf("  %-30s %s\n", "Peer Directory", g_state.peer_dir);
    printf("  %-30s %s\n", "Downloads Directory", g_state.downloads_dir);
    printf("  %-30s %s\n", "Torrents Directory", g_state.torrents_dir);
    printf("  %-30s %s:%d\n", "Auth Server", g_state.auth_ip, g_state.auth_port);
    printf("  %-30s %s:%d\n", "Tracker Server", g_state.tracker_ip, g_state.tracker_port);
    printf("  %-30s %d\n", "Connected Peers", g_state.peer_count);
    printf("  %-30s %d\n", "Seeding Files", g_seeding_count);
    
    if (g_state.torrent.total_pieces > 0) {
        int done = 0;
        for (int i = 0; i < g_state.torrent.total_pieces; i++)
            if (g_state.piece_status[i] == PIECE_DONE) done++;
        char fname_short[20];
        strncpy(fname_short, g_state.torrent.file_name, sizeof(fname_short) - 1);
        fname_short[19] = '\0';
        printf("  %-30s %s (%d/%d)\n", "Active Transfer", fname_short, done, g_state.torrent.total_pieces);
    }
    printf("  " CLR_CYAN "─────────────────────────────────────────────────" CLR_RESET "\n");
    printf("\n  " CLR_GRAY "================================================================" CLR_RESET "\n\n");
}

/* ══════════════════════════════════════════════════════════════
 *  Signal Handler
 * ══════════════════════════════════════════════════════════════ */

static void sig_handler(int sig)
{
    (void)sig;
    printf("\n  Shutting down...\n");
    ipc_cleanup(&g_ipc);
    log_close_file();
    exit(0);
}

/* ══════════════════════════════════════════════════════════════
 *  Main
 * ══════════════════════════════════════════════════════════════ */

int main(int argc, char *argv[])
{
    /* Defaults */
    memset(&g_state, 0, sizeof(g_state));
    safe_strncpy(g_state.auth_ip, "127.0.0.1", MAX_IP_LEN);
    g_state.auth_port = DEFAULT_AUTH_PORT;
    safe_strncpy(g_state.tracker_ip, "127.0.0.1", MAX_IP_LEN);
    g_state.tracker_port = DEFAULT_TRACKER_PORT;
    g_state.listen_port  = DEFAULT_PEER_PORT;
    g_state.role = ROLE_DOWNLOADER;
    snprintf(g_state.peer_dir, sizeof(g_state.peer_dir), "peer%d", g_state.listen_port);
    safe_strncpy(g_state.key_path, PUBKEY_PATH, sizeof(g_state.key_path));
    pthread_mutex_init(&g_state.peer_lock, NULL);
    pthread_mutex_init(&g_state.piece_lock, NULL);

    /* Parse args */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--port") == 0 && i + 1 < argc)
            g_state.listen_port = atoi(argv[++i]);
        else if (strcmp(argv[i], "--tracker") == 0 && i + 1 < argc) {
            char *arg = argv[++i]; char *colon = strchr(arg, ':');
            if (colon) { *colon = '\0'; safe_strncpy(g_state.tracker_ip, arg, MAX_IP_LEN);
                g_state.tracker_port = atoi(colon + 1); }
        } else if (strcmp(argv[i], "--auth") == 0 && i + 1 < argc) {
            char *arg = argv[++i]; char *colon = strchr(arg, ':');
            if (colon) { *colon = '\0'; safe_strncpy(g_state.auth_ip, arg, MAX_IP_LEN);
                g_state.auth_port = atoi(colon + 1); }
        } else if (strcmp(argv[i], "--peer-dir") == 0 && i + 1 < argc) {
            safe_strncpy(g_state.peer_dir, argv[++i], sizeof(g_state.peer_dir));
        } else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
            safe_strncpy(g_state.key_path, argv[++i], sizeof(g_state.key_path));
        }
    }

    /* Set up per-peer local directories and data folder */
    mkdirs(g_state.peer_dir);
    
    char data_dir[512];
    snprintf(data_dir, sizeof(data_dir), "%s/.data", g_state.peer_dir);
    mkdirs(data_dir);
    
    size_t peer_dir_len = strlen(g_state.peer_dir);
    if (peer_dir_len + strlen("/downloads") + 1 > sizeof(g_state.downloads_dir) ||
        peer_dir_len + strlen("/torrents") + 1 > sizeof(g_state.torrents_dir)) {
        die("--peer-dir path too long");
    }
        safe_strncpy(g_state.downloads_dir, g_state.peer_dir, sizeof(g_state.downloads_dir));
        strncat(g_state.downloads_dir, "/downloads",
            sizeof(g_state.downloads_dir) - strlen(g_state.downloads_dir) - 1);

        safe_strncpy(g_state.torrents_dir, g_state.peer_dir, sizeof(g_state.torrents_dir));
        strncat(g_state.torrents_dir, "/torrents",
            sizeof(g_state.torrents_dir) - strlen(g_state.torrents_dir) - 1);
    mkdirs(g_state.downloads_dir);
    mkdirs(g_state.torrents_dir);

    /* Per-peer log file in .data folder. Keep thread logs out of the interactive terminal. */
    snprintf(g_peer_log_path, sizeof(g_peer_log_path), "%s/.data/peer.log", g_state.peer_dir);
    if (log_init_file_session(g_peer_log_path) == 0) {
        log_set_console_output(0);
    }

    /* Set up identity path: <peer_dir>/.data/peer_identity */
    snprintf(g_identity_path, sizeof(g_identity_path),
             "%s/.data/peer_identity", g_state.peer_dir);

    /* Set up registry path: <peer_dir>/.data/.seeding */
    snprintf(g_registry_path, sizeof(g_registry_path),
             "%s/.data/.seeding", g_state.peer_dir);

    /* Check if admin mode (special argument passed) */
    int admin_mode = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "admin") == 0) {
            admin_mode = 1;
            break;
        }
    }

    /* Admin mode: direct password authentication */
    if (admin_mode) {
        printf("\n  " CLR_CYAN "Admin Authentication" CLR_RESET "\n");
        printf("  Enter admin password: ");
        fflush(stdout);
        
        char password[MAX_PASS_LEN];
        scanf("%63s", password);
        
        int sockfd = connect_to(g_state.auth_ip, g_state.auth_port);
        if (sockfd < 0) { die("Cannot connect to auth server"); }
        
        /* Send admin login request with special peer_id "admin" */
        struct LoginRequest req;
        memset(&req, 0, sizeof(req));
        safe_strncpy(req.peer_id, "admin", MAX_ID_LEN);
        safe_strncpy(req.password, password, MAX_PASS_LEN);
        
        send_msg(sockfd, MSG_LOGIN, &req, sizeof(req));
        
        char buf[MAX_PAYLOAD_SIZE];
        uint8_t type; uint32_t len;
        if (recv_msg(sockfd, &type, buf, sizeof(buf), &len) < 0) {
            close(sockfd);
            die("Failed to receive admin auth response");
        }
        close(sockfd);
        
        if (type == MSG_LOGIN_OK && len >= sizeof(struct LoginResponse)) {
            struct LoginResponse resp;
            memcpy(&resp, buf, sizeof(resp));
            
            memcpy(&g_state.token, &resp.token, sizeof(struct Token));
            safe_strncpy(g_state.peer_id, "admin", sizeof(g_state.peer_id));
            g_state.role = resp.role;
            g_state.logged_in = 1;
            const char *role_name = role_str(g_state.role);
            printf("\n  " CLR_GREEN "✓ Admin Authentication Successful" CLR_RESET "\n");
            printf("  Role: %s\n", role_name);
            printf("\n  " CLR_CYAN "================================================================" CLR_RESET "\n\n");
        } else {
            printf("  " CLR_RED "✗ Admin authentication failed" CLR_RESET "\n");
            exit(1);
        }
    } else {
        /* Regular mode: identity-based login */
        /* Check if this is first time or returning peer */
        if (identity_load() != 0) {
            /* First time: show registration screen */
            if (do_first_time_register() != 0) {
                die("Registration failed");
            }
            /* After registration, re-load identity */
            if (identity_load() != 0) {
                die("Failed to load identity after registration");
            }
        }

        /* Auto-login with stored identity; require success or exit after retries */
        {
            int attempts = 0;
            while (do_login() != 0) {
                attempts++;
                if (attempts >= 3) {
                    printf("  " CLR_RED "✗ Login failed after 3 attempts. Exiting." CLR_RESET "\n");
                    exit(1);
                }
                printf("  Retry login (attempt %d/3)...\n", attempts+1);
            }
        }
    }

    /* Load seeded file registry and begin periodic tracker polling even
     * before login if this peer already has at least one shared file. */
    registry_load();
    if (g_seeding_count > 0) {
        g_state.is_seeding = 1;
        announce_all_to_tracker();
        start_reannounce_thread();
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* Start peer listener thread */
    pthread_t listener_tid;
    pthread_create(&listener_tid, NULL, peer_listener_thread, &g_state);
    pthread_detach(listener_tid);

    /* Banner */
    printf("\n");
    printf("  ╔══════════════════════════════════════════╗\n");
    printf("  ║   " CLR_CYAN "CipherSwarm Peer Node" CLR_RESET "                  ║\n");
    printf("  ║   Listening on port %-20d ║\n", g_state.listen_port);
    printf("  ║   Peer dir: %-28s ║\n", g_state.peer_dir);
    printf("  ╚══════════════════════════════════════════╝\n");
    printf("\n");

    /* Menu loop */
    int choice;
    while (1) {
        int is_admin = (g_state.logged_in && g_state.role == ROLE_ADMIN);

        printf("\n  " CLR_CYAN "CipherSwarm Peer Menu" CLR_RESET "\n");
        printf("  " CLR_CYAN "─────────────────────────────────────" CLR_RESET "\n");
        printf("  1. Upload file to network\n");
        printf("  2. List available files\n");
        printf("  3. Download file from swarm\n");
        printf("  4. View peer status\n");
        if (is_admin) {
            printf("  " CLR_CYAN "\n  ADMIN OPTIONS:" CLR_RESET "\n");
            printf("  " CLR_CYAN "─────────────────────────────────────" CLR_RESET "\n");
            printf("  5. List users & privileges\n");
            printf("  6. Change user role\n");
            printf("  7. View file statistics\n");
            printf("  8. Exit\n");
        } else {
            printf("  5. Exit\n");
        }
        printf("  " CLR_CYAN "─────────────────────────────────────" CLR_RESET "\n");
        printf("  Choice: "); fflush(stdout);

        if (scanf("%d", &choice) != 1) {
            while (getchar() != '\n');
            continue;
        }

        if (!is_admin) {
            switch (choice) {
                case 1: do_upload_file(); break;
                case 2: do_list_files(); break;
                case 3: do_download_file(); break;
                case 4: show_status(); break;
                case 5:
                    printf("  Goodbye!\n");
                    ipc_cleanup(&g_ipc);
                    log_close_file();
                    exit(0);
                default:
                    printf("  Invalid choice.\n");
            }
        } else {
            switch (choice) {
                case 1: do_upload_file(); break;
                case 2: do_list_files(); break;
                case 3: do_download_file(); break;
                case 4: show_status(); break;
                case 5: do_admin_list_users(); break;
                case 6: do_admin_set_role(); break;
                case 7: do_admin_file_stats(); break;
                case 8:
                    printf("  Goodbye!\n");
                    ipc_cleanup(&g_ipc);
                    log_close_file();
                    exit(0);
                default:
                    printf("  Invalid choice.\n");
            }
        }
        printf("\n");
    }

    return 0;
}
