/*
 * CipherSwarm — Auth / Metadata Server
 * Central authority: user login, RSA token issuing, torrent metadata.
 * OS Concepts: TCP sockets, pthreads, file I/O
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/stat.h>

#include "common/protocol.h"
#include "common/structs.h"
#include "common/network.h"
#include "common/crypto.h"
#include "common/utils.h"
#include "auth_server.h"

static volatile int running = 1;
static int g_server_fd = -1;

/* ── User Management ──────────────────────────────────────── */

static int parse_user_record(const char *line,
                             char *username, size_t username_cap,
                             char *password, size_t password_cap,
                             int *role_out)
{
    char tmp[256];
    safe_strncpy(tmp, line, sizeof(tmp));

    char *nl = strchr(tmp, '\n');
    if (nl) *nl = '\0';

    char *u = strtok(tmp, ":");
    char *p = strtok(NULL, ":");
    char *r = strtok(NULL, ":");

    if (!u || !p) return -1;

    safe_strncpy(username, u, username_cap);
    safe_strncpy(password, p, password_cap);
    *role_out = r ? atoi(r) : ROLE_REGULAR; /* backward compatible */
    if (*role_out < ROLE_DOWNLOADER || *role_out > ROLE_ADMIN)
        *role_out = ROLE_REGULAR;

    return 0;
}

static int parse_peer_record(const char *line,
                             char *peer_id, size_t peer_id_cap,
                             char *username, size_t username_cap,
                             char *password, size_t password_cap,
                             int *role_out);

int validate_user(const char *username, const char *password, int *role_out)
{
    FILE *fp = fopen(USERS_FILE, "r");
    if (!fp) return 0;

    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        char u[MAX_USER_LEN], p[MAX_PASS_LEN];
        int role = ROLE_REGULAR;
        if (parse_user_record(line, u, sizeof(u), p, sizeof(p), &role) < 0)
            continue;

        if (strcmp(u, username) == 0 && strcmp(p, password) == 0) {
            fclose(fp);
            if (role_out) *role_out = role;
            return 1;
        }
    }

    fclose(fp);
    return 0;
}

int register_user(const char *username, const char *password, int role)
{
    mkdirs("auth_server/data");

    FILE *fp = fopen(USERS_FILE, "a");
    if (!fp) return -1;

    fprintf(fp, "%s:%s:%d\n", username, password, role);
    fclose(fp);

    LOG_INFO("Registered user: %s role=%d", username, role);
    return 0;
}

int get_user_role(const char *username, int *role_out)
{
    FILE *fp = fopen(USERS_FILE, "r");
    if (!fp) return -1;

    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        char u[MAX_USER_LEN], p[MAX_PASS_LEN];
        int role = ROLE_REGULAR;
        if (parse_user_record(line, u, sizeof(u), p, sizeof(p), &role) < 0)
            continue;

        if (strcmp(u, username) == 0) {
            fclose(fp);
            if (role_out) *role_out = role;
            return 0;
        }
    }

    fclose(fp);
    return -1;
}

int list_users_with_roles(struct UserRoleEntry *out, int max_count)
{
    FILE *fp = fopen(PEERS_FILE, "r");
    if (!fp) return 0;

    int count = 0;
    char line[512];
    while (fgets(line, sizeof(line), fp) && count < max_count) {
        char pid[MAX_ID_LEN], u[MAX_USER_LEN], p[MAX_PASS_LEN];
        int role = ROLE_REGULAR;
        if (parse_peer_record(line, pid, sizeof(pid), u, sizeof(u), p, sizeof(p), &role) < 0)
            continue;

        safe_strncpy(out[count].username, u, MAX_USER_LEN);
        out[count].role = role;
        count++;
    }

    fclose(fp);
    return count;
}

int update_user_role(const char *username, int new_role)
{
    if (new_role != ROLE_DOWNLOADER && new_role != ROLE_REGULAR)
        return -1;

    FILE *in = fopen(PEERS_FILE, "r");
    if (!in) return -1;

    const char *tmp_path = "auth_server/data/peers.tmp";
    FILE *out = fopen(tmp_path, "w");
    if (!out) {
        fclose(in);
        return -1;
    }

    int found = 0;
    char line[512];
    while (fgets(line, sizeof(line), in)) {
        char pid[MAX_ID_LEN], u[MAX_USER_LEN], p[MAX_PASS_LEN];
        int role = ROLE_REGULAR;
        if (parse_peer_record(line, pid, sizeof(pid), u, sizeof(u), p, sizeof(p), &role) < 0)
            continue;

        if (strcmp(u, username) == 0) {
            role = new_role;
            found = 1;
        }
        fprintf(out, "%s:%s:%s:%d\n", pid, u, p, role);
    }

    fclose(in);
    fclose(out);

    if (!found) {
        unlink(tmp_path);
        return -1;
    }

    if (rename(tmp_path, PEERS_FILE) != 0) {
        unlink(tmp_path);
        return -1;
    }

    return 0;
}

/* ── Peer Registration ────────────────────────────────────── */

static int parse_peer_record(const char *line,
                             char *peer_id, size_t peer_id_cap,
                             char *username, size_t username_cap,
                             char *password, size_t password_cap,
                             int *role_out)
{
    char tmp[512];
    safe_strncpy(tmp, line, sizeof(tmp));

    char *nl = strchr(tmp, '\n');
    if (nl) *nl = '\0';

    char *pid = strtok(tmp, ":");
    char *u = strtok(NULL, ":");
    char *p = strtok(NULL, ":");
    char *r = strtok(NULL, ":");

    if (!pid || !u || !p) return -1;

    safe_strncpy(peer_id, pid, peer_id_cap);
    safe_strncpy(username, u, username_cap);
    safe_strncpy(password, p, password_cap);
    *role_out = r ? atoi(r) : ROLE_REGULAR;
    if (*role_out < ROLE_DOWNLOADER || *role_out > ROLE_ADMIN)
        *role_out = ROLE_REGULAR;

    return 0;
}

int register_peer(const char *username, const char *password, char *peer_id_out)
{
    mkdirs("auth_server/data");

    /* Check if username already exists */
    FILE *fp = fopen(PEERS_FILE, "r");
    if (fp) {
        char line[512];
        while (fgets(line, sizeof(line), fp)) {
            char pid[MAX_ID_LEN], u[MAX_USER_LEN], p[MAX_PASS_LEN];
            int role = ROLE_REGULAR;
            if (parse_peer_record(line, pid, sizeof(pid), u, sizeof(u), p, sizeof(p), &role) < 0)
                continue;
            if (strcmp(u, username) == 0) {
                fclose(fp);
                LOG_WARN("Username already exists: %s", username);
                return -1;
            }
        }
        fclose(fp);
    }

    /* Generate peer_id as SHA1 of username + current timestamp + random */
    char seed[256];
    snprintf(seed, sizeof(seed), "%s_%ld_%d", username, time(NULL), rand());
    sha1_hash_hex(seed, strlen(seed), peer_id_out);

    /* Append peer entry to peers.dat */
    fp = fopen(PEERS_FILE, "a");
    if (!fp) return -1;

    fprintf(fp, "%s:%s:%s:%d\n", peer_id_out, username, password, ROLE_REGULAR);
    fclose(fp);

    LOG_INFO("Registered peer: username=%s peer_id=%s", username, peer_id_out);
    return 0;
}

int validate_peer(const char *peer_id, const char *password, int *role_out)
{
    FILE *fp = fopen(PEERS_FILE, "r");
    if (!fp) return -1;

    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        char pid[MAX_ID_LEN], u[MAX_USER_LEN], p[MAX_PASS_LEN];
        int role = ROLE_REGULAR;
        if (parse_peer_record(line, pid, sizeof(pid), u, sizeof(u), p, sizeof(p), &role) < 0)
            continue;

        if (strcmp(pid, peer_id) == 0) {
            if (strcmp(p, password) == 0) {
                fclose(fp);
                if (role_out) *role_out = role;
                LOG_INFO("Peer login OK: %s", u);
                return 0;
            } else {
                fclose(fp);
                LOG_WARN("Invalid password for peer: %s", u);
                return -1;
            }
        }
    }

    fclose(fp);
    LOG_WARN("Peer not found: %s", peer_id);
    return -1;
}

/* Look up the CURRENT role for a peer_id from peers.dat */
static int get_peer_role(const char *peer_id, int *role_out)
{
    FILE *fp = fopen(PEERS_FILE, "r");
    if (!fp) return -1;

    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        char pid[MAX_ID_LEN], u[MAX_USER_LEN], p[MAX_PASS_LEN];
        int role = ROLE_REGULAR;
        if (parse_peer_record(line, pid, sizeof(pid), u, sizeof(u), p, sizeof(p), &role) < 0)
            continue;

        if (strcmp(pid, peer_id) == 0) {
            fclose(fp);
            if (role_out) *role_out = role;
            return 0;
        }
    }

    fclose(fp);
    return -1;
}

/* ── Token Issuing (RSA-SHA256) ───────────────────────────── */

int issue_token(const char *user_id, const char *file_id, int role,
                const char *private_key_path, struct Token *token_out)
{
    memset(token_out, 0, sizeof(struct Token));
    safe_strncpy(token_out->user_id, user_id, sizeof(token_out->user_id));
    safe_strncpy(token_out->file_id, file_id, MAX_ID_LEN);
    token_out->role = role;
    token_out->expiry = time(NULL) + TOKEN_EXPIRY_SECS;

    char signable[256];
    snprintf(signable, sizeof(signable), "%s|%s|%d|%ld",
             token_out->user_id, token_out->file_id,
             token_out->role, token_out->expiry);

    size_t sig_len = 0;
    if (rsa_sign_with_private_key(private_key_path,
                                  signable, strlen(signable),
                                  token_out->signature,
                                  sizeof(token_out->signature),
                                  &sig_len) < 0) {
        LOG_ERR("Failed to sign token for user=%s", user_id);
        return -1;
    }

    if (sig_len != SIGNATURE_LEN) {
        LOG_ERR("Unexpected signature length: %zu (expected %d)",
                sig_len, SIGNATURE_LEN);
        return -1;
    }

    LOG_INFO("Issued token: user=%s role=%d file=%s", user_id, role, file_id);
    return 0;
}

static int verify_token(const struct Token *token)
{
    if (token->expiry < time(NULL)) return 0;

    char signable[256];
    snprintf(signable, sizeof(signable), "%s|%s|%d|%ld",
             token->user_id, token->file_id, token->role, token->expiry);

    return rsa_verify_with_public_key(PUBLIC_KEY_FILE,
                                      signable, strlen(signable),
                                      token->signature, SIGNATURE_LEN) == 1;
}

static int authorize_admin(const struct Token *token)
{
    if (!verify_token(token)) return 0;
    return token->role == ROLE_ADMIN;
}

static int authorize_upload(const struct Token *token)
{
    if (!verify_token(token)) return 0;
    return token->role == ROLE_REGULAR || token->role == ROLE_ADMIN;
}

/* ── Protocol Handlers ────────────────────────────────────── */

static void handle_register_peer(int sockfd, const void *payload, uint32_t len)
{
    if (len < sizeof(struct RegisterRequest)) {
        send_msg(sockfd, MSG_REGISTER_FAIL, "BAD_REQUEST", 11);
        return;
    }

    const struct RegisterRequest *req = (const struct RegisterRequest *)payload;
    LOG_INFO("Peer registration attempt: user=%s", req->username);

    char peer_id[MAX_ID_LEN];
    if (register_peer(req->username, req->password, peer_id) == 0) {
        struct RegisterResponse resp;
        safe_strncpy(resp.peer_id, peer_id, MAX_ID_LEN);
        send_msg(sockfd, MSG_REGISTER_OK, &resp, sizeof(resp));
        LOG_INFO("Peer registered: %s → %s", req->username, peer_id);
    } else {
        send_msg(sockfd, MSG_REGISTER_FAIL, "USERNAME_EXISTS", 15);
        LOG_WARN("Peer registration failed: %s", req->username);
    }
}

static void handle_login(int sockfd, const void *payload, uint32_t len)
{
    if (len < sizeof(struct LoginRequest)) {
        send_msg(sockfd, MSG_LOGIN_FAIL, "BAD_REQUEST", 11);
        return;
    }

    const struct LoginRequest *req = (const struct LoginRequest *)payload;
    LOG_INFO("Login attempt: peer=%s", req->peer_id);

    int role = ROLE_REGULAR;
    if (validate_peer(req->peer_id, req->password, &role) == 0) {
        struct LoginResponse resp;
        memset(&resp, 0, sizeof(resp));

        if (issue_token(req->peer_id, "*", role, PRIVATE_KEY_FILE, &resp.token) < 0) {
            send_msg(sockfd, MSG_ERROR, "TOKEN_SIGN_FAIL", 15);
            return;
        }

        resp.role = role;
        send_msg(sockfd, MSG_LOGIN_OK, &resp, sizeof(resp));
        LOG_INFO("Login OK: peer=%s role=%d", req->peer_id, role);
    } else {
        send_msg(sockfd, MSG_LOGIN_FAIL, "INVALID_CREDS", 13);
        LOG_WARN("Login FAIL: %s", req->peer_id);
    }
}

static void handle_upload_torrent(int sockfd, const void *payload, uint32_t len)
{
    if (len < sizeof(struct UploadTorrentRequest)) {
        send_msg(sockfd, MSG_ERROR, "BAD_UPLOAD", 10);
        return;
    }

    const struct UploadTorrentRequest *req = (const struct UploadTorrentRequest *)payload;

    if (!verify_token(&req->token)) {
        send_msg(sockfd, MSG_ERROR, "INVALID_TOKEN", 13);
        return;
    }

    /* Look up the CURRENT role from peers.dat — not the token's stale role,
     * so admin role changes take effect immediately without re-login */
    int role = ROLE_DOWNLOADER;
    if (get_peer_role(req->token.user_id, &role) < 0) {
        send_msg(sockfd, MSG_ERROR, "UNKNOWN_PEER", 12);
        return;
    }

    if (role != ROLE_REGULAR && role != ROLE_ADMIN) {
        send_msg(sockfd, MSG_ERROR, "UPLOAD_DENIED", 13);
        return;
    }

    struct Torrent t;
    memcpy(&t, &req->torrent, sizeof(t));
    safe_strncpy(t.uploader, req->token.user_id, sizeof(t.uploader));

    if (store_torrent(&t) == 0)
        send_msg(sockfd, MSG_ACK, NULL, 0);
    else
        send_msg(sockfd, MSG_ERROR, "STORE_FAILED", 12);
}

static void handle_list_torrents(int sockfd)
{
    struct Torrent list[MAX_FILES];
    int count = list_torrents(list, MAX_FILES);

    size_t resp_size = sizeof(int) + (size_t)count * sizeof(struct Torrent);
    char *resp = malloc(resp_size);
    if (!resp) {
        send_msg(sockfd, MSG_ERROR, "OUT_OF_MEMORY", 13);
        return;
    }

    memcpy(resp, &count, sizeof(int));
    memcpy(resp + sizeof(int), list, (size_t)count * sizeof(struct Torrent));
    send_msg(sockfd, MSG_TORRENT_LIST, resp, (uint32_t)resp_size);
    free(resp);

    LOG_INFO("Listed %d torrents", count);
}

static void handle_download_torrent(int sockfd, const void *payload, uint32_t len)
{
    char file_id[MAX_ID_LEN];
    memset(file_id, 0, sizeof(file_id));
    size_t copy_len = (len < MAX_ID_LEN - 1) ? len : MAX_ID_LEN - 1;
    memcpy(file_id, payload, copy_len);

    struct Torrent t;
    if (load_torrent(file_id, &t) == 0) {
        t.download_count++;
        store_torrent(&t);
        send_msg(sockfd, MSG_TORRENT_DATA, &t, sizeof(struct Torrent));
    } else {
        send_msg(sockfd, MSG_ERROR, "NOT_FOUND", 9);
    }
}

static void handle_admin_list_users(int sockfd, const void *payload, uint32_t len)
{
    if (len < sizeof(struct AdminAuthRequest)) {
        send_msg(sockfd, MSG_ERROR, "BAD_ADMIN_REQ", 13);
        return;
    }

    const struct AdminAuthRequest *req = (const struct AdminAuthRequest *)payload;
    if (!authorize_admin(&req->token)) {
        send_msg(sockfd, MSG_ERROR, "ADMIN_DENIED", 12);
        return;
    }

    struct UserRoleEntry users[MAX_FILES];
    int count = list_users_with_roles(users, MAX_FILES);

    size_t resp_size = sizeof(int) + (size_t)count * sizeof(struct UserRoleEntry);
    char *resp = malloc(resp_size);
    if (!resp) {
        send_msg(sockfd, MSG_ERROR, "OUT_OF_MEMORY", 13);
        return;
    }

    memcpy(resp, &count, sizeof(int));
    memcpy(resp + sizeof(int), users, (size_t)count * sizeof(struct UserRoleEntry));
    send_msg(sockfd, MSG_ADMIN_LIST_USERS, resp, (uint32_t)resp_size);
    free(resp);
}

static void handle_admin_set_role(int sockfd, const void *payload, uint32_t len)
{
    if (len < sizeof(struct AdminSetRoleRequest)) {
        send_msg(sockfd, MSG_ERROR, "BAD_ADMIN_REQ", 13);
        return;
    }

    const struct AdminSetRoleRequest *req = (const struct AdminSetRoleRequest *)payload;
    if (!authorize_admin(&req->token)) {
        send_msg(sockfd, MSG_ERROR, "ADMIN_DENIED", 12);
        return;
    }

    if (strcmp(req->target_user, "admin") == 0) {
        send_msg(sockfd, MSG_ERROR, "CANNOT_EDIT_ADMIN", 17);
        return;
    }

    if (update_user_role(req->target_user, req->role) == 0) {
        send_msg(sockfd, MSG_ACK, NULL, 0);
    } else {
        send_msg(sockfd, MSG_ERROR, "SET_ROLE_FAILED", 15);
    }
}

static void handle_admin_file_stats(int sockfd, const void *payload, uint32_t len)
{
    if (len < sizeof(struct AdminAuthRequest)) {
        send_msg(sockfd, MSG_ERROR, "BAD_ADMIN_REQ", 13);
        return;
    }

    const struct AdminAuthRequest *req = (const struct AdminAuthRequest *)payload;
    if (!authorize_admin(&req->token)) {
        send_msg(sockfd, MSG_ERROR, "ADMIN_DENIED", 12);
        return;
    }

    struct Torrent list[MAX_FILES];
    int count = list_torrents(list, MAX_FILES);

    struct FileStatsEntry stats[MAX_FILES];
    for (int i = 0; i < count; i++) {
        memset(&stats[i], 0, sizeof(stats[i]));
        safe_strncpy(stats[i].file_id, list[i].file_id, MAX_ID_LEN);
        safe_strncpy(stats[i].file_name, list[i].file_name, MAX_FILENAME);
        safe_strncpy(stats[i].uploader, list[i].uploader, MAX_USER_LEN);
        stats[i].download_count = list[i].download_count;
    }

    size_t resp_size = sizeof(int) + (size_t)count * sizeof(struct FileStatsEntry);
    char *resp = malloc(resp_size);
    if (!resp) {
        send_msg(sockfd, MSG_ERROR, "OUT_OF_MEMORY", 13);
        return;
    }

    memcpy(resp, &count, sizeof(int));
    memcpy(resp + sizeof(int), stats, (size_t)count * sizeof(struct FileStatsEntry));
    send_msg(sockfd, MSG_ADMIN_FILE_STATS, resp, (uint32_t)resp_size);
    free(resp);
}

static void handle_upload_check(int sockfd, const void *payload, uint32_t len)
{
    if (len < sizeof(struct AuthzCheckRequest)) {
        send_msg(sockfd, MSG_ERROR, "BAD_AUTHZ_REQ", 13);
        return;
    }

    const struct AuthzCheckRequest *req = (const struct AuthzCheckRequest *)payload;

    /* Verify the token signature is valid */
    if (!verify_token(&req->token)) {
        send_msg(sockfd, MSG_ERROR, "INVALID_TOKEN", 13);
        return;
    }

    /* Check the CURRENT role from peers.dat (not the stale token role) */
    int role = ROLE_DOWNLOADER;
    if (get_peer_role(req->token.user_id, &role) < 0) {
        send_msg(sockfd, MSG_ERROR, "UNKNOWN_PEER", 12);
        return;
    }

    if (role == ROLE_REGULAR || role == ROLE_ADMIN) {
        send_msg(sockfd, MSG_ACK, NULL, 0);
    } else {
        send_msg(sockfd, MSG_ERROR, "UPLOAD_DENIED", 13);
    }
}

/* ── Client Handler Thread ────────────────────────────────── */

static void *client_handler(void *arg)
{
    int sockfd = *(int *)arg;
    free(arg);

    char buf[MAX_PAYLOAD_SIZE];
    uint8_t type;
    uint32_t len;

    while (recv_msg(sockfd, &type, buf, sizeof(buf), &len) == 0) {
        LOG_DEBUG("Auth recv: %s (%u bytes)", msg_type_str(type), len);

        switch (type) {
            case MSG_REGISTER_PEER:
                handle_register_peer(sockfd, buf, len);
                break;
            case MSG_LOGIN:
                handle_login(sockfd, buf, len);
                break;
            case MSG_UPLOAD_TORRENT:
                handle_upload_torrent(sockfd, buf, len);
                break;
            case MSG_LIST_TORRENTS:
                handle_list_torrents(sockfd);
                break;
            case MSG_DOWNLOAD_TORRENT:
                handle_download_torrent(sockfd, buf, len);
                break;
            case MSG_ADMIN_LIST_USERS:
                handle_admin_list_users(sockfd, buf, len);
                break;
            case MSG_ADMIN_SET_ROLE:
                handle_admin_set_role(sockfd, buf, len);
                break;
            case MSG_ADMIN_FILE_STATS:
                handle_admin_file_stats(sockfd, buf, len);
                break;
            case MSG_CHECK_UPLOAD:
                handle_upload_check(sockfd, buf, len);
                break;
            default:
                send_msg(sockfd, MSG_ERROR, "UNKNOWN", 7);
                break;
        }
    }

    close(sockfd);
    return NULL;
}

static void sig_handler(int sig)
{
    (void)sig;
    running = 0;
    if (g_server_fd >= 0) {
        close(g_server_fd);
        g_server_fd = -1;
    }
}

static void init_server(void)
{
    mkdirs("auth_server/data");
    mkdirs("auth_server/data/torrents");
    mkdirs("auth_server/keys");

    struct stat st;
    if (stat(PRIVATE_KEY_FILE, &st) != 0 || stat(PUBLIC_KEY_FILE, &st) != 0) {
        LOG_INFO("Generating RSA keypair...");
        if (generate_rsa_keypair(PRIVATE_KEY_FILE, PUBLIC_KEY_FILE) < 0)
            die("Failed to generate RSA keypair");
    }

    if (stat(USERS_FILE, &st) != 0) {
        register_user("admin", "admin123", ROLE_ADMIN);
    } else {
        int role = ROLE_DOWNLOADER;
        if (get_user_role("admin", &role) < 0)
            register_user("admin", "admin123", ROLE_ADMIN);
    }

    /* Ensure admin peer exists in peers.dat with fixed peer_id "admin" */
    if (stat(PEERS_FILE, &st) != 0) {
        /* First time: create admin peer entry directly */
        FILE *fp = fopen(PEERS_FILE, "w");
        if (fp) {
            fprintf(fp, "admin:admin:admin_password:%d\n", ROLE_ADMIN);
            fclose(fp);
            LOG_INFO("Created admin peer: peer_id=admin password=admin_password");
        }
    } else {
        /* Check if admin peer exists, create if missing */
        int role = ROLE_ADMIN;
        if (validate_peer("admin", "admin_password", &role) < 0) {
            /* Admin peer doesn't exist, append it */
            FILE *fp = fopen(PEERS_FILE, "a");
            if (fp) {
                fprintf(fp, "admin:admin:admin_password:%d\n", ROLE_ADMIN);
                fclose(fp);
                LOG_INFO("Added missing admin peer: peer_id=admin password=admin_password");
            }
        }
    }
}

int main(int argc, char *argv[])
{
    int port = DEFAULT_AUTH_PORT;
    if (argc > 1) port = atoi(argv[1]);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sig_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    init_server();

    g_server_fd = create_server_socket(port);
    if (g_server_fd < 0) die("Failed to start auth server");

    printf("\n");
    printf("  ╔══════════════════════════════════════════╗\n");
    printf("  ║   " CLR_CYAN "CipherSwarm Auth/Metadata Server" CLR_RESET "      ║\n");
    printf("  ║   Listening on port %-20d ║\n", port);
    printf("  ╚══════════════════════════════════════════╝\n\n");

    while (running) {
        struct sockaddr_in addr;
        socklen_t alen = sizeof(addr);
        int *cfd = malloc(sizeof(int));
        if (!cfd) continue;

        *cfd = accept(g_server_fd, (struct sockaddr *)&addr, &alen);
        if (*cfd < 0) {
            free(cfd);
            continue;
        }

        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr.sin_addr, ip, sizeof(ip));
        LOG_INFO("Client: %s:%d", ip, ntohs(addr.sin_port));

        pthread_t tid;
        pthread_create(&tid, NULL, client_handler, cfd);
        pthread_detach(tid);
    }

    if (g_server_fd >= 0) close(g_server_fd);
    return 0;
}
