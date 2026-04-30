/*
 * ═══════════════════════════════════════════════════════════════
 *  CipherSwarm — Tracker Server
 *
 *  Lightweight, stateless peer discovery service.
 *  Maintains a mapping of file_id → list of peers (ip, port).
 *
 *  OS Concepts: TCP sockets, pthreads, mutexes
 * ═══════════════════════════════════════════════════════════════
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <arpa/inet.h>
#include <time.h>

#include "common/protocol.h"
#include "common/structs.h"
#include "common/network.h"
#include "common/utils.h"

/* ── Swarm Table ──────────────────────────────────────────── */

#define MAX_SWARM_FILES  256
#define MAX_SWARM_PEERS  128

struct Swarm {
    char            file_id[MAX_ID_LEN];
    struct PeerInfo peers[MAX_SWARM_PEERS];
    int             peer_count;
};

static struct Swarm  swarm_table[MAX_SWARM_FILES];
static int           swarm_count = 0;
static pthread_mutex_t swarm_lock = PTHREAD_MUTEX_INITIALIZER;

static volatile int running = 1;
static int g_server_fd = -1;

/* ── Swarm Helpers ────────────────────────────────────────── */

/* Find or create a swarm for a file_id. Must hold swarm_lock. */
static struct Swarm *find_or_create_swarm(const char *file_id)
{
    for (int i = 0; i < swarm_count; i++) {
        if (strcmp(swarm_table[i].file_id, file_id) == 0)
            return &swarm_table[i];
    }

    if (swarm_count >= MAX_SWARM_FILES) {
        LOG_WARN("Swarm table full, cannot track new file: %s", file_id);
        return NULL;
    }

    struct Swarm *s = &swarm_table[swarm_count++];
    memset(s, 0, sizeof(*s));
    safe_strncpy(s->file_id, file_id, MAX_ID_LEN);
    return s;
}

/* Find a swarm by file_id. Must hold swarm_lock. */
static struct Swarm *find_swarm(const char *file_id)
{
    for (int i = 0; i < swarm_count; i++) {
        if (strcmp(swarm_table[i].file_id, file_id) == 0)
            return &swarm_table[i];
    }
    return NULL;
}

/* ── Protocol Handlers ────────────────────────────────────── */

static void handle_announce(int sockfd, const void *payload, uint32_t len)
{
    if (len < sizeof(struct AnnounceRequest)) {
        send_msg(sockfd, MSG_ERROR, "BAD_ANNOUNCE", 12);
        return;
    }

    const struct AnnounceRequest *req = (const struct AnnounceRequest *)payload;

    pthread_mutex_lock(&swarm_lock);

    struct Swarm *s = find_or_create_swarm(req->file_id);
    if (!s) {
        pthread_mutex_unlock(&swarm_lock);
        send_msg(sockfd, MSG_ERROR, "SWARM_FULL", 10);
        return;
    }

    /* Check if peer already exists, update last_seen */
    int found = 0;
    for (int i = 0; i < s->peer_count; i++) {
        if (strcmp(s->peers[i].peer_id, req->peer_id) == 0) {
            safe_strncpy(s->peers[i].ip, req->ip, MAX_IP_LEN);
            s->peers[i].port      = req->port;
            s->peers[i].last_seen = time(NULL);
            found = 1;
            break;
        }
    }

    /* Add new peer */
    if (!found && s->peer_count < MAX_SWARM_PEERS) {
        struct PeerInfo *p = &s->peers[s->peer_count++];
        safe_strncpy(p->peer_id, req->peer_id, sizeof(p->peer_id));
        safe_strncpy(p->ip, req->ip, MAX_IP_LEN);
        p->port      = req->port;
        p->last_seen = time(NULL);
    }

    pthread_mutex_unlock(&swarm_lock);

    LOG_INFO("ANNOUNCE: peer=%s file=%s at %s:%d (swarm size: %d)",
             req->peer_id, req->file_id, req->ip, req->port, s->peer_count);

    send_msg(sockfd, MSG_ACK, NULL, 0);
}

static void handle_get_peers(int sockfd, const void *payload, uint32_t len)
{
    if (len < MAX_ID_LEN - 1) {
        send_msg(sockfd, MSG_ERROR, "BAD_GET_PEERS", 13);
        return;
    }

    char file_id[MAX_ID_LEN];
    memset(file_id, 0, sizeof(file_id));
    memcpy(file_id, payload, (len < MAX_ID_LEN - 1) ? len : MAX_ID_LEN - 1);

    pthread_mutex_lock(&swarm_lock);

    struct Swarm *s = find_swarm(file_id);
    if (!s || s->peer_count == 0) {
        pthread_mutex_unlock(&swarm_lock);
        /* Send empty peer list */
        int zero = 0;
        send_msg(sockfd, MSG_PEER_LIST, &zero, sizeof(int));
        return;
    }

    /* Build response: [int count][PeerListEntry * count] */
    int count = s->peer_count;
    size_t resp_size = sizeof(int) + count * sizeof(struct PeerListEntry);
    char *resp = malloc(resp_size);
    if (!resp) {
        pthread_mutex_unlock(&swarm_lock);
        send_msg(sockfd, MSG_ERROR, "OUT_OF_MEMORY", 13);
        return;
    }

    memcpy(resp, &count, sizeof(int));
    struct PeerListEntry *entries = (struct PeerListEntry *)(resp + sizeof(int));
    for (int i = 0; i < count; i++) {
        safe_strncpy(entries[i].ip, s->peers[i].ip, MAX_IP_LEN);
        entries[i].port = s->peers[i].port;
    }

    pthread_mutex_unlock(&swarm_lock);

    LOG_INFO("GET_PEERS: file=%s → %d peers", file_id, count);

    send_msg(sockfd, MSG_PEER_LIST, resp, (uint32_t)resp_size);
    free(resp);
}

static void handle_swarm_count(int sockfd, const void *payload, uint32_t len)
{
    if (len < 1) {
        send_msg(sockfd, MSG_ERROR, "BAD_SWARM_REQ", 13);
        return;
    }

    char file_id[MAX_ID_LEN];
    memset(file_id, 0, sizeof(file_id));
    size_t copy_len = (len < MAX_ID_LEN - 1) ? len : MAX_ID_LEN - 1;
    memcpy(file_id, payload, copy_len);

    int count = 0;
    pthread_mutex_lock(&swarm_lock);
    struct Swarm *s = find_swarm(file_id);
    if (s) count = s->peer_count;
    pthread_mutex_unlock(&swarm_lock);

    send_msg(sockfd, MSG_SWARM_COUNT_RESP, &count, sizeof(count));
}

static void handle_leave(int sockfd, const void *payload, uint32_t len)
{
    if (len < sizeof(struct AnnounceRequest)) {
        send_msg(sockfd, MSG_ERROR, "BAD_LEAVE", 9);
        return;
    }

    const struct AnnounceRequest *req = (const struct AnnounceRequest *)payload;

    pthread_mutex_lock(&swarm_lock);

    struct Swarm *s = find_swarm(req->file_id);
    if (s) {
        for (int i = 0; i < s->peer_count; i++) {
            if (strcmp(s->peers[i].peer_id, req->peer_id) == 0) {
                /* Shift remaining peers */
                memmove(&s->peers[i], &s->peers[i + 1],
                        (s->peer_count - i - 1) * sizeof(struct PeerInfo));
                s->peer_count--;
                LOG_INFO("LEAVE: peer=%s left file=%s (swarm size: %d)",
                         req->peer_id, req->file_id, s->peer_count);
                break;
            }
        }
    }

    pthread_mutex_unlock(&swarm_lock);
    send_msg(sockfd, MSG_ACK, NULL, 0);
}

/* ── Timeout Reaper Thread ────────────────────────────────── */

static void *reaper_thread(void *arg)
{
    (void)arg;

    while (running) {
        sleep(30);
        time_t now = time(NULL);

        pthread_mutex_lock(&swarm_lock);

        for (int i = 0; i < swarm_count; i++) {
            struct Swarm *s = &swarm_table[i];
            for (int j = 0; j < s->peer_count; ) {
                if (now - s->peers[j].last_seen > TRACKER_TIMEOUT_SECS) {
                    LOG_INFO("Reaper: removing stale peer %s from file %s",
                             s->peers[j].peer_id, s->file_id);
                    memmove(&s->peers[j], &s->peers[j + 1],
                            (s->peer_count - j - 1) * sizeof(struct PeerInfo));
                    s->peer_count--;
                } else {
                    j++;
                }
            }
        }

        pthread_mutex_unlock(&swarm_lock);
    }

    return NULL;
}

/* ── Client Handler Thread ────────────────────────────────── */

static void *client_handler(void *arg)
{
    int sockfd = *(int *)arg;
    free(arg);

    char buf[RECV_BUF_SIZE];
    uint8_t type;
    uint32_t len;

    while (recv_msg(sockfd, &type, buf, sizeof(buf), &len) == 0) {
        LOG_DEBUG("Tracker received: %s (%u bytes)", msg_type_str(type), len);

        switch (type) {
            case MSG_ANNOUNCE:
                handle_announce(sockfd, buf, len);
                break;
            case MSG_GET_PEERS:
                handle_get_peers(sockfd, buf, len);
                break;
            case MSG_LEAVE:
                handle_leave(sockfd, buf, len);
                break;
            case MSG_SWARM_COUNT_REQ:
                handle_swarm_count(sockfd, buf, len);
                break;
            default:
                LOG_WARN("Unknown message type: 0x%02x", type);
                send_msg(sockfd, MSG_ERROR, "UNKNOWN_MSG", 11);
                break;
        }
    }

    LOG_INFO("Client disconnected");
    close(sockfd);
    return NULL;
}

/* ── Signal Handler ───────────────────────────────────────── */

static void sig_handler(int sig)
{
    (void)sig;
    running = 0;
    if (g_server_fd >= 0) {
        close(g_server_fd);
        g_server_fd = -1;
    }
}

/* ── Main ─────────────────────────────────────────────────── */

int main(int argc, char *argv[])
{
    int port = DEFAULT_TRACKER_PORT;
    if (argc > 1) port = atoi(argv[1]);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sig_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;  /* no SA_RESTART: let accept() break on signal */
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    g_server_fd = create_server_socket(port);
    if (g_server_fd < 0) die("Failed to start tracker");

    printf("\n");
    printf("  ╔══════════════════════════════════════════╗\n");
    printf("  ║   " CLR_CYAN "CipherSwarm Tracker" CLR_RESET "                    ║\n");
    printf("  ║   Listening on port %-20d ║\n", port);
    printf("  ╚══════════════════════════════════════════╝\n");
    printf("\n");

    /* Start reaper thread */
    pthread_t reaper_tid;
    pthread_create(&reaper_tid, NULL, reaper_thread, NULL);
    pthread_detach(reaper_tid);

    /* Accept loop */
    while (running) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);

        int *client_fd = malloc(sizeof(int));
        *client_fd = accept(g_server_fd, (struct sockaddr *)&client_addr, &addr_len);

        if (*client_fd < 0) {
            free(client_fd);
            if (running) LOG_ERR("accept() failed: %s", strerror(errno));
            continue;
        }

        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
        LOG_INFO("Client connected: %s:%d", client_ip, ntohs(client_addr.sin_port));

        pthread_t tid;
        pthread_create(&tid, NULL, client_handler, client_fd);
        pthread_detach(tid);
    }

    if (g_server_fd >= 0) close(g_server_fd);
    LOG_INFO("Tracker stopped.");
    return 0;
}
