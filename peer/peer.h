#ifndef PEER_H
#define PEER_H

#include "common/protocol.h"
#include "common/structs.h"
#include <pthread.h>

/* ── Peer Configuration ───────────────────────────────────── */

#define MAX_CONNECTED_PEERS 32
#define PUBKEY_PATH         "auth_server/keys/server_public.pem"
#define DOWNLOADS_DIR       "downloads"

/* ── Connected Peer Info ──────────────────────────────────── */

struct ConnectedPeer {
    int    sockfd;
    char   peer_id[MAX_ID_LEN];
    char   ip[MAX_IP_LEN];
    int    port;
    int   *remote_bitfield;     /* what pieces they have      */
    int    total_pieces;
    int    active;              /* 1 = connected               */
};

/* ── Peer Global State ────────────────────────────────────── */

struct PeerState {
    /* Identity */
    char peer_id[MAX_ID_LEN];      /* 41 bytes: 40 hex + null */
    int  listen_port;
    char peer_dir[256];            /* per-peer root: e.g. peer1/ */
    char downloads_dir[256];       /* per-peer downloads directory */
    char torrents_dir[256];        /* per-peer torrent storage */
    char key_path[256];            /* auth public key path */

    /* Auth */
    char          auth_ip[MAX_IP_LEN];
    int           auth_port;
    struct Token  token;
    int           logged_in;
    int           role;

    /* Tracker */
    char tracker_ip[MAX_IP_LEN];
    int  tracker_port;

    /* Active transfer */
    struct Torrent    torrent;
    struct FileState  file_state;
    int               piece_status[MAX_FILES];   /* 0=free, 1=downloading, 2=done */

    /* Connected peers */
    struct ConnectedPeer peers[MAX_CONNECTED_PEERS];
    int                  peer_count;
    pthread_mutex_t      peer_lock;

    /* Piece selection lock */
    pthread_mutex_t      piece_lock;

    /* Transfer state */
    int  is_seeding;
    int  is_downloading;
    int  download_complete;
};

/* ── Piece Status Constants ───────────────────────────────── */
#define PIECE_FREE        0
#define PIECE_DOWNLOADING 1
#define PIECE_DONE        2

/* ── Function Declarations ────────────────────────────────── */

/* torrent.c */
int create_torrent_from_file(const char *filepath, struct Torrent *t,
                              const char *tracker_ip, int tracker_port,
                              const char *auth_ip, int auth_port);

/* disk.c */
int write_piece(const char *filepath, int piece_index, int piece_size,
                const void *data, int data_len);
int read_piece(const char *filepath, int piece_index, int piece_size,
               void *buf, int buf_size);
int create_empty_file(const char *filepath, long file_size);

/* scheduler.c */
int scheduler_next_piece(struct PeerState *state, int peer_index);

/* network.c (peer) */
void *peer_listener_thread(void *arg);
int connect_to_peer_and_handshake(struct PeerState *state,
                                   const char *ip, int port);

/* download.c */
int start_download(struct PeerState *state);

/* upload.c */
void handle_peer_request(struct PeerState *state, int peer_idx,
                         const struct RequestPayload *req);

#endif /* PEER_H */
