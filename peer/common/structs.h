#ifndef STRUCTS_H
#define STRUCTS_H

#include <time.h>
#include "protocol.h"

/* ══════════════════════════════════════════════════════════════
 *  Token — issued by auth server, verified locally by peers
 * ══════════════════════════════════════════════════════════════ */
struct Token {
    char          user_id[MAX_ID_LEN];
    char          file_id[MAX_ID_LEN];
    int           role;
    long          expiry;                      /* Unix timestamp         */
    unsigned char signature[SIGNATURE_LEN];    /* RSA-SHA256 signature   */
};

/* ══════════════════════════════════════════════════════════════
 *  Torrent — file metadata distributed by auth server
 * ══════════════════════════════════════════════════════════════ */
#define SHA1_HEX_LEN 41   /* 40 hex chars + null */

struct Torrent {
    char   file_name[MAX_FILENAME];
    long   file_size;

    int    piece_size;
    int    total_pieces;

    char   piece_hashes[MAX_FILES][SHA1_HEX_LEN];  /* SHA1 hex per piece   */

    char   file_id[MAX_ID_LEN];                     /* SHA1 of metadata     */

    char   tracker_ip[MAX_IP_LEN];
    int    tracker_port;

    char   auth_server_ip[MAX_IP_LEN];
    int    auth_server_port;

    char   uploader[MAX_USER_LEN];
    int    download_count;
};

/* ══════════════════════════════════════════════════════════════
 *  FileState — per-file download/upload state at a peer
 * ══════════════════════════════════════════════════════════════ */
struct FileState {
    char   file_id[MAX_ID_LEN];
    char   file_name[MAX_FILENAME];

    int    total_pieces;
    int   *bitfield;          /* 1 = have piece, 0 = missing (shared mem) */

    int    is_complete;
};

/* ══════════════════════════════════════════════════════════════
 *  PeerInfo — entry in the tracker's swarm table
 * ══════════════════════════════════════════════════════════════ */
struct PeerInfo {
    char   peer_id[MAX_ID_LEN];
    char   ip[MAX_IP_LEN];
    int    port;
    time_t last_seen;
};

/* ══════════════════════════════════════════════════════════════
 *  IPC Message — used with System V message queues
 * ══════════════════════════════════════════════════════════════ */
#define IPC_MSG_DATA_SIZE  (PIECE_SIZE + 64)

struct IpcMsg {
    long mtype;                            /* message type (required by SysV) */
    int  piece_index;
    int  data_len;
    char data[IPC_MSG_DATA_SIZE];
};

/* IPC message types */
#define IPC_WRITE_PIECE     1
#define IPC_READ_PIECE      2
#define IPC_READ_RESPONSE   3
#define IPC_HAVE_NOTIFY     4
#define IPC_DOWNLOAD_PIECE  5
#define IPC_UPLOAD_REQUEST  6
#define IPC_UPLOAD_RESPONSE 7
#define IPC_SHUTDOWN        99

/* ══════════════════════════════════════════════════════════════
 *  Peer Identity — stored locally on peer
 * ══════════════════════════════════════════════════════════════ */
struct PeerIdentity {
    char peer_id[MAX_ID_LEN];       /* Unique ID from auth server      */
    char username[MAX_USER_LEN];    /* Username chosen during signup   */
};

/* ══════════════════════════════════════════════════════════════
 *  Registration request / response payloads
 * ══════════════════════════════════════════════════════════════ */
struct RegisterRequest {
    char username[MAX_USER_LEN];
    char password[MAX_PASS_LEN];
};

struct RegisterResponse {
    char peer_id[MAX_ID_LEN];    /* Unique identifier from auth server */
};

/* ══════════════════════════════════════════════════════════════
 *  Login request / response payloads
 * ══════════════════════════════════════════════════════════════ */
struct LoginRequest {
    char peer_id[MAX_ID_LEN];    /* Unique peer identifier */
    char password[MAX_PASS_LEN];
};

struct LoginResponse {
    struct Token token;
    int          role;
};

struct UploadTorrentRequest {
    struct Token   token;
    struct Torrent torrent;
};

struct AdminAuthRequest {
    struct Token token;
};

struct AuthzCheckRequest {
    struct Token token;
};

struct AdminSetRoleRequest {
    struct Token token;
    char         target_user[MAX_USER_LEN];
    int          role;
};

struct UserRoleEntry {
    char username[MAX_USER_LEN];
    int  role;
};

struct FileStatsEntry {
    char file_id[MAX_ID_LEN];
    char file_name[MAX_FILENAME];
    char uploader[MAX_USER_LEN];
    int  download_count;
};

struct AnnounceRequest {
    char peer_id[MAX_ID_LEN];
    char file_id[MAX_ID_LEN];
    char ip[MAX_IP_LEN];
    int  port;
};

struct PeerListEntry {
    char ip[MAX_IP_LEN];
    int  port;
};

struct RequestPayload {
    int           piece_index;
    struct Token  token;
};

struct PiecePayload {
    int  piece_index;
    int  data_len;
    char data[PIECE_SIZE];
};

struct HavePayload {
    int piece_index;
};

struct HandshakePayload {
    char peer_id[MAX_ID_LEN];
    char file_id[MAX_ID_LEN];
    int  listen_port;
};

struct BitfieldPayload {
    int total_pieces;
    int bits[];   /* flexible array member */
};

#endif /* STRUCTS_H */
