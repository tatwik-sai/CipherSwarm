#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>

/*
 * CipherSwarm Wire Protocol
 * All messages use: [MsgHeader][Payload]
 * Header is 5 bytes: 1 byte type + 4 bytes payload length (network byte order)
 */

/* ── Auth Server Messages ─────────────────────────────────── */
#define MSG_LOGIN            0x01
#define MSG_LOGIN_OK         0x02
#define MSG_LOGIN_FAIL       0x03
#define MSG_UPLOAD_TORRENT   0x04
#define MSG_LIST_TORRENTS    0x05
#define MSG_DOWNLOAD_TORRENT 0x06
#define MSG_TORRENT_DATA     0x07
#define MSG_TORRENT_LIST     0x08
#define MSG_ADMIN_LIST_USERS 0x09
#define MSG_ADMIN_SET_ROLE   0x0A
#define MSG_ADMIN_FILE_STATS 0x0B
#define MSG_CHECK_UPLOAD     0x0C

/* ── Tracker Messages ─────────────────────────────────────── */
#define MSG_ANNOUNCE         0x10
#define MSG_GET_PEERS        0x11
#define MSG_PEER_LIST        0x12
#define MSG_LEAVE            0x13
#define MSG_ACK              0x14
#define MSG_SWARM_COUNT_REQ  0x15
#define MSG_SWARM_COUNT_RESP 0x16

/* ── Peer-to-Peer Messages ────────────────────────────────── */
#define MSG_HANDSHAKE        0x20
#define MSG_BITFIELD         0x21
#define MSG_REQUEST          0x22
#define MSG_PIECE            0x23
#define MSG_HAVE             0x24

/* ── Generic ──────────────────────────────────────────────── */
#define MSG_ERROR            0xFF

/* ── System Constants ─────────────────────────────────────── */
#define PIECE_SIZE           (256 * 1024)   /* 256 KB per piece          */
#define MAX_PEERS            64
#define MAX_FILES            128
#define MAX_FILENAME         256
#define MAX_ID_LEN           41             /* 40 hex chars + null       */
#define MAX_USER_LEN         32
#define MAX_PASS_LEN         64
#define MAX_IP_LEN           20
#define SIGNATURE_LEN        256            /* RSA 2048 signature bytes  */
#define TOKEN_EXPIRY_SECS    3600           /* 1 hour                    */
#define TRACKER_TIMEOUT_SECS 120            /* remove peer after 2 min   */
#define MAX_PAYLOAD_SIZE     (PIECE_SIZE + 1024)
#define RECV_BUF_SIZE        4096
#define LISTEN_BACKLOG       32

/* ── Default Ports ────────────────────────────────────────── */
#define DEFAULT_AUTH_PORT    8080
#define DEFAULT_TRACKER_PORT 9090
#define DEFAULT_PEER_PORT    6001

/* ── Peer Role Types ─────────────────────────────────────── */
#define ROLE_DOWNLOADER      0
#define ROLE_REGULAR         1
#define ROLE_ADMIN           2

/* ── Wire Protocol Header ────────────────────────────────── */
struct MsgHeader {
    uint8_t  type;
    uint32_t length;   /* payload length, network byte order */
} __attribute__((packed));

#define HEADER_SIZE sizeof(struct MsgHeader)

/* ── Readable message type name (for logging) ─────────────── */
static inline const char *msg_type_str(uint8_t type) {
    switch (type) {
        case MSG_LOGIN:            return "LOGIN";
        case MSG_LOGIN_OK:         return "LOGIN_OK";
        case MSG_LOGIN_FAIL:       return "LOGIN_FAIL";
        case MSG_UPLOAD_TORRENT:   return "UPLOAD_TORRENT";
        case MSG_LIST_TORRENTS:    return "LIST_TORRENTS";
        case MSG_DOWNLOAD_TORRENT: return "DOWNLOAD_TORRENT";
        case MSG_TORRENT_DATA:     return "TORRENT_DATA";
        case MSG_TORRENT_LIST:     return "TORRENT_LIST";
        case MSG_ADMIN_LIST_USERS: return "ADMIN_LIST_USERS";
        case MSG_ADMIN_SET_ROLE:   return "ADMIN_SET_ROLE";
        case MSG_ADMIN_FILE_STATS: return "ADMIN_FILE_STATS";
        case MSG_ANNOUNCE:         return "ANNOUNCE";
        case MSG_GET_PEERS:        return "GET_PEERS";
        case MSG_PEER_LIST:        return "PEER_LIST";
        case MSG_LEAVE:            return "LEAVE";
        case MSG_ACK:              return "ACK";
        case MSG_SWARM_COUNT_REQ:  return "SWARM_COUNT_REQ";
        case MSG_SWARM_COUNT_RESP: return "SWARM_COUNT_RESP";
        case MSG_HANDSHAKE:        return "HANDSHAKE";
        case MSG_BITFIELD:         return "BITFIELD";
        case MSG_REQUEST:          return "REQUEST";
        case MSG_PIECE:            return "PIECE";
        case MSG_HAVE:             return "HAVE";
        case MSG_ERROR:            return "ERROR";
        default:                   return "UNKNOWN";
    }
}

#endif /* PROTOCOL_H */
