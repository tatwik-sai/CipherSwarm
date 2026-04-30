/*
 * ═══════════════════════════════════════════════════════════════
 *  CipherSwarm — Peer Network Module
 *
 *  Handles incoming peer connections (listener thread),
 *  outgoing peer connections (handshake + bitfield exchange),
 *  and per-connection message handling.
 *
 *  OS Concepts: TCP sockets, pthreads (thread per connection)
 * ═══════════════════════════════════════════════════════════════
 */

#include "peer.h"
#include "common/network.h"
#include "common/crypto.h"
#include "common/utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>

/* ══════════════════════════════════════════════════════════════
 *  Add a connected peer to the state
 * ══════════════════════════════════════════════════════════════ */

static int add_peer(struct PeerState *state, int sockfd,
                    const char *peer_id, const char *ip, int port)
{
    pthread_mutex_lock(&state->peer_lock);

    if (state->peer_count >= MAX_CONNECTED_PEERS) {
        pthread_mutex_unlock(&state->peer_lock);
        LOG_WARN("Max peers reached, rejecting %s", peer_id);
        return -1;
    }

    int idx = state->peer_count;
    struct ConnectedPeer *cp = &state->peers[idx];
    memset(cp, 0, sizeof(*cp));

    cp->sockfd = sockfd;
    safe_strncpy(cp->peer_id, peer_id, sizeof(cp->peer_id));
    safe_strncpy(cp->ip, ip, MAX_IP_LEN);
    cp->port   = port;
    cp->active = 1;
    cp->total_pieces = state->torrent.total_pieces;

    if (cp->total_pieces > 0) {
        cp->remote_bitfield = calloc(cp->total_pieces, sizeof(int));
    }

    state->peer_count++;
    pthread_mutex_unlock(&state->peer_lock);

    LOG_INFO("Added peer [%d]: %s (%s:%d)", idx, peer_id, ip, port);
    return idx;
}

/* ══════════════════════════════════════════════════════════════
 *  Send our bitfield to a peer
 * ══════════════════════════════════════════════════════════════ */

static int send_bitfield(struct PeerState *state, int sockfd)
{
    int total = state->torrent.total_pieces;
    if (total <= 0) return 0;

    size_t payload_size = sizeof(int) + total * sizeof(int);
    char *payload = malloc(payload_size);
    if (!payload) return -1;

    memcpy(payload, &total, sizeof(int));
    memcpy(payload + sizeof(int), state->piece_status, total * sizeof(int));

    /* Convert piece_status to bitfield: 2 (done) → 1, else 0 */
    int *bits = (int *)(payload + sizeof(int));
    for (int i = 0; i < total; i++) {
        bits[i] = (state->piece_status[i] == PIECE_DONE) ? 1 : 0;
    }

    int ret = send_msg(sockfd, MSG_BITFIELD, payload, (uint32_t)payload_size);
    free(payload);
    return ret;
}

/* ══════════════════════════════════════════════════════════════
 *  Handle incoming messages from a connected peer
 * ══════════════════════════════════════════════════════════════ */

struct PeerThreadArg {
    struct PeerState *state;
    int peer_idx;
};

static void *peer_recv_thread(void *arg)
{
    struct PeerThreadArg *pta = (struct PeerThreadArg *)arg;
    struct PeerState *state = pta->state;
    int peer_idx = pta->peer_idx;
    free(pta);

    struct ConnectedPeer *cp = &state->peers[peer_idx];
    int sockfd = cp->sockfd;

    char buf[MAX_PAYLOAD_SIZE];
    uint8_t type;
    uint32_t len;

    while (cp->active && recv_msg(sockfd, &type, buf, sizeof(buf), &len) == 0) {
        switch (type) {
            case MSG_BITFIELD: {
                /* Parse remote bitfield */
                if (len >= sizeof(int)) {
                    int total;
                    memcpy(&total, buf, sizeof(int));
                    if (total == cp->total_pieces && len >= sizeof(int) + total * sizeof(int)) {
                        pthread_mutex_lock(&state->peer_lock);
                        if (cp->remote_bitfield) {
                            memcpy(cp->remote_bitfield, buf + sizeof(int),
                                   total * sizeof(int));
                        }
                        pthread_mutex_unlock(&state->peer_lock);
                        LOG_DEBUG("Received bitfield from %s (%d pieces)",
                                  cp->peer_id, total);
                    }
                }
                break;
            }

            case MSG_REQUEST: {
                /* Peer is requesting a piece from us */
                if (len >= sizeof(struct RequestPayload)) {
                    struct RequestPayload req;
                    memcpy(&req, buf, sizeof(struct RequestPayload));
                    handle_peer_request(state, peer_idx, &req);
                }
                break;
            }

            case MSG_PIECE: {
                /* Received a piece (response to our request) */
                if (len >= sizeof(int) * 2) {
                    int piece_index, data_len;
                    memcpy(&piece_index, buf, sizeof(int));
                    memcpy(&data_len, buf + sizeof(int), sizeof(int));

                    if (data_len > 0 && (size_t)(sizeof(int) * 2 + data_len) <= len) {
                        char *piece_data = buf + sizeof(int) * 2;

                        /* Verify hash */
                        if (sha1_verify(piece_data, data_len,
                                        state->torrent.piece_hashes[piece_index])) {
                            /* Build download path */
                            char filepath[512];
                            snprintf(filepath, sizeof(filepath), "%s/%s",
                                     state->downloads_dir, state->torrent.file_name);

                            /* Write piece to disk */
                            if (write_piece(filepath, piece_index,
                                           state->torrent.piece_size,
                                           piece_data, data_len) == 0) {
                                pthread_mutex_lock(&state->piece_lock);
                                state->piece_status[piece_index] = PIECE_DONE;
                                pthread_mutex_unlock(&state->piece_lock);

                                LOG_INFO("✓ Piece %d/%d downloaded and verified",
                                         piece_index + 1, state->torrent.total_pieces);

                                /* Send HAVE to all peers */
                                struct HavePayload have;
                                have.piece_index = piece_index;
                                pthread_mutex_lock(&state->peer_lock);
                                for (int i = 0; i < state->peer_count; i++) {
                                    if (state->peers[i].active) {
                                        send_msg(state->peers[i].sockfd, MSG_HAVE,
                                                 &have, sizeof(have));
                                    }
                                }
                                pthread_mutex_unlock(&state->peer_lock);
                            }
                        } else {
                            LOG_WARN("✗ Piece %d hash mismatch! Discarding.", piece_index);
                            pthread_mutex_lock(&state->piece_lock);
                            state->piece_status[piece_index] = PIECE_FREE;
                            pthread_mutex_unlock(&state->piece_lock);
                        }
                    }
                }
                break;
            }

            case MSG_HAVE: {
                /* Peer got a new piece */
                if (len >= sizeof(struct HavePayload)) {
                    struct HavePayload have;
                    memcpy(&have, buf, sizeof(have));

                    pthread_mutex_lock(&state->peer_lock);
                    if (cp->remote_bitfield && have.piece_index < cp->total_pieces) {
                        cp->remote_bitfield[have.piece_index] = 1;
                    }
                    pthread_mutex_unlock(&state->peer_lock);

                    LOG_DEBUG("Peer %s has piece %d", cp->peer_id, have.piece_index);
                }
                break;
            }

            default:
                LOG_WARN("Unknown peer message: 0x%02x from %s", type, cp->peer_id);
                break;
        }
    }

    /* Peer disconnected */
    LOG_INFO("Peer %s disconnected", cp->peer_id);
    pthread_mutex_lock(&state->peer_lock);
    cp->active = 0;
    close(sockfd);
    pthread_mutex_unlock(&state->peer_lock);

    return NULL;
}

/* ══════════════════════════════════════════════════════════════
 *  Listener thread — accepts incoming peer connections
 * ══════════════════════════════════════════════════════════════ */

void *peer_listener_thread(void *arg)
{
    struct PeerState *state = (struct PeerState *)arg;

    int server_fd = create_server_socket(state->listen_port);
    if (server_fd < 0) {
        LOG_ERR("Failed to start peer listener on port %d", state->listen_port);
        return NULL;
    }

    LOG_INFO("Peer listener started on port %d", state->listen_port);

    while (1) {
        struct sockaddr_in addr;
        socklen_t addr_len = sizeof(addr);

        int client_fd = accept(server_fd, (struct sockaddr *)&addr, &addr_len);
        if (client_fd < 0) continue;

        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr.sin_addr, client_ip, sizeof(client_ip));
        int client_port = ntohs(addr.sin_port);

        LOG_INFO("Incoming peer connection from %s:%d", client_ip, client_port);

        /* Expect HANDSHAKE */
        char buf[RECV_BUF_SIZE];
        uint8_t type;
        uint32_t len;

        if (recv_msg(client_fd, &type, buf, sizeof(buf), &len) == 0 &&
            type == MSG_HANDSHAKE && len >= sizeof(struct HandshakePayload)) {

            struct HandshakePayload hs;
            memcpy(&hs, buf, sizeof(hs));

            LOG_INFO("Handshake from peer %s for file %s", hs.peer_id, hs.file_id);

            /* Send our handshake back */
            struct HandshakePayload our_hs;
            memset(&our_hs, 0, sizeof(our_hs));
            safe_strncpy(our_hs.peer_id, state->peer_id, sizeof(our_hs.peer_id));
            safe_strncpy(our_hs.file_id, state->torrent.file_id, MAX_ID_LEN);
            our_hs.listen_port = state->listen_port;
            send_msg(client_fd, MSG_HANDSHAKE, &our_hs, sizeof(our_hs));

            /* Use the peer's actual listen port, not the ephemeral source port */
            int peer_listen_port = (hs.listen_port > 0) ? hs.listen_port : client_port;
            int idx = add_peer(state, client_fd, hs.peer_id, client_ip, peer_listen_port);
            if (idx >= 0) {
                /* Exchange bitfields */
                send_bitfield(state, client_fd);

                struct PeerThreadArg *pta = malloc(sizeof(*pta));
                pta->state = state;
                pta->peer_idx = idx;

                pthread_t tid;
                pthread_create(&tid, NULL, peer_recv_thread, pta);
                pthread_detach(tid);
            } else {
                close(client_fd);
            }
        } else {
            LOG_WARN("Invalid handshake, closing connection");
            close(client_fd);
        }
    }

    close(server_fd);
    return NULL;
}

/* ══════════════════════════════════════════════════════════════
 *  Connect to a peer (outgoing) and perform handshake
 * ══════════════════════════════════════════════════════════════ */

int connect_to_peer_and_handshake(struct PeerState *state,
                                   const char *ip, int port)
{
    int sockfd = connect_to(ip, port);
    if (sockfd < 0) return -1;

    /* Send HANDSHAKE */
    struct HandshakePayload hs;
    memset(&hs, 0, sizeof(hs));
    safe_strncpy(hs.peer_id, state->peer_id, sizeof(hs.peer_id));
    safe_strncpy(hs.file_id, state->torrent.file_id, MAX_ID_LEN);
    hs.listen_port = state->listen_port;

    if (send_msg(sockfd, MSG_HANDSHAKE, &hs, sizeof(hs)) < 0) {
        close(sockfd);
        return -1;
    }

    /* Receive HANDSHAKE response */
    char buf[RECV_BUF_SIZE];
    uint8_t type;
    uint32_t len;

    if (recv_msg(sockfd, &type, buf, sizeof(buf), &len) < 0 ||
        type != MSG_HANDSHAKE) {
        LOG_ERR("Handshake failed with %s:%d", ip, port);
        close(sockfd);
        return -1;
    }

    struct HandshakePayload remote_hs;
    memcpy(&remote_hs, buf, sizeof(remote_hs));

    /* Add peer */
    int idx = add_peer(state, sockfd, remote_hs.peer_id, ip, port);
    if (idx < 0) {
        close(sockfd);
        return -1;
    }

    /* Send our bitfield */
    send_bitfield(state, sockfd);

    /* Start recv thread for this peer */
    struct PeerThreadArg *pta = malloc(sizeof(*pta));
    pta->state = state;
    pta->peer_idx = idx;

    pthread_t tid;
    pthread_create(&tid, NULL, peer_recv_thread, pta);
    pthread_detach(tid);

    return idx;
}
