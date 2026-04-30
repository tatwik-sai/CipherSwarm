/*
 * CipherSwarm — Upload Manager
 * Handles incoming piece requests, verifies RSA-signed tokens, serves pieces.
 * OS Concepts: signature verification, file locking (via disk.c)
 */

#include "peer.h"
#include "common/network.h"
#include "common/crypto.h"
#include "common/utils.h"

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* ── Verify a token using auth server public key ───────────── */

static int verify_token(struct PeerState *state,
                        const struct Token *token,
                        const char *expected_file_id)
{
    /* Check expiry */
    if (token->expiry < time(NULL)) {
        LOG_WARN("Token expired for user %s", token->user_id);
        return 0;
    }

    char signable[256];
    snprintf(signable, sizeof(signable), "%s|%s|%d|%ld",
             token->user_id, token->file_id, token->role, token->expiry);

    /* Verify RSA signature with public key */
    if (rsa_verify_with_public_key(state->key_path,
                                   signable, strlen(signable),
                                   token->signature, SIGNATURE_LEN) != 1) {
        LOG_WARN("Invalid RSA signature for user %s", token->user_id);
        return 0;
    }

    /* Check file_id match ("*" = wildcard) */
    if (strcmp(token->file_id, "*") != 0 &&
        strcmp(token->file_id, expected_file_id) != 0) {
        LOG_WARN("Token file_id mismatch");
        return 0;
    }

    return 1;
}

/* ── Handle a REQUEST from a peer ─────────────────────────── */

void handle_peer_request(struct PeerState *state, int peer_idx,
                         const struct RequestPayload *req)
{
    struct ConnectedPeer *cp = &state->peers[peer_idx];
    int piece_index = req->piece_index;

    LOG_INFO("Upload request: piece %d from %s", piece_index, cp->peer_id);

    if (piece_index < 0 || piece_index >= state->torrent.total_pieces) {
        send_msg(cp->sockfd, MSG_ERROR, "INVALID_PIECE", 13);
        return;
    }

    /* Verify token */
    if (!verify_token(state, &req->token, state->torrent.file_id)) {
        send_msg(cp->sockfd, MSG_ERROR, "INVALID_TOKEN", 13);
        return;
    }

    /* Check we have this piece */
    pthread_mutex_lock(&state->piece_lock);
    int have = (state->piece_status[piece_index] == PIECE_DONE);
    pthread_mutex_unlock(&state->piece_lock);

    if (!have) {
        send_msg(cp->sockfd, MSG_ERROR, "NO_PIECE", 8);
        return;
    }

    /* Calculate actual size (last piece may be smaller) */
    int piece_size = state->torrent.piece_size;
    int actual_size = piece_size;
    if (piece_index == state->torrent.total_pieces - 1) {
        long rem = state->torrent.file_size - (long)piece_index * piece_size;
        if (rem < piece_size) actual_size = (int)rem;
    }

    /* Read piece from disk.
     * Prefer peer-specific storage (original upload path), then fallback
     * to downloads for peers that became seeders after downloading. */
    char filepath[512];
    snprintf(filepath, sizeof(filepath), "%s/%s",
             state->downloads_dir, state->torrent.file_name);
    if (access(filepath, R_OK) != 0) {
        send_msg(cp->sockfd, MSG_ERROR, "READ_FAILED", 11);
        return;
    }

    char piece_data[PIECE_SIZE];
    int nread = read_piece(filepath, piece_index, piece_size,
                           piece_data, actual_size);
    if (nread < 0) {
        send_msg(cp->sockfd, MSG_ERROR, "READ_FAILED", 11);
        return;
    }

    /* Send PIECE: [piece_index][data_len][data] */
    size_t resp_size = sizeof(int) * 2 + nread;
    char *resp = malloc(resp_size);
    memcpy(resp, &piece_index, sizeof(int));
    memcpy(resp + sizeof(int), &nread, sizeof(int));
    memcpy(resp + sizeof(int) * 2, piece_data, nread);

    send_msg(cp->sockfd, MSG_PIECE, resp, (uint32_t)resp_size);
    free(resp);

    LOG_INFO("✓ Uploaded piece %d (%d bytes) to %s",
             piece_index, nread, cp->peer_id);
}
