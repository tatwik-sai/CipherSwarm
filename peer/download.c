/*
 * ═══════════════════════════════════════════════════════════════
 *  CipherSwarm — Download Manager
 *
 *  Orchestrates the download process: connects to peers,
 *  requests pieces via the scheduler, and tracks progress.
 *
 *  OS Concepts: threads (one per peer for parallel download),
 *               mutexes (protecting piece assignment)
 * ═══════════════════════════════════════════════════════════════
 */

#include "peer.h"
#include "common/network.h"
#include "common/utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

/* ── Per-peer download worker thread ──────────────────────── */

struct DownloadWorkerArg {
    struct PeerState *state;
    int peer_idx;
};

static void *download_worker(void *arg)
{
    struct DownloadWorkerArg *dwa = (struct DownloadWorkerArg *)arg;
    struct PeerState *state = dwa->state;
    int peer_idx = dwa->peer_idx;
    free(dwa);

    struct ConnectedPeer *cp = &state->peers[peer_idx];
    int consecutive_failures = 0;
    const int MAX_RETRIES = 5;

    while (!state->download_complete && cp->active && consecutive_failures < MAX_RETRIES) {
        /* Pick next piece (mutex-protected) */
        pthread_mutex_lock(&state->piece_lock);
        int piece = scheduler_next_piece(state, peer_idx);
        if (piece >= 0) {
            state->piece_status[piece] = PIECE_DOWNLOADING;
        }
        pthread_mutex_unlock(&state->piece_lock);

        if (piece < 0) {
            /* No more pieces available from this peer, wait and retry */
            usleep(500000);  /* 500ms */

            /* Check if download is complete */
            int done = 1;
            pthread_mutex_lock(&state->piece_lock);
            for (int i = 0; i < state->torrent.total_pieces; i++) {
                if (state->piece_status[i] != PIECE_DONE) {
                    done = 0;
                    break;
                }
            }
            pthread_mutex_unlock(&state->piece_lock);

            if (done) {
                state->download_complete = 1;
                break;
            }
            continue;
        }

        /* Build REQUEST payload with token */
        struct RequestPayload req;
        req.piece_index = piece;
        memcpy(&req.token, &state->token, sizeof(struct Token));

        LOG_INFO("Requesting piece %d/%d from %s",
                 piece + 1, state->torrent.total_pieces, cp->peer_id);

        /* Show progress on console */
        int done_so_far = 0;
        for (int k = 0; k < state->torrent.total_pieces; k++) {
            if (state->piece_status[k] == PIECE_DONE) done_so_far++;
        }
        printf("    " CLR_BLUE "↓" CLR_RESET " [%d/%d] Requesting piece %d from %s:%d\n",
               done_so_far + 1, state->torrent.total_pieces,
               piece + 1, cp->ip, cp->port);
        fflush(stdout);

        if (send_msg(cp->sockfd, MSG_REQUEST, &req, sizeof(req)) < 0) {
            printf("    " CLR_RED "✗" CLR_RESET " Failed to send request for piece %d\n", piece + 1);
            LOG_ERR("Failed to send REQUEST for piece %d", piece);
            pthread_mutex_lock(&state->piece_lock);
            state->piece_status[piece] = PIECE_FREE;  /* Release piece */
            pthread_mutex_unlock(&state->piece_lock);
            break;
        }

        /* Wait for piece to be received (handled by peer_recv_thread) */
        /* Poll piece_status until it changes from DOWNLOADING */
        int timeout = 30;  /* 30 seconds max wait */
        while (timeout > 0) {
            usleep(100000);  /* 100ms */
            timeout--;

            pthread_mutex_lock(&state->piece_lock);
            int status = state->piece_status[piece];
            pthread_mutex_unlock(&state->piece_lock);

            if (status == PIECE_DONE) break;
            if (status == PIECE_FREE) break;  /* Hash failed, will retry */
        }

        if (timeout <= 0) {
            consecutive_failures++;
            printf("    " CLR_YELLOW "⏳" CLR_RESET " Piece %d timed out (%d/%d retries)\n", piece + 1, consecutive_failures, MAX_RETRIES);
            LOG_WARN("Timeout waiting for piece %d", piece);
            pthread_mutex_lock(&state->piece_lock);
            if (state->piece_status[piece] == PIECE_DOWNLOADING) {
                state->piece_status[piece] = PIECE_FREE;
            }
            pthread_mutex_unlock(&state->piece_lock);
        } else {
            pthread_mutex_lock(&state->piece_lock);
            int final_status = state->piece_status[piece];
            pthread_mutex_unlock(&state->piece_lock);
            if (final_status == PIECE_DONE) {
                consecutive_failures = 0;
                printf("    " CLR_GREEN "✓" CLR_RESET " Piece %d received and SHA1 verified\n", piece + 1);
                fflush(stdout);
            } else {
                consecutive_failures++;
                printf("    " CLR_YELLOW "↻" CLR_RESET " Piece %d hash mismatch, queued for retry\n", piece + 1);
            }
        }
    }

    LOG_INFO("Download worker for peer %s finished", cp->peer_id);
    return NULL;
}

/* ══════════════════════════════════════════════════════════════
 *  Start Download — main download orchestrator
 * ══════════════════════════════════════════════════════════════ */

int start_download(struct PeerState *state)
{
    if (state->torrent.total_pieces <= 0) {
        LOG_ERR("No torrent loaded");
        return -1;
    }

    /* Create peer-local downloads directory */
    mkdirs(state->downloads_dir);

    /* Create empty output file */
    char filepath[512];
    snprintf(filepath, sizeof(filepath), "%s/%s",
             state->downloads_dir, state->torrent.file_name);
    create_empty_file(filepath, state->torrent.file_size);

    /* Initialize piece status */
    pthread_mutex_lock(&state->piece_lock);
    for (int i = 0; i < state->torrent.total_pieces; i++) {
        state->piece_status[i] = PIECE_FREE;
    }
    state->download_complete = 0;
    state->is_downloading = 1;
    pthread_mutex_unlock(&state->piece_lock);

    LOG_INFO("Starting download: %s (%d pieces)",
             state->torrent.file_name, state->torrent.total_pieces);

    /* Wait briefly for bitfield exchange to complete */
    usleep(500000);

    /* Spawn a download worker thread per connected peer */
    pthread_t *threads = calloc(state->peer_count, sizeof(pthread_t));
    int thread_count = 0;

    for (int i = 0; i < state->peer_count; i++) {
        if (!state->peers[i].active) continue;

        struct DownloadWorkerArg *dwa = malloc(sizeof(*dwa));
        dwa->state = state;
        dwa->peer_idx = i;

        pthread_create(&threads[thread_count], NULL, download_worker, dwa);
        thread_count++;
    }

    /* Wait for all download workers to finish */
    for (int i = 0; i < thread_count; i++) {
        pthread_join(threads[i], NULL);
    }
    free(threads);

    /* Check completion */
    int completed = 1;
    for (int i = 0; i < state->torrent.total_pieces; i++) {
        if (state->piece_status[i] != PIECE_DONE) {
            completed = 0;
            break;
        }
    }

    state->is_downloading = 0;

    if (completed) {
        state->is_seeding = 1;
        printf("\n");
        printf("  " CLR_GREEN "╔══════════════════════════════════════════════╗" CLR_RESET "\n");
        printf("  " CLR_GREEN "║  ✓ Download Complete                        ║" CLR_RESET "\n");
        printf("  " CLR_GREEN "║  File: %-37s ║" CLR_RESET "\n", state->torrent.file_name);
        printf("  " CLR_GREEN "║  Size: %-37ld ║" CLR_RESET "\n", state->torrent.file_size);
        printf("  " CLR_GREEN "║  Pieces: %-35d ║" CLR_RESET "\n", state->torrent.total_pieces);
        printf("  " CLR_GREEN "║  Saved: %-36s ║" CLR_RESET "\n", state->downloads_dir);
        printf("  " CLR_GREEN "╚══════════════════════════════════════════════╝" CLR_RESET "\n");
        printf("\n");
        return 0;
    } else {
        int done_count = 0;
        for (int i = 0; i < state->torrent.total_pieces; i++) {
            if (state->piece_status[i] == PIECE_DONE) done_count++;
        }
        printf("\n  " CLR_RED "✗ Download incomplete: %d/%d pieces received" CLR_RESET "\n",
               done_count, state->torrent.total_pieces);
        printf("    Retry the download to fetch remaining pieces.\n\n");
        return -1;
    }
}
