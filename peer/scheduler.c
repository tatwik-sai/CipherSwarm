/*
 * ═══════════════════════════════════════════════════════════════
 *  CipherSwarm — Piece Scheduler
 *
 *  Implements rarest-first piece selection strategy.
 *  Selects the next piece to download based on availability
 *  across connected peers.
 *
 *  OS Concepts: mutex-protected critical section
 * ═══════════════════════════════════════════════════════════════
 */

#include "peer.h"
#include "common/utils.h"

#include <string.h>
#include <limits.h>

/*
 * scheduler_next_piece — Select the next piece to download from a given peer.
 *
 * Strategy: Rarest-first
 *   1. Count how many peers have each piece (availability).
 *   2. Among pieces that are:
 *      - NOT yet done (piece_status != PIECE_DONE)
 *      - NOT currently being downloaded (piece_status != PIECE_DOWNLOADING)
 *      - Available from the specified peer
 *      Pick the one with the LOWEST availability count.
 *
 * The caller must hold state->piece_lock.
 *
 * Returns: piece index (>= 0) on success, -1 if no piece available.
 */
int scheduler_next_piece(struct PeerState *state, int peer_index)
{
    int total = state->torrent.total_pieces;

    if (peer_index < 0 || peer_index >= state->peer_count) return -1;

    struct ConnectedPeer *target = &state->peers[peer_index];
    if (!target->active || !target->remote_bitfield) return -1;

    /* Step 1: Compute availability of each piece across all peers */
    int availability[MAX_FILES];
    memset(availability, 0, sizeof(int) * total);

    for (int p = 0; p < state->peer_count; p++) {
        struct ConnectedPeer *cp = &state->peers[p];
        if (!cp->active || !cp->remote_bitfield) continue;

        for (int i = 0; i < total; i++) {
            if (cp->remote_bitfield[i]) {
                availability[i]++;
            }
        }
    }

    /* Step 2: Find the rarest free piece that the target peer has */
    int best_piece = -1;
    int best_avail = INT_MAX;

    for (int i = 0; i < total; i++) {
        /* Skip pieces we already have or are downloading */
        if (state->piece_status[i] != PIECE_FREE) continue;

        /* Skip pieces the target peer doesn't have */
        if (!target->remote_bitfield[i]) continue;

        /* Rarest-first: prefer lower availability */
        if (availability[i] < best_avail) {
            best_avail = availability[i];
            best_piece = i;
        }
    }

    if (best_piece >= 0) {
        LOG_DEBUG("Scheduler: selected piece %d (availability=%d) from peer %s",
                  best_piece, best_avail, target->peer_id);
    }

    return best_piece;
}
