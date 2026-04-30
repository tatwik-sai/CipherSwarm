/*
 * ═══════════════════════════════════════════════════════════════
 *  CipherSwarm — IPC Module Implementation
 *
 *  Sets up and manages System V IPC resources:
 *    - Shared Memory: bitfield shared across processes
 *    - Message Queues: inter-process command passing
 *    - Semaphores: synchronization for shared memory access
 *
 *  OS Concepts: shmget, shmat, shmdt, shmctl,
 *               msgget, msgsnd, msgrcv, msgctl,
 *               semget, semop, semctl
 * ═══════════════════════════════════════════════════════════════
 */

#include "ipc.h"
#include "common/utils.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/msg.h>
#include <sys/sem.h>

/* ══════════════════════════════════════════════════════════════
 *  Semaphore helper — perform semop
 * ══════════════════════════════════════════════════════════════ */

static int sem_wait(int sem_id, int sem_num)
{
    struct sembuf op = { .sem_num = sem_num, .sem_op = -1, .sem_flg = 0 };
    while (semop(sem_id, &op, 1) < 0) {
        if (errno == EINTR) continue;
        LOG_ERR("sem_wait failed: %s", strerror(errno));
        return -1;
    }
    return 0;
}

static int sem_post(int sem_id, int sem_num)
{
    struct sembuf op = { .sem_num = sem_num, .sem_op = 1, .sem_flg = 0 };
    if (semop(sem_id, &op, 1) < 0) {
        LOG_ERR("sem_post failed: %s", strerror(errno));
        return -1;
    }
    return 0;
}

/* ══════════════════════════════════════════════════════════════
 *  Initialize all IPC resources
 * ══════════════════════════════════════════════════════════════ */

int ipc_init(struct IpcResources *ipc, int total_pieces)
{
    memset(ipc, 0, sizeof(*ipc));
    ipc->shm_total_pieces = total_pieces;

    /* ── Shared Memory: bitfield ─────────────────────────── */
    size_t shm_size = total_pieces * sizeof(int);
    ipc->shm_id = shmget(IPC_PRIVATE, shm_size, IPC_CREAT | 0600);
    if (ipc->shm_id < 0) {
        LOG_ERR("shmget failed: %s", strerror(errno));
        return -1;
    }

    ipc->shm_bitfield = (int *)shmat(ipc->shm_id, NULL, 0);
    if (ipc->shm_bitfield == (int *)-1) {
        LOG_ERR("shmat failed: %s", strerror(errno));
        return -1;
    }

    /* Initialize bitfield to all zeros */
    memset(ipc->shm_bitfield, 0, shm_size);
    LOG_INFO("IPC: Shared memory created (id=%d, %zu bytes)", ipc->shm_id, shm_size);

    /* ── Message Queues ──────────────────────────────────── */
    ipc->mq_net_to_download = msgget(IPC_PRIVATE, IPC_CREAT | 0600);
    if (ipc->mq_net_to_download < 0) {
        LOG_ERR("msgget (net→dl) failed: %s", strerror(errno));
        return -1;
    }

    ipc->mq_download_to_disk = msgget(IPC_PRIVATE, IPC_CREAT | 0600);
    if (ipc->mq_download_to_disk < 0) {
        LOG_ERR("msgget (dl→disk) failed: %s", strerror(errno));
        return -1;
    }

    ipc->mq_net_to_upload = msgget(IPC_PRIVATE, IPC_CREAT | 0600);
    if (ipc->mq_net_to_upload < 0) {
        LOG_ERR("msgget (net→ul) failed: %s", strerror(errno));
        return -1;
    }

    ipc->mq_upload_to_disk = msgget(IPC_PRIVATE, IPC_CREAT | 0600);
    if (ipc->mq_upload_to_disk < 0) {
        LOG_ERR("msgget (ul→disk) failed: %s", strerror(errno));
        return -1;
    }

    ipc->mq_disk_response = msgget(IPC_PRIVATE, IPC_CREAT | 0600);
    if (ipc->mq_disk_response < 0) {
        LOG_ERR("msgget (disk resp) failed: %s", strerror(errno));
        return -1;
    }

    LOG_INFO("IPC: Message queues created (5 queues)");

    /* ── Semaphores ──────────────────────────────────────── */
    ipc->sem_id = semget(IPC_PRIVATE, SEM_COUNT, IPC_CREAT | 0600);
    if (ipc->sem_id < 0) {
        LOG_ERR("semget failed: %s", strerror(errno));
        return -1;
    }

    /* Initialize semaphore values */
    /* SEM_BITFIELD: binary semaphore (mutex), initial = 1 */
    if (semctl(ipc->sem_id, SEM_BITFIELD, SETVAL, 1) < 0) {
        LOG_ERR("semctl SETVAL failed: %s", strerror(errno));
        return -1;
    }

    /* SEM_MQ_FULL: counting semaphore for items, initial = 0 */
    semctl(ipc->sem_id, SEM_MQ_FULL, SETVAL, 0);

    /* SEM_MQ_EMPTY: counting semaphore for slots, initial = 64 */
    semctl(ipc->sem_id, SEM_MQ_EMPTY, SETVAL, 64);

    LOG_INFO("IPC: Semaphores created (id=%d, %d sems)", ipc->sem_id, SEM_COUNT);

    return 0;
}

/* ══════════════════════════════════════════════════════════════
 *  Cleanup all IPC resources
 * ══════════════════════════════════════════════════════════════ */

void ipc_cleanup(struct IpcResources *ipc)
{
    /* Detach and remove shared memory */
    if (ipc->shm_bitfield && ipc->shm_bitfield != (int *)-1) {
        shmdt(ipc->shm_bitfield);
    }
    if (ipc->shm_id > 0) {
        shmctl(ipc->shm_id, IPC_RMID, NULL);
        LOG_INFO("IPC: Shared memory removed (id=%d)", ipc->shm_id);
    }

    /* Remove message queues */
    if (ipc->mq_net_to_download > 0) msgctl(ipc->mq_net_to_download, IPC_RMID, NULL);
    if (ipc->mq_download_to_disk > 0) msgctl(ipc->mq_download_to_disk, IPC_RMID, NULL);
    if (ipc->mq_net_to_upload > 0) msgctl(ipc->mq_net_to_upload, IPC_RMID, NULL);
    if (ipc->mq_upload_to_disk > 0) msgctl(ipc->mq_upload_to_disk, IPC_RMID, NULL);
    if (ipc->mq_disk_response > 0) msgctl(ipc->mq_disk_response, IPC_RMID, NULL);
    LOG_INFO("IPC: Message queues removed");

    /* Remove semaphores */
    if (ipc->sem_id > 0) {
        semctl(ipc->sem_id, 0, IPC_RMID);
        LOG_INFO("IPC: Semaphores removed (id=%d)", ipc->sem_id);
    }

    memset(ipc, 0, sizeof(*ipc));
}

/* ══════════════════════════════════════════════════════════════
 *  Semaphore-protected bitfield operations
 * ══════════════════════════════════════════════════════════════ */

void ipc_bitfield_set(struct IpcResources *ipc, int piece_index)
{
    if (piece_index < 0 || piece_index >= ipc->shm_total_pieces) return;

    sem_wait(ipc->sem_id, SEM_BITFIELD);
    ipc->shm_bitfield[piece_index] = 1;
    sem_post(ipc->sem_id, SEM_BITFIELD);
}

int ipc_bitfield_get(struct IpcResources *ipc, int piece_index)
{
    if (piece_index < 0 || piece_index >= ipc->shm_total_pieces) return 0;

    sem_wait(ipc->sem_id, SEM_BITFIELD);
    int val = ipc->shm_bitfield[piece_index];
    sem_post(ipc->sem_id, SEM_BITFIELD);

    return val;
}

/* ══════════════════════════════════════════════════════════════
 *  Message Queue operations
 * ══════════════════════════════════════════════════════════════ */

int ipc_send_msg(int mq_id, struct IpcMsg *msg)
{
    /* msgsnd: send the message (skip the mtype field for size calculation) */
    size_t msg_size = sizeof(struct IpcMsg) - sizeof(long);

    while (msgsnd(mq_id, msg, msg_size, 0) < 0) {
        if (errno == EINTR) continue;
        LOG_ERR("msgsnd failed: %s", strerror(errno));
        return -1;
    }
    return 0;
}

int ipc_recv_msg(int mq_id, struct IpcMsg *msg, long mtype)
{
    size_t msg_size = sizeof(struct IpcMsg) - sizeof(long);

    while (msgrcv(mq_id, msg, msg_size, mtype, 0) < 0) {
        if (errno == EINTR) continue;
        LOG_ERR("msgrcv failed: %s", strerror(errno));
        return -1;
    }
    return 0;
}
