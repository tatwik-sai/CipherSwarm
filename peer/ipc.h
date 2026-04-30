#ifndef IPC_H
#define IPC_H

#include "peer.h"
#include "common/structs.h"

/*
 * CipherSwarm — IPC Module
 *
 * Sets up System V shared memory, message queues, and semaphores
 * for the multi-process peer architecture.
 *
 * OS Concepts: shmget/shmat, msgget/msgsnd/msgrcv, semget/semop
 */

/* ── IPC Resource IDs ─────────────────────────────────────── */

struct IpcResources {
    /* Shared Memory */
    int   shm_id;              /* System V shared memory ID       */
    int  *shm_bitfield;        /* Pointer to attached bitfield    */
    int   shm_total_pieces;

    /* Message Queues */
    int   mq_net_to_download;  /* Network → Download Manager      */
    int   mq_download_to_disk; /* Download Manager → Disk Manager */
    int   mq_net_to_upload;    /* Network → Upload Manager        */
    int   mq_upload_to_disk;   /* Upload Manager → Disk Manager   */
    int   mq_disk_response;    /* Disk Manager → requesters       */

    /* Semaphores */
    int   sem_id;              /* Semaphore set ID                */
};

/* Semaphore indices within the set */
#define SEM_BITFIELD   0       /* Protects shared memory bitfield */
#define SEM_MQ_FULL    1       /* Producer-consumer: items in MQ  */
#define SEM_MQ_EMPTY   2       /* Producer-consumer: empty slots  */
#define SEM_COUNT      3       /* Total semaphores in the set     */

/* ── Functions ────────────────────────────────────────────── */

/* Initialize all IPC resources. Returns 0 on success. */
int ipc_init(struct IpcResources *ipc, int total_pieces);

/* Cleanup all IPC resources (shmctl RMID, msgctl RMID, semctl RMID) */
void ipc_cleanup(struct IpcResources *ipc);

/* Shared memory bitfield operations (semaphore-protected) */
void ipc_bitfield_set(struct IpcResources *ipc, int piece_index);
int  ipc_bitfield_get(struct IpcResources *ipc, int piece_index);

/* Message queue operations */
int ipc_send_msg(int mq_id, struct IpcMsg *msg);
int ipc_recv_msg(int mq_id, struct IpcMsg *msg, long mtype);

#endif /* IPC_H */
