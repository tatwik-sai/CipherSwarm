#ifndef AUTH_SERVER_H
#define AUTH_SERVER_H

#include "common/protocol.h"
#include "common/structs.h"

/* ── Configuration ────────────────────────────────────────── */
#define USERS_FILE      "auth_server/data/users.dat"
#define PEERS_FILE      "auth_server/data/peers.dat"
#define TORRENTS_DIR    "auth_server/data/torrents"
#define PRIVATE_KEY_FILE "auth_server/keys/server_private.pem"
#define PUBLIC_KEY_FILE  "auth_server/keys/server_public.pem"

/* ── Peer Registration ────────────────────────────────────── */
int register_peer(const char *username, const char *password, char *peer_id_out);
int validate_peer(const char *peer_id, const char *password, int *role_out);

/* ── User Management ──────────────────────────────────────── */
int validate_user(const char *username, const char *password, int *role_out);
int register_user(const char *username, const char *password, int role);
int get_user_role(const char *username, int *role_out);
int list_users_with_roles(struct UserRoleEntry *out, int max_count);
int update_user_role(const char *username, int new_role);

/* ── Token Issuing ────────────────────────────────────────── */
int issue_token(const char *user_id, const char *file_id, int role,
                const char *private_key_path, struct Token *token_out);

/* ── Metadata Management ──────────────────────────────────── */
int store_torrent(const struct Torrent *t);
int load_torrent(const char *file_id, struct Torrent *t_out);
int list_torrents(struct Torrent *out_list, int max_count);

#endif /* AUTH_SERVER_H */
