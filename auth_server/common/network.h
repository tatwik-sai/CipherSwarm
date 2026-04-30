#ifndef NETWORK_H
#define NETWORK_H

#include <stdint.h>
#include <stddef.h>

/*
 * Socket abstraction layer for CipherSwarm.
 * All components use these helpers to send/receive framed messages.
 */

/* Create a server socket: bind + listen */
int create_server_socket(int port);

/* Connect to a remote host */
int connect_to(const char *ip, int port);

/*
 * Send a framed message: [MsgHeader][payload]
 * Returns 0 on success, -1 on failure.
 */
int send_msg(int sockfd, uint8_t type, const void *payload, uint32_t len);

/*
 * Receive a framed message.
 * Caller provides buffer (buf) of size buf_size.
 * On return: *type = message type, *out_len = payload length.
 * Returns 0 on success, -1 on failure / disconnect.
 */
int recv_msg(int sockfd, uint8_t *type, void *buf, uint32_t buf_size, uint32_t *out_len);

/*
 * Low-level: send exactly n bytes.
 * Returns 0 on success, -1 on failure.
 */
int send_all(int sockfd, const void *data, size_t n);

/*
 * Low-level: receive exactly n bytes.
 * Returns 0 on success, -1 on failure / disconnect.
 */
int recv_all(int sockfd, void *buf, size_t n);

#endif /* NETWORK_H */
