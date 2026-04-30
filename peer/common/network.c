#include "network.h"
#include "protocol.h"
#include "utils.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

/* ══════════════════════════════════════════════════════════════
 *  Low-level send/recv helpers
 * ══════════════════════════════════════════════════════════════ */

int send_all(int sockfd, const void *data, size_t n)
{
    const char *ptr = (const char *)data;
    size_t remaining = n;

    while (remaining > 0) {
        ssize_t sent = send(sockfd, ptr, remaining, MSG_NOSIGNAL);
        if (sent <= 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        ptr += sent;
        remaining -= (size_t)sent;
    }
    return 0;
}

int recv_all(int sockfd, void *buf, size_t n)
{
    char *ptr = (char *)buf;
    size_t remaining = n;

    while (remaining > 0) {
        ssize_t received = recv(sockfd, ptr, remaining, 0);
        if (received < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (received == 0) {
            return -1;   /* connection closed */
        }
        ptr += received;
        remaining -= (size_t)received;
    }
    return 0;
}

/* ══════════════════════════════════════════════════════════════
 *  Framed message send/recv
 *
 *  Wire format: [uint8_t type][uint32_t length (net order)][payload]
 * ══════════════════════════════════════════════════════════════ */

int send_msg(int sockfd, uint8_t type, const void *payload, uint32_t len)
{
    struct MsgHeader hdr;
    hdr.type   = type;
    hdr.length = htonl(len);

    if (send_all(sockfd, &hdr, HEADER_SIZE) < 0) return -1;

    if (len > 0 && payload) {
        if (send_all(sockfd, payload, len) < 0) return -1;
    }
    return 0;
}

int recv_msg(int sockfd, uint8_t *type, void *buf, uint32_t buf_size, uint32_t *out_len)
{
    struct MsgHeader hdr;

    if (recv_all(sockfd, &hdr, HEADER_SIZE) < 0) return -1;

    *type = hdr.type;
    uint32_t payload_len = ntohl(hdr.length);

    if (payload_len > buf_size) {
        LOG_ERR("Message too large: %u > %u", payload_len, buf_size);
        return -1;
    }

    *out_len = payload_len;

    if (payload_len > 0) {
        if (recv_all(sockfd, buf, payload_len) < 0) return -1;
    }

    return 0;
}

/* ══════════════════════════════════════════════════════════════
 *  Socket creation
 * ══════════════════════════════════════════════════════════════ */

int create_server_socket(int port)
{
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        LOG_ERR("socket() failed: %s", strerror(errno));
        return -1;
    }

    int opt = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons((uint16_t)port);

    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        LOG_ERR("bind() failed on port %d: %s", port, strerror(errno));
        close(sockfd);
        return -1;
    }

    if (listen(sockfd, LISTEN_BACKLOG) < 0) {
        LOG_ERR("listen() failed: %s", strerror(errno));
        close(sockfd);
        return -1;
    }

    return sockfd;
}

int connect_to(const char *ip, int port)
{
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        LOG_ERR("socket() failed: %s", strerror(errno));
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons((uint16_t)port);

    if (inet_pton(AF_INET, ip, &addr.sin_addr) <= 0) {
        LOG_ERR("Invalid IP address: %s", ip);
        close(sockfd);
        return -1;
    }

    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        LOG_ERR("connect() to %s:%d failed: %s", ip, port, strerror(errno));
        close(sockfd);
        return -1;
    }

    return sockfd;
}
