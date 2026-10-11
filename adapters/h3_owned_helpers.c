#define MIL_H3_BRIDGE_IMPLEMENTATION
#include "h3_owned_helpers.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

extern char **environ;

#define BROKER_FD 198
#define MAX_TARGET 1023
#define MAX_PAYLOAD 16384
#define ACTION_MAGIC 0x48464131u
#define WIRE_MAGIC 0x3142484du

static pthread_mutex_t client_lock = PTHREAD_MUTEX_INITIALIZER;
static int connection_state; /* 0 uninitialized, 1 connected, -1 permanently failed */
static int timeout_ms;
static uint32_t request_id = 1;
static uint32_t outstanding;

static void put32(unsigned char *p, uint32_t n) {
    p[0] = (unsigned char)n;
    p[1] = (unsigned char)(n >> 8);
    p[2] = (unsigned char)(n >> 16);
    p[3] = (unsigned char)(n >> 24);
}

static uint32_t get32(const unsigned char *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static int64_t now_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return -1;
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int disconnect_with(int error) {
    if (connection_state == 1) {
        (void)shutdown(BROKER_FD, SHUT_RDWR);
        (void)close(BROKER_FD);
    }
    connection_state = -1;
    outstanding = 0;
    return error;
}

static int connect_inherited(void) {
    if (connection_state < 0) return EIO;
    if (connection_state == 1) return 0;
    const char *fd_text = getenv("MIL_H3_BROKER_FD");
    const char *timeout_text = getenv("MIL_H3_BROKER_TIMEOUT_MS");
    if (!fd_text || strcmp(fd_text, "198") != 0) return disconnect_with(EINVAL);
    timeout_ms = 10000;
    if (timeout_text) {
        unsigned long value = 0;
        if (!*timeout_text) return disconnect_with(EINVAL);
        for (const unsigned char *p = (const unsigned char *)timeout_text; *p; ++p) {
            if (*p < '0' || *p > '9' || value > 600000 / 10)
                return disconnect_with(EINVAL);
            value = value * 10 + (*p - '0');
            if (value > 600000) return disconnect_with(EINVAL);
        }
        if (!value) return disconnect_with(EINVAL);
        timeout_ms = (int)value;
    }
    int kind = 0;
    socklen_t size = sizeof(kind);
    struct sockaddr_un peer;
    socklen_t peer_size = sizeof(peer);
    memset(&peer, 0, sizeof(peer));
    if (getsockopt(BROKER_FD, SOL_SOCKET, SO_TYPE, &kind, &size) != 0 ||
        kind != SOCK_STREAM || getpeername(BROKER_FD, (struct sockaddr *)&peer, &peer_size) != 0 ||
        peer.sun_family != AF_UNIX) return disconnect_with(ENOTSOCK);
    connection_state = 1;
    int flags = fcntl(BROKER_FD, F_GETFD);
    int yes = 1;
    if (flags < 0 || fcntl(BROKER_FD, F_SETFD, flags | FD_CLOEXEC) != 0 ||
        setsockopt(BROKER_FD, SOL_SOCKET, SO_NOSIGPIPE, &yes, sizeof(yes)) != 0)
        return disconnect_with(errno);
    return 0;
}

static int ready(short events, int64_t deadline) {
    int64_t now = now_ms();
    if (now < 0) return errno;
    if (now >= deadline) return ETIMEDOUT;
    struct pollfd fd = { BROKER_FD, events, 0 };
    int result = poll(&fd, 1, (int)(deadline - now));
    if (result < 0) return errno;
    if (!result) return ETIMEDOUT;
    if (fd.revents & events) return 0;
    return EIO;
}

/* One frame, one deadline. Partial I/O continues the frame, never a request retry. */
static int exchange(uint32_t op, const unsigned char *payload, size_t payload_size,
                    const int *fds, size_t fd_count, uint32_t *value) {
    int error = connect_inherited();
    if (error) return error;
    if (!request_id || request_id == UINT32_MAX) return disconnect_with(EOVERFLOW);
    uint32_t id = request_id++;
    unsigned char frame[24 + MAX_PAYLOAD];
    put32(frame, WIRE_MAGIC);
    put32(frame + 4, op);
    put32(frame + 8, id);
    put32(frame + 12, (uint32_t)payload_size);
    put32(frame + 16, (uint32_t)fd_count);
    put32(frame + 20, 0);
    memcpy(frame + 24, payload, payload_size);
    int64_t start = now_ms();
    if (start < 0) return disconnect_with(errno);
    int64_t deadline = start + timeout_ms;
    size_t offset = 0;
    while (offset < 24 + payload_size) {
        error = ready(POLLOUT, deadline);
        if (error) return disconnect_with(error);
        struct iovec iov = { frame + offset, 24 + payload_size - offset };
        union { struct cmsghdr alignment; unsigned char bytes[CMSG_SPACE(4 * sizeof(int))]; } control;
        struct msghdr message;
        memset(&message, 0, sizeof(message));
        message.msg_iov = &iov;
        message.msg_iovlen = 1;
        if (!offset && fd_count) {
            memset(&control, 0, sizeof(control));
            message.msg_control = control.bytes;
            message.msg_controllen = CMSG_SPACE(fd_count * sizeof(int));
            struct cmsghdr *cmsg = CMSG_FIRSTHDR(&message);
            cmsg->cmsg_level = SOL_SOCKET;
            cmsg->cmsg_type = SCM_RIGHTS;
            cmsg->cmsg_len = CMSG_LEN(fd_count * sizeof(int));
            memcpy(CMSG_DATA(cmsg), fds, fd_count * sizeof(int));
        }
        ssize_t sent = sendmsg(BROKER_FD, &message, MSG_DONTWAIT);
        if (sent <= 0) return disconnect_with(sent < 0 ? errno : EIO);
        offset += (size_t)sent;
    }
    unsigned char reply[24];
    offset = 0;
    while (offset < sizeof(reply)) {
        error = ready(POLLIN, deadline);
        if (error) return disconnect_with(error);
        struct iovec iov = { reply + offset, sizeof(reply) - offset };
        union { struct cmsghdr alignment; unsigned char bytes[CMSG_SPACE(4 * sizeof(int))]; } control;
        struct msghdr message;
        memset(&message, 0, sizeof(message));
        message.msg_iov = &iov;
        message.msg_iovlen = 1;
        message.msg_control = control.bytes;
        message.msg_controllen = sizeof(control);
        ssize_t received = recvmsg(BROKER_FD, &message, MSG_DONTWAIT);
        if (received <= 0) return disconnect_with(received < 0 ? errno : EIO);
        int unexpected_control = message.msg_flags & (MSG_CTRUNC | MSG_TRUNC);
        for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&message); cmsg;
             cmsg = CMSG_NXTHDR(&message, cmsg)) {
            unexpected_control = 1;
            if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS &&
                cmsg->cmsg_len >= CMSG_LEN(0)) {
                size_t count = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);
                for (size_t i = 0; i < count; ++i) {
                    int received_fd;
                    memcpy(&received_fd, CMSG_DATA(cmsg) + i * sizeof(int), sizeof(int));
                    (void)close(received_fd);
                }
            }
        }
        if (unexpected_control) return disconnect_with(EPROTO);
        offset += (size_t)received;
    }
    if (get32(reply) != WIRE_MAGIC || get32(reply + 4) != (op | 0x80000000u) ||
        get32(reply + 8) != id || get32(reply + 20) != 0) return disconnect_with(EPROTO);
    uint32_t remote_error = get32(reply + 12);
    if (remote_error) return disconnect_with(remote_error <= INT_MAX ? (int)remote_error : EIO);
    *value = get32(reply + 16);
    return 0;
}

int mil_h3_posix_spawn_file_actions_init(mil_h3_posix_spawn_file_actions_t *actions) {
    if (!actions) return EINVAL;
    actions->magic = ACTION_MAGIC;
    actions->count = 0;
    return 0;
}

static int append_action(mil_h3_posix_spawn_file_actions_t *actions, int kind, int source, int target) {
    if (!actions || actions->magic != ACTION_MAGIC) return EINVAL;
    if (source < 0 || source > MAX_TARGET || target < 0 || target > MAX_TARGET) return EBADF;
    if (source == BROKER_FD || target == BROKER_FD) return EPERM;
    if (actions->count >= MIL_H3_MAX_ACTIONS) return E2BIG;
    actions->actions[actions->count++] = (struct mil_h3_file_action){ kind, source, target };
    return 0;
}

int mil_h3_posix_spawn_file_actions_adddup2(mil_h3_posix_spawn_file_actions_t *actions, int source, int target) {
    return append_action(actions, 1, source, target);
}

int mil_h3_posix_spawn_file_actions_addclose(mil_h3_posix_spawn_file_actions_t *actions, int fd) {
    return append_action(actions, 2, fd, fd);
}

int mil_h3_posix_spawn_file_actions_destroy(mil_h3_posix_spawn_file_actions_t *actions) {
    if (!actions || actions->magic != ACTION_MAGIC) return EINVAL;
    actions->magic = 0;
    actions->count = 0;
    return 0;
}

/* Resolve in a logical child table. Nothing closes or overwrites a parent FD. */
static int resolve_actions(const mil_h3_posix_spawn_file_actions_t *actions,
                           int sources[4], uint32_t targets[4], size_t *count) {
    int table[MAX_TARGET + 1];
    unsigned char included[MAX_TARGET + 1] = {0};
    for (int i = 0; i <= MAX_TARGET; ++i) table[i] = i;
    included[1] = included[2] = 1;
    if (actions) {
        if (actions->magic != ACTION_MAGIC || actions->count > MIL_H3_MAX_ACTIONS) return EINVAL;
        for (size_t i = 0; i < actions->count; ++i) {
            const struct mil_h3_file_action *action = &actions->actions[i];
            int source = action->source, target = action->target;
            if (source < 0 || source > MAX_TARGET || target < 0 || target > MAX_TARGET) return EBADF;
            if (source == BROKER_FD || target == BROKER_FD) return EPERM;
            if (action->kind == 1) {
                if (table[source] < 0 || fcntl(table[source], F_GETFD) < 0) return EBADF;
                table[target] = table[source];
                included[target] = 1;
            } else if (action->kind == 2) {
                table[target] = -1;
                included[target] = 0;
            } else return ENOTSUP;
        }
    }
    /* The v1 protocol has no close-stdio action. Never silently change it to inheritance. */
    if (table[0] < 0 || table[1] < 0 || table[2] < 0) return ENOTSUP;
    *count = 0;
    for (int target = 0; target <= MAX_TARGET; ++target) {
        if (!included[target]) continue;
        if (*count == 4) return E2BIG;
        struct stat info;
        if (table[target] == BROKER_FD) return EPERM;
        if (fstat(table[target], &info) != 0) return errno;
        if (!S_ISFIFO(info.st_mode)) return ENOTSUP;
        sources[*count] = table[target];
        targets[*count] = (uint32_t)target;
        ++*count;
    }
    return 0;
}

static int utf8_valid(const unsigned char *s, size_t length) {
    size_t i = 0;
    while (i < length) {
        uint32_t code = s[i++];
        if (code < 0x80) continue;
        unsigned int continuation;
        uint32_t minimum;
        if (code >= 0xc2 && code <= 0xdf) { continuation = 1; minimum = 0x80; code &= 0x1f; }
        else if (code >= 0xe0 && code <= 0xef) { continuation = 2; minimum = 0x800; code &= 0x0f; }
        else if (code >= 0xf0 && code <= 0xf4) { continuation = 3; minimum = 0x10000; code &= 7; }
        else return 0;
        if (length - i < continuation) return 0;
        while (continuation--) {
            if ((s[i] & 0xc0) != 0x80) return 0;
            code = (code << 6) | (s[i++] & 0x3f);
        }
        if (code < minimum || code > 0x10ffff || (code >= 0xd800 && code <= 0xdfff)) return 0;
    }
    return 1;
}

static int spawn_locked(pid_t *pid, const char *program,
                        const mil_h3_posix_spawn_file_actions_t *actions,
                        const posix_spawnattr_t *attributes, char *const argv[], char *const envp[]) {
    if (!pid || !program || !argv || !argv[0]) return EINVAL;
    if (attributes || envp != environ) return ENOTSUP;
    if (outstanding) return EBUSY;
    if (connection_state < 0) return EIO;
    const char *ffmpeg = getenv("H3_FFMPEG"), *ffprobe = getenv("H3_FFPROBE");
    if (!ffmpeg || !*ffmpeg || !ffprobe || !*ffprobe || !strcmp(ffmpeg, ffprobe)) return EINVAL;
    uint32_t selector;
    if (!strcmp(program, ffmpeg)) selector = 1;
    else if (!strcmp(program, ffprobe)) selector = 2;
    else return ENOENT;
    int sources[4], duplicates[4];
    uint32_t targets[4];
    size_t count;
    int error = resolve_actions(actions, sources, targets, &count);
    if (error) return error;
    unsigned char payload[MAX_PAYLOAD];
    put32(payload, selector);
    size_t size = 8 + count * 4;
    for (size_t i = 0; i < count; ++i) put32(payload + 8 + i * 4, targets[i]);
    size_t argc = 0;
    for (; argc < 128 && argv[argc]; ++argc) {
        size_t length = strnlen(argv[argc], MAX_PAYLOAD + 1);
        if (length > MAX_PAYLOAD || size + 4 + length > MAX_PAYLOAD) return E2BIG;
        if (!utf8_valid((const unsigned char *)argv[argc], length)) return EILSEQ;
        put32(payload + size, (uint32_t)length);
        memcpy(payload + size + 4, argv[argc], length);
        size += 4 + length;
    }
    if (argc == 128 && argv[argc]) return E2BIG;
    put32(payload + 4, (uint32_t)argc);
    size_t duplicated = 0;
    for (; duplicated < count; ++duplicated) {
        duplicates[duplicated] = fcntl(sources[duplicated], F_DUPFD_CLOEXEC, 3);
        if (duplicates[duplicated] < 0) { error = errno; break; }
    }
    uint32_t token = 0;
    if (!error) error = exchange(1, payload, size, duplicates, count, &token);
    for (size_t i = 0; i < duplicated; ++i) (void)close(duplicates[i]);
    if (error) return error;
    if (!token || token > INT_MAX) return disconnect_with(EPROTO);
    outstanding = token;
    *pid = (pid_t)token;
    return 0;
}

int mil_h3_posix_spawnp(pid_t *pid, const char *program,
                        const mil_h3_posix_spawn_file_actions_t *actions,
                        const posix_spawnattr_t *attributes, char *const argv[], char *const envp[]) {
    if (pthread_mutex_trylock(&client_lock) != 0) return EBUSY;
    int error = spawn_locked(pid, program, actions, attributes, argv, envp);
    (void)pthread_mutex_unlock(&client_lock);
    return error;
}

pid_t mil_h3_waitpid(pid_t pid, int *status, int options) {
    if (pthread_mutex_trylock(&client_lock) != 0) { errno = EBUSY; return -1; }
    int error = 0;
    uint32_t value = 0;
    if (options != 0) error = ENOTSUP;
    else if (pid <= 0 || (uint32_t)pid != outstanding) error = ECHILD;
    else {
        unsigned char payload[4];
        put32(payload, (uint32_t)pid);
        error = exchange(2, payload, sizeof(payload), NULL, 0, &value);
        if (!error) {
            uint32_t signal_number = value & 0xff;
            if (value > 0xffff || (signal_number &&
                (signal_number >= NSIG || value != signal_number))) error = disconnect_with(EPROTO);
            else {
                outstanding = 0;
                if (status) *status = (int)value;
            }
        }
    }
    (void)pthread_mutex_unlock(&client_lock);
    if (error) { errno = error; return -1; }
    return pid;
}
