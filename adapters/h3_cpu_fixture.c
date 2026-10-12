#include "h3_owned_helpers.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

extern char **environ;

#define FIXTURE_TIMEOUT_MS 10000
#define VIDEO_BYTES (8u * 64u * 32u * 3u)
#define AUDIO_BYTES (10666u * 2u * 4u)

static int64_t fixture_now_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return -1;
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int fixture_ready(int fd, short events, int64_t deadline) {
    int64_t now = fixture_now_ms();
    if (now < 0) return errno;
    if (now >= deadline) return ETIMEDOUT;
    struct pollfd item = { fd, events, 0 };
    int result = poll(&item, 1, (int)(deadline - now));
    if (result < 0) return errno;
    if (!result) return ETIMEDOUT;
    return (item.revents & (events | (events == POLLIN ? POLLHUP : 0))) ? 0 : EIO;
}

static void close_pipe(int pair[2]) {
    for (int i = 0; i < 2; ++i) {
        if (pair[i] >= 0) (void)close(pair[i]);
        pair[i] = -1;
    }
}

static int fixture_pipe(int pair[2]) {
    if (pipe(pair) != 0) return errno;
    for (int i = 0; i < 2; ++i) {
        if (fcntl(pair[i], F_SETFD, FD_CLOEXEC) != 0) {
            int error = errno;
            close_pipe(pair);
            return error;
        }
    }
    return 0;
}

static int nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) return errno;
    return 0;
}

static int helper_status(pid_t token) {
    int status;
    if (waitpid(token, &status, 0) != token) return 70;
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return 70;
}

static int probe_dimensions(void) {
    int output[2] = {-1, -1};
    int error = fixture_pipe(output);
    if (error) return 70;
    posix_spawn_file_actions_t actions;
    error = posix_spawn_file_actions_init(&actions);
    if (!error) error = posix_spawn_file_actions_adddup2(&actions, output[1], STDOUT_FILENO);
    if (!error) error = posix_spawn_file_actions_addclose(&actions, output[0]);
    if (!error) error = posix_spawn_file_actions_addclose(&actions, output[1]);
    char *argv[] = { "ffprobe", "--mil-cpu-probe", NULL };
    pid_t token = 0;
    if (!error) error = posix_spawnp(&token, getenv("H3_FFPROBE"), &actions, NULL, argv, environ);
    (void)posix_spawn_file_actions_destroy(&actions);
    (void)close(output[1]);
    output[1] = -1;
    if (error) { close_pipe(output); return 70; }
    error = nonblocking(output[0]);
    char reply[7];
    size_t used = 0;
    int64_t now = fixture_now_ms();
    if (now < 0) error = errno;
    int64_t deadline = now + FIXTURE_TIMEOUT_MS;
    while (!error && used < sizeof(reply)) {
        error = fixture_ready(output[0], POLLIN, deadline);
        if (error) break;
        ssize_t got = read(output[0], reply + used, sizeof(reply) - used);
        if (got < 0) { error = errno; break; }
        if (!got) break;
        used += (size_t)got;
    }
    close_pipe(output);
    int result = helper_status(token);
    if (result) return result;
    return (!error && used == 6 && !memcmp(reply, "64x32\n", 6)) ? 0 : 65;
}

struct writer {
    int fd;
    int audio;
    int error;
    int64_t deadline;
};

static void *stream_writer(void *opaque) {
    struct writer *writer = opaque;
    sigset_t blocked;
    (void)sigemptyset(&blocked);
    (void)sigaddset(&blocked, SIGPIPE);
    writer->error = pthread_sigmask(SIG_BLOCK, &blocked, NULL);
    if (!writer->error) writer->error = nonblocking(writer->fd);
    size_t total = writer->audio ? AUDIO_BYTES : VIDEO_BYTES;
    size_t offset = 0;
    unsigned char buffer[4096];
    while (!writer->error && offset < total) {
        size_t length = total - offset;
        if (length > sizeof(buffer)) length = sizeof(buffer);
        if (writer->audio) {
            for (size_t i = 0; i < length; i += 4) {
                size_t sample = (offset + i) / 4;
                float value = (float)(sample % 101) / 101.0f;
                uint32_t bits;
                memcpy(&bits, &value, sizeof(bits));
                buffer[i] = (unsigned char)bits;
                buffer[i + 1] = (unsigned char)(bits >> 8);
                buffer[i + 2] = (unsigned char)(bits >> 16);
                buffer[i + 3] = (unsigned char)(bits >> 24);
            }
        } else {
            for (size_t i = 0; i < length; ++i)
                buffer[i] = (unsigned char)(((offset + i) * 17 + 3) % 256);
        }
        size_t sent = 0;
        while (!writer->error && sent < length) {
            writer->error = fixture_ready(writer->fd, POLLOUT, writer->deadline);
            if (writer->error) break;
            ssize_t wrote = write(writer->fd, buffer + sent, length - sent);
            if (wrote <= 0) { writer->error = wrote < 0 ? errno : EIO; break; }
            sent += (size_t)wrote;
        }
        offset += sent;
    }
    (void)close(writer->fd);
    writer->fd = -1;
    return NULL;
}

static int stream_codec(const char *scenario, const char *output_dir) {
    int video[2] = {-1, -1}, audio[2] = {-1, -1};
    int error = fixture_pipe(video);
    if (!error) error = fixture_pipe(audio);
    if (error) { close_pipe(video); close_pipe(audio); return 70; }
    int audio_target = video[0];
    for (int i = 0; i < 2; ++i) {
        if (video[i] > audio_target) audio_target = video[i];
        if (audio[i] > audio_target) audio_target = audio[i];
    }
    ++audio_target;
    char audio_number[16];
    (void)snprintf(audio_number, sizeof(audio_number), "%d", audio_target);
    posix_spawn_file_actions_t actions;
    error = posix_spawn_file_actions_init(&actions);
    if (!error) error = posix_spawn_file_actions_adddup2(&actions, video[0], STDIN_FILENO);
    if (!error) error = posix_spawn_file_actions_adddup2(&actions, audio[0], audio_target);
    for (int i = 0; i < 2; ++i) {
        if (!error) error = posix_spawn_file_actions_addclose(&actions, video[i]);
        if (!error) error = posix_spawn_file_actions_addclose(&actions, audio[i]);
    }
    char *argv[] = { "ffmpeg", "--mil-cpu-mode", (char *)scenario,
                     "--audio-fd", audio_number, "--output-dir", (char *)output_dir, NULL };
    pid_t token = 0;
    if (!error) error = posix_spawnp(&token, getenv("H3_FFMPEG"), &actions, NULL, argv, environ);
    (void)posix_spawn_file_actions_destroy(&actions);
    (void)close(video[0]); video[0] = -1;
    (void)close(audio[0]); audio[0] = -1;
    if (error) { close_pipe(video); close_pipe(audio); return 70; }
    int64_t now = fixture_now_ms();
    struct writer writers[2] = {
        { video[1], 0, 0, now + FIXTURE_TIMEOUT_MS },
        { audio[1], 1, 0, now + FIXTURE_TIMEOUT_MS }
    };
    pthread_t threads[2];
    size_t started = 0;
    if (now < 0) error = errno;
    while (!error && started < 2) {
        error = pthread_create(&threads[started], NULL, stream_writer, &writers[started]);
        if (!error) ++started;
    }
    for (size_t i = started; i < 2; ++i) {
        (void)close(writers[i].fd);
        writers[i].fd = -1;
    }
    for (size_t i = 0; i < started; ++i) {
        int join_error = pthread_join(threads[i], NULL);
        if (!error) error = join_error ? join_error : writers[i].error;
    }
    int result = helper_status(token);
    if (result) return result;
    if (error) return 74;
    return !strcmp(scenario, "root-failure") ? 74 : 0;
}

int mil_h3_cpu_fixture(const char *scenario, const char *output_dir) {
    if (!scenario || !output_dir || !*output_dir) return 64;
    const char *allowed[] = { "success", "codec-failure", "cancel", "guard-denial",
                             "root-failure", "unknown-tool", "direct-fork", "helper-fork" };
    int recognized = 0;
    for (size_t i = 0; i < sizeof(allowed) / sizeof(allowed[0]); ++i)
        if (!strcmp(scenario, allowed[i])) recognized = 1;
    if (!recognized) return 64;
    int result;
    if (!strcmp(scenario, "direct-fork")) {
        /* This sole native fork is the explicit negative qualification actor. */
        pid_t child = fork();
        if (child == 0) _exit(79);
        int fork_error = child < 0 ? errno : 0;
        result = child < 0 ? 77 : 78;
        if (child < 0) {
            printf("MIL_CPU_DIRECT_FORK_DENIED errno=%d\n", fork_error);
            (void)fflush(stdout);
        }
        fprintf(stderr, "mil-h3-cpu-fixture: direct-fork %s errno=%d; status=%d\n",
                child < 0 ? "denied" : "UNEXPECTEDLY allowed", fork_error, result);
        return result;
    }
    if (!strcmp(scenario, "unknown-tool")) {
        char *argv[] = { "mil-unconfigured-tool", NULL };
        pid_t token = 0;
        int error = posix_spawnp(&token, "mil-unconfigured-tool", NULL, NULL, argv, environ);
        if (!error) (void)helper_status(token);
        if (error == ENOENT) {
            printf("MIL_CPU_UNKNOWN_TOOL_DENIED errno=%d\n", error);
            (void)fflush(stdout);
        }
        result = error == ENOENT ? 77 : 78;
        fprintf(stderr, "mil-h3-cpu-fixture: unknown-tool errno=%d; status=%d\n", error, result);
        return result;
    }
    result = probe_dimensions();
    if (!result) result = stream_codec(scenario, output_dir);
    fprintf(stderr, "mil-h3-cpu-fixture: scenario=%s status=%d\n", scenario, result);
    return result;
}
