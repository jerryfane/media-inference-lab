/* Real CPU codec plumbing through the owned helper bridge, not H3 generation. */
#include "h3_ffmpeg.h"
#define MIL_H3_BRIDGE_IMPLEMENTATION
#include "h3_owned_helpers.h"

#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

enum {
    WIDTH = 64, HEIGHT = 32, FRAMES = 36, FPS = 12,
    CHANNELS = 2, AUDIO_RATE = 32000, AUDIO_FRAMES = 96000,
    API_AUDIO_FRAMES = 64000, AAC_PADDING = 1024,
    AREA = WIDTH * HEIGHT, IMAGE_VALUES = AREA * 3,
    VIDEO_BYTES = IMAGE_VALUES * FRAMES, READ_FRAMES = 5
};

extern char **environ;

/* Use the bridge explicitly: this fixture never spawns an actor itself. */
static int capture(const char *program, char *const arguments[],
                   void *buffer, size_t capacity, size_t *received,
                   char *error, size_t error_size) {
    int stream[2];
    *received = 0;
    if (!program || !*program) {
        snprintf(error, error_size, "missing enrolled codec selector");
        return 0;
    }
    if (pipe(stream) != 0) {
        snprintf(error, error_size, "capture pipe: %s", strerror(errno));
        return 0;
    }
    if (fcntl(stream[0], F_SETFD, FD_CLOEXEC) < 0 ||
        fcntl(stream[1], F_SETFD, FD_CLOEXEC) < 0) {
        snprintf(error, error_size, "capture cloexec: %s", strerror(errno));
        close(stream[0]);
        close(stream[1]);
        return 0;
    }
    mil_h3_posix_spawn_file_actions_t actions;
    int code = mil_h3_posix_spawn_file_actions_init(&actions);
    if (!code) code = mil_h3_posix_spawn_file_actions_adddup2(&actions, stream[1], 1);
    if (!code) code = mil_h3_posix_spawn_file_actions_addclose(&actions, stream[0]);
    if (!code) code = mil_h3_posix_spawn_file_actions_addclose(&actions, stream[1]);
    pid_t child = -1;
    if (!code) code = mil_h3_posix_spawnp(&child, program, &actions, NULL,
                                        arguments, environ);
    mil_h3_posix_spawn_file_actions_destroy(&actions);
    close(stream[1]);
    if (code) {
        close(stream[0]);
        snprintf(error, error_size, "capture spawn: %s", strerror(code));
        return 0;
    }
    while (*received < capacity) {
        ssize_t amount = read(stream[0], (uint8_t *)buffer + *received,
                              capacity - *received);
        if (amount < 0 && errno == EINTR) continue;
        if (amount < 0) code = errno;
        if (amount <= 0) break;
        *received += (size_t)amount;
    }
    unsigned char extra;
    ssize_t trailing = 0;
    if (!code && *received == capacity) {
        do trailing = read(stream[0], &extra, 1);
        while (trailing < 0 && errno == EINTR);
        if (trailing < 0) code = errno;
        else if (trailing > 0) code = EFBIG;
    }
    close(stream[0]);
    int status = 0;
    pid_t waited;
    do waited = mil_h3_waitpid(child, &status, 0);
    while (waited < 0 && errno == EINTR);
    if (waited < 0 || code || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        if (waited < 0) code = errno;
        snprintf(error, error_size, "capture read/wait: %s (status %d)",
                 code ? strerror(code) : "codec failed", status);
        return 0;
    }
    return 1;
}

static int closed_descriptor(int fd) {
    return fcntl(fd, F_GETFD) < 0 && errno == EBADF;
}

/* Padding is private and close-on-exec; never overwrite a live root descriptor. */
static int collision_shape(const char *scenario, int *padding, size_t *count) {
    *count = 0;
    if (strcmp(scenario, "descriptor-collision") == 0) {
        for (int fd = 3; fd <= 6; ++fd)
            if (!closed_descriptor(fd)) return 0;
        return fcntl(7, F_GETFD) >= 0 && fcntl(198, F_GETFD) >= 0;
    }
    if (strcmp(scenario, "broker-collision") != 0) return 1;
    mil_h3_posix_spawn_file_actions_t actions;
    if (mil_h3_posix_spawn_file_actions_init(&actions) != 0) return 0;
    int protected_dup = mil_h3_posix_spawn_file_actions_adddup2(&actions, 198, 0);
    int protected_close = mil_h3_posix_spawn_file_actions_addclose(&actions, 198);
    int destroyed = mil_h3_posix_spawn_file_actions_destroy(&actions);
    if (protected_dup != EPERM || protected_close != EPERM || destroyed != 0) return 0;
    for (int fd = 3; fd <= 193; ++fd) {
        if (fcntl(fd, F_GETFD) >= 0) continue;
        if (errno != EBADF) return 0;
        int opened = open("/dev/null", O_RDONLY | O_CLOEXEC);
        if (opened < 0) return 0;
        padding[(*count)++] = opened;
        if (opened != fd) return 0;
    }
    for (int fd = 194; fd <= 197; ++fd)
        if (!closed_descriptor(fd)) return 0;
    return fcntl(198, F_GETFD) >= 0;
}

static void close_padding(int *padding, size_t *count) {
    while (*count) close(padding[--*count]);
}

/* Independent channels make swapped, duplicated and downmixed content fail. */
static int audio_content(const float *actual, size_t frames, int planar,
                         const float *expected, size_t compared_frames,
                         double rmse[CHANNELS]) {
    for (size_t i = 0; i < frames * CHANNELS; ++i)
        if (!isfinite(actual[i])) return 0;
    for (size_t channel = 0; channel < CHANNELS; ++channel) {
        double squared_error = 0.0;
        for (size_t sample = AAC_PADDING; sample < compared_frames - AAC_PADDING; ++sample) {
            size_t index = planar ? channel * frames + sample : sample * CHANNELS + channel;
            double difference = (double)actual[index] - expected[channel * AUDIO_FRAMES + sample];
            squared_error += difference * difference;
        }
        rmse[channel] = sqrt(squared_error / (double)(compared_frames - 2 * AAC_PADDING));
        if (rmse[channel] > 0.025) return 0;
    }
    return 1;
}

static void deadline(int signal_number) {
    (void)signal_number;
    static const char message[] =
        "{\"schema\":\"mil.h3-real-codec-fixture.v1\",\"outcome\":\"deadline\","
        "\"native_generation\":false}\n";
    ssize_t ignored = write(STDOUT_FILENO, message, sizeof(message) - 1);
    (void)ignored;
    _exit(124);
}

static int failure(const char *stage, const char *detail) {
    fprintf(stderr, "real CPU codec fixture %s: %s\n", stage, detail);
    printf("{\"schema\":\"mil.h3-real-codec-fixture.v1\","
           "\"outcome\":\"failure\",\"stage\":\"%s\","
           "\"native_generation\":false}\n", stage);
    return 1;
}

static char *output_path(const char *directory, const char *name) {
    size_t length = strlen(directory) + strlen(name) + 2;
    char *path = malloc(length);
    if (path) snprintf(path, length, "%s/%s", directory, name);
    return path;
}

static int absent(const char *path) {
    struct stat info;
    return lstat(path, &info) < 0 && errno == ENOENT;
}

static int run(const char *scenario, const char *directory) {
    struct stat info;
    if (directory[0] != '/' || stat(directory, &info) != 0 ||
        !S_ISDIR(info.st_mode))
        return failure("output-directory", "an existing absolute directory is required");
    char *canonical = realpath(directory, NULL);
    if (!canonical) return failure("output-directory", strerror(errno));
    int canonical_match = strcmp(directory, canonical) == 0;
    free(canonical);
    if (!canonical_match)
        return failure("output-directory", "directory must be canonical without symlinks");

    char *media = output_path(directory, "fixture.mp4");
    char *invalid = output_path(directory, "invalid-media.bin");
    uint8_t *rgb = malloc(VIDEO_BYTES);
    float *pcm = malloc((size_t)CHANNELS * AUDIO_FRAMES * sizeof(*pcm));
    float *image = NULL, *video = NULL, *native_audio = NULL, *api_audio = NULL;
    int padding[191];
    size_t padding_count = 0;
    char error[512] = {0};
    int result = 1;
    if (!media || !invalid || !rgb || !pcm) {
        result = failure("allocation", "out of memory");
        goto done;
    }
    if (!absent(media) || !absent(invalid)) {
        result = failure("output-path", "fixture paths must not already exist");
        goto done;
    }
    for (size_t i = 0; i < VIDEO_BYTES; ++i)
        rgb[i] = (uint8_t)((i * 17 + 3) % 256);
    /* The actual H3 writer accepts planar [channel,sample], then interleaves. */
    for (size_t channel = 0; channel < CHANNELS; ++channel)
        for (size_t sample = 0; sample < AUDIO_FRAMES; ++sample) {
            double frequency = channel == 0 ? 440.0 : 733.0;
            pcm[channel * AUDIO_FRAMES + sample] = (float)(0.2 *
                sin(6.28318530717958647693 * frequency * (double)sample / AUDIO_RATE));
        }
    if (!collision_shape(scenario, padding, &padding_count)) {
        result = failure("descriptor-shape", "root descriptors differ from collision enrollment");
        goto done;
    }
    if (!h3_ffmpeg_write_av_rgb24_f32(media, rgb, FRAMES, WIDTH, HEIGHT,
                                    FPS, pcm, AUDIO_FRAMES, CHANNELS,
                                    AUDIO_RATE, error, sizeof(error))) {
        result = failure("write-av", error);
        goto done;
    }
    close_padding(padding, &padding_count);
    int width = 0, height = 0;
    if (!h3_ffprobe_visual_size(media, &width, &height, error, sizeof(error))) {
        result = failure("probe", error);
        goto done;
    }
    if (width != WIDTH || height != HEIGHT) {
        result = failure("dimensions", "encoded visual dimensions differ");
        goto done;
    }
    if (!h3_ffmpeg_read_image_f32(media, WIDTH, HEIGHT, H3_IMAGE_FIT_STRETCH,
                                 &image, error, sizeof(error))) {
        result = failure("read-image", error);
        goto done;
    }
    double image_error = 0.0, image_mean = 0.0;
    for (size_t channel = 0; channel < 3; ++channel)
        for (size_t pixel = 0; pixel < AREA; ++pixel) {
            float actual = image[channel * AREA + pixel];
            if (!isfinite(actual) || actual < 0.0f || actual > 1.0f) {
                result = failure("image-values", "nonfinite or out-of-range RGB");
                goto done;
            }
            double expected = (double)rgb[pixel * 3 + channel] / 255.0;
            image_error += fabs((double)actual - expected);
            image_mean += (double)actual;
        }
    image_error /= IMAGE_VALUES;
    image_mean /= IMAGE_VALUES;
    /* H.264/yuv420p is lossy: validate content without requiring byte equality. */
    if (image_error > 0.18 || image_mean < 0.3 || image_mean > 0.7) {
        result = failure("image-content", "decoded RGB differs beyond lossy tolerance");
        goto done;
    }
    int frames = 0;
    if (!h3_ffmpeg_read_video_f32(media, WIDTH, HEIGHT, READ_FRAMES,
                                 &video, &frames, error, sizeof(error))) {
        result = failure("read-video", error);
        goto done;
    }
    if (frames != READ_FRAMES) {
        result = failure("video-frames", "bounded readback did not return five frames");
        goto done;
    }
    double video_error = 0.0;
    for (size_t channel = 0; channel < 3; ++channel)
        for (size_t frame = 0; frame < READ_FRAMES; ++frame)
            for (size_t pixel = 0; pixel < AREA; ++pixel) {
                float actual = video[(channel * READ_FRAMES + frame) * AREA + pixel];
                if (!isfinite(actual) || actual < 0.0f || actual > 1.0f) {
                    result = failure("video-values", "nonfinite or out-of-range RGB");
                    goto done;
                }
                /* The specified RGB byte pattern repeats exactly every frame. */
                video_error += fabs((double)actual - (double)image[channel * AREA + pixel]);
            }
    video_error /= IMAGE_VALUES * READ_FRAMES;
    if (video_error > 0.03) {
        result = failure("video-content", "decoded frames differ from decoded image");
        goto done;
    }
    char metadata[128];
    size_t metadata_bytes = 0;
    char *probe_arguments[] = {
        "ffprobe", "-v", "error", "-select_streams", "a:0",
        "-show_entries", "stream=sample_rate,channels", "-of",
        "default=noprint_wrappers=1", media, NULL
    };
    if (!capture(getenv("H3_FFPROBE"), probe_arguments, metadata,
                 sizeof(metadata) - 1, &metadata_bytes, error, sizeof(error))) {
        result = failure("probe-audio", error);
        goto done;
    }
    metadata[metadata_bytes] = '\0';
    int original_rate = 0, original_channels = 0, consumed = 0;
    if (sscanf(metadata, "sample_rate=%d\nchannels=%d\n%n",
               &original_rate, &original_channels, &consumed) != 2 ||
        (size_t)consumed != metadata_bytes ||
        original_rate != AUDIO_RATE || original_channels != CHANNELS) {
        result = failure("original-audio-metadata", "muxed stream is not 32000 Hz stereo");
        goto done;
    }
    size_t native_capacity = (size_t)(AUDIO_FRAMES + AAC_PADDING) * CHANNELS * sizeof(float);
    native_audio = malloc(native_capacity);
    if (!native_audio) {
        result = failure("native-audio-allocation", "out of memory");
        goto done;
    }
    char *native_arguments[] = {
        "ffmpeg", "-nostdin", "-v", "error", "-i", media, "-map", "0:a:0",
        "-f", "f32le", "-acodec", "pcm_f32le", "-", NULL
    };
    size_t native_bytes = 0;
    if (!capture(getenv("H3_FFMPEG"), native_arguments, native_audio,
                 native_capacity, &native_bytes, error, sizeof(error))) {
        result = failure("read-native-audio", error);
        goto done;
    }
    size_t native_frames = native_bytes / (CHANNELS * sizeof(float));
    if (native_bytes % (CHANNELS * sizeof(float)) || native_frames < AUDIO_FRAMES) {
        result = failure("native-audio-count", "decoded PCM has partial frames or insufficient duration");
        goto done;
    }
    double native_rmse[CHANNELS] = {0}, api_rmse[CHANNELS] = {0};
    if (!audio_content(native_audio, native_frames, 0, pcm, AUDIO_FRAMES, native_rmse)) {
        result = failure("native-audio-content", "original-rate stereo differs from generated channels");
        goto done;
    }
    int api_frames = 0;
    /* The selected upstream API forces 32 kHz stereo, then returns planar PCM.
       Its conversion is deliberately NOT used as evidence of muxed metadata. */
    if (!h3_ffmpeg_read_audio_f32(media, API_AUDIO_FRAMES, 1, &api_audio,
                                 &api_frames, error, sizeof(error))) {
        result = failure("read-audio", error);
        goto done;
    }
    if (api_frames != API_AUDIO_FRAMES ||
        !audio_content(api_audio, (size_t)api_frames, 1, pcm, API_AUDIO_FRAMES, api_rmse)) {
        result = failure("api-audio-content", "two-second API read differs from generated channels");
        goto done;
    }
    printf("{\"schema\":\"mil.h3-real-codec-fixture.v1\",\"scenario\":\"%s\","
           "\"event\":\"codec-validated\",\"native_generation\":false,"
           "\"benchmark\":false,\"models_loaded\":false,\"width\":%d,\"height\":%d,"
           "\"written_frames\":%d,\"fps\":%d,"
           "\"generated_audio\":{\"channels\":%d,\"rate\":%d,\"frames\":%d,"
           "\"pcm_layout\":\"channel-major\",\"left_hz\":440,\"right_hz\":733},"
           "\"original_audio\":{\"channels\":%d,\"rate\":%d,"
           "\"metadata_probed\":true,\"decoded_frames\":%zu,"
           "\"pcm_layout\":\"interleaved\",\"rate_channels_forced\":false,"
           "\"channel_rmse\":[%.9f,%.9f]},"
           "\"read_audio\":{\"api\":\"h3_ffmpeg_read_audio_f32\","
           "\"transformed_rate\":%d,\"transformed_channels\":%d,"
           "\"frames\":%d,\"pcm_layout\":\"channel-major\","
           "\"channel_rmse\":[%.9f,%.9f]},"
           "\"audio_content_edge_trim_frames\":%d,\"audio_content_rmse_limit\":0.025,"
           "\"read_frames\":%d,\"image_mean\":%.9f,\"image_mae\":%.9f,"
           "\"video_image_mae\":%.9f}\n",
           scenario, width, height, FRAMES, FPS, CHANNELS, AUDIO_RATE, AUDIO_FRAMES,
           original_channels, original_rate, native_frames, native_rmse[0], native_rmse[1],
           AUDIO_RATE, CHANNELS, api_frames, api_rmse[0], api_rmse[1], AAC_PADDING,
           frames, image_mean, image_error, video_error);

    if (strcmp(scenario, "codec-failure") == 0) {
        int fd = open(invalid, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (fd < 0) {
            result = failure("invalid-media-create", strerror(errno));
            goto done;
        }
        static const char bytes[] = "MIL deliberately invalid media fixture\n";
        ssize_t amount = write(fd, bytes, sizeof(bytes) - 1);
        int closed = close(fd);
        if (amount != (ssize_t)(sizeof(bytes) - 1) || closed != 0) {
            result = failure("invalid-media-write", "cannot write bounded invalid input");
            goto done;
        }
        float *rejected = NULL;
        int decoded = h3_ffmpeg_read_image_f32(invalid, WIDTH, HEIGHT,
            H3_IMAGE_FIT_STRETCH, &rejected, error, sizeof(error));
        free(rejected);
        if (decoded) {
            result = failure("invalid-media-decode", "invalid media unexpectedly decoded");
            goto done;
        }
        /* Require the post-wait decode error, not an IPC/spawn failure. */
        if (strncmp(error, "FFmpeg could not decode image ",
                    strlen("FFmpeg could not decode image ")) != 0) {
            result = failure("invalid-media-decode", error);
            goto done;
        }
        puts("{\"schema\":\"mil.h3-real-codec-fixture.v1\",\"outcome\":\"codec-rejected-invalid-media\",\"native_generation\":false}");
        result = 7;
    } else if (strcmp(scenario, "root-failure") == 0) {
        puts("{\"schema\":\"mil.h3-real-codec-fixture.v1\",\"outcome\":\"root-failure-after-codec-success\",\"native_generation\":false}");
        result = 9;
    } else if (strcmp(scenario, "cancel") == 0) {
        puts("MIL_H3_REAL_CODEC_READY");
        struct timespec remaining = {5, 0};
        while (nanosleep(&remaining, &remaining) != 0) {
            if (errno != EINTR) {
                result = failure("cancel-window", strerror(errno));
                goto done;
            }
        }
        puts("{\"schema\":\"mil.h3-real-codec-fixture.v1\",\"outcome\":\"cancel-window-expired\",\"native_generation\":false}");
        result = 8;
    } else {
        puts("{\"schema\":\"mil.h3-real-codec-fixture.v1\",\"outcome\":\"success\",\"native_generation\":false}");
        result = 0;
    }
done:
    close_padding(padding, &padding_count);
    free(api_audio);
    free(native_audio);
    free(video);
    free(image);
    free(pcm);
    free(rgb);
    free(invalid);
    free(media);
    return result;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = deadline;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGALRM, &action, NULL) != 0)
        return failure("deadline-setup", strerror(errno));
    alarm(15);
    if (argc != 5 || strcmp(argv[1], "--scenario") != 0 ||
        strcmp(argv[3], "--output-dir") != 0 ||
        (strcmp(argv[2], "success") != 0 && strcmp(argv[2], "codec-failure") != 0 &&
         strcmp(argv[2], "cancel") != 0 && strcmp(argv[2], "root-failure") != 0 &&
         strcmp(argv[2], "descriptor-collision") != 0 && strcmp(argv[2], "broker-collision") != 0))
        return failure("arguments", "--scenario success|codec-failure|cancel|root-failure|descriptor-collision|broker-collision --output-dir ABSOLUTE");
    if (setenv("MIL_H3_BROKER_TIMEOUT_MS", "10000", 1) != 0)
        return failure("ipc-timeout", strerror(errno));
    int result = run(argv[2], argv[4]);
    alarm(0);
    return result;
}
