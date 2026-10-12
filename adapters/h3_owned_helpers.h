#ifndef MIL_H3_OWNED_HELPERS_H
#define MIL_H3_OWNED_HELPERS_H

/* Force-include only for h3_ffmpeg.c, never for the rest of the native host. */
#include <spawn.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MIL_H3_MAX_ACTIONS 128
struct mil_h3_file_action {
    int kind;
    int source;
    int target;
};
typedef struct {
    unsigned int magic;
    size_t count;
    struct mil_h3_file_action actions[MIL_H3_MAX_ACTIONS];
} mil_h3_posix_spawn_file_actions_t;

int mil_h3_posix_spawn_file_actions_init(mil_h3_posix_spawn_file_actions_t *);
int mil_h3_posix_spawn_file_actions_adddup2(mil_h3_posix_spawn_file_actions_t *, int, int);
int mil_h3_posix_spawn_file_actions_addclose(mil_h3_posix_spawn_file_actions_t *, int);
int mil_h3_posix_spawn_file_actions_destroy(mil_h3_posix_spawn_file_actions_t *);
int mil_h3_posix_spawnp(pid_t *, const char *, const mil_h3_posix_spawn_file_actions_t *,
                        const posix_spawnattr_t *, char *const[], char *const[]);
pid_t mil_h3_waitpid(pid_t, int *, int);
int mil_h3_cpu_fixture(const char *, const char *);

#ifdef __cplusplus
}
#endif

#ifndef MIL_H3_BRIDGE_IMPLEMENTATION
#define posix_spawn_file_actions_t mil_h3_posix_spawn_file_actions_t
#define posix_spawn_file_actions_init mil_h3_posix_spawn_file_actions_init
#define posix_spawn_file_actions_adddup2 mil_h3_posix_spawn_file_actions_adddup2
#define posix_spawn_file_actions_addclose mil_h3_posix_spawn_file_actions_addclose
#define posix_spawn_file_actions_destroy mil_h3_posix_spawn_file_actions_destroy
#define posix_spawnp mil_h3_posix_spawnp
#define waitpid mil_h3_waitpid
#endif
#endif
