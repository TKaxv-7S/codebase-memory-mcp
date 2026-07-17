/*
 * bootstrap.c — Mandatory per-account daemon startup policy.
 */
#include "daemon/bootstrap.h"

#include "daemon/ipc.h"
#include "daemon/service.h"
#include "foundation/compat.h"
#include "foundation/platform.h"

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include "foundation/subprocess.h"
#include "foundation/win_utf8.h"
#include <windows.h>
#else
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

enum {
    BOOTSTRAP_RETRY_NS = 1000000,
    BOOTSTRAP_COORDINATION_CLEANUP_MS = 500,
    BOOTSTRAP_PATH_CAP = 4096,
};

static bool bootstrap_arg_is(const char *arg, const char *expected) {
    return arg && expected && strcmp(arg, expected) == 0;
}

static int bootstrap_find_arg(int argc, char *const argv[], const char *expected) {
    for (int i = 1; argv && i < argc; i++) {
        if (bootstrap_arg_is(argv[i], expected)) {
            return i;
        }
    }
    return -1;
}

static bool bootstrap_has_help_after(int argc, char *const argv[], int start) {
    for (int i = start; argv && i < argc; i++) {
        if (bootstrap_arg_is(argv[i], "--help") || bootstrap_arg_is(argv[i], "-h")) {
            return true;
        }
    }
    return false;
}

static bool bootstrap_worker_fingerprint_valid(const char *fingerprint) {
    if (!fingerprint || strlen(fingerprint) != 64U) {
        return false;
    }
    for (size_t i = 0; i < 64U; i++) {
        char ch = fingerprint[i];
        if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f'))) {
            return false;
        }
    }
    return true;
}

static bool bootstrap_worker_budget_valid(const char *text) {
    if (!text || !text[0]) {
        return false;
    }
    size_t value = 0;
    for (const unsigned char *cursor = (const unsigned char *)text; *cursor; cursor++) {
        if (*cursor < '0' || *cursor > '9') {
            return false;
        }
        size_t digit = (size_t)(*cursor - '0');
        if (value > (SIZE_MAX - digit) / 10U) {
            return false;
        }
        value = value * 10U + digit;
    }
    return value > 0;
}

/* Keep the bootstrap role boundary exact and fail closed before any client or
 * worker state is initialized. index_supervisor owns the matching builder and
 * performs the captured-build comparison after this syntax-only classification. */
static bool bootstrap_worker_argv_exact(int argc, char *const argv[]) {
    if (argc < 9 || !argv || !bootstrap_arg_is(argv[1], "cli") ||
        !bootstrap_arg_is(argv[2], "--index-worker") ||
        !bootstrap_arg_is(argv[3], "--index-worker-build") ||
        !bootstrap_worker_fingerprint_valid(argv[4]) ||
        !bootstrap_arg_is(argv[5], "index_repository") || !argv[6] || !argv[6][0] ||
        !bootstrap_arg_is(argv[7], "--response-out") || !argv[8] || !argv[8][0]) {
        return false;
    }
    int next = 9;
    if (next < argc && bootstrap_arg_is(argv[next], "--index-worker-memory-budget-bytes")) {
        if (next + 1 >= argc || !bootstrap_worker_budget_valid(argv[next + 1])) {
            return false;
        }
        next += 2;
    }
    if (next < argc && bootstrap_arg_is(argv[next], "--index-worker-single-thread")) {
        next++;
    }
    if (next < argc && bootstrap_arg_is(argv[next], "--index-worker-marker")) {
        if (next + 1 >= argc || !argv[next + 1] || !argv[next + 1][0]) {
            return false;
        }
        next += 2;
    }
    if (next < argc && bootstrap_arg_is(argv[next], "--index-worker-quarantine")) {
        if (next + 1 >= argc || !argv[next + 1] || !argv[next + 1][0]) {
            return false;
        }
        next += 2;
    }
    return next == argc;
}

cbm_daemon_process_role_t cbm_daemon_process_role(int argc, char *const argv[]) {
    if (argc <= 0 || !argv || !argv[0] || argv[0][0] == '\0') {
        return CBM_DAEMON_PROCESS_INVALID;
    }

    int daemon_arg = bootstrap_find_arg(argc, argv, CBM_DAEMON_INTERNAL_ARG);
    if (daemon_arg >= 0) {
        return argc == 2 && daemon_arg == 1 ? CBM_DAEMON_PROCESS_DAEMON
                                            : CBM_DAEMON_PROCESS_INVALID;
    }

    int worker_arg = bootstrap_find_arg(argc, argv, "--index-worker");
    if (worker_arg >= 0) {
        return bootstrap_worker_argv_exact(argc, argv) ? CBM_DAEMON_PROCESS_WORKER
                                                       : CBM_DAEMON_PROCESS_INVALID;
    }

    static const char *const stateless_commands[] = {
        "install",
        "uninstall",
        "update",
    };
    /* Stop at the first top-level mode token. Tool names, flag values, and JSON
     * following `cli` are opaque user input: a search query named "install"
     * or containing "--version" must never bypass the mandatory daemon. */
    for (int arg = 1; arg < argc; arg++) {
        if (bootstrap_arg_is(argv[arg], "cli")) {
            if (bootstrap_has_help_after(argc, argv, arg + 1)) {
                return CBM_DAEMON_PROCESS_STATELESS;
            }
            return CBM_DAEMON_PROCESS_LOCAL_CLI;
        }
        if (bootstrap_arg_is(argv[arg], "hook-augment")) {
            return CBM_DAEMON_PROCESS_HOOK_CLIENT;
        }
        if (bootstrap_arg_is(argv[arg], "config")) {
            return bootstrap_has_help_after(argc, argv, arg + 1) ? CBM_DAEMON_PROCESS_STATELESS
                                                                 : CBM_DAEMON_PROCESS_LOCAL_CLI;
        }
        if (bootstrap_arg_is(argv[arg], "--version") || bootstrap_arg_is(argv[arg], "--help") ||
            bootstrap_arg_is(argv[arg], "-h")) {
            return CBM_DAEMON_PROCESS_STATELESS;
        }
        for (size_t command = 0;
             command < sizeof(stateless_commands) / sizeof(stateless_commands[0]); command++) {
            if (bootstrap_arg_is(argv[arg], stateless_commands[command])) {
                return CBM_DAEMON_PROCESS_STATELESS;
            }
        }
    }
    return CBM_DAEMON_PROCESS_MCP_CLIENT;
}

bool cbm_daemon_process_role_requires_client(cbm_daemon_process_role_t role) {
    return role == CBM_DAEMON_PROCESS_MCP_CLIENT || role == CBM_DAEMON_PROCESS_HOOK_CLIENT;
}

cbm_daemon_ipc_endpoint_t *cbm_daemon_bootstrap_endpoint_new(const char *runtime_parent) {
    char key[CBM_DAEMON_KEY_SIZE];
    if (!cbm_daemon_rendezvous_key(key)) {
        return NULL;
    }
    return cbm_daemon_ipc_endpoint_new(key, runtime_parent);
}

bool cbm_daemon_bootstrap_launch_spec_init(const char *executable_path,
                                           cbm_daemon_bootstrap_launch_spec_t *spec_out) {
    if (!executable_path || executable_path[0] == '\0' || !spec_out) {
        return false;
    }
    memset(spec_out, 0, sizeof(*spec_out));
    spec_out->executable_path = executable_path;
    spec_out->argv[0] = executable_path;
    spec_out->argv[1] = CBM_DAEMON_INTERNAL_ARG;
    spec_out->argc = CBM_DAEMON_BOOTSTRAP_LAUNCH_ARGC;
    spec_out->detached = true;
    spec_out->inherit_standard_handles = false;
    spec_out->use_shell = false;
    return true;
}

static uint64_t bootstrap_deadline_after(uint32_t timeout_ms) {
    uint64_t now = cbm_now_ms();
    return UINT64_MAX - now < timeout_ms ? UINT64_MAX : now + (uint64_t)timeout_ms;
}

static _Noreturn void bootstrap_cleanup_fail_stop(const char *component) {
    (void)fprintf(stderr,
                  "codebase-memory-mcp: coordination cleanup failed (%s); "
                  "terminating so the OS releases retained claims\n",
                  component ? component : "unknown");
    (void)fflush(stderr);
#ifdef _WIN32
    (void)TerminateProcess(GetCurrentProcess(), EXIT_FAILURE);
    abort();
#else
    _exit(EXIT_FAILURE);
#endif
}

static void bootstrap_pause(uint64_t deadline) {
    uint64_t now = cbm_now_ms();
    if (now >= deadline) {
        return;
    }
    uint64_t remaining_ms = deadline - now;
    struct timespec pause = {
        .tv_sec = 0,
        .tv_nsec = remaining_ms > 1 ? BOOTSTRAP_RETRY_NS : (long)(remaining_ms * 1000000ULL),
    };
    (void)cbm_nanosleep(&pause, NULL);
}

static void bootstrap_startup_lock_release_complete(const cbm_daemon_bootstrap_ops_t *ops,
                                                    cbm_daemon_bootstrap_lock_t *lock_io) {
    uint64_t deadline = bootstrap_deadline_after(BOOTSTRAP_COORDINATION_CLEANUP_MS);
    while (ops && ops->startup_lock_release && lock_io && *lock_io) {
        (void)ops->startup_lock_release(ops->context, lock_io);
        if (!*lock_io) {
            return;
        }
        if (cbm_now_ms() >= deadline) {
            bootstrap_cleanup_fail_stop("startup_lock_cleanup");
        }
        cbm_usleep(1000);
    }
}

static void bootstrap_result_reset(cbm_daemon_bootstrap_result_t *result,
                                   cbm_daemon_process_role_t role) {
    memset(result, 0, sizeof(*result));
    result->status = cbm_daemon_process_role_requires_client(role) ? CBM_DAEMON_BOOTSTRAP_FAILED
                                                                   : CBM_DAEMON_BOOTSTRAP_BYPASSED;
}

static cbm_daemon_bootstrap_status_t bootstrap_finish_probe(
    cbm_daemon_bootstrap_probe_status_t probe, cbm_daemon_runtime_client_t *client,
    const cbm_daemon_runtime_connect_result_t *connect_result,
    const cbm_daemon_bootstrap_ops_t *ops, cbm_daemon_bootstrap_result_t *result) {
    if (connect_result) {
        result->connect_result = *connect_result;
    }
    result->client = client;
    if (probe == CBM_DAEMON_BOOTSTRAP_PROBE_CONNECTED && client) {
        result->status = CBM_DAEMON_BOOTSTRAP_CONNECTED;
        return result->status;
    }
    result->client = NULL;
    if (probe == CBM_DAEMON_BOOTSTRAP_PROBE_CONFLICT) {
        result->status = CBM_DAEMON_BOOTSTRAP_CONFLICT;
        (void)snprintf(result->message, sizeof(result->message), "%s",
                       connect_result && connect_result->message[0]
                           ? connect_result->message
                           : "CBM could not start because a conflicting CBM process is active; "
                             "close all CBM sessions and commands, then retry");
        if (ops->visible_diagnostic) {
            ops->visible_diagnostic(ops->context, result->message);
        }
        return result->status;
    }
    return CBM_DAEMON_BOOTSTRAP_FAILED;
}

static cbm_daemon_bootstrap_probe_status_t bootstrap_probe(
    const cbm_daemon_bootstrap_config_t *config, const cbm_daemon_bootstrap_ops_t *ops,
    cbm_daemon_runtime_client_t **client_out, cbm_daemon_runtime_connect_result_t *connect_result) {
    memset(connect_result, 0, sizeof(*connect_result));
    *client_out = NULL;
    return ops->probe(ops->context, config->endpoint, config->identity, config->connect_timeout_ms,
                      client_out, connect_result);
}

static bool bootstrap_probe_is_finishable(cbm_daemon_bootstrap_probe_status_t probe) {
    return probe == CBM_DAEMON_BOOTSTRAP_PROBE_CONNECTED ||
           probe == CBM_DAEMON_BOOTSTRAP_PROBE_CONFLICT;
}

static bool bootstrap_probe_is_waitable(cbm_daemon_bootstrap_probe_status_t probe) {
    return probe == CBM_DAEMON_BOOTSTRAP_PROBE_UNAVAILABLE ||
           probe == CBM_DAEMON_BOOTSTRAP_PROBE_RESERVED ||
           probe == CBM_DAEMON_BOOTSTRAP_PROBE_TERMINAL;
}

static bool bootstrap_config_valid(const cbm_daemon_bootstrap_config_t *config,
                                   const cbm_daemon_bootstrap_ops_t *ops) {
    return config && ops && config->endpoint && config->identity && config->executable_path &&
           config->executable_path[0] && config->connect_timeout_ms > 0 &&
           config->startup_timeout_ms > 0 && ops->cohort_acquire && ops->cohort_release &&
           ops->probe && ops->startup_lock_try_acquire && ops->startup_lock_prepare_handoff &&
           ops->startup_lock_release && ops->spawn_daemon;
}

cbm_daemon_bootstrap_status_t cbm_daemon_bootstrap_execute_with_ops(
    const cbm_daemon_bootstrap_config_t *config, const cbm_daemon_bootstrap_ops_t *ops,
    cbm_daemon_bootstrap_result_t *result_out) {
    if (!result_out) {
        return CBM_DAEMON_BOOTSTRAP_FAILED;
    }
    cbm_daemon_process_role_t role = config ? config->role : CBM_DAEMON_PROCESS_INVALID;
    bootstrap_result_reset(result_out, role);
    if (!cbm_daemon_process_role_requires_client(role)) {
        return role == CBM_DAEMON_PROCESS_INVALID ? CBM_DAEMON_BOOTSTRAP_FAILED
                                                  : CBM_DAEMON_BOOTSTRAP_BYPASSED;
    }
    if (!bootstrap_config_valid(config, ops)) {
        return CBM_DAEMON_BOOTSTRAP_FAILED;
    }

    uint64_t deadline = bootstrap_deadline_after(config->startup_timeout_ms);
    cbm_daemon_bootstrap_cohort_t cohort = NULL;
    cbm_daemon_conflict_t cohort_conflict;
    cbm_version_cohort_status_t cohort_status = ops->cohort_acquire(
        ops->context, config->endpoint, config->identity, deadline, &cohort, &cohort_conflict);
    if (cohort_status != CBM_VERSION_COHORT_OK) {
        result_out->status = cohort_status == CBM_VERSION_COHORT_CONFLICT
                                 ? CBM_DAEMON_BOOTSTRAP_CONFLICT
                                 : CBM_DAEMON_BOOTSTRAP_FAILED;
        bool formatted = cohort_status == CBM_VERSION_COHORT_CONFLICT &&
                         cbm_daemon_conflict_format(&cohort_conflict, result_out->message,
                                                    sizeof(result_out->message));
        if (!formatted) {
            const char *reason = cohort_status == CBM_VERSION_COHORT_BUSY
                                     ? "another CBM activation is in progress"
                                     : "exact-build admission could not be verified";
            (void)snprintf(result_out->message, sizeof(result_out->message),
                           "CBM daemon could not start: %s", reason);
        }
        if (ops->visible_diagnostic) {
            ops->visible_diagnostic(ops->context, result_out->message);
        }
        if (cohort) {
            ops->cohort_release(ops->context, cohort);
        }
        return result_out->status;
    }

    cbm_daemon_runtime_client_t *client = NULL;
    cbm_daemon_runtime_connect_result_t connect_result;
    cbm_daemon_bootstrap_probe_status_t probe =
        bootstrap_probe(config, ops, &client, &connect_result);
    if (bootstrap_probe_is_finishable(probe)) {
        cbm_daemon_bootstrap_status_t status =
            bootstrap_finish_probe(probe, client, &connect_result, ops, result_out);
        ops->cohort_release(ops->context, cohort);
        return status;
    }
    if (!bootstrap_probe_is_waitable(probe)) {
        probe = CBM_DAEMON_BOOTSTRAP_PROBE_ERROR;
    }

    cbm_daemon_bootstrap_lock_t startup_lock = NULL;
    bool lock_acquired = false;
    bool generation_observed = probe == CBM_DAEMON_BOOTSTRAP_PROBE_RESERVED ||
                               probe == CBM_DAEMON_BOOTSTRAP_PROBE_TERMINAL;
    while (cbm_now_ms() < deadline) {
        if (!bootstrap_probe_is_waitable(probe)) {
            break;
        }
        if (probe == CBM_DAEMON_BOOTSTRAP_PROBE_RESERVED ||
            probe == CBM_DAEMON_BOOTSTRAP_PROBE_TERMINAL) {
            /* A live or stopping generation owns the transition for now. Its
             * disappearance is not sticky: after observing true absence, the
             * same bootstrap attempt may serialize and become the next first
             * client. The startup lock and the re-probe below prevent two
             * replacements from being launched. */
            generation_observed = true;
            bootstrap_pause(deadline);
            probe = bootstrap_probe(config, ops, &client, &connect_result);
            continue;
        }

        int lock_status =
            ops->startup_lock_try_acquire(ops->context, config->endpoint, &startup_lock);
        if (lock_status < 0) {
            probe = CBM_DAEMON_BOOTSTRAP_PROBE_ERROR;
            break;
        }
        if (lock_status == 0) {
            bootstrap_pause(deadline);
            probe = bootstrap_probe(config, ops, &client, &connect_result);
            continue;
        }
        if (lock_status != 1 || !startup_lock) {
            probe = CBM_DAEMON_BOOTSTRAP_PROBE_ERROR;
            break;
        }

        lock_acquired = true;
        probe = bootstrap_probe(config, ops, &client, &connect_result);
        if (probe == CBM_DAEMON_BOOTSTRAP_PROBE_RESERVED ||
            probe == CBM_DAEMON_BOOTSTRAP_PROBE_TERMINAL) {
            generation_observed = true;
            bootstrap_startup_lock_release_complete(ops, &startup_lock);
            lock_acquired = false;
            continue;
        }
        if (bootstrap_probe_is_finishable(probe) || probe == CBM_DAEMON_BOOTSTRAP_PROBE_ERROR) {
            break;
        }
        if (probe != CBM_DAEMON_BOOTSTRAP_PROBE_UNAVAILABLE) {
            probe = CBM_DAEMON_BOOTSTRAP_PROBE_ERROR;
            break;
        }

        cbm_daemon_bootstrap_launch_spec_t spec;
        if (!cbm_daemon_bootstrap_launch_spec_init(config->executable_path, &spec) ||
            !ops->startup_lock_prepare_handoff(ops->context, startup_lock) ||
            !ops->spawn_daemon(ops->context, &spec)) {
            probe = CBM_DAEMON_BOOTSTRAP_PROBE_ERROR;
            break;
        }
        result_out->daemon_spawned = true;

        /* Keep startup ownership until the child becomes observable. A
         * RESERVED response here belongs to the generation we just launched,
         * so it remains a wait state rather than a reason to release/spawn. */
        do {
            bootstrap_pause(deadline);
            probe = bootstrap_probe(config, ops, &client, &connect_result);
            if (!bootstrap_probe_is_waitable(probe)) {
                break;
            }
        } while (cbm_now_ms() < deadline);
        break;
    }

    if (lock_acquired) {
        bootstrap_startup_lock_release_complete(ops, &startup_lock);
    }
    if (bootstrap_probe_is_finishable(probe)) {
        cbm_daemon_bootstrap_status_t status =
            bootstrap_finish_probe(probe, client, &connect_result, ops, result_out);
        ops->cohort_release(ops->context, cohort);
        return status;
    }

    result_out->status = CBM_DAEMON_BOOTSTRAP_FAILED;
    if (generation_observed) {
        (void)snprintf(result_out->message, sizeof(result_out->message),
                       "CBM daemon is active or starting but could not accept this client "
                       "within %u ms",
                       config->startup_timeout_ms);
    } else {
        (void)snprintf(result_out->message, sizeof(result_out->message),
                       "CBM daemon could not start within %u ms", config->startup_timeout_ms);
    }
    if (ops->visible_diagnostic) {
        ops->visible_diagnostic(ops->context, result_out->message);
    }
    ops->cohort_release(ops->context, cohort);
    return result_out->status;
}

cbm_daemon_bootstrap_probe_status_t cbm_daemon_bootstrap_classify_failed_connect(
    const cbm_daemon_runtime_connect_result_t *connect_result, int lifetime_status) {
    if (!connect_result) {
        return CBM_DAEMON_BOOTSTRAP_PROBE_ERROR;
    }
    if (connect_result->status == CBM_DAEMON_RUNTIME_CONNECT_CONFLICT) {
        return CBM_DAEMON_BOOTSTRAP_PROBE_CONFLICT;
    }
    if (connect_result->status == CBM_DAEMON_RUNTIME_CONNECT_REJECTED) {
        if (strstr(connect_result->message, "stopping") ||
            strstr(connect_result->message, "shutting down")) {
            return CBM_DAEMON_BOOTSTRAP_PROBE_TERMINAL;
        }
        /* Capacity, admission, and other protocol-level rejections prove an
         * existing generation answered. Never reinterpret them as absence. */
        return CBM_DAEMON_BOOTSTRAP_PROBE_RESERVED;
    }
    if (lifetime_status == 1) {
        return CBM_DAEMON_BOOTSTRAP_PROBE_RESERVED;
    }
    if (lifetime_status != 0) {
        return CBM_DAEMON_BOOTSTRAP_PROBE_ERROR;
    }
    return connect_result->status == CBM_DAEMON_RUNTIME_CONNECT_ERROR
               ? CBM_DAEMON_BOOTSTRAP_PROBE_UNAVAILABLE
               : CBM_DAEMON_BOOTSTRAP_PROBE_ERROR;
}

typedef struct bootstrap_production_cohort {
    cbm_version_cohort_manager_t *manager;
    cbm_version_cohort_lease_t *lease;
} bootstrap_production_cohort_t;

typedef struct {
    bootstrap_production_cohort_t *cohort;
} bootstrap_production_context_t;

static cbm_daemon_bootstrap_probe_status_t bootstrap_production_probe(
    void *context, const cbm_daemon_ipc_endpoint_t *endpoint,
    const cbm_daemon_build_identity_t *identity, uint32_t timeout_ms,
    cbm_daemon_runtime_client_t **client_out, cbm_daemon_runtime_connect_result_t *result_out) {
    bootstrap_production_context_t *production = context;
    if (!production || !production->cohort || !production->cohort->manager) {
        return CBM_DAEMON_BOOTSTRAP_PROBE_ERROR;
    }
    cbm_version_cohort_daemon_presence_t claim =
        cbm_version_cohort_daemon_claim_presence(production->cohort->manager);
    if (claim == CBM_VERSION_COHORT_DAEMON_ABSENT) {
        int lifetime = cbm_daemon_ipc_lifetime_reservation_probe(endpoint);
        if (lifetime == 0) {
            /* Do not spend the per-connect timeout polling a generation that
             * both independent ownership signals prove absent. The startup
             * lock and its mandatory re-probe serialize a concurrent launch. */
            return CBM_DAEMON_BOOTSTRAP_PROBE_UNAVAILABLE;
        }
        if (lifetime != 1) {
            return CBM_DAEMON_BOOTSTRAP_PROBE_ERROR;
        }
    } else if (claim != CBM_VERSION_COHORT_DAEMON_COORDINATED) {
        return CBM_DAEMON_BOOTSTRAP_PROBE_ERROR;
    }

    *client_out = cbm_daemon_runtime_client_connect(endpoint, identity, timeout_ms, result_out);
    if (*client_out) {
        return CBM_DAEMON_BOOTSTRAP_PROBE_CONNECTED;
    }

    /* Ownership may turn over while the connection attempt is in flight.
     * Re-observe both signals so disappearance is not sticky and a live or
     * cleaning-up generation is never mistaken for absence. */
    claim = cbm_version_cohort_daemon_claim_presence(production->cohort->manager);
    if (claim == CBM_VERSION_COHORT_DAEMON_COORDINATED) {
        return cbm_daemon_bootstrap_classify_failed_connect(result_out, 1);
    }
    if (claim != CBM_VERSION_COHORT_DAEMON_ABSENT) {
        return CBM_DAEMON_BOOTSTRAP_PROBE_ERROR;
    }
    int lifetime_status = cbm_daemon_ipc_lifetime_reservation_probe(endpoint);
    return cbm_daemon_bootstrap_classify_failed_connect(result_out, lifetime_status);
}

static cbm_version_cohort_status_t bootstrap_production_cohort_acquire(
    void *context, const cbm_daemon_ipc_endpoint_t *endpoint,
    const cbm_daemon_build_identity_t *identity, uint64_t deadline_ms,
    cbm_daemon_bootstrap_cohort_t *cohort_out, cbm_daemon_conflict_t *conflict_out) {
    *cohort_out = NULL;
    bootstrap_production_cohort_t *cohort = calloc(1, sizeof(*cohort));
    if (cohort) {
        cohort->manager = cbm_version_cohort_manager_new(endpoint);
    }
    if (!cohort || !cohort->manager) {
        free(cohort);
        return CBM_VERSION_COHORT_IO;
    }
    cbm_version_cohort_status_t status = cbm_version_cohort_acquire(
        cohort->manager, identity, deadline_ms, &cohort->lease, conflict_out);
    if (status == CBM_VERSION_COHORT_CONFLICT) {
        (void)cbm_version_cohort_log_conflict(conflict_out);
    }
    if (status == CBM_VERSION_COHORT_OK || cohort->lease) {
        *cohort_out = cohort;
        if (context) {
            bootstrap_production_context_t *production = context;
            production->cohort = cohort;
        }
        return status;
    }
    uint64_t cleanup_deadline = bootstrap_deadline_after(BOOTSTRAP_COORDINATION_CLEANUP_MS);
    cbm_private_file_lock_status_t cleanup = CBM_PRIVATE_FILE_LOCK_OK;
    while (cohort->manager) {
        cleanup = cbm_version_cohort_manager_free(&cohort->manager);
        if (!cohort->manager) {
            break;
        }
        if (cbm_now_ms() >= cleanup_deadline) {
            bootstrap_cleanup_fail_stop("cohort_manager_cleanup");
        }
        cbm_usleep(1000);
    }
    free(cohort);
    return cleanup == CBM_PRIVATE_FILE_LOCK_OK ? status : CBM_VERSION_COHORT_IO;
}

static void bootstrap_production_cohort_release(void *context,
                                                cbm_daemon_bootstrap_cohort_t opaque) {
    bootstrap_production_context_t *production = context;
    bootstrap_production_cohort_t *cohort = opaque;
    if (!cohort) {
        return;
    }
    uint64_t cleanup_deadline = bootstrap_deadline_after(BOOTSTRAP_COORDINATION_CLEANUP_MS);
    while (cohort->lease) {
        (void)cbm_version_cohort_lease_release(&cohort->lease);
        if (!cohort->lease) {
            break;
        }
        if (cbm_now_ms() >= cleanup_deadline) {
            bootstrap_cleanup_fail_stop("cohort_lease_cleanup");
        }
        cbm_usleep(1000);
    }
    cleanup_deadline = bootstrap_deadline_after(BOOTSTRAP_COORDINATION_CLEANUP_MS);
    while (cohort->manager) {
        (void)cbm_version_cohort_manager_free(&cohort->manager);
        if (!cohort->manager) {
            break;
        }
        if (cbm_now_ms() >= cleanup_deadline) {
            bootstrap_cleanup_fail_stop("cohort_manager_cleanup");
        }
        cbm_usleep(1000);
    }
    if (production && production->cohort == cohort) {
        production->cohort = NULL;
    }
    free(cohort);
}

static int bootstrap_production_lock(void *context, const cbm_daemon_ipc_endpoint_t *endpoint,
                                     cbm_daemon_bootstrap_lock_t *lock_out) {
    (void)context;
    cbm_daemon_ipc_startup_lock_t *lock = NULL;
    int status = cbm_daemon_ipc_startup_lock_try_acquire(endpoint, &lock);
    *lock_out = lock;
    return status;
}

static bool bootstrap_production_unlock(void *context, cbm_daemon_bootstrap_lock_t *lock_io) {
    (void)context;
    if (!lock_io) {
        return false;
    }
    cbm_daemon_ipc_startup_lock_t *lock = *lock_io;
    bool released = cbm_daemon_ipc_startup_lock_release(&lock);
    *lock_io = lock;
    return released;
}

static bool bootstrap_production_handoff(void *context, cbm_daemon_bootstrap_lock_t lock) {
    (void)context;
    return cbm_daemon_ipc_startup_lock_prepare_handoff((cbm_daemon_ipc_startup_lock_t *)lock);
}

#ifdef _WIN32
static bool bootstrap_production_spawn(void *context,
                                       const cbm_daemon_bootstrap_launch_spec_t *spec) {
    (void)context;
    if (!spec || !spec->detached || spec->inherit_standard_handles || spec->use_shell) {
        return false;
    }
    char command_line[BOOTSTRAP_PATH_CAP * 2];
    if (!cbm_build_win_cmdline(command_line, sizeof(command_line), spec->argv)) {
        return false;
    }
    wchar_t *application = cbm_utf8_to_wide(spec->executable_path);
    wchar_t *command = cbm_utf8_to_wide(command_line);
    if (!application || !command) {
        free(application);
        free(command);
        return false;
    }
    STARTUPINFOW startup;
    PROCESS_INFORMATION child;
    ZeroMemory(&startup, sizeof(startup));
    ZeroMemory(&child, sizeof(child));
    startup.cb = sizeof(startup);
    DWORD flags = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW;
    /* A managed frontend payload is intentionally contained in the permanent
     * launcher's kill-on-close job. The account daemon outlives that one
     * frontend and therefore uses breakaway when the containing job explicitly
     * permits it. Do not request breakaway from an unrelated restrictive job:
     * CreateProcess would fail and regress portable/package-manager payloads. */
    BOOL in_job = FALSE;
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION job_limits;
    memset(&job_limits, 0, sizeof(job_limits));
    if (IsProcessInJob(GetCurrentProcess(), NULL, &in_job) && in_job &&
        QueryInformationJobObject(NULL, JobObjectExtendedLimitInformation, &job_limits,
                                  sizeof(job_limits), NULL) &&
        (job_limits.BasicLimitInformation.LimitFlags &
         (JOB_OBJECT_LIMIT_BREAKAWAY_OK | JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK)) != 0) {
        flags |= CREATE_BREAKAWAY_FROM_JOB;
    }
    BOOL created = CreateProcessW(application, command, NULL, NULL, FALSE, flags, NULL, NULL,
                                  &startup, &child);
    free(application);
    free(command);
    if (!created) {
        return false;
    }
    (void)CloseHandle(child.hThread);
    (void)CloseHandle(child.hProcess);
    return true;
}
#else
static void bootstrap_child_close_fds(void) {
    long open_max = sysconf(_SC_OPEN_MAX);
    if (open_max < 0 || open_max > 1048576L) {
        open_max = 65536L;
    }
    for (int fd = 3; fd < open_max; fd++) {
        (void)close(fd);
    }
}

static void bootstrap_daemon_grandchild(const cbm_daemon_bootstrap_launch_spec_t *spec) {
    (void)umask(077);
    sigset_t empty;
    (void)sigemptyset(&empty);
    (void)sigprocmask(SIG_SETMASK, &empty, NULL);
    int null_fd = open("/dev/null", O_RDWR);
    if (null_fd < 0 || dup2(null_fd, STDIN_FILENO) < 0 || dup2(null_fd, STDOUT_FILENO) < 0 ||
        dup2(null_fd, STDERR_FILENO) < 0) {
        _exit(127);
    }
    if (null_fd > STDERR_FILENO) {
        (void)close(null_fd);
    }
    bootstrap_child_close_fds();
    execv(spec->executable_path, (char *const *)spec->argv);
    _exit(127);
}

static bool bootstrap_production_spawn(void *context,
                                       const cbm_daemon_bootstrap_launch_spec_t *spec) {
    (void)context;
    if (!spec || !spec->detached || spec->inherit_standard_handles || spec->use_shell) {
        return false;
    }
    pid_t first = fork();
    if (first < 0) {
        return false;
    }
    if (first == 0) {
        if (setsid() < 0) {
            _exit(127);
        }
        pid_t daemon = fork();
        if (daemon < 0) {
            _exit(127);
        }
        if (daemon > 0) {
            _exit(0);
        }
        bootstrap_daemon_grandchild(spec);
    }

    int status = 0;
    pid_t waited;
    do {
        waited = waitpid(first, &status, 0);
    } while (waited < 0 && errno == EINTR);
    return waited == first && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}
#endif

static void bootstrap_production_diagnostic(void *context, const char *message) {
    (void)context;
    (void)fprintf(stderr, "codebase-memory-mcp: %s\n", message ? message : "daemon startup failed");
    (void)fflush(stderr);
}

cbm_daemon_bootstrap_status_t cbm_daemon_bootstrap_execute(
    const cbm_daemon_bootstrap_config_t *config, cbm_daemon_bootstrap_result_t *result_out) {
    bootstrap_production_context_t context = {0};
    const cbm_daemon_bootstrap_ops_t ops = {
        .context = &context,
        .cohort_acquire = bootstrap_production_cohort_acquire,
        .cohort_release = bootstrap_production_cohort_release,
        .probe = bootstrap_production_probe,
        .startup_lock_try_acquire = bootstrap_production_lock,
        .startup_lock_prepare_handoff = bootstrap_production_handoff,
        .startup_lock_release = bootstrap_production_unlock,
        .spawn_daemon = bootstrap_production_spawn,
        .visible_diagnostic = bootstrap_production_diagnostic,
    };
    return cbm_daemon_bootstrap_execute_with_ops(config, &ops, result_out);
}
