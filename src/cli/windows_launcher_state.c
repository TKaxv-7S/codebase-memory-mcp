#include "cli/windows_launcher_state.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const uint8_t current_v1_magic[8] = {
    'C', 'B', 'M', 'C', 'U', 'R', '1', '\0',
};

static const uint8_t release_descriptor_v1_magic[8] = {
    'C', 'B', 'M', 'W', 'R', 'D', '1', '\0',
};

static uint32_t read_u32_le(const uint8_t *input) {
    return (uint32_t)input[0] | ((uint32_t)input[1] << 8U) | ((uint32_t)input[2] << 16U) |
           ((uint32_t)input[3] << 24U);
}

static uint64_t read_u64_le(const uint8_t *input) {
    uint64_t value = 0;
    for (unsigned int index = 0; index < 8U; index++) {
        value |= (uint64_t)input[index] << (index * 8U);
    }
    return value;
}

static void write_u32_le(uint8_t *output, uint32_t value) {
    for (unsigned int index = 0; index < 4U; index++) {
        output[index] = (uint8_t)(value >> (index * 8U));
    }
}

static void write_u64_le(uint8_t *output, uint64_t value) {
    for (unsigned int index = 0; index < 8U; index++) {
        output[index] = (uint8_t)(value >> (index * 8U));
    }
}

static bool lowercase_sha256_valid(const char *digest) {
    if (!digest) {
        return false;
    }
    for (size_t index = 0; index < 64U; index++) {
        char value = digest[index];
        if (!((value >= '0' && value <= '9') || (value >= 'a' && value <= 'f'))) {
            return false;
        }
    }
    return digest[64] == '\0';
}

static bool current_v1_state_valid(const cbm_windows_current_v1_t *state) {
    return state && state->launcher_abi_min > 0U &&
           state->launcher_abi_min <= state->launcher_abi_max && state->payload_size > 0U &&
           lowercase_sha256_valid(state->payload_sha256);
}

static bool release_descriptor_v1_valid(const cbm_windows_release_descriptor_v1_t *descriptor) {
    return descriptor && descriptor->launcher_abi > 0U &&
           descriptor->payload_launcher_abi_min > 0U &&
           descriptor->payload_launcher_abi_min <= descriptor->payload_launcher_abi_max &&
           descriptor->launcher_abi >= descriptor->payload_launcher_abi_min &&
           descriptor->launcher_abi <= descriptor->payload_launcher_abi_max &&
           descriptor->payload_size > 0U && lowercase_sha256_valid(descriptor->payload_sha256);
}

bool cbm_windows_current_v1_encode(const cbm_windows_current_v1_t *state,
                                   uint8_t out[CBM_WINDOWS_CURRENT_V1_SIZE]) {
    if (!current_v1_state_valid(state) || !out) {
        return false;
    }
    memset(out, 0, CBM_WINDOWS_CURRENT_V1_SIZE);
    memcpy(out, current_v1_magic, sizeof(current_v1_magic));
    write_u32_le(out + 8U, 1U);
    write_u32_le(out + 12U, CBM_WINDOWS_CURRENT_V1_SIZE);
    write_u32_le(out + 16U, state->launcher_abi_min);
    write_u32_le(out + 20U, state->launcher_abi_max);
    write_u64_le(out + 24U, state->payload_size);
    memcpy(out + 32U, state->payload_sha256, 64U);
    return true;
}

bool cbm_windows_current_v1_decode(const uint8_t *record, size_t record_size,
                                   cbm_windows_current_v1_t *state_out) {
    if (state_out) {
        memset(state_out, 0, sizeof(*state_out));
    }
    if (!record || !state_out || record_size != CBM_WINDOWS_CURRENT_V1_SIZE ||
        memcmp(record, current_v1_magic, sizeof(current_v1_magic)) != 0 ||
        read_u32_le(record + 8U) != 1U ||
        read_u32_le(record + 12U) != CBM_WINDOWS_CURRENT_V1_SIZE) {
        return false;
    }
    for (size_t index = 96U; index < CBM_WINDOWS_CURRENT_V1_SIZE; index++) {
        if (record[index] != 0U) {
            return false;
        }
    }
    cbm_windows_current_v1_t decoded;
    memset(&decoded, 0, sizeof(decoded));
    decoded.launcher_abi_min = read_u32_le(record + 16U);
    decoded.launcher_abi_max = read_u32_le(record + 20U);
    decoded.payload_size = read_u64_le(record + 24U);
    memcpy(decoded.payload_sha256, record + 32U, 64U);
    decoded.payload_sha256[64] = '\0';
    if (!current_v1_state_valid(&decoded)) {
        return false;
    }
    *state_out = decoded;
    return true;
}

bool cbm_windows_current_v1_supports_launcher_abi(const cbm_windows_current_v1_t *state,
                                                  uint32_t launcher_abi) {
    return current_v1_state_valid(state) && launcher_abi > 0U &&
           launcher_abi >= state->launcher_abi_min && launcher_abi <= state->launcher_abi_max;
}

bool cbm_windows_release_descriptor_v1_encode(const cbm_windows_release_descriptor_v1_t *descriptor,
                                              uint8_t out[CBM_WINDOWS_RELEASE_DESCRIPTOR_V1_SIZE]) {
    if (!release_descriptor_v1_valid(descriptor) || !out) {
        return false;
    }
    memset(out, 0, CBM_WINDOWS_RELEASE_DESCRIPTOR_V1_SIZE);
    memcpy(out, release_descriptor_v1_magic, sizeof(release_descriptor_v1_magic));
    write_u32_le(out + 8U, 1U);
    write_u32_le(out + 12U, CBM_WINDOWS_RELEASE_DESCRIPTOR_V1_SIZE);
    write_u32_le(out + 16U, descriptor->launcher_abi);
    write_u32_le(out + 20U, descriptor->payload_launcher_abi_min);
    write_u32_le(out + 24U, descriptor->payload_launcher_abi_max);
    write_u32_le(out + 28U, 0U);
    write_u64_le(out + 32U, descriptor->payload_size);
    memcpy(out + 40U, descriptor->payload_sha256, 64U);
    return true;
}

bool cbm_windows_release_descriptor_v1_decode(const uint8_t *record, size_t record_size,
                                              cbm_windows_release_descriptor_v1_t *descriptor_out) {
    if (descriptor_out) {
        memset(descriptor_out, 0, sizeof(*descriptor_out));
    }
    if (!record || !descriptor_out || record_size != CBM_WINDOWS_RELEASE_DESCRIPTOR_V1_SIZE ||
        memcmp(record, release_descriptor_v1_magic, sizeof(release_descriptor_v1_magic)) != 0 ||
        read_u32_le(record + 8U) != 1U ||
        read_u32_le(record + 12U) != CBM_WINDOWS_RELEASE_DESCRIPTOR_V1_SIZE ||
        read_u32_le(record + 28U) != 0U) {
        return false;
    }
    for (size_t index = 104U; index < CBM_WINDOWS_RELEASE_DESCRIPTOR_V1_SIZE; index++) {
        if (record[index] != 0U) {
            return false;
        }
    }
    cbm_windows_release_descriptor_v1_t decoded;
    memset(&decoded, 0, sizeof(decoded));
    decoded.launcher_abi = read_u32_le(record + 16U);
    decoded.payload_launcher_abi_min = read_u32_le(record + 20U);
    decoded.payload_launcher_abi_max = read_u32_le(record + 24U);
    decoded.payload_size = read_u64_le(record + 32U);
    memcpy(decoded.payload_sha256, record + 40U, 64U);
    decoded.payload_sha256[64] = '\0';
    if (!release_descriptor_v1_valid(&decoded)) {
        return false;
    }
    *descriptor_out = decoded;
    return true;
}

cbm_windows_transition_plan_t cbm_windows_transition_plan(
    const cbm_windows_current_v1_t *current, const cbm_windows_release_descriptor_v1_t *candidate) {
    if (!current_v1_state_valid(current) || !release_descriptor_v1_valid(candidate)) {
        return CBM_WINDOWS_TRANSITION_INCOMPATIBLE;
    }
    if (cbm_windows_current_v1_supports_launcher_abi(current, candidate->launcher_abi)) {
        return CBM_WINDOWS_TRANSITION_LAUNCHER_FIRST;
    }
    if (candidate->payload_launcher_abi_min <= current->launcher_abi_min &&
        candidate->payload_launcher_abi_max >= current->launcher_abi_max) {
        return CBM_WINDOWS_TRANSITION_CURRENT_FIRST;
    }
    return CBM_WINDOWS_TRANSITION_INCOMPATIBLE;
}

bool cbm_windows_generation_payload_path(const wchar_t *canonical_launcher_path,
                                         const char payload_sha256[65], wchar_t *path_out,
                                         size_t path_capacity) {
    if (path_out && path_capacity > 0U) {
        path_out[0] = L'\0';
    }
    if (!canonical_launcher_path || !lowercase_sha256_valid(payload_sha256) || !path_out ||
        path_capacity == 0U) {
        return false;
    }
    const wchar_t *last_backslash = wcsrchr(canonical_launcher_path, L'\\');
    const wchar_t *last_slash = wcsrchr(canonical_launcher_path, L'/');
    const wchar_t *separator = last_backslash;
    if (!separator || (last_slash && last_slash > separator)) {
        separator = last_slash;
    }
    if (!separator || separator == canonical_launcher_path ||
        (separator == canonical_launcher_path + 2 && canonical_launcher_path[1] != L':')) {
        return false;
    }
    size_t directory_length = (size_t)(separator - canonical_launcher_path);
    if (directory_length == 2U && canonical_launcher_path[1] == L':') {
        directory_length = 3U; /* Preserve C:\ rather than producing C:.cbm. */
    }
    static const wchar_t middle[] = L".cbm\\generations\\";
    static const wchar_t leaf[] = L"\\codebase-memory-mcp.payload.exe";
    size_t middle_length = sizeof(middle) / sizeof(middle[0]) - 1U;
    size_t leaf_length = sizeof(leaf) / sizeof(leaf[0]) - 1U;
    bool root = directory_length == 3U && canonical_launcher_path[1] == L':' &&
                (canonical_launcher_path[2] == L'\\' || canonical_launcher_path[2] == L'/');
    size_t separator_count = root ? 0U : 1U;
    size_t needed = directory_length + separator_count + middle_length + 64U + leaf_length + 1U;
    if (needed > path_capacity) {
        return false;
    }
    size_t offset = 0U;
    memcpy(path_out + offset, canonical_launcher_path, directory_length * sizeof(*path_out));
    offset += directory_length;
    if (!root) {
        path_out[offset++] = L'\\';
    } else {
        path_out[2] = L'\\';
    }
    memcpy(path_out + offset, middle, middle_length * sizeof(*path_out));
    offset += middle_length;
    for (size_t index = 0; index < 64U; index++) {
        path_out[offset++] = (wchar_t)(unsigned char)payload_sha256[index];
    }
    memcpy(path_out + offset, leaf, (leaf_length + 1U) * sizeof(*path_out));
    return true;
}

static bool argument_is(const char *argument, const char *expected) {
    return argument && expected && strcmp(argument, expected) == 0;
}

cbm_windows_launcher_action_t cbm_windows_launcher_classify_action(int argc,
                                                                   const char *const argv[]) {
    if (argc <= 1 || !argv) {
        return CBM_WINDOWS_LAUNCHER_ACTION_ORDINARY;
    }
    for (int index = 1; index < argc; index++) {
        const char *argument = argv[index];
        if (argument_is(argument, "cli") || argument_is(argument, "hook-augment") ||
            argument_is(argument, "config") || argument_is(argument, "install") ||
            argument_is(argument, "--help") || argument_is(argument, "-h") ||
            argument_is(argument, "--version")) {
            return CBM_WINDOWS_LAUNCHER_ACTION_ORDINARY;
        }
        if (argument_is(argument, "update")) {
            return CBM_WINDOWS_LAUNCHER_ACTION_UPDATE;
        }
        if (argument_is(argument, "uninstall")) {
            return CBM_WINDOWS_LAUNCHER_ACTION_UNINSTALL;
        }
    }
    return CBM_WINDOWS_LAUNCHER_ACTION_ORDINARY;
}

bool cbm_windows_launcher_action_allowed(cbm_windows_launcher_action_t action, bool managed) {
    switch (action) {
    case CBM_WINDOWS_LAUNCHER_ACTION_ORDINARY:
        return true;
    case CBM_WINDOWS_LAUNCHER_ACTION_UPDATE:
    case CBM_WINDOWS_LAUNCHER_ACTION_UNINSTALL:
        return managed;
    default:
        return false;
    }
}

static void launcher_error(char *error, size_t error_size, const char *message) {
    if (error && error_size > 0U) {
        (void)snprintf(error, error_size, "%s", message ? message : "error");
    }
}

#ifndef _WIN32

bool cbm_windows_launcher_context_consume(cbm_windows_launcher_context_t *context_out, char *error,
                                          size_t error_size) {
    if (context_out) {
        memset(context_out, 0, sizeof(*context_out));
    }
    if (!context_out) {
        launcher_error(error, error_size, "invalid launcher context output");
        return false;
    }
    if (error && error_size > 0U) {
        error[0] = '\0';
    }
    return true;
}

bool cbm_windows_launcher_context_complete(cbm_windows_launcher_context_t *context, bool accepted,
                                           char *error, size_t error_size) {
    (void)accepted;
    if (error && error_size > 0U)
        error[0] = '\0';
    if (!context || context->_authority_handle != 0U) {
        launcher_error(error, error_size, "invalid launcher context completion");
        return false;
    }
    return true;
}

bool cbm_windows_launcher_capability_probe(const wchar_t *target_directory,
                                           const wchar_t *launcher_candidate, char *error,
                                           size_t error_size) {
    (void)target_directory;
    (void)launcher_candidate;
    launcher_error(error, error_size, "Windows launcher support is unavailable");
    return false;
}

bool cbm_windows_launcher_file_secure(const wchar_t *launcher_path, char *error,
                                      size_t error_size) {
    (void)launcher_path;
    launcher_error(error, error_size, "Windows launcher support is unavailable");
    return false;
}

bool cbm_windows_release_descriptor_probe(const wchar_t *launcher_candidate,
                                          cbm_windows_release_descriptor_v1_t *descriptor_out,
                                          char *error, size_t error_size) {
    (void)launcher_candidate;
    if (descriptor_out) {
        memset(descriptor_out, 0, sizeof(*descriptor_out));
    }
    launcher_error(error, error_size, "Windows launcher support is unavailable");
    return false;
}

bool cbm_windows_current_v1_write_atomic(const wchar_t *canonical_launcher_path,
                                         const cbm_windows_current_v1_t *state, char *error,
                                         size_t error_size) {
    (void)canonical_launcher_path;
    (void)state;
    launcher_error(error, error_size, "Windows launcher support is unavailable");
    return false;
}

bool cbm_windows_launcher_replace_atomic(const wchar_t *target_path, const wchar_t *candidate_path,
                                         char *error, size_t error_size) {
    (void)target_path;
    (void)candidate_path;
    launcher_error(error, error_size, "Windows launcher support is unavailable");
    return false;
}

bool cbm_windows_launcher_remove_posix(const wchar_t *target_path, char *error, size_t error_size) {
    (void)target_path;
    launcher_error(error, error_size, "Windows launcher support is unavailable");
    return false;
}

bool cbm_windows_generation_rollback_if_unreferenced(const wchar_t *canonical_launcher_path,
                                                     const char payload_sha256[65],
                                                     bool created_by_activation, char *error,
                                                     size_t error_size) {
    (void)canonical_launcher_path;
    (void)payload_sha256;
    (void)created_by_activation;
    launcher_error(error, error_size, "Windows launcher support is unavailable");
    return false;
}

bool cbm_windows_generations_prune(const wchar_t *canonical_launcher_path, size_t *removed_out,
                                   char *error, size_t error_size) {
    (void)canonical_launcher_path;
    if (removed_out) {
        *removed_out = 0U;
    }
    launcher_error(error, error_size, "Windows launcher support is unavailable");
    return false;
}

#else

/* The Windows implementation follows below.  Keep the byte codec above free
 * of platform conditionals so all hosts continuously test the release ABI. */

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>

#ifndef PROC_THREAD_ATTRIBUTE_JOB_LIST
#define PROC_THREAD_ATTRIBUTE_JOB_LIST ((DWORD_PTR)0x0002000dU)
#endif

#define CBM_LAUNCH_CONTEXT_ENV L"CBM_WINDOWS_LAUNCH_CONTEXT_HANDLE_V1"
#define CBM_LAUNCH_CONTEXT_HEADER_SIZE 128U
#define CBM_LAUNCH_CONTEXT_FLAG_MANAGED 0x00000001U
#define CBM_LAUNCH_CONTEXT_FLAG_PRIVATE 0x00000002U

static const uint8_t launch_context_magic[8] = {
    'C', 'B', 'M', 'L', 'C', 'T', '1', '\0',
};

/* The launcher source writes this exact explicit byte layout. */
static bool launch_context_header_decode(const uint8_t input[CBM_LAUNCH_CONTEXT_HEADER_SIZE],
                                         uint32_t *flags_out,
                                         cbm_windows_launcher_action_t *action_out,
                                         DWORD *server_pid_out, FILETIME *creation_out,
                                         uint64_t *payload_size_out, char digest_out[65],
                                         uint32_t *path_chars_out) {
    if (memcmp(input, launch_context_magic, sizeof(launch_context_magic)) != 0 ||
        read_u32_le(input + 8U) != 1U ||
        read_u32_le(input + 12U) != CBM_LAUNCH_CONTEXT_HEADER_SIZE) {
        return false;
    }
    uint32_t flags = read_u32_le(input + 16U);
    uint32_t action = read_u32_le(input + 20U);
    uint32_t server_pid = read_u32_le(input + 24U);
    uint32_t path_chars = read_u32_le(input + 28U);
    uint64_t creation = read_u64_le(input + 32U);
    uint64_t payload_size = read_u64_le(input + 40U);
    char digest[65];
    memcpy(digest, input + 48U, 64U);
    digest[64] = '\0';
    for (size_t index = 112U; index < CBM_LAUNCH_CONTEXT_HEADER_SIZE; index++) {
        if (input[index] != 0U) {
            return false;
        }
    }
    bool managed = (flags & CBM_LAUNCH_CONTEXT_FLAG_MANAGED) != 0U;
    bool digest_zero = true;
    for (size_t index = 0U; index < 64U; index++) {
        if (input[48U + index] != 0U) {
            digest_zero = false;
        }
    }
    if ((flags & ~(CBM_LAUNCH_CONTEXT_FLAG_MANAGED | CBM_LAUNCH_CONTEXT_FLAG_PRIVATE)) != 0U ||
        (!managed && (flags & CBM_LAUNCH_CONTEXT_FLAG_PRIVATE) != 0U) ||
        action > (uint32_t)CBM_WINDOWS_LAUNCHER_ACTION_UNINSTALL || server_pid == 0U ||
        path_chars < 4U || path_chars >= CBM_WINDOWS_LAUNCHER_PATH_CAP || creation == 0U ||
        (managed && (payload_size == 0U || !lowercase_sha256_valid(digest))) ||
        (!managed && (payload_size != 0U || !digest_zero))) {
        return false;
    }
    *flags_out = flags;
    *action_out = (cbm_windows_launcher_action_t)action;
    *server_pid_out = server_pid;
    creation_out->dwLowDateTime = (DWORD)creation;
    creation_out->dwHighDateTime = (DWORD)(creation >> 32U);
    *payload_size_out = payload_size;
    memcpy(digest_out, digest, sizeof(digest));
    *path_chars_out = path_chars;
    return true;
}

static bool windows_read_exact(HANDLE file, void *buffer, size_t size) {
    size_t offset = 0U;
    while (offset < size) {
        DWORD chunk = size - offset > (size_t)MAXDWORD ? MAXDWORD : (DWORD)(size - offset);
        DWORD amount = 0U;
        if (!ReadFile(file, (uint8_t *)buffer + offset, chunk, &amount, NULL) || amount == 0U) {
            return false;
        }
        offset += amount;
    }
    return true;
}

static bool windows_pipe_wait_available(HANDLE pipe, size_t needed, uint64_t deadline) {
    if (needed > (size_t)MAXDWORD)
        return false;
    while (GetTickCount64() < deadline) {
        DWORD available = 0U;
        if (!PeekNamedPipe(pipe, NULL, 0U, NULL, &available, NULL)) {
            return false;
        }
        if ((size_t)available >= needed)
            return true;
        Sleep(2U);
    }
    return false;
}

static bool windows_file_identity(HANDLE file, BY_HANDLE_FILE_INFORMATION *information) {
    return file && file != INVALID_HANDLE_VALUE && GetFileType(file) == FILE_TYPE_DISK &&
           GetFileInformationByHandle(file, information) != 0 &&
           (information->dwFileAttributes &
            (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) == 0 &&
           information->nNumberOfLinks == 1U;
}

static bool windows_same_identity(const BY_HANDLE_FILE_INFORMATION *first,
                                  const BY_HANDLE_FILE_INFORMATION *second) {
    return first->dwVolumeSerialNumber == second->dwVolumeSerialNumber &&
           first->nFileIndexHigh == second->nFileIndexHigh &&
           first->nFileIndexLow == second->nFileIndexLow;
}

static uint32_t windows_sid_read_u32_le(const uint8_t *bytes) {
    return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8U) | ((uint32_t)bytes[2] << 16U) |
           ((uint32_t)bytes[3] << 24U);
}

static bool windows_sid_is_trusted_installer(PSID sid) {
    static const uint32_t subauthorities[] = {
        80U, 956008885U, 3418522649U, 1831038044U, 1853292631U, 2271478464U,
    };
    if (!sid || !IsValidSid(sid)) {
        return false;
    }
    DWORD sid_length = GetLengthSid(sid);
    const uint8_t *bytes = (const uint8_t *)sid;
    if (sid_length != 32U || bytes[0] != 1U || bytes[1] != 6U || bytes[2] != 0U || bytes[3] != 0U ||
        bytes[4] != 0U || bytes[5] != 0U || bytes[6] != 0U || bytes[7] != 5U) {
        return false;
    }
    for (size_t index = 0U; index < sizeof(subauthorities) / sizeof(subauthorities[0]); index++) {
        if (windows_sid_read_u32_le(bytes + 8U + index * 4U) != subauthorities[index]) {
            return false;
        }
    }
    return true;
}

static bool windows_sid_is_trusted(PSID sid, PSID current_user) {
    return sid && current_user && IsValidSid(sid) &&
           (EqualSid(sid, current_user) || IsWellKnownSid(sid, WinLocalSystemSid) ||
            IsWellKnownSid(sid, WinBuiltinAdministratorsSid) ||
            windows_sid_is_trusted_installer(sid));
}

static bool windows_bounded_ace_sid_is_trusted(const ACE_HEADER *header, PSID current_user) {
    size_t sid_offset = offsetof(ACCESS_ALLOWED_ACE, SidStart);
    if (!header || (size_t)header->AceSize < sid_offset + 8U) {
        return false;
    }
    const ACCESS_ALLOWED_ACE *ace = (const ACCESS_ALLOWED_ACE *)header;
    const uint8_t *sid = (const uint8_t *)&ace->SidStart;
    size_t sid_capacity = (size_t)header->AceSize - sid_offset;
    if (sid[0] != 1U || sid[1] > 15U) {
        return false;
    }
    size_t sid_length = 8U + (size_t)sid[1] * 4U;
    return sid_length <= sid_capacity && IsValidSid((PSID)sid) &&
           GetLengthSid((PSID)sid) == (DWORD)sid_length &&
           (windows_sid_is_trusted((PSID)sid, current_user) ||
            (((header->AceFlags & INHERIT_ONLY_ACE) != 0U) &&
             IsWellKnownSid((PSID)sid, WinCreatorOwnerSid)));
}

static bool windows_owner_secure(HANDLE file, bool require_current_user) {
    HANDLE token = NULL;
    DWORD token_size = 0U;
    PTOKEN_USER user = NULL;
    PSID owner = NULL;
    PSECURITY_DESCRIPTOR descriptor = NULL;
    bool ok = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token) != 0;
    if (ok) {
        (void)GetTokenInformation(token, TokenUser, NULL, 0U, &token_size);
        user = token_size ? (PTOKEN_USER)malloc(token_size) : NULL;
        ok = user && GetTokenInformation(token, TokenUser, user, token_size, &token_size) != 0;
    }
    if (ok) {
        ok = GetSecurityInfo(file, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, &owner, NULL, NULL,
                             NULL, &descriptor) == ERROR_SUCCESS &&
             owner && IsValidSid(owner) &&
             (require_current_user ? EqualSid(owner, user->User.Sid) != 0
                                   : windows_sid_is_trusted(owner, user->User.Sid));
    }
    if (descriptor) {
        (void)LocalFree(descriptor);
    }
    free(user);
    if (token) {
        (void)CloseHandle(token);
    }
    return ok;
}

static bool windows_owner_is_current(HANDLE file) {
    return windows_owner_secure(file, true);
}

static bool windows_acl_secure(HANDLE file) {
    HANDLE token = NULL;
    DWORD token_size = 0U;
    PTOKEN_USER user = NULL;
    PACL dacl = NULL;
    PSECURITY_DESCRIPTOR descriptor = NULL;
    bool secure = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token) != 0;
    if (secure) {
        (void)GetTokenInformation(token, TokenUser, NULL, 0U, &token_size);
        user = token_size ? (PTOKEN_USER)malloc(token_size) : NULL;
        secure = user && GetTokenInformation(token, TokenUser, user, token_size, &token_size) != 0;
    }
    DWORD status = secure ? GetSecurityInfo(file, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL,
                                            NULL, &dacl, NULL, &descriptor)
                          : ERROR_ACCESS_DENIED;
    ACL_SIZE_INFORMATION information;
    memset(&information, 0, sizeof(information));
    secure = secure && status == ERROR_SUCCESS && descriptor && dacl && IsValidAcl(dacl) != 0 &&
             GetAclInformation(dacl, &information, sizeof(information), AclSizeInformation) != 0;
    const DWORD mutation = GENERIC_ALL | GENERIC_WRITE | FILE_WRITE_DATA | FILE_APPEND_DATA |
                           FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | FILE_DELETE_CHILD |
                           FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | DELETE | WRITE_DAC |
                           WRITE_OWNER | ACCESS_SYSTEM_SECURITY;
    enum {
        CBM_ACE_ALLOW = 0x00,
        CBM_ACE_DENY = 0x01,
        CBM_ACE_DENY_OBJECT = 0x06,
        CBM_ACE_DENY_CALLBACK = 0x0a,
        CBM_ACE_DENY_CALLBACK_OBJECT = 0x0c,
    };
    for (DWORD index = 0U; secure && index < information.AceCount; index++) {
        void *opaque = NULL;
        if (!GetAce(dacl, index, &opaque) || !opaque) {
            secure = false;
            break;
        }
        ACE_HEADER *header = opaque;
        if (header->AceType == CBM_ACE_DENY || header->AceType == CBM_ACE_DENY_OBJECT ||
            header->AceType == CBM_ACE_DENY_CALLBACK ||
            header->AceType == CBM_ACE_DENY_CALLBACK_OBJECT) {
            continue;
        }
        if (header->AceType != CBM_ACE_ALLOW ||
            (size_t)header->AceSize <
                offsetof(ACCESS_ALLOWED_ACE, SidStart) + offsetof(SID, SubAuthority)) {
            secure = false;
            break;
        }
        ACCESS_ALLOWED_ACE *ace = opaque;
        if ((ace->Mask & mutation) == 0U) {
            continue;
        }
        if (!windows_bounded_ace_sid_is_trusted(header, user->User.Sid)) {
            secure = false;
        }
    }
    if (descriptor)
        (void)LocalFree(descriptor);
    free(user);
    if (token)
        (void)CloseHandle(token);
    return secure;
}

static bool windows_path_tree_plain(const wchar_t *file_path) {
    size_t length = file_path ? wcslen(file_path) : 0U;
    if (length < 4U || length >= CBM_WINDOWS_LAUNCHER_PATH_CAP || file_path[1] != L':' ||
        (file_path[2] != L'\\' && file_path[2] != L'/')) {
        return false;
    }
    wchar_t *path = malloc((length + 1U) * sizeof(*path));
    if (!path) {
        return false;
    }
    memcpy(path, file_path, (length + 1U) * sizeof(*path));
    for (size_t index = 0U; index < length; index++) {
        if (path[index] == L'/')
            path[index] = L'\\';
    }
    wchar_t *last = wcsrchr(path, L'\\');
    if (!last || last <= path + 2) {
        free(path);
        return false;
    }
    *last = L'\0';
    size_t directory_length = wcslen(path);
    bool valid = true;
    for (size_t index = 3U; valid && index <= directory_length; index++) {
        if (index < directory_length && path[index] != L'\\')
            continue;
        wchar_t saved = path[index];
        path[index] = L'\0';
        HANDLE component =
            CreateFileW(path, FILE_READ_ATTRIBUTES | READ_CONTROL,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
                        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
        BY_HANDLE_FILE_INFORMATION information;
        valid = component != INVALID_HANDLE_VALUE && GetFileType(component) == FILE_TYPE_DISK &&
                GetFileInformationByHandle(component, &information) != 0 &&
                (information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 &&
                (information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0 &&
                windows_owner_secure(component, false) && windows_acl_secure(component);
        if (component != INVALID_HANDLE_VALUE)
            (void)CloseHandle(component);
        path[index] = saved;
    }
    free(path);
    return valid;
}

static HANDLE windows_open_regular_no_reparse(const wchar_t *path, DWORD access) {
    HANDLE file =
        CreateFileW(path, access | FILE_READ_ATTRIBUTES | READ_CONTROL,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
                    FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    BY_HANDLE_FILE_INFORMATION information;
    if (!windows_path_tree_plain(path) || !windows_file_identity(file, &information) ||
        !windows_owner_is_current(file) || !windows_acl_secure(file)) {
        if (file != INVALID_HANDLE_VALUE) {
            (void)CloseHandle(file);
        }
        return INVALID_HANDLE_VALUE;
    }
    return file;
}

static HANDLE windows_open_directory_secure(const wchar_t *path) {
    HANDLE directory =
        CreateFileW(path, FILE_READ_ATTRIBUTES | READ_CONTROL,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    BY_HANDLE_FILE_INFORMATION information;
    bool valid = directory != INVALID_HANDLE_VALUE && GetFileType(directory) == FILE_TYPE_DISK &&
                 GetFileInformationByHandle(directory, &information) != 0 &&
                 (information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 &&
                 (information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0 &&
                 windows_owner_is_current(directory) && windows_acl_secure(directory);
    if (!valid) {
        if (directory != INVALID_HANDLE_VALUE)
            (void)CloseHandle(directory);
        return INVALID_HANDLE_VALUE;
    }
    return directory;
}

static bool windows_process_creation(HANDLE process, FILETIME *creation_out) {
    FILETIME exit_time;
    FILETIME kernel_time;
    FILETIME user_time;
    return GetProcessTimes(process, creation_out, &exit_time, &kernel_time, &user_time) != 0;
}

static bool windows_filetime_equal(const FILETIME *first, const FILETIME *second) {
    return first->dwLowDateTime == second->dwLowDateTime &&
           first->dwHighDateTime == second->dwHighDateTime;
}

bool cbm_windows_launcher_context_consume(cbm_windows_launcher_context_t *context_out, char *error,
                                          size_t error_size) {
    if (context_out) {
        memset(context_out, 0, sizeof(*context_out));
    }
    if (error && error_size > 0U) {
        error[0] = '\0';
    }
    if (!context_out) {
        launcher_error(error, error_size, "invalid launcher context output");
        return false;
    }
    wchar_t encoded[32];
    DWORD length = GetEnvironmentVariableW(CBM_LAUNCH_CONTEXT_ENV, encoded,
                                           (DWORD)(sizeof(encoded) / sizeof(encoded[0])));
    if (length == 0U && GetLastError() == ERROR_ENVVAR_NOT_FOUND) {
        return true;
    }
    /* Scrub before validation: malformed authority must never reach a child. */
    (void)SetEnvironmentVariableW(CBM_LAUNCH_CONTEXT_ENV, NULL);
    if (length == 0U || length >= sizeof(encoded) / sizeof(encoded[0])) {
        launcher_error(error, error_size, "invalid inherited launcher context handle");
        return false;
    }
    wchar_t *end = NULL;
    unsigned long long raw = wcstoull(encoded, &end, 16);
    if (!end || *end != L'\0' || raw == 0ULL || raw > (unsigned long long)(uintptr_t)UINTPTR_MAX) {
        launcher_error(error, error_size, "invalid inherited launcher context handle");
        return false;
    }
    HANDLE pipe = (HANDLE)(uintptr_t)raw;
    uint8_t header[CBM_LAUNCH_CONTEXT_HEADER_SIZE];
    uint32_t flags = 0U;
    cbm_windows_launcher_action_t action = CBM_WINDOWS_LAUNCHER_ACTION_ORDINARY;
    DWORD claimed_pid = 0U;
    FILETIME claimed_creation;
    uint64_t payload_size = 0U;
    char digest[65];
    uint32_t path_chars = 0U;
    ULONG actual_pid = 0U;
    uint64_t context_now = GetTickCount64();
    uint64_t context_deadline = UINT64_MAX - context_now < 5000U ? UINT64_MAX : context_now + 5000U;
    bool valid =
        GetFileType(pipe) == FILE_TYPE_PIPE &&
        GetNamedPipeServerProcessId(pipe, &actual_pid) != 0 &&
        windows_pipe_wait_available(pipe, sizeof(header), context_deadline) &&
        windows_read_exact(pipe, header, sizeof(header)) &&
        launch_context_header_decode(header, &flags, &action, &claimed_pid, &claimed_creation,
                                     &payload_size, digest, &path_chars) &&
        actual_pid == claimed_pid;
    wchar_t claimed_path[CBM_WINDOWS_LAUNCHER_PATH_CAP];
    memset(claimed_path, 0, sizeof(claimed_path));
    valid = valid &&
            windows_pipe_wait_available(pipe, (size_t)path_chars * sizeof(*claimed_path),
                                        context_deadline) &&
            windows_read_exact(pipe, claimed_path, (size_t)path_chars * sizeof(*claimed_path)) &&
            claimed_path[path_chars - 1U] == L'\0' &&
            wmemchr(claimed_path, L'\0', path_chars) == claimed_path + path_chars - 1U;
    DWORD trailing_count = 0U;
    valid = valid && PeekNamedPipe(pipe, NULL, 0U, NULL, &trailing_count, NULL) != 0 &&
            trailing_count == 0U;

    HANDLE server =
        valid ? OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, actual_pid) : NULL;
    FILETIME actual_creation;
    wchar_t actual_path[CBM_WINDOWS_LAUNCHER_PATH_CAP];
    DWORD actual_path_length = CBM_WINDOWS_LAUNCHER_PATH_CAP;
    valid = valid && server && windows_process_creation(server, &actual_creation) &&
            windows_filetime_equal(&actual_creation, &claimed_creation) &&
            QueryFullProcessImageNameW(server, 0U, actual_path, &actual_path_length) != 0;
    if (server) {
        (void)CloseHandle(server);
    }
    HANDLE actual_file =
        valid ? windows_open_regular_no_reparse(actual_path, GENERIC_READ) : INVALID_HANDLE_VALUE;
    HANDLE claimed_file =
        valid ? windows_open_regular_no_reparse(claimed_path, GENERIC_READ) : INVALID_HANDLE_VALUE;
    BY_HANDLE_FILE_INFORMATION actual_info;
    BY_HANDLE_FILE_INFORMATION claimed_info;
    valid = valid && windows_file_identity(actual_file, &actual_info) &&
            windows_file_identity(claimed_file, &claimed_info) &&
            windows_same_identity(&actual_info, &claimed_info);
    if (actual_file != INVALID_HANDLE_VALUE) {
        (void)CloseHandle(actual_file);
    }
    if (claimed_file != INVALID_HANDLE_VALUE) {
        (void)CloseHandle(claimed_file);
    }
    if (!valid) {
        (void)CloseHandle(pipe);
        launcher_error(error, error_size, "invalid or unauthenticated Windows launcher context");
        memset(context_out, 0, sizeof(*context_out));
        return false;
    }
    context_out->present = true;
    context_out->managed = (flags & CBM_LAUNCH_CONTEXT_FLAG_MANAGED) != 0U;
    context_out->private_activation = (flags & CBM_LAUNCH_CONTEXT_FLAG_PRIVATE) != 0U;
    context_out->action = action;
    context_out->payload_size = payload_size;
    memcpy(context_out->expected_payload_sha256, digest, sizeof(digest));
    memcpy(context_out->canonical_launcher_path, claimed_path,
           (size_t)path_chars * sizeof(*claimed_path));
    context_out->_authority_handle = (uintptr_t)pipe;
    return true;
}

static bool windows_pipe_read_byte_until(HANDLE pipe, uint8_t *value_out, uint64_t deadline) {
    while (GetTickCount64() < deadline) {
        DWORD available = 0U;
        if (!PeekNamedPipe(pipe, NULL, 0U, NULL, &available, NULL)) {
            return false;
        }
        if (available > 0U) {
            DWORD received = 0U;
            return ReadFile(pipe, value_out, 1U, &received, NULL) != 0 && received == 1U;
        }
        Sleep(2U);
    }
    return false;
}

bool cbm_windows_launcher_context_complete(cbm_windows_launcher_context_t *context, bool accepted,
                                           char *error, size_t error_size) {
    if (error && error_size > 0U)
        error[0] = '\0';
    if (!context) {
        launcher_error(error, error_size, "invalid launcher context completion");
        return false;
    }
    if (!context->present) {
        return context->_authority_handle == 0U;
    }
    HANDLE pipe = (HANDLE)context->_authority_handle;
    context->_authority_handle = 0U;
    if (!pipe || pipe == INVALID_HANDLE_VALUE) {
        launcher_error(error, error_size, "launcher context authority was already consumed");
        return false;
    }
    uint8_t ready = accepted ? (uint8_t)'R' : (uint8_t)'X';
    DWORD written = 0U;
    bool ok = WriteFile(pipe, &ready, 1U, &written, NULL) != 0 && written == 1U;
    if (ok && accepted) {
        uint8_t result = 0U;
        uint64_t now = GetTickCount64();
        uint64_t deadline = UINT64_MAX - now < 30000U ? UINT64_MAX : now + 30000U;
        ok = windows_pipe_read_byte_until(pipe, &result, deadline) && result == (uint8_t)'G';
    }
    (void)CloseHandle(pipe);
    if (!ok) {
        launcher_error(error, error_size,
                       "launcher rejected or timed out completing payload authentication");
    }
    return ok;
}

/* Remaining native transaction/probe helpers are below the launcher-facing
 * context code to keep their private Windows structures out of the ABI. */

typedef struct {
    DWORD Flags;
} cbm_file_disposition_info_ex_t;

typedef struct {
    DWORD Flags;
    HANDLE RootDirectory;
    DWORD FileNameLength;
    WCHAR FileName[1];
} cbm_file_rename_info_ex_t;

#define CBM_FILE_DISPOSITION_INFO_EX_CLASS ((FILE_INFO_BY_HANDLE_CLASS)21)
#define CBM_FILE_RENAME_INFO_EX_CLASS ((FILE_INFO_BY_HANDLE_CLASS)22)
#define CBM_FILE_DISPOSITION_DELETE 0x00000001U
#define CBM_FILE_DISPOSITION_POSIX 0x00000002U
#define CBM_FILE_RENAME_REPLACE 0x00000001U
#define CBM_FILE_RENAME_POSIX 0x00000002U

static bool windows_posix_remove_handle(HANDLE file) {
    cbm_file_disposition_info_ex_t disposition = {
        .Flags = CBM_FILE_DISPOSITION_DELETE | CBM_FILE_DISPOSITION_POSIX,
    };
    return SetFileInformationByHandle(file, CBM_FILE_DISPOSITION_INFO_EX_CLASS, &disposition,
                                      sizeof(disposition)) != 0;
}

static bool windows_posix_rename_handle(HANDLE file, const wchar_t *target_path) {
    size_t chars = wcslen(target_path);
    if (chars == 0U || chars > (size_t)UINT32_MAX / sizeof(wchar_t)) {
        return false;
    }
    size_t bytes = chars * sizeof(wchar_t);
    size_t allocation = offsetof(cbm_file_rename_info_ex_t, FileName) + bytes;
    cbm_file_rename_info_ex_t *rename = calloc(1U, allocation);
    if (!rename) {
        return false;
    }
    rename->Flags = CBM_FILE_RENAME_REPLACE | CBM_FILE_RENAME_POSIX;
    rename->RootDirectory = NULL;
    rename->FileNameLength = (DWORD)bytes;
    memcpy(rename->FileName, target_path, bytes);
    bool renamed = SetFileInformationByHandle(file, CBM_FILE_RENAME_INFO_EX_CLASS, rename,
                                              (DWORD)allocation) != 0;
    free(rename);
    return renamed;
}

static bool windows_parent_path(const wchar_t *path, wchar_t *parent, size_t capacity) {
    if (!path || !parent || capacity == 0U) {
        return false;
    }
    size_t length = wcslen(path);
    if (length + 1U > capacity) {
        return false;
    }
    memcpy(parent, path, (length + 1U) * sizeof(*parent));
    wchar_t *separator = wcsrchr(parent, L'\\');
    wchar_t *slash = wcsrchr(parent, L'/');
    if (!separator || (slash && slash > separator)) {
        separator = slash;
    }
    if (!separator || separator <= parent + 2) {
        return false;
    }
    *separator = L'\0';
    return true;
}

static bool windows_copy_flush_private(const wchar_t *candidate, const wchar_t *stage) {
    HANDLE source = windows_open_regular_no_reparse(candidate, GENERIC_READ);
    if (source == INVALID_HANDLE_VALUE || !windows_path_tree_plain(stage) ||
        !CopyFileW(candidate, stage, TRUE)) {
        if (source != INVALID_HANDLE_VALUE)
            (void)CloseHandle(source);
        return false;
    }
    (void)CloseHandle(source);
    HANDLE file =
        CreateFileW(stage, GENERIC_READ | GENERIC_WRITE | DELETE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
                    FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH, NULL);
    BY_HANDLE_FILE_INFORMATION information;
    bool ok = windows_file_identity(file, &information) && windows_owner_is_current(file) &&
              windows_acl_secure(file) && FlushFileBuffers(file) != 0;
    if (file != INVALID_HANDLE_VALUE) {
        (void)CloseHandle(file);
    }
    if (!ok) {
        (void)DeleteFileW(stage);
    }
    return ok;
}

static bool windows_unique_sibling(const wchar_t *target, const wchar_t *tag, wchar_t *path,
                                   size_t capacity) {
    static volatile LONG counter = 0;
    LONG sequence = InterlockedIncrement(&counter);
    int written = swprintf(path, capacity, L"%ls.cbm-%ls-%lu-%ld.tmp", target, tag,
                           (unsigned long)GetCurrentProcessId(), (long)sequence);
    return written > 0 && (size_t)written < capacity;
}

bool cbm_windows_launcher_replace_atomic(const wchar_t *target_path, const wchar_t *candidate_path,
                                         char *error, size_t error_size) {
    if (error && error_size > 0U)
        error[0] = '\0';
    if (!target_path || !candidate_path || !target_path[0] || !candidate_path[0]) {
        launcher_error(error, error_size, "invalid launcher replacement paths");
        return false;
    }
    HANDLE candidate = windows_open_regular_no_reparse(candidate_path, GENERIC_READ);
    DWORD target_attributes = GetFileAttributesW(target_path);
    DWORD target_error =
        target_attributes == INVALID_FILE_ATTRIBUTES ? GetLastError() : ERROR_SUCCESS;
    HANDLE target = target_attributes == INVALID_FILE_ATTRIBUTES
                        ? INVALID_HANDLE_VALUE
                        : windows_open_regular_no_reparse(target_path, GENERIC_READ);
    bool target_absent =
        target_attributes == INVALID_FILE_ATTRIBUTES &&
        (target_error == ERROR_FILE_NOT_FOUND || target_error == ERROR_PATH_NOT_FOUND);
    if (candidate == INVALID_HANDLE_VALUE || (!target_absent && target == INVALID_HANDLE_VALUE) ||
        !windows_path_tree_plain(target_path)) {
        if (candidate != INVALID_HANDLE_VALUE)
            (void)CloseHandle(candidate);
        if (target != INVALID_HANDLE_VALUE)
            (void)CloseHandle(target);
        launcher_error(error, error_size, "launcher candidate or existing target is unsafe");
        return false;
    }
    (void)CloseHandle(candidate);
    if (target != INVALID_HANDLE_VALUE)
        (void)CloseHandle(target);
    wchar_t stage[CBM_WINDOWS_LAUNCHER_PATH_CAP];
    if (!windows_unique_sibling(target_path, L"replace", stage, CBM_WINDOWS_LAUNCHER_PATH_CAP) ||
        !windows_copy_flush_private(candidate_path, stage)) {
        launcher_error(error, error_size, "could not stage launcher replacement");
        return false;
    }
    HANDLE file =
        CreateFileW(stage, DELETE | FILE_READ_ATTRIBUTES | READ_CONTROL,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
                    FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH, NULL);
    BY_HANDLE_FILE_INFORMATION information;
    bool ok = windows_file_identity(file, &information) && windows_owner_is_current(file) &&
              windows_acl_secure(file) && windows_posix_rename_handle(file, target_path);
    if (file != INVALID_HANDLE_VALUE)
        (void)CloseHandle(file);
    if (!ok) {
        (void)DeleteFileW(stage);
        launcher_error(error, error_size, "atomic launcher replacement is unsupported or failed");
    }
    return ok;
}

bool cbm_windows_launcher_remove_posix(const wchar_t *target_path, char *error, size_t error_size) {
    if (error && error_size > 0U)
        error[0] = '\0';
    if (!target_path || !target_path[0]) {
        launcher_error(error, error_size, "invalid launcher removal path");
        return false;
    }
    HANDLE file = windows_open_regular_no_reparse(target_path, DELETE);
    if (file == INVALID_HANDLE_VALUE) {
        DWORD attributes = GetFileAttributesW(target_path);
        DWORD remove_error = attributes == INVALID_FILE_ATTRIBUTES ? GetLastError() : ERROR_SUCCESS;
        if (attributes == INVALID_FILE_ATTRIBUTES &&
            (remove_error == ERROR_FILE_NOT_FOUND || remove_error == ERROR_PATH_NOT_FOUND)) {
            return true;
        }
        launcher_error(error, error_size, "could not securely open launcher for removal");
        return false;
    }
    bool removed = windows_posix_remove_handle(file);
    (void)CloseHandle(file);
    if (!removed) {
        launcher_error(error, error_size, "POSIX launcher deletion is unsupported or failed");
    }
    return removed;
}

/* 1 = valid current, 0 = absent, -1 = unsafe/corrupt. */
static int windows_current_v1_read(const wchar_t *canonical_launcher_path,
                                   cbm_windows_current_v1_t *state_out) {
    if (state_out)
        memset(state_out, 0, sizeof(*state_out));
    wchar_t directory[CBM_WINDOWS_LAUNCHER_PATH_CAP];
    wchar_t state_directory[CBM_WINDOWS_LAUNCHER_PATH_CAP];
    wchar_t current[CBM_WINDOWS_LAUNCHER_PATH_CAP];
    if (!canonical_launcher_path || !state_out ||
        !windows_parent_path(canonical_launcher_path, directory, CBM_WINDOWS_LAUNCHER_PATH_CAP)) {
        return -1;
    }
    int state_written =
        swprintf(state_directory, CBM_WINDOWS_LAUNCHER_PATH_CAP, L"%ls\\.cbm", directory);
    int current_written =
        swprintf(current, CBM_WINDOWS_LAUNCHER_PATH_CAP, L"%ls\\current-v1", state_directory);
    if (state_written <= 0 || current_written <= 0 ||
        (size_t)state_written >= CBM_WINDOWS_LAUNCHER_PATH_CAP ||
        (size_t)current_written >= CBM_WINDOWS_LAUNCHER_PATH_CAP) {
        return -1;
    }
    HANDLE file = windows_open_regular_no_reparse(current, GENERIC_READ);
    if (file == INVALID_HANDLE_VALUE) {
        DWORD attributes = GetFileAttributesW(current);
        DWORD open_error = attributes == INVALID_FILE_ATTRIBUTES ? GetLastError() : ERROR_SUCCESS;
        return attributes == INVALID_FILE_ATTRIBUTES &&
                       (open_error == ERROR_FILE_NOT_FOUND || open_error == ERROR_PATH_NOT_FOUND)
                   ? 0
                   : -1;
    }
    LARGE_INTEGER size;
    uint8_t record[CBM_WINDOWS_CURRENT_V1_SIZE];
    uint8_t trailing = 0U;
    DWORD trailing_count = 0U;
    bool valid = GetFileSizeEx(file, &size) != 0 && size.QuadPart == CBM_WINDOWS_CURRENT_V1_SIZE &&
                 windows_read_exact(file, record, sizeof(record)) &&
                 ReadFile(file, &trailing, 1U, &trailing_count, NULL) != 0 &&
                 trailing_count == 0U &&
                 cbm_windows_current_v1_decode(record, sizeof(record), state_out);
    (void)CloseHandle(file);
    return valid ? 1 : -1;
}

static bool windows_generation_directory_path(
    const wchar_t *canonical_launcher_path, const char payload_sha256[65],
    wchar_t directory_out[CBM_WINDOWS_LAUNCHER_PATH_CAP]) {
    wchar_t payload[CBM_WINDOWS_LAUNCHER_PATH_CAP];
    return cbm_windows_generation_payload_path(canonical_launcher_path, payload_sha256, payload,
                                               CBM_WINDOWS_LAUNCHER_PATH_CAP) &&
           windows_parent_path(payload, directory_out, CBM_WINDOWS_LAUNCHER_PATH_CAP);
}

bool cbm_windows_launcher_file_secure(const wchar_t *launcher_path, char *error,
                                      size_t error_size) {
    if (error && error_size > 0U)
        error[0] = '\0';
    HANDLE launcher = launcher_path ? windows_open_regular_no_reparse(launcher_path, GENERIC_READ)
                                    : INVALID_HANDLE_VALUE;
    if (launcher == INVALID_HANDLE_VALUE) {
        launcher_error(error, error_size, "launcher path, owner, or access policy is unsafe");
        return false;
    }
    (void)CloseHandle(launcher);
    return true;
}

static bool windows_generation_name_valid(const wchar_t *name) {
    if (!name || wcslen(name) != 64U)
        return false;
    for (size_t index = 0U; index < 64U; index++) {
        wchar_t value = name[index];
        if (!((value >= L'0' && value <= L'9') || (value >= L'a' && value <= L'f'))) {
            return false;
        }
    }
    return true;
}

static bool windows_remove_generation_directory(const wchar_t *generation_directory) {
    DWORD attributes = GetFileAttributesW(generation_directory);
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        DWORD missing_error = GetLastError();
        return missing_error == ERROR_FILE_NOT_FOUND || missing_error == ERROR_PATH_NOT_FOUND;
    }
    HANDLE directory = windows_open_directory_secure(generation_directory);
    if (directory == INVALID_HANDLE_VALUE)
        return false;
    (void)CloseHandle(directory);

    wchar_t pattern[CBM_WINDOWS_LAUNCHER_PATH_CAP];
    int pattern_written =
        swprintf(pattern, CBM_WINDOWS_LAUNCHER_PATH_CAP, L"%ls\\*", generation_directory);
    if (pattern_written <= 0 || (size_t)pattern_written >= CBM_WINDOWS_LAUNCHER_PATH_CAP) {
        return false;
    }
    WIN32_FIND_DATAW entry;
    HANDLE search = FindFirstFileW(pattern, &entry);
    if (search == INVALID_HANDLE_VALUE)
        return false;
    bool exact = true;
    size_t payload_entries = 0U;
    do {
        if (wcscmp(entry.cFileName, L".") == 0 || wcscmp(entry.cFileName, L"..") == 0) {
            continue;
        }
        bool payload = wcscmp(entry.cFileName, L"codebase-memory-mcp.payload.exe") == 0 &&
                       (entry.dwFileAttributes &
                        (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) == 0;
        if (!payload) {
            exact = false;
            break;
        }
        payload_entries++;
    } while (FindNextFileW(search, &entry));
    DWORD find_error = GetLastError();
    (void)FindClose(search);
    exact = exact && find_error == ERROR_NO_MORE_FILES && payload_entries == 1U;
    if (!exact)
        return false;

    wchar_t payload_path[CBM_WINDOWS_LAUNCHER_PATH_CAP];
    int payload_written = swprintf(payload_path, CBM_WINDOWS_LAUNCHER_PATH_CAP,
                                   L"%ls\\codebase-memory-mcp.payload.exe", generation_directory);
    HANDLE payload = payload_written > 0 && (size_t)payload_written < CBM_WINDOWS_LAUNCHER_PATH_CAP
                         ? windows_open_regular_no_reparse(payload_path, DELETE)
                         : INVALID_HANDLE_VALUE;
    bool removed = payload != INVALID_HANDLE_VALUE && windows_posix_remove_handle(payload);
    if (payload != INVALID_HANDLE_VALUE)
        (void)CloseHandle(payload);
    return removed && RemoveDirectoryW(generation_directory) != 0;
}

bool cbm_windows_generation_rollback_if_unreferenced(const wchar_t *canonical_launcher_path,
                                                     const char payload_sha256[65],
                                                     bool created_by_activation, char *error,
                                                     size_t error_size) {
    if (error && error_size > 0U)
        error[0] = '\0';
    if (!created_by_activation)
        return true;
    if (!canonical_launcher_path || !lowercase_sha256_valid(payload_sha256)) {
        launcher_error(error, error_size, "invalid generation rollback request");
        return false;
    }
    cbm_windows_current_v1_t current;
    int current_status = windows_current_v1_read(canonical_launcher_path, &current);
    if (current_status < 0) {
        launcher_error(error, error_size, "current-v1 is unsafe during generation rollback");
        return false;
    }
    if (current_status == 1 && strcmp(current.payload_sha256, payload_sha256) == 0) {
        return true;
    }
    wchar_t generation[CBM_WINDOWS_LAUNCHER_PATH_CAP];
    if (!windows_generation_directory_path(canonical_launcher_path, payload_sha256, generation) ||
        !windows_remove_generation_directory(generation)) {
        launcher_error(error, error_size,
                       "new unreferenced generation could not be rolled back safely");
        return false;
    }
    return true;
}

bool cbm_windows_generations_prune(const wchar_t *canonical_launcher_path, size_t *removed_out,
                                   char *error, size_t error_size) {
    if (removed_out)
        *removed_out = 0U;
    if (error && error_size > 0U)
        error[0] = '\0';
    cbm_windows_current_v1_t current;
    if (!canonical_launcher_path ||
        windows_current_v1_read(canonical_launcher_path, &current) != 1) {
        launcher_error(error, error_size, "current-v1 is unsafe during generation pruning");
        return false;
    }
    wchar_t current_generation[CBM_WINDOWS_LAUNCHER_PATH_CAP];
    wchar_t generations_root[CBM_WINDOWS_LAUNCHER_PATH_CAP];
    if (!windows_generation_directory_path(canonical_launcher_path, current.payload_sha256,
                                           current_generation) ||
        !windows_parent_path(current_generation, generations_root, CBM_WINDOWS_LAUNCHER_PATH_CAP)) {
        launcher_error(error, error_size, "generation root path could not be resolved");
        return false;
    }
    HANDLE root = windows_open_directory_secure(generations_root);
    if (root == INVALID_HANDLE_VALUE) {
        launcher_error(error, error_size, "generation root is missing or unsafe");
        return false;
    }
    (void)CloseHandle(root);

    wchar_t pattern[CBM_WINDOWS_LAUNCHER_PATH_CAP];
    int pattern_written =
        swprintf(pattern, CBM_WINDOWS_LAUNCHER_PATH_CAP, L"%ls\\*", generations_root);
    if (pattern_written <= 0 || (size_t)pattern_written >= CBM_WINDOWS_LAUNCHER_PATH_CAP) {
        launcher_error(error, error_size, "generation enumeration path is too long");
        return false;
    }
    WIN32_FIND_DATAW entry;
    HANDLE search = FindFirstFileW(pattern, &entry);
    if (search == INVALID_HANDLE_VALUE) {
        launcher_error(error, error_size, "generation root could not be enumerated");
        return false;
    }
    wchar_t current_name[65];
    for (size_t index = 0U; index < 64U; index++) {
        current_name[index] = (wchar_t)(unsigned char)current.payload_sha256[index];
    }
    current_name[64] = L'\0';
    bool ok = true;
    size_t removed = 0U;
    do {
        if (wcscmp(entry.cFileName, L".") == 0 || wcscmp(entry.cFileName, L"..") == 0) {
            continue;
        }
        if (_wcsicmp(entry.cFileName, current_name) == 0) {
            bool canonical_current = wcscmp(entry.cFileName, current_name) == 0 &&
                                     (entry.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 &&
                                     (entry.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0;
            if (!canonical_current)
                ok = false;
            continue;
        }
        if (!windows_generation_name_valid(entry.cFileName) ||
            (entry.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
            (entry.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
            ok = false;
            continue;
        }
        wchar_t generation[CBM_WINDOWS_LAUNCHER_PATH_CAP];
        int generation_written = swprintf(generation, CBM_WINDOWS_LAUNCHER_PATH_CAP, L"%ls\\%ls",
                                          generations_root, entry.cFileName);
        if (generation_written <= 0 ||
            (size_t)generation_written >= CBM_WINDOWS_LAUNCHER_PATH_CAP ||
            !windows_remove_generation_directory(generation)) {
            ok = false;
            continue;
        }
        removed++;
    } while (FindNextFileW(search, &entry));
    DWORD find_error = GetLastError();
    (void)FindClose(search);
    ok = ok && find_error == ERROR_NO_MORE_FILES;
    if (removed_out)
        *removed_out = removed;
    if (!ok) {
        launcher_error(error, error_size,
                       "one or more non-current generations were unsafe or could not be pruned");
    }
    return ok;
}

bool cbm_windows_current_v1_write_atomic(const wchar_t *canonical_launcher_path,
                                         const cbm_windows_current_v1_t *state, char *error,
                                         size_t error_size) {
    if (error && error_size > 0U)
        error[0] = '\0';
    uint8_t record[CBM_WINDOWS_CURRENT_V1_SIZE];
    wchar_t directory[CBM_WINDOWS_LAUNCHER_PATH_CAP];
    HANDLE canonical = canonical_launcher_path
                           ? windows_open_regular_no_reparse(canonical_launcher_path, GENERIC_READ)
                           : INVALID_HANDLE_VALUE;
    if (!canonical_launcher_path || canonical == INVALID_HANDLE_VALUE ||
        !cbm_windows_current_v1_encode(state, record) ||
        !windows_parent_path(canonical_launcher_path, directory, CBM_WINDOWS_LAUNCHER_PATH_CAP)) {
        if (canonical != INVALID_HANDLE_VALUE)
            (void)CloseHandle(canonical);
        launcher_error(error, error_size, "invalid current-v1 write request");
        return false;
    }
    (void)CloseHandle(canonical);
    wchar_t state_directory[CBM_WINDOWS_LAUNCHER_PATH_CAP];
    wchar_t current[CBM_WINDOWS_LAUNCHER_PATH_CAP];
    int state_written =
        swprintf(state_directory, CBM_WINDOWS_LAUNCHER_PATH_CAP, L"%ls\\.cbm", directory);
    int current_written =
        swprintf(current, CBM_WINDOWS_LAUNCHER_PATH_CAP, L"%ls\\current-v1", state_directory);
    if (state_written <= 0 || current_written <= 0 ||
        (size_t)state_written >= CBM_WINDOWS_LAUNCHER_PATH_CAP ||
        (size_t)current_written >= CBM_WINDOWS_LAUNCHER_PATH_CAP ||
        (!CreateDirectoryW(state_directory, NULL) && GetLastError() != ERROR_ALREADY_EXISTS)) {
        launcher_error(error, error_size, "could not create launcher state directory");
        return false;
    }
    HANDLE state_handle = windows_open_directory_secure(state_directory);
    DWORD current_attributes = GetFileAttributesW(current);
    DWORD current_error =
        current_attributes == INVALID_FILE_ATTRIBUTES ? GetLastError() : ERROR_SUCCESS;
    HANDLE existing = current_attributes == INVALID_FILE_ATTRIBUTES
                          ? INVALID_HANDLE_VALUE
                          : windows_open_regular_no_reparse(current, GENERIC_READ);
    bool current_absent =
        current_attributes == INVALID_FILE_ATTRIBUTES &&
        (current_error == ERROR_FILE_NOT_FOUND || current_error == ERROR_PATH_NOT_FOUND);
    if (state_handle == INVALID_HANDLE_VALUE ||
        (!current_absent && existing == INVALID_HANDLE_VALUE)) {
        if (state_handle != INVALID_HANDLE_VALUE)
            (void)CloseHandle(state_handle);
        if (existing != INVALID_HANDLE_VALUE)
            (void)CloseHandle(existing);
        launcher_error(error, error_size, "launcher state directory or current-v1 is unsafe");
        return false;
    }
    (void)CloseHandle(state_handle);
    if (existing != INVALID_HANDLE_VALUE)
        (void)CloseHandle(existing);
    wchar_t stage[CBM_WINDOWS_LAUNCHER_PATH_CAP];
    if (!windows_unique_sibling(current, L"current", stage, CBM_WINDOWS_LAUNCHER_PATH_CAP)) {
        launcher_error(error, error_size, "current-v1 stage path is too long");
        return false;
    }
    HANDLE file = CreateFileW(
        stage, GENERIC_WRITE | DELETE | FILE_READ_ATTRIBUTES | READ_CONTROL,
        FILE_SHARE_READ | FILE_SHARE_DELETE, NULL, CREATE_NEW,
        FILE_ATTRIBUTE_HIDDEN | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH, NULL);
    DWORD written = 0U;
    BY_HANDLE_FILE_INFORMATION information;
    bool ok = file != INVALID_HANDLE_VALUE &&
              WriteFile(file, record, sizeof(record), &written, NULL) != 0 &&
              written == sizeof(record) && FlushFileBuffers(file) != 0 &&
              windows_file_identity(file, &information) && windows_owner_is_current(file) &&
              windows_acl_secure(file) && windows_posix_rename_handle(file, current);
    if (file != INVALID_HANDLE_VALUE)
        (void)CloseHandle(file);
    if (!ok) {
        (void)DeleteFileW(stage);
        launcher_error(error, error_size, "atomic current-v1 publication is unsupported or failed");
    }
    return ok;
}

#define CBM_RELEASE_DESCRIPTOR_ARG L"__cbm_windows_release_descriptor_v1"

bool cbm_windows_release_descriptor_probe(const wchar_t *launcher_candidate,
                                          cbm_windows_release_descriptor_v1_t *descriptor_out,
                                          char *error, size_t error_size) {
    if (descriptor_out) {
        memset(descriptor_out, 0, sizeof(*descriptor_out));
    }
    if (error && error_size > 0U)
        error[0] = '\0';
    HANDLE candidate = launcher_candidate
                           ? windows_open_regular_no_reparse(launcher_candidate, GENERIC_READ)
                           : INVALID_HANDLE_VALUE;
    if (!descriptor_out || candidate == INVALID_HANDLE_VALUE) {
        if (candidate != INVALID_HANDLE_VALUE)
            (void)CloseHandle(candidate);
        launcher_error(error, error_size, "launcher descriptor candidate is unsafe");
        return false;
    }
    (void)CloseHandle(candidate);

    SECURITY_ATTRIBUTES security = {
        .nLength = sizeof(security),
        .lpSecurityDescriptor = NULL,
        .bInheritHandle = TRUE,
    };
    HANDLE read_pipe = NULL;
    HANDLE write_pipe = NULL;
    HANDLE null_input = INVALID_HANDLE_VALUE;
    HANDLE null_error = INVALID_HANDLE_VALUE;
    HANDLE job = NULL;
    PROCESS_INFORMATION child;
    memset(&child, 0, sizeof(child));
    bool ready = CreatePipe(&read_pipe, &write_pipe, &security, 4096U) != 0 &&
                 SetHandleInformation(read_pipe, HANDLE_FLAG_INHERIT, 0U) != 0;
    null_input = ready ? CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                     &security, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)
                       : INVALID_HANDLE_VALUE;
    null_error = ready ? CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                     &security, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)
                       : INVALID_HANDLE_VALUE;
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits;
    memset(&limits, 0, sizeof(limits));
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    job = ready ? CreateJobObjectW(NULL, NULL) : NULL;
    ready =
        ready && null_input != INVALID_HANDLE_VALUE && null_error != INVALID_HANDLE_VALUE && job &&
        SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits)) !=
            0;

    HANDLE inherited[3] = {write_pipe, null_input, null_error};
    SIZE_T attribute_size = 0U;
    (void)InitializeProcThreadAttributeList(NULL, 2U, 0U, &attribute_size);
    LPPROC_THREAD_ATTRIBUTE_LIST attributes =
        ready && attribute_size ? malloc(attribute_size) : NULL;
    bool initialized =
        attributes && InitializeProcThreadAttributeList(attributes, 2U, 0U, &attribute_size) != 0;
    ready = ready && initialized &&
            UpdateProcThreadAttribute(attributes, 0U, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherited,
                                      sizeof(inherited), NULL, NULL) != 0 &&
            UpdateProcThreadAttribute(attributes, 0U, PROC_THREAD_ATTRIBUTE_JOB_LIST, &job,
                                      sizeof(job), NULL, NULL) != 0;

    wchar_t command[CBM_WINDOWS_LAUNCHER_PATH_CAP];
    int command_length = launcher_candidate
                             ? swprintf(command, CBM_WINDOWS_LAUNCHER_PATH_CAP, L"\"%ls\" %ls",
                                        launcher_candidate, CBM_RELEASE_DESCRIPTOR_ARG)
                             : -1;
    STARTUPINFOEXW startup;
    memset(&startup, 0, sizeof(startup));
    startup.StartupInfo.cb = sizeof(startup);
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = null_input;
    startup.StartupInfo.hStdOutput = write_pipe;
    startup.StartupInfo.hStdError = null_error;
    startup.lpAttributeList = attributes;
    bool spawned = ready && command_length > 0 &&
                   (size_t)command_length < CBM_WINDOWS_LAUNCHER_PATH_CAP &&
                   CreateProcessW(launcher_candidate, command, NULL, NULL, TRUE,
                                  CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT, NULL, NULL,
                                  &startup.StartupInfo, &child) != 0;
    if (initialized)
        DeleteProcThreadAttributeList(attributes);
    free(attributes);
    if (write_pipe) {
        (void)CloseHandle(write_pipe);
        write_pipe = NULL;
    }
    if (null_input != INVALID_HANDLE_VALUE) {
        (void)CloseHandle(null_input);
        null_input = INVALID_HANDLE_VALUE;
    }
    if (null_error != INVALID_HANDLE_VALUE) {
        (void)CloseHandle(null_error);
        null_error = INVALID_HANDLE_VALUE;
    }

    uint8_t record[CBM_WINDOWS_RELEASE_DESCRIPTOR_V1_SIZE + 1U];
    size_t received_total = 0U;
    bool pipe_closed = false;
    uint64_t now = GetTickCount64();
    uint64_t deadline = UINT64_MAX - now < 30000U ? UINT64_MAX : now + 30000U;
    while (spawned && GetTickCount64() < deadline && !pipe_closed) {
        DWORD available = 0U;
        if (!PeekNamedPipe(read_pipe, NULL, 0U, NULL, &available, NULL)) {
            pipe_closed = GetLastError() == ERROR_BROKEN_PIPE;
            break;
        }
        if (available > 0U) {
            DWORD capacity = (DWORD)(sizeof(record) - received_total);
            DWORD request = available < capacity ? available : capacity;
            DWORD amount = 0U;
            if (request == 0U ||
                !ReadFile(read_pipe, record + received_total, request, &amount, NULL) ||
                amount == 0U) {
                break;
            }
            received_total += amount;
            if (received_total == sizeof(record)) {
                break;
            }
            continue;
        }
        Sleep(2U);
    }
    DWORD wait = spawned ? WaitForSingleObject(child.hProcess, 0U) : WAIT_FAILED;
    if (spawned && wait != WAIT_OBJECT_0) {
        (void)TerminateJobObject(job, 1U);
        (void)WaitForSingleObject(child.hProcess, 5000U);
    }
    DWORD exit_code = 1U;
    bool valid =
        spawned && pipe_closed && received_total == CBM_WINDOWS_RELEASE_DESCRIPTOR_V1_SIZE &&
        WaitForSingleObject(child.hProcess, 0U) == WAIT_OBJECT_0 &&
        GetExitCodeProcess(child.hProcess, &exit_code) != 0 && exit_code == 0U &&
        cbm_windows_release_descriptor_v1_decode(record, CBM_WINDOWS_RELEASE_DESCRIPTOR_V1_SIZE,
                                                 descriptor_out);
    if (child.hThread)
        (void)CloseHandle(child.hThread);
    if (child.hProcess)
        (void)CloseHandle(child.hProcess);
    if (read_pipe)
        (void)CloseHandle(read_pipe);
    if (job)
        (void)CloseHandle(job);
    if (!valid) {
        memset(descriptor_out, 0, sizeof(*descriptor_out));
        launcher_error(error, error_size,
                       "launcher release descriptor was missing, malformed, or timed out");
    }
    return valid;
}

/* Probe subprocess protocol.  The standalone launcher recognizes this private
 * mode, signals ready, and remains mapped until the release event is set. */
#define CBM_LAUNCHER_PROBE_ARG L"__cbm_launcher_capability_probe_v1"

static bool windows_probe_volume(const wchar_t *directory, char *error, size_t error_size) {
    wchar_t volume[MAX_PATH + 1U];
    wchar_t filesystem[MAX_PATH + 1U];
    if (!GetVolumePathNameW(directory, volume, MAX_PATH + 1U) ||
        GetDriveTypeW(volume) != DRIVE_FIXED ||
        !GetVolumeInformationW(volume, NULL, 0U, NULL, NULL, NULL, filesystem, MAX_PATH + 1U) ||
        _wcsicmp(filesystem, L"NTFS") != 0) {
        launcher_error(error, error_size, "managed launcher requires a local fixed NTFS volume");
        return false;
    }
    return true;
}

static bool windows_probe_spawn(const wchar_t *image, HANDLE ready, HANDLE release,
                                PROCESS_INFORMATION *child) {
    wchar_t command[CBM_WINDOWS_LAUNCHER_PATH_CAP];
    int written = swprintf(command, CBM_WINDOWS_LAUNCHER_PATH_CAP, L"\"%ls\" %ls %llx %llx", image,
                           CBM_LAUNCHER_PROBE_ARG, (unsigned long long)(uintptr_t)ready,
                           (unsigned long long)(uintptr_t)release);
    if (written <= 0 || (size_t)written >= CBM_WINDOWS_LAUNCHER_PATH_CAP) {
        return false;
    }
    HANDLE inherited[2] = {ready, release};
    SIZE_T attribute_size = 0U;
    (void)InitializeProcThreadAttributeList(NULL, 1U, 0U, &attribute_size);
    LPPROC_THREAD_ATTRIBUTE_LIST attributes = attribute_size ? malloc(attribute_size) : NULL;
    bool initialized =
        attributes && InitializeProcThreadAttributeList(attributes, 1U, 0U, &attribute_size) != 0;
    bool ready_attributes =
        initialized && UpdateProcThreadAttribute(attributes, 0U, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                                 inherited, sizeof(inherited), NULL, NULL) != 0;
    STARTUPINFOEXW startup;
    memset(&startup, 0, sizeof(startup));
    memset(child, 0, sizeof(*child));
    startup.StartupInfo.cb = sizeof(startup);
    startup.lpAttributeList = attributes;
    bool spawned =
        ready_attributes && CreateProcessW(image, command, NULL, NULL, TRUE,
                                           CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT, NULL,
                                           NULL, &startup.StartupInfo, child) != 0;
    if (initialized)
        DeleteProcThreadAttributeList(attributes);
    free(attributes);
    return spawned;
}

static void windows_probe_child_stop(PROCESS_INFORMATION *child, HANDLE release) {
    if (release)
        (void)SetEvent(release);
    if (child->hProcess) {
        if (WaitForSingleObject(child->hProcess, 5000U) != WAIT_OBJECT_0) {
            (void)TerminateProcess(child->hProcess, 1U);
            (void)WaitForSingleObject(child->hProcess, 5000U);
        }
        (void)CloseHandle(child->hProcess);
    }
    if (child->hThread)
        (void)CloseHandle(child->hThread);
    memset(child, 0, sizeof(*child));
}

typedef struct {
    wchar_t **paths;
    size_t count;
    size_t capacity;
} windows_created_directories_t;

static void windows_created_directories_close(windows_created_directories_t *created,
                                              bool remove_directories) {
    if (!created)
        return;
    for (size_t index = 0U; index < created->count; index++) {
        if (remove_directories)
            (void)RemoveDirectoryW(created->paths[index]);
        free(created->paths[index]);
    }
    free(created->paths);
    memset(created, 0, sizeof(*created));
}

static bool windows_created_directories_push(windows_created_directories_t *created,
                                             const wchar_t *path) {
    if (created->count == created->capacity) {
        size_t next_capacity = created->capacity == 0U ? 8U : created->capacity * 2U;
        if (next_capacity < created->capacity || next_capacity > CBM_WINDOWS_LAUNCHER_PATH_CAP) {
            return false;
        }
        wchar_t **next = realloc(created->paths, next_capacity * sizeof(*next));
        if (!next)
            return false;
        created->paths = next;
        created->capacity = next_capacity;
    }
    size_t length = wcslen(path);
    wchar_t *copy = malloc((length + 1U) * sizeof(*copy));
    if (!copy)
        return false;
    memcpy(copy, path, (length + 1U) * sizeof(*copy));
    created->paths[created->count++] = copy;
    return true;
}

static bool windows_prepare_probe_directory(const wchar_t *target,
                                            windows_created_directories_t *created) {
    memset(created, 0, sizeof(*created));
    size_t length = target ? wcslen(target) : 0U;
    if (length < 3U || length >= CBM_WINDOWS_LAUNCHER_PATH_CAP || target[1] != L':' ||
        (target[2] != L'\\' && target[2] != L'/')) {
        return false;
    }
    wchar_t *cursor = malloc((length + 1U) * sizeof(*cursor));
    if (!cursor)
        return false;
    memcpy(cursor, target, (length + 1U) * sizeof(*cursor));
    for (size_t index = 0U; index < length; index++) {
        if (cursor[index] == L'/')
            cursor[index] = L'\\';
    }
    while (length > 3U && cursor[length - 1U] == L'\\') {
        cursor[--length] = L'\0';
    }
    bool valid = true;
    for (;;) {
        DWORD attributes = GetFileAttributesW(cursor);
        if (attributes != INVALID_FILE_ATTRIBUTES) {
            HANDLE ancestor = CreateFileW(
                cursor, FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
            BY_HANDLE_FILE_INFORMATION information;
            valid = ancestor != INVALID_HANDLE_VALUE && GetFileType(ancestor) == FILE_TYPE_DISK &&
                    GetFileInformationByHandle(ancestor, &information) != 0 &&
                    (information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 &&
                    (information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0 &&
                    windows_owner_secure(ancestor, false) && windows_acl_secure(ancestor);
            if (ancestor != INVALID_HANDLE_VALUE)
                (void)CloseHandle(ancestor);
            break;
        }
        DWORD error = GetLastError();
        if ((error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND) ||
            !windows_created_directories_push(created, cursor)) {
            valid = false;
            break;
        }
        wchar_t *separator = wcsrchr(cursor, L'\\');
        if (!separator || separator <= cursor + 2) {
            valid = false;
            break;
        }
        *separator = L'\0';
    }
    for (size_t remaining = created->count; valid && remaining > 0U; remaining--) {
        const wchar_t *directory = created->paths[remaining - 1U];
        if (!CreateDirectoryW(directory, NULL)) {
            valid = false;
            break;
        }
        HANDLE handle = windows_open_directory_secure(directory);
        valid = handle != INVALID_HANDLE_VALUE;
        if (handle != INVALID_HANDLE_VALUE)
            (void)CloseHandle(handle);
    }
    free(cursor);
    if (!valid) {
        windows_created_directories_close(created, true);
    }
    return valid;
}

bool cbm_windows_launcher_capability_probe(const wchar_t *target_directory,
                                           const wchar_t *launcher_candidate, char *error,
                                           size_t error_size) {
    if (error && error_size > 0U)
        error[0] = '\0';
    if (!target_directory || !target_directory[0] || !launcher_candidate ||
        !launcher_candidate[0]) {
        launcher_error(error, error_size, "invalid launcher capability probe request");
        return false;
    }
    wchar_t forced[16];
    if (GetEnvironmentVariableW(L"CBM_TEST_WINDOWS_LAUNCHER_CAPABILITY_PROBE", forced,
                                (DWORD)(sizeof(forced) / sizeof(forced[0]))) > 0U &&
        _wcsicmp(forced, L"fail") == 0) {
        launcher_error(error, error_size, "Windows launcher capability probe was forced to fail");
        return false;
    }
    windows_created_directories_t created;
    if (!windows_prepare_probe_directory(target_directory, &created)) {
        launcher_error(error, error_size, "could not safely prepare capability probe directory");
        return false;
    }
    wchar_t probe_tree_path[CBM_WINDOWS_LAUNCHER_PATH_CAP];
    int tree_written = swprintf(probe_tree_path, CBM_WINDOWS_LAUNCHER_PATH_CAP,
                                L"%ls\\.cbm-probe-path-check", target_directory);
    HANDLE target_handle = windows_open_directory_secure(target_directory);
    bool ok = tree_written > 0 && (size_t)tree_written < CBM_WINDOWS_LAUNCHER_PATH_CAP &&
              windows_path_tree_plain(probe_tree_path) && target_handle != INVALID_HANDLE_VALUE &&
              windows_probe_volume(target_directory, error, error_size);
    if (target_handle != INVALID_HANDLE_VALUE)
        (void)CloseHandle(target_handle);
    HANDLE mutex =
        ok ? CreateMutexW(NULL, FALSE, L"Local\\CBMWindowsLauncherCapabilityProbe-v1") : NULL;
    DWORD mutex_wait = mutex ? WaitForSingleObject(mutex, 30000U) : WAIT_FAILED;
    ok = ok && mutex_wait == WAIT_OBJECT_0;
    wchar_t probe_a[CBM_WINDOWS_LAUNCHER_PATH_CAP];
    wchar_t probe_b[CBM_WINDOWS_LAUNCHER_PATH_CAP];
    int a_written =
        swprintf(probe_a, CBM_WINDOWS_LAUNCHER_PATH_CAP, L"%ls\\.cbm-launcher-probe-a-%lu.exe",
                 target_directory, (unsigned long)GetCurrentProcessId());
    int b_written =
        swprintf(probe_b, CBM_WINDOWS_LAUNCHER_PATH_CAP, L"%ls\\.cbm-launcher-probe-b-%lu.exe",
                 target_directory, (unsigned long)GetCurrentProcessId());
    ok = ok && a_written > 0 && b_written > 0 &&
         (size_t)a_written < CBM_WINDOWS_LAUNCHER_PATH_CAP &&
         (size_t)b_written < CBM_WINDOWS_LAUNCHER_PATH_CAP &&
         windows_copy_flush_private(launcher_candidate, probe_a) &&
         windows_copy_flush_private(launcher_candidate, probe_b);

    SECURITY_ATTRIBUTES security = {
        .nLength = sizeof(security),
        .lpSecurityDescriptor = NULL,
        .bInheritHandle = TRUE,
    };
    HANDLE ready_a = ok ? CreateEventW(&security, TRUE, FALSE, NULL) : NULL;
    HANDLE release_a = ok ? CreateEventW(&security, TRUE, FALSE, NULL) : NULL;
    PROCESS_INFORMATION child_a;
    memset(&child_a, 0, sizeof(child_a));
    ok = ok && ready_a && release_a && windows_probe_spawn(probe_a, ready_a, release_a, &child_a) &&
         WaitForSingleObject(ready_a, 10000U) == WAIT_OBJECT_0;

    HANDLE source = ok ? CreateFileW(probe_b, DELETE | FILE_READ_ATTRIBUTES | READ_CONTROL,
                                     FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                                     OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL)
                       : INVALID_HANDLE_VALUE;
    BY_HANDLE_FILE_INFORMATION source_info;
    ok = ok && windows_file_identity(source, &source_info) && windows_owner_is_current(source) &&
         windows_posix_rename_handle(source, probe_a) &&
         GetFileAttributesW(probe_a) != INVALID_FILE_ATTRIBUTES;
    if (source != INVALID_HANDLE_VALUE)
        (void)CloseHandle(source);
    windows_probe_child_stop(&child_a, release_a);
    if (ready_a)
        (void)CloseHandle(ready_a);
    if (release_a)
        (void)CloseHandle(release_a);

    /* The replacement at probe_a is now a fresh candidate.  Map it and prove
     * POSIX deletion removes the visible name while the image remains live. */
    HANDLE ready_b = ok ? CreateEventW(&security, TRUE, FALSE, NULL) : NULL;
    HANDLE release_b = ok ? CreateEventW(&security, TRUE, FALSE, NULL) : NULL;
    PROCESS_INFORMATION child_b;
    memset(&child_b, 0, sizeof(child_b));
    ok = ok && ready_b && release_b && windows_probe_spawn(probe_a, ready_b, release_b, &child_b) &&
         WaitForSingleObject(ready_b, 10000U) == WAIT_OBJECT_0;
    HANDLE mapped = ok ? windows_open_regular_no_reparse(probe_a, DELETE) : INVALID_HANDLE_VALUE;
    ok = ok && mapped != INVALID_HANDLE_VALUE && windows_posix_remove_handle(mapped) &&
         GetFileAttributesW(probe_a) == INVALID_FILE_ATTRIBUTES &&
         GetLastError() == ERROR_FILE_NOT_FOUND;
    if (mapped != INVALID_HANDLE_VALUE)
        (void)CloseHandle(mapped);
    windows_probe_child_stop(&child_b, release_b);
    if (ready_b)
        (void)CloseHandle(ready_b);
    if (release_b)
        (void)CloseHandle(release_b);

    (void)DeleteFileW(probe_a);
    (void)DeleteFileW(probe_b);
    if (mutex_wait == WAIT_OBJECT_0)
        (void)ReleaseMutex(mutex);
    if (mutex)
        (void)CloseHandle(mutex);
    windows_created_directories_close(&created, true);
    if (!ok && (!error || error_size == 0U || error[0] == '\0')) {
        launcher_error(error, error_size,
                       "mapped-image POSIX replace/delete capability probe failed");
    }
    return ok;
}

#endif /* _WIN32 */
