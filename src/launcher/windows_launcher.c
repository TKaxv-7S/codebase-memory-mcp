/*
 * windows_launcher.c -- Permanent, self-relative Windows CBM launcher.
 *
 * This executable intentionally stays tiny.  It owns no indexer or config
 * state: it validates one fixed current-v1 pointer and contains the selected
 * payload in a kill-on-close job while relaying stdio and the exact exit code.
 */
#include "cli/windows_launcher_state.h"

#ifndef _WIN32

#include <stdio.h>

int main(void) {
    (void)fprintf(stderr, "codebase-memory-mcp-launcher is available only on Windows\n");
    return 1;
}

#else

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <aclapi.h>
#include <bcrypt.h>
#include <shellapi.h>
#include <tlhelp32.h>

#ifndef PIPE_REJECT_REMOTE_CLIENTS
#define PIPE_REJECT_REMOTE_CLIENTS 0x00000008
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#define LAUNCHER_CONTEXT_ENV L"CBM_WINDOWS_LAUNCH_CONTEXT_HANDLE_V1"
#define LAUNCHER_CONTEXT_HEADER_SIZE 128U
#define LAUNCHER_CONTEXT_MANAGED 0x00000001U
#define LAUNCHER_CONTEXT_PRIVATE 0x00000002U
#define LAUNCHER_PIPE_BUFFER (128U * 1024U)
#define LAUNCHER_PROBE_ARG L"__cbm_launcher_capability_probe_v1"
#define LAUNCHER_RELEASE_DESCRIPTOR_ARG L"__cbm_windows_release_descriptor_v1"
#define PAYLOAD_RELEASE_DESCRIPTOR_ARG L"__cbm_windows_payload_descriptor_v1"

static const uint8_t launcher_context_magic[8] = {
    'C', 'B', 'M', 'L', 'C', 'T', '1', '\0',
};

typedef struct {
    DWORD Flags;
} launcher_disposition_info_ex_t;

#define LAUNCHER_FILE_DISPOSITION_INFO_EX ((FILE_INFO_BY_HANDLE_CLASS)21)
#define LAUNCHER_FILE_DISPOSITION_DELETE 0x00000001U
#define LAUNCHER_FILE_DISPOSITION_POSIX 0x00000002U
#ifndef PROC_THREAD_ATTRIBUTE_JOB_LIST
#define PROC_THREAD_ATTRIBUTE_JOB_LIST ((DWORD_PTR)0x0002000dU)
#endif

static void launcher_write_u32(uint8_t *output, uint32_t value) {
    for (unsigned int index = 0; index < 4U; index++) {
        output[index] = (uint8_t)(value >> (index * 8U));
    }
}

static void launcher_write_u64(uint8_t *output, uint64_t value) {
    for (unsigned int index = 0; index < 8U; index++) {
        output[index] = (uint8_t)(value >> (index * 8U));
    }
}

static uint64_t launcher_filetime_value(const FILETIME *time) {
    return (uint64_t)time->dwLowDateTime | ((uint64_t)time->dwHighDateTime << 32U);
}

static int launcher_failure(const wchar_t *message) {
    if (message) {
        (void)fwprintf(stderr, L"codebase-memory-mcp: %ls\n", message);
        (void)fflush(stderr);
    }
    return 1;
}

static bool launcher_same_identity(const BY_HANDLE_FILE_INFORMATION *first,
                                   const BY_HANDLE_FILE_INFORMATION *second) {
    return first->dwVolumeSerialNumber == second->dwVolumeSerialNumber &&
           first->nFileIndexHigh == second->nFileIndexHigh &&
           first->nFileIndexLow == second->nFileIndexLow;
}

static bool launcher_file_information(HANDLE file, BY_HANDLE_FILE_INFORMATION *information) {
    return file && file != INVALID_HANDLE_VALUE && GetFileType(file) == FILE_TYPE_DISK &&
           GetFileInformationByHandle(file, information) != 0 &&
           (information->dwFileAttributes &
            (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) == 0 &&
           information->nNumberOfLinks == 1U;
}

static bool launcher_current_user(void **token_user_out, PSID *sid_out) {
    *token_user_out = NULL;
    *sid_out = NULL;
    HANDLE token = NULL;
    DWORD needed = 0U;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        return false;
    }
    (void)GetTokenInformation(token, TokenUser, NULL, 0U, &needed);
    void *memory = needed ? malloc(needed) : NULL;
    bool ok = memory && GetTokenInformation(token, TokenUser, memory, needed, &needed) != 0;
    (void)CloseHandle(token);
    if (!ok) {
        free(memory);
        return false;
    }
    *token_user_out = memory;
    *sid_out = ((TOKEN_USER *)memory)->User.Sid;
    return true;
}

static uint32_t launcher_sid_read_u32_le(const uint8_t *bytes) {
    return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8U) | ((uint32_t)bytes[2] << 16U) |
           ((uint32_t)bytes[3] << 24U);
}

static bool launcher_sid_is_trusted_installer(PSID sid) {
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
        if (launcher_sid_read_u32_le(bytes + 8U + index * 4U) != subauthorities[index]) {
            return false;
        }
    }
    return true;
}

static bool launcher_sid_is_trusted(PSID sid, PSID current_user) {
    return sid && current_user && IsValidSid(sid) &&
           (EqualSid(sid, current_user) || IsWellKnownSid(sid, WinLocalSystemSid) ||
            IsWellKnownSid(sid, WinBuiltinAdministratorsSid) ||
            launcher_sid_is_trusted_installer(sid));
}

static bool launcher_bounded_ace_sid_is_trusted(const ACE_HEADER *header, PSID current_user) {
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
           (launcher_sid_is_trusted((PSID)sid, current_user) ||
            (((header->AceFlags & INHERIT_ONLY_ACE) != 0U) &&
             IsWellKnownSid((PSID)sid, WinCreatorOwnerSid)));
}

static bool launcher_security_is_safe(HANDLE file, bool require_current_owner) {
    void *token_user = NULL;
    PSID user_sid = NULL;
    if (!launcher_current_user(&token_user, &user_sid)) {
        return false;
    }
    PSID owner = NULL;
    PACL dacl = NULL;
    PSECURITY_DESCRIPTOR descriptor = NULL;
    DWORD status = GetSecurityInfo(file, SE_FILE_OBJECT,
                                   OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner,
                                   NULL, &dacl, NULL, &descriptor);
    ACL_SIZE_INFORMATION information;
    memset(&information, 0, sizeof(information));
    bool secure =
        status == ERROR_SUCCESS && owner && IsValidSid(owner) &&
        (require_current_owner ? EqualSid(owner, user_sid) != 0
                               : launcher_sid_is_trusted(owner, user_sid)) &&
        dacl && IsValidAcl(dacl) &&
        GetAclInformation(dacl, &information, sizeof(information), AclSizeInformation) != 0;
    const DWORD mutation = GENERIC_ALL | GENERIC_WRITE | FILE_WRITE_DATA | FILE_APPEND_DATA |
                           FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | FILE_DELETE_CHILD |
                           FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | DELETE | WRITE_DAC |
                           WRITE_OWNER | ACCESS_SYSTEM_SECURITY;
    for (DWORD index = 0; secure && index < information.AceCount; index++) {
        void *opaque = NULL;
        if (!GetAce(dacl, index, &opaque) || !opaque) {
            secure = false;
            break;
        }
        ACE_HEADER *header = opaque;
        enum {
            LAUNCHER_ACE_ALLOW = 0x00,
            LAUNCHER_ACE_DENY = 0x01,
            LAUNCHER_ACE_DENY_OBJECT = 0x06,
            LAUNCHER_ACE_DENY_CALLBACK = 0x0a,
            LAUNCHER_ACE_DENY_CALLBACK_OBJECT = 0x0c,
        };
        if (header->AceType == LAUNCHER_ACE_DENY || header->AceType == LAUNCHER_ACE_DENY_OBJECT ||
            header->AceType == LAUNCHER_ACE_DENY_CALLBACK ||
            header->AceType == LAUNCHER_ACE_DENY_CALLBACK_OBJECT) {
            continue;
        }
        if (header->AceType != LAUNCHER_ACE_ALLOW ||
            header->AceSize <
                offsetof(ACCESS_ALLOWED_ACE, SidStart) + offsetof(SID, SubAuthority)) {
            secure = false;
            break;
        }
        ACCESS_ALLOWED_ACE *ace = opaque;
        if ((ace->Mask & mutation) == 0U) {
            continue;
        }
        if (!launcher_bounded_ace_sid_is_trusted(header, user_sid)) {
            secure = false;
        }
    }
    if (descriptor)
        (void)LocalFree(descriptor);
    free(token_user);
    return secure;
}

static bool launcher_security_is_private(HANDLE file) {
    return launcher_security_is_safe(file, true);
}

static HANDLE launcher_open_regular(const wchar_t *path, DWORD access, bool require_private) {
    HANDLE file =
        CreateFileW(path, access | FILE_READ_ATTRIBUTES | (require_private ? READ_CONTROL : 0U),
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
                    FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    BY_HANDLE_FILE_INFORMATION information;
    if (!launcher_file_information(file, &information) ||
        (require_private && !launcher_security_is_private(file))) {
        if (file != INVALID_HANDLE_VALUE)
            (void)CloseHandle(file);
        return INVALID_HANDLE_VALUE;
    }
    return file;
}

static HANDLE launcher_open_directory_private(const wchar_t *path) {
    HANDLE directory =
        CreateFileW(path, FILE_READ_ATTRIBUTES | READ_CONTROL,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    BY_HANDLE_FILE_INFORMATION information;
    bool valid = directory != INVALID_HANDLE_VALUE && GetFileType(directory) == FILE_TYPE_DISK &&
                 GetFileInformationByHandle(directory, &information) != 0 &&
                 (information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 &&
                 (information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0 &&
                 launcher_security_is_private(directory);
    if (!valid) {
        if (directory != INVALID_HANDLE_VALUE)
            (void)CloseHandle(directory);
        return INVALID_HANDLE_VALUE;
    }
    return directory;
}

static bool launcher_path_tree_plain(const wchar_t *file_path) {
    size_t length = wcslen(file_path);
    if (length < 4U || length >= CBM_WINDOWS_LAUNCHER_PATH_CAP || file_path[1] != L':' ||
        (file_path[2] != L'\\' && file_path[2] != L'/')) {
        return false;
    }
    wchar_t *path = malloc((length + 1U) * sizeof(*path));
    if (!path)
        return false;
    memcpy(path, file_path, (length + 1U) * sizeof(*path));
    for (size_t index = 0; index < length; index++) {
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
                launcher_security_is_safe(component, false);
        if (component != INVALID_HANDLE_VALUE)
            (void)CloseHandle(component);
        path[index] = saved;
    }
    free(path);
    return valid;
}

static bool launcher_self_path(wchar_t output[CBM_WINDOWS_LAUNCHER_PATH_CAP]) {
    DWORD length = GetModuleFileNameW(NULL, output, CBM_WINDOWS_LAUNCHER_PATH_CAP);
    return length > 3U && length < CBM_WINDOWS_LAUNCHER_PATH_CAP &&
           launcher_path_tree_plain(output);
}

static bool launcher_parent_path(const wchar_t *path, wchar_t *output, size_t capacity) {
    size_t length = wcslen(path);
    if (length + 1U > capacity)
        return false;
    memcpy(output, path, (length + 1U) * sizeof(*output));
    wchar_t *separator = wcsrchr(output, L'\\');
    wchar_t *slash = wcsrchr(output, L'/');
    if (!separator || (slash && slash > separator))
        separator = slash;
    if (!separator || separator <= output + 2)
        return false;
    *separator = L'\0';
    return true;
}

static bool launcher_read_all(HANDLE file, void *buffer, size_t size) {
    size_t offset = 0U;
    while (offset < size) {
        DWORD amount = 0U;
        DWORD request = size - offset > (size_t)MAXDWORD ? MAXDWORD : (DWORD)(size - offset);
        if (!ReadFile(file, (uint8_t *)buffer + offset, request, &amount, NULL) || amount == 0U) {
            return false;
        }
        offset += amount;
    }
    return true;
}

/* 1 = managed valid state, 0 = current absent (portable bundle), -1 = corrupt. */
static int launcher_load_current(const wchar_t *canonical_launcher,
                                 cbm_windows_current_v1_t *state_out) {
    wchar_t directory[CBM_WINDOWS_LAUNCHER_PATH_CAP];
    wchar_t current[CBM_WINDOWS_LAUNCHER_PATH_CAP];
    if (!launcher_parent_path(canonical_launcher, directory, CBM_WINDOWS_LAUNCHER_PATH_CAP)) {
        return -1;
    }
    int written =
        swprintf(current, CBM_WINDOWS_LAUNCHER_PATH_CAP, L"%ls\\.cbm\\current-v1", directory);
    if (written <= 0 || (size_t)written >= CBM_WINDOWS_LAUNCHER_PATH_CAP) {
        return -1;
    }
    wchar_t state_directory[CBM_WINDOWS_LAUNCHER_PATH_CAP];
    int state_written =
        swprintf(state_directory, CBM_WINDOWS_LAUNCHER_PATH_CAP, L"%ls\\.cbm", directory);
    HANDLE install_handle = launcher_open_directory_private(directory);
    HANDLE state_handle = state_written > 0 && (size_t)state_written < CBM_WINDOWS_LAUNCHER_PATH_CAP
                              ? launcher_open_directory_private(state_directory)
                              : INVALID_HANDLE_VALUE;
    if (install_handle == INVALID_HANDLE_VALUE || state_handle == INVALID_HANDLE_VALUE) {
        if (install_handle != INVALID_HANDLE_VALUE)
            (void)CloseHandle(install_handle);
        if (state_handle != INVALID_HANDLE_VALUE)
            (void)CloseHandle(state_handle);
        DWORD state_attributes = GetFileAttributesW(state_directory);
        DWORD state_error =
            state_attributes == INVALID_FILE_ATTRIBUTES ? GetLastError() : ERROR_SUCCESS;
        return state_attributes == INVALID_FILE_ATTRIBUTES &&
                       (state_error == ERROR_FILE_NOT_FOUND || state_error == ERROR_PATH_NOT_FOUND)
                   ? 0
                   : -1;
    }
    (void)CloseHandle(install_handle);
    (void)CloseHandle(state_handle);
    HANDLE file = launcher_open_regular(current, GENERIC_READ, true);
    if (file == INVALID_HANDLE_VALUE) {
        DWORD attributes = GetFileAttributesW(current);
        return attributes == INVALID_FILE_ATTRIBUTES && (GetLastError() == ERROR_FILE_NOT_FOUND ||
                                                         GetLastError() == ERROR_PATH_NOT_FOUND)
                   ? 0
                   : -1;
    }
    LARGE_INTEGER size;
    uint8_t record[CBM_WINDOWS_CURRENT_V1_SIZE];
    uint8_t trailing = 0U;
    DWORD trailing_count = 0U;
    bool valid = GetFileSizeEx(file, &size) && size.QuadPart == CBM_WINDOWS_CURRENT_V1_SIZE &&
                 launcher_read_all(file, record, sizeof(record)) &&
                 ReadFile(file, &trailing, 1U, &trailing_count, NULL) != 0 &&
                 trailing_count == 0U &&
                 cbm_windows_current_v1_decode(record, sizeof(record), state_out);
    (void)CloseHandle(file);
    return valid ? 1 : -1;
}

static bool launcher_adjacent_payload(const wchar_t *canonical_launcher,
                                      wchar_t output[CBM_WINDOWS_LAUNCHER_PATH_CAP]) {
    wchar_t directory[CBM_WINDOWS_LAUNCHER_PATH_CAP];
    if (!launcher_parent_path(canonical_launcher, directory, CBM_WINDOWS_LAUNCHER_PATH_CAP)) {
        return false;
    }
    int written = swprintf(output, CBM_WINDOWS_LAUNCHER_PATH_CAP,
                           L"%ls\\codebase-memory-mcp.payload.exe", directory);
    return written > 0 && (size_t)written < CBM_WINDOWS_LAUNCHER_PATH_CAP;
}

/* WHY: wmain supplies wchar_t **. Adding nested pointee const would make these
 * read-only helpers' parameter types incompatible with that Windows ABI. */
// cppcheck-suppress constParameter
static cbm_windows_launcher_action_t launcher_wide_action(int argc, wchar_t *const argv[]) {
    if (argc <= 1 || !argv)
        return CBM_WINDOWS_LAUNCHER_ACTION_ORDINARY;
    for (int index = 1; index < argc; index++) {
        const wchar_t *argument = argv[index];
        if (!argument)
            continue;
        if (wcscmp(argument, L"cli") == 0 || wcscmp(argument, L"hook-augment") == 0 ||
            wcscmp(argument, L"config") == 0 || wcscmp(argument, L"install") == 0 ||
            wcscmp(argument, L"--help") == 0 || wcscmp(argument, L"-h") == 0 ||
            wcscmp(argument, L"--version") == 0) {
            return CBM_WINDOWS_LAUNCHER_ACTION_ORDINARY;
        }
        if (wcscmp(argument, L"update") == 0)
            return CBM_WINDOWS_LAUNCHER_ACTION_UPDATE;
        if (wcscmp(argument, L"uninstall") == 0)
            return CBM_WINDOWS_LAUNCHER_ACTION_UNINSTALL;
    }
    return CBM_WINDOWS_LAUNCHER_ACTION_ORDINARY;
}

static size_t launcher_quoted_length(const wchar_t *argument) {
    bool quote = argument[0] == L'\0' || wcspbrk(argument, L" \t\n\v\"") != NULL;
    size_t length = quote ? 2U : 0U;
    size_t slashes = 0U;
    for (const wchar_t *cursor = argument;; cursor++) {
        if (*cursor == L'\\') {
            slashes++;
            continue;
        }
        if (*cursor == L'\"') {
            length += slashes * 2U + 2U;
            slashes = 0U;
            continue;
        }
        if (*cursor == L'\0') {
            length += quote ? slashes * 2U : slashes;
            break;
        }
        length += slashes + 1U;
        slashes = 0U;
    }
    return length;
}

static wchar_t *launcher_quote_into(wchar_t *output, const wchar_t *argument) {
    bool quote = argument[0] == L'\0' || wcspbrk(argument, L" \t\n\v\"") != NULL;
    if (quote)
        *output++ = L'\"';
    size_t slashes = 0U;
    for (const wchar_t *cursor = argument;; cursor++) {
        if (*cursor == L'\\') {
            slashes++;
            continue;
        }
        if (*cursor == L'\"') {
            size_t count = slashes * 2U + 1U;
            while (count-- > 0U)
                *output++ = L'\\';
            *output++ = L'\"';
            slashes = 0U;
            continue;
        }
        if (*cursor == L'\0') {
            size_t count = quote ? slashes * 2U : slashes;
            while (count-- > 0U)
                *output++ = L'\\';
            break;
        }
        while (slashes-- > 0U)
            *output++ = L'\\';
        slashes = 0U;
        *output++ = *cursor;
    }
    if (quote)
        *output++ = L'\"';
    return output;
}

static wchar_t *launcher_command_line(const wchar_t *image, int argc, wchar_t *const argv[]) {
    size_t capacity = launcher_quoted_length(image) + 1U;
    for (int index = 1; index < argc; index++) {
        size_t addition = launcher_quoted_length(argv[index]) + 1U;
        if (SIZE_MAX - capacity < addition)
            return NULL;
        capacity += addition;
    }
    wchar_t *command = calloc(capacity, sizeof(*command));
    if (!command)
        return NULL;
    wchar_t *cursor = launcher_quote_into(command, image);
    for (int index = 1; index < argc; index++) {
        *cursor++ = L' ';
        cursor = launcher_quote_into(cursor, argv[index]);
    }
    *cursor = L'\0';
    return command;
}

typedef struct {
    HANDLE server;
    HANDLE client;
} launcher_context_pipe_t;

static void launcher_context_pipe_close(launcher_context_pipe_t *pipe) {
    if (pipe->server && pipe->server != INVALID_HANDLE_VALUE)
        (void)CloseHandle(pipe->server);
    if (pipe->client && pipe->client != INVALID_HANDLE_VALUE)
        (void)CloseHandle(pipe->client);
    memset(pipe, 0, sizeof(*pipe));
}

static bool launcher_context_pipe_open(launcher_context_pipe_t *pipe) {
    memset(pipe, 0, sizeof(*pipe));
    uint8_t random[16];
    if (BCryptGenRandom(NULL, random, sizeof(random), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
        return false;
    }
    wchar_t name[160];
    int written =
        swprintf(name, sizeof(name) / sizeof(name[0]),
                 L"\\\\.\\pipe\\cbm-launch-context-v1-%lu-"
                 L"%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                 (unsigned long)GetCurrentProcessId(), random[0], random[1], random[2], random[3],
                 random[4], random[5], random[6], random[7], random[8], random[9], random[10],
                 random[11], random[12], random[13], random[14], random[15]);
    if (written <= 0 || (size_t)written >= sizeof(name) / sizeof(name[0])) {
        return false;
    }
    pipe->server = CreateNamedPipeW(name, PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                                    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT |
                                        PIPE_REJECT_REMOTE_CLIENTS,
                                    1U, LAUNCHER_PIPE_BUFFER, 4096U, 0U, NULL);
    if (pipe->server == INVALID_HANDLE_VALUE) {
        launcher_context_pipe_close(pipe);
        return false;
    }
    SECURITY_ATTRIBUTES security = {
        .nLength = sizeof(security),
        .lpSecurityDescriptor = NULL,
        .bInheritHandle = TRUE,
    };
    pipe->client = CreateFileW(name, GENERIC_READ | GENERIC_WRITE, 0U, &security, OPEN_EXISTING,
                               FILE_ATTRIBUTE_NORMAL, NULL);
    if (pipe->client == INVALID_HANDLE_VALUE) {
        launcher_context_pipe_close(pipe);
        return false;
    }
    BOOL connected = ConnectNamedPipe(pipe->server, NULL);
    if (!connected && GetLastError() != ERROR_PIPE_CONNECTED) {
        launcher_context_pipe_close(pipe);
        return false;
    }
    return true;
}

static bool launcher_write_all(HANDLE file, const void *data, size_t size) {
    size_t offset = 0U;
    while (offset < size) {
        DWORD amount = 0U;
        DWORD request = size - offset > (size_t)MAXDWORD ? MAXDWORD : (DWORD)(size - offset);
        if (!WriteFile(file, (const uint8_t *)data + offset, request, &amount, NULL) ||
            amount == 0U) {
            return false;
        }
        offset += amount;
    }
    return true;
}

static bool launcher_wait_context_ready(HANDLE server, HANDLE child, HANDLE parent,
                                        bool *explicit_rejection_out) {
    *explicit_rejection_out = false;
    uint64_t now = GetTickCount64();
    uint64_t deadline = UINT64_MAX - now < 30000U ? UINT64_MAX : now + 30000U;
    while (GetTickCount64() < deadline) {
        DWORD available = 0U;
        if (!PeekNamedPipe(server, NULL, 0U, NULL, &available, NULL)) {
            return false;
        }
        if (available > 0U) {
            uint8_t ready = 0U;
            DWORD received = 0U;
            if (ReadFile(server, &ready, 1U, &received, NULL) == 0 || received != 1U) {
                return false;
            }
            *explicit_rejection_out = ready == (uint8_t)'X';
            return ready == (uint8_t)'R';
        }
        if (WaitForSingleObject(child, 0U) == WAIT_OBJECT_0) {
            return false;
        }
        if (WaitForSingleObject(parent, 0U) == WAIT_OBJECT_0) {
            return false;
        }
        Sleep(2U);
    }
    return false;
}

static bool launcher_context_send(HANDLE server, const wchar_t *canonical_launcher, bool managed,
                                  bool private_activation, cbm_windows_launcher_action_t action,
                                  const cbm_windows_current_v1_t *state) {
    size_t path_chars = wcslen(canonical_launcher) + 1U;
    if (path_chars >= CBM_WINDOWS_LAUNCHER_PATH_CAP || (managed && !state)) {
        return false;
    }
    FILETIME creation;
    FILETIME exit_time;
    FILETIME kernel_time;
    FILETIME user_time;
    if (!GetProcessTimes(GetCurrentProcess(), &creation, &exit_time, &kernel_time, &user_time)) {
        return false;
    }
    uint8_t header[LAUNCHER_CONTEXT_HEADER_SIZE];
    memset(header, 0, sizeof(header));
    memcpy(header, launcher_context_magic, sizeof(launcher_context_magic));
    launcher_write_u32(header + 8U, 1U);
    launcher_write_u32(header + 12U, LAUNCHER_CONTEXT_HEADER_SIZE);
    uint32_t flags = managed ? LAUNCHER_CONTEXT_MANAGED : 0U;
    if (private_activation)
        flags |= LAUNCHER_CONTEXT_PRIVATE;
    launcher_write_u32(header + 16U, flags);
    launcher_write_u32(header + 20U, (uint32_t)action);
    launcher_write_u32(header + 24U, GetCurrentProcessId());
    launcher_write_u32(header + 28U, (uint32_t)path_chars);
    launcher_write_u64(header + 32U, launcher_filetime_value(&creation));
    if (managed) {
        launcher_write_u64(header + 40U, state->payload_size);
        memcpy(header + 48U, state->payload_sha256, 64U);
    }
    return launcher_write_all(server, header, sizeof(header)) &&
           launcher_write_all(server, canonical_launcher, path_chars * sizeof(*canonical_launcher));
}

static HANDLE launcher_duplicate_standard(DWORD identifier, DWORD desired) {
    HANDLE source = GetStdHandle(identifier);
    HANDLE duplicate = NULL;
    if (source && source != INVALID_HANDLE_VALUE &&
        DuplicateHandle(GetCurrentProcess(), source, GetCurrentProcess(), &duplicate, 0U, TRUE,
                        DUPLICATE_SAME_ACCESS)) {
        return duplicate;
    }
    SECURITY_ATTRIBUTES security = {
        .nLength = sizeof(security),
        .lpSecurityDescriptor = NULL,
        .bInheritHandle = TRUE,
    };
    return CreateFileW(L"NUL", desired, FILE_SHARE_READ | FILE_SHARE_WRITE, &security,
                       OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
}

static bool launcher_posix_remove(HANDLE file) {
    launcher_disposition_info_ex_t disposition = {
        .Flags = LAUNCHER_FILE_DISPOSITION_DELETE | LAUNCHER_FILE_DISPOSITION_POSIX,
    };
    return SetFileInformationByHandle(file, LAUNCHER_FILE_DISPOSITION_INFO_EX, &disposition,
                                      sizeof(disposition)) != 0;
}

static int launcher_spawn_payload(const wchar_t *execution_path, const wchar_t *canonical_launcher,
                                  bool managed, bool private_activation,
                                  cbm_windows_launcher_action_t action,
                                  const cbm_windows_current_v1_t *state, HANDLE parent, int argc,
                                  wchar_t *const argv[]) {
    wchar_t *command = launcher_command_line(execution_path, argc, argv);
    launcher_context_pipe_t context_pipe = {0};
    HANDLE standard[3] = {
        launcher_duplicate_standard(STD_INPUT_HANDLE, GENERIC_READ),
        launcher_duplicate_standard(STD_OUTPUT_HANDLE, GENERIC_WRITE),
        launcher_duplicate_standard(STD_ERROR_HANDLE, GENERIC_WRITE),
    };
    bool handles_valid = standard[0] && standard[0] != INVALID_HANDLE_VALUE && standard[1] &&
                         standard[1] != INVALID_HANDLE_VALUE && standard[2] &&
                         standard[2] != INVALID_HANDLE_VALUE;
    bool pipe_valid = handles_valid && launcher_context_pipe_open(&context_pipe);
    HANDLE inherited[4] = {
        standard[0],
        standard[1],
        standard[2],
        pipe_valid ? context_pipe.client : NULL,
    };
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits;
    memset(&limits, 0, sizeof(limits));
    limits.BasicLimitInformation.LimitFlags =
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_BREAKAWAY_OK;
    HANDLE job = CreateJobObjectW(NULL, NULL);
    bool job_ready = job && SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits,
                                                    sizeof(limits)) != 0;
    SIZE_T attribute_size = 0U;
    (void)InitializeProcThreadAttributeList(NULL, 2U, 0U, &attribute_size);
    LPPROC_THREAD_ATTRIBUTE_LIST attributes = attribute_size ? malloc(attribute_size) : NULL;
    bool attribute_initialized =
        attributes && InitializeProcThreadAttributeList(attributes, 2U, 0U, &attribute_size) != 0;
    bool attribute_ready =
        attribute_initialized && job_ready &&
        UpdateProcThreadAttribute(attributes, 0U, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherited,
                                  sizeof(inherited), NULL, NULL) != 0 &&
        UpdateProcThreadAttribute(attributes, 0U, PROC_THREAD_ATTRIBUTE_JOB_LIST, &job, sizeof(job),
                                  NULL, NULL) != 0;

    wchar_t context_handle[32];
    int context_written =
        pipe_valid ? swprintf(context_handle, sizeof(context_handle) / sizeof(context_handle[0]),
                              L"%llx", (unsigned long long)(uintptr_t)context_pipe.client)
                   : -1;
    bool environment_set =
        context_written > 0 &&
        (size_t)context_written < sizeof(context_handle) / sizeof(context_handle[0]) &&
        SetEnvironmentVariableW(LAUNCHER_CONTEXT_ENV, context_handle) != 0;
    STARTUPINFOEXW startup;
    PROCESS_INFORMATION child;
    memset(&startup, 0, sizeof(startup));
    memset(&child, 0, sizeof(child));
    startup.StartupInfo.cb = sizeof(startup);
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = standard[0];
    startup.StartupInfo.hStdOutput = standard[1];
    startup.StartupInfo.hStdError = standard[2];
    startup.lpAttributeList = attributes;
    DWORD flags = EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT;
    bool parent_alive =
        parent && parent != INVALID_HANDLE_VALUE && WaitForSingleObject(parent, 0U) == WAIT_TIMEOUT;
    bool created = command && pipe_valid && attribute_ready && job_ready && parent_alive &&
                   environment_set &&
                   CreateProcessW(execution_path, command, NULL, NULL, TRUE, flags, NULL, NULL,
                                  &startup.StartupInfo, &child) != 0;
    (void)SetEnvironmentVariableW(LAUNCHER_CONTEXT_ENV, NULL);
    if (attribute_initialized)
        DeleteProcThreadAttributeList(attributes);
    free(attributes);
    free(command);
    for (size_t index = 0U; index < 3U; index++) {
        if (standard[index] && standard[index] != INVALID_HANDLE_VALUE)
            (void)CloseHandle(standard[index]);
    }
    if (context_pipe.client && context_pipe.client != INVALID_HANDLE_VALUE) {
        (void)CloseHandle(context_pipe.client);
        context_pipe.client = NULL;
    }
    bool context_sent =
        created && launcher_context_send(context_pipe.server, canonical_launcher, managed,
                                         private_activation, action, state);
    bool resumed = context_sent && ResumeThread(child.hThread) != (DWORD)-1;
    bool explicit_rejection = false;
    bool payload_ready = resumed && launcher_wait_context_ready(context_pipe.server, child.hProcess,
                                                                parent, &explicit_rejection);
    HANDLE private_file = INVALID_HANDLE_VALUE;
    bool private_removed = true;
    if (payload_ready && private_activation) {
        private_file =
            launcher_open_regular(execution_path, GENERIC_READ | GENERIC_WRITE | DELETE, true);
        private_removed =
            private_file != INVALID_HANDLE_VALUE && launcher_posix_remove(private_file);
    }
    uint8_t handshake_result = private_removed ? (uint8_t)'G' : (uint8_t)'F';
    bool authenticated = payload_ready &&
                         launcher_write_all(context_pipe.server, &handshake_result, 1U) &&
                         private_removed;
    bool graceful_failure = explicit_rejection || (payload_ready && !private_removed);
    if (context_pipe.server && context_pipe.server != INVALID_HANDLE_VALUE) {
        (void)CloseHandle(context_pipe.server);
        context_pipe.server = NULL;
    }
    if (!authenticated && created && !graceful_failure) {
        (void)TerminateProcess(child.hProcess, 1U);
    }
    if (private_file != INVALID_HANDLE_VALUE)
        (void)CloseHandle(private_file);
    HANDLE waits[2] = {child.hProcess, parent};
    DWORD wait = created
                     ? WaitForMultipleObjects(2U, waits, FALSE, authenticated ? INFINITE : 5000U)
                     : WAIT_FAILED;
    bool parent_died = wait == WAIT_OBJECT_0 + 1U;
    if ((wait != WAIT_OBJECT_0 || parent_died) && created) {
        (void)TerminateJobObject(job, 1U);
        (void)WaitForSingleObject(child.hProcess, 5000U);
    }
    DWORD exit_code = 1U;
    bool exit_valid = authenticated && wait == WAIT_OBJECT_0 &&
                      GetExitCodeProcess(child.hProcess, &exit_code) != 0;
    if (child.hThread)
        (void)CloseHandle(child.hThread);
    if (child.hProcess)
        (void)CloseHandle(child.hProcess);
    if (job)
        (void)CloseHandle(job);
    launcher_context_pipe_close(&context_pipe);
    return exit_valid ? (int)exit_code : 1;
}

static HANDLE launcher_parent_liveness_open(void) {
    DWORD self_pid = GetCurrentProcessId();
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0U);
    if (snapshot == INVALID_HANDLE_VALUE)
        return NULL;
    PROCESSENTRY32W entry;
    memset(&entry, 0, sizeof(entry));
    entry.dwSize = sizeof(entry);
    DWORD parent_pid = 0U;
    bool found = Process32FirstW(snapshot, &entry) != 0;
    while (found) {
        if (entry.th32ProcessID == self_pid) {
            parent_pid = entry.th32ParentProcessID;
            break;
        }
        found = Process32NextW(snapshot, &entry) != 0;
    }
    (void)CloseHandle(snapshot);
    if (parent_pid == 0U || parent_pid == self_pid)
        return NULL;
    HANDLE parent = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, parent_pid);
    if (!parent || WaitForSingleObject(parent, 0U) != WAIT_TIMEOUT) {
        if (parent)
            (void)CloseHandle(parent);
        return NULL;
    }
    FILETIME self_creation;
    FILETIME self_exit;
    FILETIME self_kernel;
    FILETIME self_user;
    FILETIME parent_creation;
    FILETIME parent_exit;
    FILETIME parent_kernel;
    FILETIME parent_user;
    bool chronological =
        GetProcessTimes(GetCurrentProcess(), &self_creation, &self_exit, &self_kernel,
                        &self_user) != 0 &&
        GetProcessTimes(parent, &parent_creation, &parent_exit, &parent_kernel, &parent_user) !=
            0 &&
        launcher_filetime_value(&parent_creation) <= launcher_filetime_value(&self_creation);
    if (!chronological) {
        (void)CloseHandle(parent);
        return NULL;
    }
    return parent;
}

static bool launcher_private_payload_path(const wchar_t *canonical_launcher, const wchar_t *payload,
                                          wchar_t output[CBM_WINDOWS_LAUNCHER_PATH_CAP]) {
    wchar_t directory[CBM_WINDOWS_LAUNCHER_PATH_CAP];
    wchar_t state_directory[CBM_WINDOWS_LAUNCHER_PATH_CAP];
    wchar_t runtime[CBM_WINDOWS_LAUNCHER_PATH_CAP];
    if (!launcher_parent_path(canonical_launcher, directory, CBM_WINDOWS_LAUNCHER_PATH_CAP)) {
        return false;
    }
    int state_written =
        swprintf(state_directory, CBM_WINDOWS_LAUNCHER_PATH_CAP, L"%ls\\.cbm", directory);
    int runtime_written =
        swprintf(runtime, CBM_WINDOWS_LAUNCHER_PATH_CAP, L"%ls\\runtime", state_directory);
    int output_written = swprintf(
        output, CBM_WINDOWS_LAUNCHER_PATH_CAP, L"%ls\\activation-%lu-%llu.payload.exe", runtime,
        (unsigned long)GetCurrentProcessId(), (unsigned long long)GetTickCount64());
    if (state_written <= 0 || runtime_written <= 0 || output_written <= 0 ||
        (size_t)state_written >= CBM_WINDOWS_LAUNCHER_PATH_CAP ||
        (size_t)runtime_written >= CBM_WINDOWS_LAUNCHER_PATH_CAP ||
        (size_t)output_written >= CBM_WINDOWS_LAUNCHER_PATH_CAP) {
        return false;
    }
    HANDLE install_handle = launcher_open_directory_private(directory);
    HANDLE state_handle = launcher_open_directory_private(state_directory);
    bool runtime_created = CreateDirectoryW(runtime, NULL) != 0;
    DWORD runtime_error = runtime_created ? ERROR_SUCCESS : GetLastError();
    HANDLE runtime_handle = (runtime_created || runtime_error == ERROR_ALREADY_EXISTS)
                                ? launcher_open_directory_private(runtime)
                                : INVALID_HANDLE_VALUE;
    bool directories_valid =
        install_handle != INVALID_HANDLE_VALUE && state_handle != INVALID_HANDLE_VALUE &&
        runtime_handle != INVALID_HANDLE_VALUE && launcher_path_tree_plain(output);
    if (install_handle != INVALID_HANDLE_VALUE)
        (void)CloseHandle(install_handle);
    if (state_handle != INVALID_HANDLE_VALUE)
        (void)CloseHandle(state_handle);
    if (runtime_handle != INVALID_HANDLE_VALUE)
        (void)CloseHandle(runtime_handle);
    if (!directories_valid || !CopyFileW(payload, output, TRUE)) {
        if (runtime_created)
            (void)RemoveDirectoryW(runtime);
        return false;
    }
    HANDLE source = launcher_open_regular(payload, GENERIC_READ, true);
    HANDLE copy = launcher_open_regular(output, GENERIC_READ | GENERIC_WRITE | DELETE, true);
    BY_HANDLE_FILE_INFORMATION source_info;
    BY_HANDLE_FILE_INFORMATION copy_info;
    LARGE_INTEGER source_size;
    LARGE_INTEGER copy_size;
    bool valid = launcher_file_information(source, &source_info) &&
                 launcher_file_information(copy, &copy_info) &&
                 GetFileSizeEx(source, &source_size) && GetFileSizeEx(copy, &copy_size) &&
                 source_size.QuadPart == copy_size.QuadPart && FlushFileBuffers(copy) != 0;
    if (source != INVALID_HANDLE_VALUE)
        (void)CloseHandle(source);
    if (copy != INVALID_HANDLE_VALUE)
        (void)CloseHandle(copy);
    if (!valid)
        (void)DeleteFileW(output);
    return valid;
}

/* WHY: See launcher_wide_action; this role parser reads but never owns wmain's
 * mutable argv array. */
// cppcheck-suppress constParameter
static int launcher_probe_role(int argc, wchar_t *const argv[]) {
    if (argc != 4 || wcscmp(argv[1], LAUNCHER_PROBE_ARG) != 0)
        return -1;
    wchar_t *ready_end = NULL;
    wchar_t *release_end = NULL;
    unsigned long long ready_raw = wcstoull(argv[2], &ready_end, 16);
    unsigned long long release_raw = wcstoull(argv[3], &release_end, 16);
    if (!ready_end || *ready_end != L'\0' || !release_end || *release_end != L'\0' ||
        ready_raw == 0ULL || release_raw == 0ULL) {
        return 1;
    }
    HANDLE ready = (HANDLE)(uintptr_t)ready_raw;
    HANDLE release = (HANDLE)(uintptr_t)release_raw;
    if (!SetEvent(ready))
        return 1;
    return WaitForSingleObject(release, 30000U) == WAIT_OBJECT_0 ? 0 : 1;
}

/* WHY: See launcher_wide_action; retain the exact wmain-compatible argv type. */
// cppcheck-suppress constParameter
static int launcher_release_descriptor_role(int argc, wchar_t *const argv[]) {
    if (argc != 2 || wcscmp(argv[1], LAUNCHER_RELEASE_DESCRIPTOR_ARG) != 0) {
        return -1;
    }
    wchar_t canonical[CBM_WINDOWS_LAUNCHER_PATH_CAP];
    wchar_t payload[CBM_WINDOWS_LAUNCHER_PATH_CAP];
    if (!launcher_self_path(canonical) || !launcher_adjacent_payload(canonical, payload)) {
        return 1;
    }
    HANDLE launcher_file = launcher_open_regular(canonical, GENERIC_READ, true);
    HANDLE payload_file = launcher_open_regular(payload, GENERIC_READ, true);
    BY_HANDLE_FILE_INFORMATION launcher_information;
    BY_HANDLE_FILE_INFORMATION payload_information;
    bool paths_ready = launcher_file_information(launcher_file, &launcher_information) &&
                       launcher_file_information(payload_file, &payload_information) &&
                       launcher_path_tree_plain(payload);
    if (launcher_file != INVALID_HANDLE_VALUE) {
        (void)CloseHandle(launcher_file);
    }
    if (payload_file != INVALID_HANDLE_VALUE) {
        (void)CloseHandle(payload_file);
    }
    if (!paths_ready)
        return 1;

    wchar_t command[CBM_WINDOWS_LAUNCHER_PATH_CAP];
    int written =
        swprintf(command, CBM_WINDOWS_LAUNCHER_PATH_CAP, L"\"%ls\" %ls %u", payload,
                 PAYLOAD_RELEASE_DESCRIPTOR_ARG, (unsigned int)CBM_WINDOWS_LAUNCHER_ABI_CURRENT);
    if (written <= 0 || (size_t)written >= CBM_WINDOWS_LAUNCHER_PATH_CAP) {
        return 1;
    }
    HANDLE standard[3] = {
        GetStdHandle(STD_INPUT_HANDLE),
        GetStdHandle(STD_OUTPUT_HANDLE),
        GetStdHandle(STD_ERROR_HANDLE),
    };
    bool handles_ready = true;
    for (size_t index = 0U; index < 3U; index++) {
        handles_ready = handles_ready && standard[index] && standard[index] != INVALID_HANDLE_VALUE;
    }
    SIZE_T attribute_size = 0U;
    (void)InitializeProcThreadAttributeList(NULL, 1U, 0U, &attribute_size);
    LPPROC_THREAD_ATTRIBUTE_LIST attributes =
        handles_ready && attribute_size ? malloc(attribute_size) : NULL;
    bool initialized =
        attributes && InitializeProcThreadAttributeList(attributes, 1U, 0U, &attribute_size) != 0;
    bool attributes_ready =
        initialized && UpdateProcThreadAttribute(attributes, 0U, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                                 standard, sizeof(standard), NULL, NULL) != 0;
    STARTUPINFOEXW startup;
    PROCESS_INFORMATION child;
    memset(&startup, 0, sizeof(startup));
    memset(&child, 0, sizeof(child));
    startup.StartupInfo.cb = sizeof(startup);
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = standard[0];
    startup.StartupInfo.hStdOutput = standard[1];
    startup.StartupInfo.hStdError = standard[2];
    startup.lpAttributeList = attributes;
    bool spawned =
        attributes_ready && CreateProcessW(payload, command, NULL, NULL, TRUE,
                                           CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT, NULL,
                                           NULL, &startup.StartupInfo, &child) != 0;
    if (initialized)
        DeleteProcThreadAttributeList(attributes);
    free(attributes);
    DWORD wait = spawned ? WaitForSingleObject(child.hProcess, 30000U) : WAIT_FAILED;
    if (spawned && wait != WAIT_OBJECT_0) {
        (void)TerminateProcess(child.hProcess, 1U);
        (void)WaitForSingleObject(child.hProcess, 5000U);
    }
    DWORD exit_code = 1U;
    bool valid = spawned && wait == WAIT_OBJECT_0 &&
                 GetExitCodeProcess(child.hProcess, &exit_code) != 0 && exit_code == 0U;
    if (child.hThread)
        (void)CloseHandle(child.hThread);
    if (child.hProcess)
        (void)CloseHandle(child.hProcess);
    return valid ? 0 : 1;
}

int wmain(void) {
    int argc = 0;
    LPWSTR *argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv || argc <= 0) {
        if (argv)
            (void)LocalFree(argv);
        return launcher_failure(L"could not parse the Windows command line");
    }
    int descriptor_result = launcher_release_descriptor_role(argc, argv);
    if (descriptor_result >= 0) {
        (void)LocalFree(argv);
        return descriptor_result;
    }
    int probe_result = launcher_probe_role(argc, argv);
    if (probe_result >= 0) {
        (void)LocalFree(argv);
        return probe_result;
    }
    wchar_t canonical[CBM_WINDOWS_LAUNCHER_PATH_CAP];
    if (!launcher_self_path(canonical)) {
        (void)LocalFree(argv);
        return launcher_failure(L"could not securely resolve the launcher path");
    }
    HANDLE canonical_file = launcher_open_regular(canonical, GENERIC_READ, true);
    if (canonical_file == INVALID_HANDLE_VALUE) {
        (void)LocalFree(argv);
        return launcher_failure(L"launcher ownership or access policy is unsafe");
    }
    (void)CloseHandle(canonical_file);

    cbm_windows_current_v1_t state;
    memset(&state, 0, sizeof(state));
    int state_status = launcher_load_current(canonical, &state);
    if (state_status < 0) {
        (void)LocalFree(argv);
        return launcher_failure(L"current-v1 launcher state is corrupt or unsafe");
    }
    bool managed = state_status == 1;
    if (managed &&
        !cbm_windows_current_v1_supports_launcher_abi(&state, CBM_WINDOWS_LAUNCHER_ABI_CURRENT)) {
        (void)LocalFree(argv);
        return launcher_failure(L"current-v1 requires an incompatible launcher ABI");
    }
    cbm_windows_launcher_action_t action = launcher_wide_action(argc, argv);
    if (!cbm_windows_launcher_action_allowed(action, managed)) {
        (void)LocalFree(argv);
        return launcher_failure(L"portable CBM cannot update or uninstall itself; run install "
                                L"first or use your package manager");
    }

    wchar_t payload[CBM_WINDOWS_LAUNCHER_PATH_CAP];
    bool path_valid =
        managed ? cbm_windows_generation_payload_path(canonical, state.payload_sha256, payload,
                                                      CBM_WINDOWS_LAUNCHER_PATH_CAP)
                : launcher_adjacent_payload(canonical, payload);
    HANDLE payload_file =
        path_valid ? launcher_open_regular(payload, GENERIC_READ, true) : INVALID_HANDLE_VALUE;
    LARGE_INTEGER payload_size;
    BY_HANDLE_FILE_INFORMATION payload_before;
    bool payload_valid = launcher_file_information(payload_file, &payload_before) &&
                         GetFileSizeEx(payload_file, &payload_size) && payload_size.QuadPart > 0 &&
                         (!managed || (uint64_t)payload_size.QuadPart == state.payload_size) &&
                         launcher_path_tree_plain(payload);
    if (!payload_valid) {
        if (payload_file != INVALID_HANDLE_VALUE)
            (void)CloseHandle(payload_file);
        (void)LocalFree(argv);
        return launcher_failure(L"selected payload is missing, unsafe, or has the wrong size");
    }
    HANDLE payload_recheck = launcher_open_regular(payload, GENERIC_READ, true);
    BY_HANDLE_FILE_INFORMATION payload_after;
    payload_valid = launcher_file_information(payload_recheck, &payload_after) &&
                    launcher_same_identity(&payload_before, &payload_after);
    if (payload_recheck != INVALID_HANDLE_VALUE)
        (void)CloseHandle(payload_recheck);
    (void)CloseHandle(payload_file);
    if (!payload_valid) {
        (void)LocalFree(argv);
        return launcher_failure(L"selected payload changed during validation");
    }

    bool private_activation = managed && action != CBM_WINDOWS_LAUNCHER_ACTION_ORDINARY;
    wchar_t private_payload[CBM_WINDOWS_LAUNCHER_PATH_CAP];
    const wchar_t *execution = payload;
    if (private_activation) {
        if (!launcher_private_payload_path(canonical, payload, private_payload)) {
            (void)LocalFree(argv);
            return launcher_failure(L"could not create a private activation payload");
        }
        execution = private_payload;
    }
    HANDLE parent = launcher_parent_liveness_open();
    if (!parent) {
        if (private_activation)
            (void)DeleteFileW(private_payload);
        (void)LocalFree(argv);
        return launcher_failure(L"could not establish immediate-parent liveness supervision");
    }
    int result = launcher_spawn_payload(execution, canonical, managed, private_activation, action,
                                        managed ? &state : NULL, parent, argc, argv);
    (void)CloseHandle(parent);
    if (private_activation)
        (void)DeleteFileW(private_payload);
    (void)LocalFree(argv);
    return result;
}

#endif /* _WIN32 */
