/*
 * Windows implementation of command hook execution (synchronous with logging)
 */

#include <string.h>

#include "putty.h"

static void read_and_log_pipe(HANDLE pipe, LogContext *logctx, const char *label)
{
    char buf[512];
    DWORD bytesRead;
    bool has_output = false;

    while (ReadFile(pipe, buf, sizeof(buf) - 1, &bytesRead, NULL) && bytesRead > 0) {
        buf[bytesRead] = '\0';
        if (!has_output) {
            logeventf(logctx, "Pre-connect command %s:", label);
            has_output = true;
        }
        logevent(logctx, buf);
    }
}

void execute_command_hook(LogContext *logctx, const char *command_pattern,
                          SockAddr *addr, int port, Conf *conf)
{
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    BOOL result;
    HANDLE stdout_read = INVALID_HANDLE_VALUE;
    HANDLE stdout_write = INVALID_HANDLE_VALUE;
    HANDLE stderr_read = INVALID_HANDLE_VALUE;
    HANDLE stderr_write = INVALID_HANDLE_VALUE;
    SECURITY_ATTRIBUTES sa;
    DWORD exit_code = 0;

    if (!command_pattern || !*command_pattern)
        return;

    /* Format the hook command, but first, make sure %user and %pass
     * aren't expanded. (Those will refer to the _proxy_ username and
     * password.) */
    Conf *tmpconf = conf_copy(conf);
    conf_set_str(conf, CONF_proxy_username, "");
    conf_set_str(conf, CONF_proxy_password, "");
    unsigned flags;
    char *command = format_connection_setup_command(
        command_pattern, addr, port, tmpconf, &flags);
    if (flags & (TELNET_CMD_MISSING_USERNAME |
                 TELNET_CMD_MISSING_PASSWORD)) {
        logeventf(logctx, "Pre-connect command: references to %%user or "
                  "%%pass not supported");
        sfree(command);
        return;
    }
    conf_free(tmpconf);

    /* Set up security attributes for pipes */
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;

    /* Create pipes for capturing stdout and stderr */
    if (!CreatePipe(&stdout_read, &stdout_write, &sa, 0) ||
        !CreatePipe(&stderr_read, &stderr_write, &sa, 0)) {
        DWORD error = GetLastError();
        if (stdout_read != INVALID_HANDLE_VALUE) CloseHandle(stdout_read);
        if (stdout_write != INVALID_HANDLE_VALUE) CloseHandle(stdout_write);
        if (stderr_read != INVALID_HANDLE_VALUE) CloseHandle(stderr_read);
        if (stderr_write != INVALID_HANDLE_VALUE) CloseHandle(stderr_write);
        logeventf(logctx, "Pre-connect command: failed to create pipes: %s",
                  win_strerror(error));
        return;
    }

    /* Prepare startup info */
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.hStdOutput = stdout_write;
    si.hStdError = stderr_write;
    si.dwFlags |= STARTF_USESTDHANDLES;
    ZeroMemory(&pi, sizeof(pi));

    /* Log the command being executed */
    logeventf(logctx, "Running pre-connect command: %s", command);

    /* Execute the command through cmd.exe */
    result = CreateProcess(
        NULL,           /* No module name (use command line) */
        (char *)command,/* Command line (cast away const for Win32 API) */
        NULL,           /* Process handle not inheritable */
        NULL,           /* Thread handle not inheritable */
        TRUE,           /* Set handle inheritance to TRUE */
        0,              /* No creation flags */
        NULL,           /* Use parent's environment block */
        NULL,           /* Use parent's starting directory */
        &si,            /* Pointer to STARTUPINFO structure */
        &pi             /* Pointer to PROCESS_INFORMATION structure */
    );

    if (result) {
        /* Close the write ends of pipes in parent */
        CloseHandle(stdout_write);
        CloseHandle(stderr_write);
        stdout_write = INVALID_HANDLE_VALUE;
        stderr_write = INVALID_HANDLE_VALUE;

        /* Read and log stdout */
        read_and_log_pipe(stdout_read, logctx, "stdout");
        CloseHandle(stdout_read);
        stdout_read = INVALID_HANDLE_VALUE;

        /* Read and log stderr */
        read_and_log_pipe(stderr_read, logctx, "stderr");
        CloseHandle(stderr_read);
        stderr_read = INVALID_HANDLE_VALUE;

        /* Wait for command to complete */
        WaitForSingleObject(pi.hProcess, INFINITE);

        /* Get exit code */
        GetExitCodeProcess(pi.hProcess, &exit_code);
        logeventf(logctx, "Pre-connect command exited with status %lu",
                  exit_code);

        /* Close process and thread handles */
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    } else {
        /* CreateProcess failed */
        DWORD error = GetLastError();
        CloseHandle(stdout_read);
        CloseHandle(stdout_write);
        CloseHandle(stderr_read);
        CloseHandle(stderr_write);
        logeventf(logctx, "Pre-connect command: CreateProcess failed: %s",
                  win_strerror(error));
    }
}
