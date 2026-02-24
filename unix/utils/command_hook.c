/*
 * Unix implementation of command hook execution (synchronous with logging)
 */

#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <fcntl.h>

#include "putty.h"

void execute_command_hook(LogContext *logctx, const char *command_pattern,
                          SockAddr *addr, int port, Conf *conf)
{
    pid_t pid;
    int status;
    int stdout_pipe[2] = {-1, -1};
    int stderr_pipe[2] = {-1, -1};

    if (!command_pattern || !*command_pattern)
        return;

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

    /* Create pipes for capturing stdout and stderr */
    if (pipe(stdout_pipe) < 0 || pipe(stderr_pipe) < 0) {
        logeventf(logctx, "Pre-connect command: failed to create pipes: %s",
                  strerror(errno));
        if (stdout_pipe[0] >= 0) close(stdout_pipe[0]);
        if (stdout_pipe[1] >= 0) close(stdout_pipe[1]);
        if (stderr_pipe[0] >= 0) close(stderr_pipe[0]);
        if (stderr_pipe[1] >= 0) close(stderr_pipe[1]);
        return;
    }

    /* Log the command being executed */
    logeventf(logctx, "Running pre-connect command: %s", command);

    /* Fork and execute */
    pid = fork();
    if (pid == 0) {
        /* Child process */
        /* Close read ends of pipes */
        close(stdout_pipe[0]);
        close(stderr_pipe[0]);

        /* Redirect stdout and stderr */
        dup2(stdout_pipe[1], STDOUT_FILENO);
        dup2(stderr_pipe[1], STDERR_FILENO);
        close(stdout_pipe[1]);
        close(stderr_pipe[1]);

        /* Execute the command through shell */
        execl("/bin/sh", "sh", "-c", command, (char *)NULL);

        /* If execl fails, exit */
        _exit(127);
    } else if (pid > 0) {
        char buf[512];
        ssize_t n;
        bool has_output = false;

        /* Parent process - close write ends of pipes */
        close(stdout_pipe[1]);
        close(stderr_pipe[1]);
        stdout_pipe[1] = -1;
        stderr_pipe[1] = -1;

        /* Read and log stdout */
        while ((n = read(stdout_pipe[0], buf, sizeof(buf) - 1)) > 0) {
            buf[n] = '\0';
            if (!has_output) {
                logevent(logctx, "Pre-connect command:");
                has_output = true;
            }
            logevent(logctx, buf);
        }
        close(stdout_pipe[0]);

        /* Read and log stderr */
        has_output = false;
        while ((n = read(stderr_pipe[0], buf, sizeof(buf) - 1)) > 0) {
            buf[n] = '\0';
            if (!has_output) {
                logevent(logctx, "Pre-connect command stderr:");
                has_output = true;
            }
            logevent(logctx, buf);
        }
        close(stderr_pipe[0]);

        /* Wait for command to complete and log exit status */
        waitpid(pid, &status, 0);
        if (WIFEXITED(status)) {
            logeventf(logctx, "Pre-connect command exited with status %d",
                      WEXITSTATUS(status));
        } else if (WIFSIGNALED(status)) {
            logeventf(logctx, "Pre-connect command killed by signal %d",
                      WTERMSIG(status));
        } else {
            logevent(logctx, "Pre-connect command terminated abnormally");
        }
    } else {
        /* Fork failed */
        close(stdout_pipe[0]);
        close(stdout_pipe[1]);
        close(stderr_pipe[0]);
        close(stderr_pipe[1]);
        logeventf(logctx, "Pre-connect command: fork failed: %s",
                  strerror(errno));
    }

    sfree(command);
}
