/*
 * ProFTPD - mod_loiter API testsuite
 * Copyright (c) 2016-2021 TJ Saunders <tj@castaglia.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Suite 500, Boston, MA 02110-1335, USA.
 *
 * As a special exemption, TJ Saunders and other respective copyright holders
 * give permission to link this program with OpenSSL, and distribute the
 * resulting executable, without including the source code for OpenSSL in the
 * source distribution.
 */

#include "tests.h"

/* Stubs */

session_t session;
int ServerUseReverseDNS = FALSE;
server_rec *main_server = NULL;
pid_t mpid = 1;
unsigned char is_master = TRUE;
volatile unsigned int recvd_signal_flags = 0;
module *static_modules[] = { NULL };
module *loaded_modules = NULL;
xaset_t *server_list = NULL;

int loiter_logfd = -1;
module loiter_module;
pool *loiter_pool = NULL;

static cmd_rec *next_cmd = NULL;

int login_check_limits(xaset_t *set, int recurse, int and, int *found) {
  return TRUE;
}

int xferlog_open(const char *path) {
  return 0;
}

int pr_cmd_read(cmd_rec **cmd) {
  if (next_cmd != NULL) {
    *cmd = next_cmd;
    next_cmd = NULL;

  } else {
    errno = ENOENT;
    *cmd = NULL;
  }

  return 0;
}

int pr_config_get_server_xfer_bufsz(int direction) {
  int bufsz = -1;

  switch (direction) {
    case PR_NETIO_IO_RD:
      bufsz = PR_TUNABLE_DEFAULT_RCVBUFSZ;
      break;

    case PR_NETIO_IO_WR:
      bufsz = PR_TUNABLE_DEFAULT_SNDBUFSZ;
      break;

    default:
      errno = EINVAL;
      return -1;
  }

  return bufsz;
}

void pr_log_auth(int priority, const char *fmt, ...) {
  if (getenv("TEST_VERBOSE") != NULL) {
    va_list msg;

    fprintf(stderr, "AUTH: ");

    va_start(msg, fmt);
    vfprintf(stderr, fmt, msg);
    va_end(msg);

    fprintf(stderr, "\n");
  }
}

void pr_log_debug(int level, const char *fmt, ...) {
  if (getenv("TEST_VERBOSE") != NULL) {
    va_list msg;

    fprintf(stderr, "DEBUG%d: ", level);

    va_start(msg, fmt);
    vfprintf(stderr, fmt, msg);
    va_end(msg);

    fprintf(stderr, "\n");
  }
}

int pr_log_event_generate(unsigned int log_type, int log_fd, int log_level,
    const char *log_msg, size_t log_msglen) {
  errno = ENOSYS;
  return -1;
}

int pr_log_event_listening(unsigned int log_type) {
  return FALSE;
}

int pr_log_openfile(const char *log_file, int *log_fd, mode_t log_mode) {
  int res;
  struct stat st;

  if (log_file == NULL ||
      log_fd == NULL) {
    errno = EINVAL;
    return -1;
  }

  res = stat(log_file, &st);
  if (res < 0) {
    if (errno != ENOENT) {
      return -1;
    }

  } else {
    if (S_ISDIR(st.st_mode)) {
      errno = EISDIR;
      return -1;
    }
  }

  *log_fd = STDERR_FILENO;
  return 0;
}

void pr_log_pri(int prio, const char *fmt, ...) {
  if (getenv("TEST_VERBOSE") != NULL) {
    va_list msg;

    fprintf(stderr, "PRI%d: ", prio);

    va_start(msg, fmt);
    vfprintf(stderr, fmt, msg);
    va_end(msg);

    fprintf(stderr, "\n");
  }
}

void pr_log_stacktrace(int fd, const char *name) {
}

int pr_log_writefile(int fd, const char *name, const char *fmt, ...) {
  int res;
  va_list msg;

  va_start(msg, fmt);
  res = pr_log_vwritefile(fd, name, fmt, msg);
  va_end(msg);

  return res;
}

int pr_log_vwritefile(int fd, const char *name, const char *fmt, va_list msg) {
  if (getenv("TEST_VERBOSE") != NULL) {
    fprintf(stderr, "%s: ", name);
    vfprintf(stderr, fmt, msg);
    fprintf(stderr, "\n");
  }

  return 0;
}

int pr_scoreboard_entry_update(pid_t pid, ...) {
  return 0;
}

void pr_session_disconnect(module *m, int reason_code, const char *details) {
}

const char *pr_session_get_protocol(int flags) {
  return "ftp";
}

void pr_signals_handle(void) {
}

/* Module-specific stubs */
