/*
 * ProFTPD - mod_loiter shm
 * Copyright (c) 2014 TJ Saunders
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

#include "mod_loiter.h"
#include "shm.h"

#include <sys/ipc.h>
#include <sys/shm.h>

#define LOITER_SHM_PROJ_ID		4582

struct loiter_shm_data {
  /* Connection count. */
  unsigned int conn_count;

  /* Count of authenticated connections. */
  unsigned int authd_count;

  /* Track number of ejected connections. */
  unsigned int nejects;
};

static struct loiter_shm_data *loiter_data = NULL;
static size_t loiter_datasz = 0;
static int loiter_shmid = -1;
static pr_fh_t *loiter_datafh = NULL;

static const char *get_lock_desc(int lock_type) {
  const char *lock_desc;

  switch (lock_type) {
    case F_RDLCK:
      lock_desc = "read-lock";
      break;

    case F_WRLCK:
      lock_desc = "write-lock";
      break;

    case F_UNLCK:
      lock_desc = "unlock";
      break;

    default:
      lock_desc = "<unknown>";
  }

  return lock_desc;
}

static int lock_shm(int lock_type) {
  const char *lock_desc;
  int fd;
  struct flock lock;
  unsigned int nattempts = 1;

  lock.l_type = lock_type;
  lock.l_whence = SEEK_SET;
  lock.l_start = 0;
  lock.l_len = 0;

  fd = PR_FH_FD(loiter_datafh);
  lock_desc = get_lock_desc(lock_type);

  pr_trace_msg(loiter_channel, 9, "attempting to %s shm fd %d", lock_desc, fd);

  while (fcntl(fd, F_SETLK, &lock) < 0) {
    int xerrno = errno;

    if (xerrno == EINTR) {
      pr_signals_handle();
      continue;
    }

    pr_trace_msg(loiter_channel, 3, "%s of shm fd %d failed: %s",
      lock_desc, fd, strerror(xerrno));
    if (xerrno == EACCES) {
      struct flock locker;

      /* Get the PID of the process blocking this lock. */
      if (fcntl(fd, F_GETLK, &locker) == 0) {
        pr_trace_msg(loiter_channel, 3, "process ID %lu has blocking %s on "
          "shm fd %d", (unsigned long) locker.l_pid,
          get_lock_desc(locker.l_type), fd);
      }

      /* Treat this as an interrupted call, call pr_signals_handle() (which
       * will delay for a few msecs because of EINTR), and try again.
       * After 10 attempts, give up altogether.
       */

      nattempts++;
      if (nattempts <= 10) {
        errno = EINTR;

        pr_signals_handle();
        continue;
      }

      errno = xerrno;
      return -1;
    }

    errno = xerrno;
    return -1;
  }

  pr_trace_msg(loiter_channel, 9, "%s of shm fd %d succeeded", lock_desc, fd);
  return 0;
}

static struct loiter_shm_data *create_shm(pr_fh_t *fh) {
  int rem, shmid, xerrno = 0;
  int shm_existed = FALSE;
  struct loiter_shm_data *data = NULL;
  size_t shm_size;
  key_t key;

  shm_size = sizeof(struct loiter_shm_data);
  rem = shm_size % SHMLBA;
  if (rem != 0) {
    shm_size = (shm_size - rem + SHMLBA);
    pr_trace_msg(loiter_channel, 9,
      "rounded requested size up to %lu bytes", (unsigned long) shm_size);
  }

  key = ftok(fh->fh_path, LOITER_SHM_PROJ_ID);
  if (key == (key_t) -1) {
    xerrno = errno;

    pr_trace_msg(trace_channel, 1,
      "unable to get key for path '%s': %s", fh->fh_path, strerror(xerrno));

    errno = xerrno;
    return NULL;
  }

  /* Try first using IPC_CREAT|IPC_EXCL, to check if there is an existing
   * shm for this key.  If so, use a flags value of zero.
   *
   * We use root privs for this, to make sure that the shm can only be
   * access by a process with root privs.  This is equivalent to having
   * a root-owned file in the filesystem.
   */

  PRIVS_ROOT
  shmid = shmget(key, shm_size, IPC_CREAT|IPC_EXCL|0600);
  xerrno = errno;
  PRIVS_RELINQUISH

  if (shmid < 0) {
    if (xerrno == EEXIST) {
      shm_existed = TRUE;

      PRIVS_ROOT
      shmid = shmget(key, 0, 0);
      xerrno = errno;
      PRIVS_RELINQUISH

      if (shmid < 0) {
        pr_trace_msg(loiter_channel, 1,
          "unable to get shm for existing key: %s", strerror(xerrno));
        errno = xerrno;
        return NULL;
      }

    } else {
      /* Try to provide more helpful/informative log messages. */
      if (xerrno == ENOMEM) {
        pr_trace_msg(loiter_channel, 1,
          "not enough memory for %lu shm bytes; try specifying a smaller size",
          (unsigned long) shm_size);

      } else if (xerrno == ENOSPC) {
        pr_trace_msg(loiter_channel, 1, "%s",
          "unable to allocate a new shm ID; system limit of shm IDs reached");
      }

      errno = xerrno;
      return NULL;
    }
  }

  /* Attach to the shm. */
  pr_trace_msg(loiter_channel, 10, "attempting to attach to shm ID %d", shmid);

  PRIVS_ROOT
  data = (struct loiter_shm_data *) shmat(shmid, NULL, 0);
  xerrno = errno;
  PRIVS_RELINQUISH

  if (data == NULL) {
    pr_trace_msg(loiter_channel, 1,
      "unable to attach to shm ID %d: %s", shmid, strerror(xerrno));
    errno = xerrno;
    return NULL;
  }

  if (shm_existed) {
    struct shmid_ds ds;
    int res;

    /* If we already have a shmid, check for size differences. */

    PRIVS_ROOT
    res = shmctl(shmid, IPC_STAT, &ds);
    xerrno = errno;
    PRIVS_RELINQUISH

    if (res == 0) {
      pr_trace_msg(loiter_channel, 10,
        "existing shm size: %u bytes", (unsigned int) ds.shm_segsz);

      if (ds.shm_segsz != shm_size) {
        if (ds.shm_segsz > shm_size) {
          pr_log_pri(PR_LOG_NOTICE, MOD_LOITER_VERSION
            ": requested shm size (%lu bytes) is smaller than existing shm "
            "size, migrating to smaller shm (may result in loss of data)",
            (unsigned long) shm_size);

        } else if (ds.shm_segsz < shm_size) {
          pr_log_pri(PR_LOG_NOTICE, MOD_LOITER_VERSION
            ": requested shm size (%lu bytes) is larger than existing shm "
            "size, migrating to larger shm", (unsigned long) shm_size);
        }

        /* For now, though, we complain about this, and tell the admin to
         * manually remove shm.
         */

        pr_log_pri(PR_LOG_NOTICE, MOD_LOITER_VERSION
          ": remove existing shm using 'ftpdctl loiter shm remove' "
          "before using new size");

        shmcache_close(NULL);

        errno = EINVAL;
        return NULL;
      }

    } else {
      pr_trace_msg(loiter_channel, 1,
        "unable to stat shm ID %d: %s", shmid, strerror(xerrno));
      errno = xerrno;
    }

  } else {
    /* Make sure the memory is initialized. */
    if (lock_shm(F_WRLCK) < 0) {
      pr_trace_msg(loiter_channel, 1,
        "error write-locking shm: %s", strerror(errno));
    }

    memset(data, 0, shm_size);

    if (lock_shm(F_UNLCK) < 0) {
      pr_trace_msg(loiter_channel, 1,
        "error unlocking shm: %s", strerror(errno));
    }
  }

  loiter_datasz = shm_size;
  loiter_shmid = shmid;
  pr_trace_msg(loiter_channel, 9,
    "using shm ID %d for shm path '%s'", loiter_shmid, fh->fh_path);

  return data;
}

int loiter_shm_create(pool *p, const char *path) {
  int xerrno;

  if (p == NULL ||
      path == NULL) {
    errno = EINVAL;
    return -1;
  }

  PRIVS_ROOT
  loiter_datafh = pr_fsio_open(path, O_RDWR|O_CREAT);
  xerrno = errno;
  PRIVS_RELINQUISH

  if (loiter_datafh == NULL) {
    pr_log_debug(DEBUG1, MOD_LOITER_VERSION,
      ": error: unable to open file '%s': %s", path, strerror(xerrno));

    errno = EINVAL;
    return -1;
  }

  if (pr_fsio_fstat(loiter_datafh, &st) < 0) {
    xerrno = errno;

    pr_log_debug(DEBUG1, MOD_LOITER_VERSION
      ": error: unable to stat file '%s': %s", path, strerror(xerrno));

    pr_fsio_close(loiter_datafh);
    loiter_datafh = NULL;

    errno = EINVAL;
    return -1;
  }

  if (S_ISDIR(st.st_mode)) {
    xerrno = EISDIR;

    pr_log_debug(DEBUG1, MOD_LOITER_VERSION
      ": error: unable to use file '%s': %s", path, strerror(xerrno));

    pr_fsio_close(loiter_datafh);
    loiter_datafh = NULL;

    errno = EINVAL;
    return -1;
  }

  /* Make sure that we don't inadvertently get one of the Big Three file
   * descriptors (stdin/stdout/stderr), as can happen especially if the
   * server has restarted.
   */
  fd = PR_FH_FD(loiter_datafh);
  (void) pr_fs_get_usable_fd2(&fd);

  pr_trace_msg(loiter_channel, 9,
    "requested shme file: %s (fd %d)", loiter_datafh->fh_path, fd);

  loiter_data = create_shm(loiter_datafh);
  if (loiter_data == NULL) {
    xerrno = errno;

    pr_trace_msg(trace_channel, 1,
      "unable to allocate shm: %s", strerror(xerrno));
    pr_log_debug(DEBUG1, MOD_LOITER_VERSION
      ": unable to allocate shm: %s", strerror(xerrno));

    pr_fsio_close(loiter_datafh);
    loiter_datafh = NULL;

    errno = EINVAL;
    return -1;
  }

  return 0;
}

int loiter_shm_destroy(pool *p) {
  if (loiter_shmid >= 0) {
    int res, xerrno = 0;

    PRIVS_ROOT
#if !defined(_POSIX_SOURCE)
    res = shmdt((char *) loiter_data);
#else
    res = shmdt((const char *) loiter_data);
#endif
    xerrno = errno;
    PRIVS_RELINQUISH

    if (res < 0) {
      pr_log_debug(DEBUG1, MOD_LOITER_VERSION
        ": error detaching shm ID %d: %s", loiter_shmid, strerror(xerrno));
    }

    loiter_data = NULL;
  }

  pr_fsio_close(loiter_datafh);
  loiter_datafh = NULL;
  return 0;
}

int loiter_shm_get(pool *p, unsigned int *conn_count,
    unsigned int *authd_count) {
  if (p == NULL ||
      (conn_count == NULL && authd_count == NULL)) {
    errno = EINVAL;
    return -1;
  }

  if (lock_shm(F_WRLCK) < 0) {
    pr_trace_msg(loiter_channel, 1,
      "error write-locking shm: %s", strerror(errno));
  }

  if (conn_count != NULL) {
    *conn_count = loiter_data->conn_count;
  }

  if (authd_count != NULL) {
    *authd_count = loiter_data->authd_count;
  }

  if (lock_shm(F_UNLCK) < 0) {
    pr_trace_msg(loiter_channel, 1,
      "error unlocking shm: %s", strerror(errno));
  }

  return 0;
}

int loiter_shm_incr(pool *p, int field_id, int incr) {
  if (p == NULL) {
    errno = EINVAL;
    return -1;
  }

  switch (field_id) {
    case LOITER_FIELD_ID_CONN_COUNT:
    case LOITER_FIELD_ID_AUTHD_COUNT:
      break;

    default:
      errno = EINVAL;
      return -1;
  }

  /* If given an increment of zero for any reason, do nothing. */
  if (incr == 0) {
    return 0;
  }

  if (lock_shm(F_WRLCK) < 0) {
    pr_trace_msg(loiter_channel, 1,
      "error write-locking shm: %s", strerror(errno));
  }

  switch (field_id) {
    case LOITER_FIELD_ID_CONN_COUNT:
      if (incr > loiter_data->conn_count) {
        loiter_data->conn_count = 0;
      } else {
        loiter_data->conn_count += incr;
      }
      break;

    case LOITER_FIELD_ID_AUTHD_COUNT:
      if (incr > loiter_data->conn_count) {
        loiter_data->authd_count = 0;
      } else {
        loiter_data->authd_count += incr;
      }
      break;
  }

  if (lock_shm(F_UNLCK) < 0) {
    pr_trace_msg(loiter_channel, 1,
      "error unlocking shm: %s", strerror(errno));
  }

  return 0;
}
