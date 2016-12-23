/*
 * ProFTPD - mod_loiter
 * Copyright (c) 2014-2016 TJ Saunders
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
 *
 * -----DO NOT EDIT BELOW THIS LINE-----
 * $Archive: mod_loiter.a$
 */

#include "mod_loiter.h"
#include "shm.h"

#if PROFTPD_VERSION_NUMBER >= 0x0001030602
extern unsigned long ServerMaxInstances;
#else
extern int ServerMaxInstances;
#endif /* ProFTPD 1.3.6rc2 and earlier. */

extern pid_t mpid;

module loiter_module;
int loiter_logfd = -1;
pool *loiter_pool = NULL;

static int loiter_engine = FALSE;
static int loiter_has_authenticated = FALSE;
static const char *trace_channel = "loiter";

/* Default values for the low/high watermarks and rate. */
#define LOITER_RULES_DEFAULT_LOW	20
#define LOITER_RULES_DEFAULT_HIGH	100
#define LOITER_RULES_DEFAULT_RATE	30

static int loiter_openlog(void) {
  int res = 0;
  config_rec *c;

  c = find_config(main_server->conf, CONF_PARAM, "LoiterLog", FALSE);
  if (c) {
    char *path;

    path = c->argv[0];

    if (strncasecmp(path, "none", 5) != 0) {
      int xerrno;

      pr_signals_block();
      PRIVS_ROOT
      res = pr_log_openfile(path, &loiter_logfd, 0600);
      xerrno = errno;
      PRIVS_RELINQUISH
      pr_signals_unblock();

      if (res < 0) {
        if (res == -1) {
          pr_log_pri(PR_LOG_NOTICE, MOD_LOITER_VERSION
            ": notice: unable to open LoiterLog '%s': %s", path,
            strerror(xerrno));

        } else if (res == PR_LOG_WRITABLE_DIR) {
          pr_log_pri(PR_LOG_NOTICE, MOD_LOITER_VERSION
            ": notice: unable to open LoiterLog '%s': parent directory is "
            "world-writable", path);

        } else if (res == PR_LOG_SYMLINK) {
          pr_log_pri(PR_LOG_NOTICE, MOD_LOITER_VERSION
            ": notice: unable to open LoiterLog '%s': cannot log to a symlink",
            path);
        }
      }
    }
  }

  return res;
}

/* Returns TRUE if the connection should be dropped, FALSE otherwise.
 *
 * Query the database (shared memory segment) to find the count of connections,
 * and how many of those have authenticated; the difference gives us the
 * number of unauthenticated connections.  We want to keep that count from
 * getting too high; such loitering connections should be dropped.
 *
 * If the loiterering count is below the low watermark, we do nothing.  If
 * if it above the high watermark, we drop this connection.  If the configured
 * dropout rate is at 100%, we drop this connection.  Otherwise, the dropout
 * rate is calculated to linearly increase from the low to the high watermarks;
 * we roll the dice to see, then, whether the dropout rate should apply, and
 * thus drop this connection.
 */
static int loiter_drop_conn(unsigned int low, unsigned int high,
    unsigned int rate) {
  unsigned int authd_count = 0, conn_count = 0, unauthd_count = 0;
  unsigned int p, r;

  if (loiter_shm_get(loiter_pool, &conn_count, &authd_count) < 0) {
    (void) pr_log_writefile(loiter_logfd, MOD_LOITER_VERSION,
      "error getting connection counts: %s", strerror(errno));
    return FALSE;
  }

  /* Sanity check. */
  if (authd_count > conn_count) {
    (void) pr_log_writefile(loiter_logfd, MOD_LOITER_VERSION,
      "count of authenticated connections (%u) exceeds total connections (%u); "
      "mod_loiter bug?", authd_count, conn_count);
    return FALSE;
  }

  unauthd_count = conn_count - authd_count;

  if (unauthd_count < low) {
    pr_trace_msg(trace_channel, 5,
      "unauthenticated connection count (%u) < low watermark (%u)",
      unauthd_count, low);
    return FALSE;
  }

  if (unauthd_count >= high) {
    pr_trace_msg(trace_channel, 5,
      "unauthenticated connection count (%u) >= high watermark (%u)",
      unauthd_count, high);
    return TRUE;
  }

  if (rate == 100) {
    pr_trace_msg(trace_channel, 5, "drop connection rate (%u) == 100", rate);
    return TRUE;
  }

  p = 100 - rate;
  p *= unauthd_count - low;
  p /= high - low;
  p += rate;
#ifdef HAVE_RANDOM
  r = (unsigned int) ((1 + random()) / (RAND_MAX / 100) + 1);
#else
  r = (unsigned int) ((1 + rand()) / (RAND_MAX / 100) + 1);
#endif /* HAVE_RANDOM */

  pr_trace_msg(trace_channel, 4,
    "drop connection? probability %u, rate %u", p, r);
  return (r < p) ? TRUE : FALSE;
}

/* Command handlers
 */

MODRET loiter_post_pass(cmd_rec *cmd) {
  if (loiter_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  if (loiter_shm_incr(loiter_pool, LOITER_FIELD_ID_AUTHD_COUNT, 1) < 0) {
    (void) pr_log_writefile(loiter_logfd, MOD_LOITER_VERSION,
      "error incrementing authenticated connection count: %s", strerror(errno));

  } else {
    loiter_has_authenticated = TRUE;
  }

  return PR_DECLINED(cmd);
}

/* Configuration handlers
 */

/* usage: LoiterEngine on|off */
MODRET set_loiterengine(cmd_rec *cmd) {
  int engine = 1;
  config_rec *c;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  engine = get_boolean(cmd, 1);
  if (engine == -1) {
    CONF_ERROR(cmd, "expected Boolean parameter");
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = engine;

  return PR_HANDLED(cmd);
}

/* usage: LoiterLog path|"none" */
MODRET set_loiterlog(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  (void) add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  return PR_HANDLED(cmd);
}

/* usage: LoiterMessage msg */
MODRET set_loitermessage(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  (void) add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  return PR_HANDLED(cmd);
}

/* usage: LoiterRules [low ...] [high ...] [rate ...] */
MODRET set_loiterrules(cmd_rec *cmd) {
  register unsigned int i;
  config_rec *c;
  unsigned int low = LOITER_RULES_DEFAULT_LOW;
  unsigned int high = LOITER_RULES_DEFAULT_HIGH;
  unsigned int rate = LOITER_RULES_DEFAULT_RATE;

  if (cmd->argc < 3 ||
      ((cmd->argc-1) % 2) != 0) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  for (i = 1; i < cmd->argc; i++) {
    if (strcasecmp(cmd->argv[i], "low") == 0) {
      char *ptr = NULL;
      long v;

      v = strtol(cmd->argv[i+1], &ptr, 10);
      if (ptr && *ptr) {
        CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "invalid low watermark value: ",
          cmd->argv[i+1], NULL));
      }

      if (v < 1) {
        CONF_ERROR(cmd, "low watermark must be >= 1");
      }

      low = (unsigned int) v;
      i++;

    } else if (strcasecmp(cmd->argv[i], "high") == 0) {
      char *ptr = NULL;
      long v;

      v = strtol(cmd->argv[i+1], &ptr, 10);
      if (ptr && *ptr) {
        CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "invalid high watermark value: ",
          cmd->argv[i+1], NULL));
      }

      if (v < 1) {
        CONF_ERROR(cmd, "high watermark must be >= 1");
      }

      high = (unsigned int) v;
      i++;

    } else if (strcasecmp(cmd->argv[i], "rate") == 0) {
      char *ptr = NULL;
      long v;

      v = strtol(cmd->argv[i+1], &ptr, 10);
      if (ptr && *ptr) {
        CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "invalid rate value: ",
          cmd->argv[i+1], NULL));
      }

      if (v < 1 ||
          v > 100) {
        CONF_ERROR(cmd, "rate must be 1 <= r <= 100");
      }

      rate = (unsigned int) v;
      i++;

    } else {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unknown keyword: ", cmd->argv[i],
        NULL));
    }
  }

  c = add_config_param(cmd->argv[0], 3, NULL, NULL, NULL);
  c->argv[0] = palloc(c->pool, sizeof(unsigned int));
  *((unsigned int *) c->argv[0]) = low;
  c->argv[1] = palloc(c->pool, sizeof(unsigned int));
  *((unsigned int *) c->argv[1]) = high;
  c->argv[2] = palloc(c->pool, sizeof(unsigned int));
  *((unsigned int *) c->argv[2]) = rate;

  return PR_HANDLED(cmd);
}

/* usage: LoiterTable path */
MODRET set_loitertable(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  (void) add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  return PR_HANDLED(cmd);
}

/* Event listeners
 */

static void loiter_exit_ev(const void *event_data, void *user_data) {
  if (loiter_has_authenticated == TRUE) {
    if (loiter_shm_incr(loiter_pool, LOITER_FIELD_ID_AUTHD_COUNT, -1) < 0) {
      (void) pr_log_writefile(loiter_logfd, MOD_LOITER_VERSION,
        "error decrementing authenticated connection count: %s",
        strerror(errno));
    }
  }

  if (loiter_shm_incr(loiter_pool, LOITER_FIELD_ID_CONN_COUNT, -1) < 0) {
    (void) pr_log_writefile(loiter_logfd, MOD_LOITER_VERSION,
      "error decrementing connection count: %s", strerror(errno));
  }
}

#if defined(PR_SHARED_MODULE)
static void loiter_mod_unload_ev(const void *event_data, void *user_data) {
  if (strncmp((const char *) event_data, "mod_loiter.c", 13) == 0) {
    /* Unregister ourselves from all events. */
    pr_event_unregister(&loiter_module, NULL, NULL);

    (void) loiter_shm_destroy(loiter_pool);

    destroy_pool(loiter_pool);
    loiter_pool = NULL;
  }
}
#endif

static void loiter_restart_ev(const void *event_data, void *user_data) {
  /* Seed the random(3) generator. */ 
#ifdef HAVE_RANDOM
  srandom((unsigned int) (time(NULL) * getpid())); 
#else
  srand((unsigned int) (time(NULL) * getpid())); 
#endif /* HAVE_RANDOM */
}

static void loiter_startup_ev(const void *event_data, void *user_data) {
  config_rec *c;
  int engine = FALSE;

  c = find_config(main_server->conf, CONF_PARAM, "LoiterEngine", FALSE);
  if (c != NULL) {
    engine = *((int *) c->argv[0]);
  }

  if (engine == TRUE) {
    c = find_config(main_server->conf, CONF_PARAM, "LoiterTable", FALSE);
    if (c != NULL) {
      char *path;

      path = c->argv[0];

      if (loiter_shm_create(loiter_pool, path) < 0) {
        pr_log_pri(PR_LOG_NOTICE, MOD_LOITER_VERSION
          ": unable to create shared memory segment using '%s': %s", path,
          strerror(errno));
      }

    } else {
      pr_log_pri(PR_LOG_NOTICE, MOD_LOITER_VERSION
        ": missing required LoiterTable directive, module disabled");
    }
  }
}

static void loiter_shutdown_ev(const void *event_data, void *user_data) {
  /* Remove the shm from the system.  We can only do this reliably
   * when the standalone daemon process exits; if it's an inetd process,
   * there many be other proftpd processes still running.
   */

  if (getpid() == mpid &&
      ServerType == SERVER_STANDALONE) {
    (void) loiter_shm_destroy(loiter_pool);
  }
}

/* Initialization routines
 */

static int loiter_init(void) {
  loiter_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(loiter_pool, MOD_LOITER_VERSION);

#if defined(PR_SHARED_MODULE)
  pr_event_register(&loiter_module, "core.module-unload", loiter_mod_unload_ev,
    NULL);
#endif
  pr_event_register(&loiter_module, "core.restart", loiter_restart_ev, NULL);
  pr_event_register(&loiter_module, "core.startup", loiter_startup_ev, NULL);
  pr_event_register(&loiter_module, "core.shutdown", loiter_shutdown_ev, NULL);

  /* Seed the random(3) generator. */ 
#ifdef HAVE_RANDOM
  srandom((unsigned int) (time(NULL) * getpid())); 
#else
  srand((unsigned int) (time(NULL) * getpid())); 
#endif /* HAVE_RANDOM */

  return 0;
}

static int loiter_sess_init(void) {
  config_rec *c;
  unsigned int rules_low, rules_high, rules_rate;
  int adjusted_rules = FALSE;

  c = find_config(main_server->conf, CONF_PARAM, "LoiterEngine", FALSE);
  if (c) {
    loiter_engine = *((int *) c->argv[0]);
  }

  if (loiter_engine == FALSE) {
    return 0;
  }

  loiter_openlog();

  if (loiter_shm_incr(loiter_pool, LOITER_FIELD_ID_CONN_COUNT, 1) < 0) {
    (void) pr_log_writefile(loiter_logfd, MOD_LOITER_VERSION,
      "error incrementing connection count: %s", strerror(errno));
  }

  pr_event_register(&loiter_module, "core.exit", loiter_exit_ev, NULL);

  /* Reseed the random(3) generator. */ 
#ifdef HAVE_RANDOM
  srandom((unsigned int) (time(NULL) ^ getpid())); 
#else
  srand((unsigned int) (time(NULL) ^ getpid())); 
#endif /* HAVE_RANDOM */

  c = find_config(main_server->conf, CONF_PARAM, "LoiterRules", FALSE);
  if (c != NULL) {
    rules_low = *((unsigned int *) c->argv[0]);
    rules_high = *((unsigned int *) c->argv[1]);
    rules_rate = *((unsigned int *) c->argv[2]); 

  } else {
    rules_low = LOITER_RULES_DEFAULT_LOW;
    rules_high = LOITER_RULES_DEFAULT_HIGH;
    rules_rate = LOITER_RULES_DEFAULT_RATE;
  }

  if (ServerMaxInstances > 0 &&
      rules_high > ServerMaxInstances) {
    float ratio;

    /* Adjust for MaxInstances.
     *
     * if (rules_high > ServerMaxInstances)
     *   rules_high = ServerMaxInstances
     *
     * rules_low = %20 of rules_high
     */

    ratio = (float) rules_low / (float) rules_high;

    rules_high = ServerMaxInstances;
    rules_low = (unsigned int) (ratio * rules_high);

    adjusted_rules = TRUE;
  }

  if (c != NULL &&
      adjusted_rules == TRUE) {
    /* If rules were explicitly configured, AND adjusted for MaxInstances,
     * log the new/adjusted rules.
     */
    pr_trace_msg(trace_channel, 6,
      "adjusted rules for MaxInstances %d, now using "
      "'LoiterRules low %u high %u rate %u'", ServerMaxInstances,
      rules_low, rules_high, rules_rate);
  }

  if (loiter_drop_conn(rules_low, rules_high, rules_rate) == TRUE) {
    const char *msg = NULL;

    c = find_config(main_server->conf, CONF_PARAM, "LoiterMessage", FALSE);
    if (c != NULL) {
      msg = c->argv[0];
    }

    if (msg != NULL) {
      /* XXX Should we support %a, %c variables? */
      pr_response_send_async(R_530, "%s", msg);
    }

    (void) pr_log_writefile(loiter_logfd, MOD_LOITER_VERSION,
      "dropping connection");
    pr_log_pri(PR_LOG_NOTICE, MOD_LOITER_VERSION ": dropping connection");
    pr_session_disconnect(&loiter_module, PR_SESS_DISCONNECT_MODULE_ACL,
      "Too many loitering connections");
  }

  return 0;
}

/* Module API tables
 */

static conftable loiter_conftab[] = {
  { "LoiterEngine",	set_loiterengine,	NULL },
  { "LoiterLog",	set_loiterlog,		NULL },
  { "LoiterMessage",	set_loitermessage,	NULL },
  { "LoiterRules",	set_loiterrules,	NULL },
  { "LoiterTable",	set_loitertable,	NULL },
  { NULL }
};

static cmdtable loiter_cmdtab[] = {
  { POST_CMD,	C_PASS,	G_NONE,	loiter_post_pass,	FALSE,	FALSE },
  { 0, NULL }
};

module loiter_module = {
  /* Always NULL */
  NULL, NULL,

  /* Module API version */
  0x20,

  /* Module name */
  "loiter",

  /* Module configuration handler table */
  loiter_conftab,

  /* Module command handler table */
  loiter_cmdtab,

  /* Module authentication handler table */
  NULL,

  /* Module initialization */
  loiter_init,

  /* Session initialization */
  loiter_sess_init,

  /* Module version */
  MOD_LOITER_VERSION
};
