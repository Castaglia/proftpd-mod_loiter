/*
 * ProFTPD - mod_loiter shm
 * Copyright (c) 2014-2015 TJ Saunders
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

#ifndef MOD_LOITER_SHM_H
#define MOD_LOITER_SHM_H

#include "mod_loiter.h"

int loiter_shm_create(pool *p, const char *path);
int loiter_shm_destroy(pool *p);

#define LOITER_FIELD_ID_CONN_COUNT			1
#define LOITER_FIELD_ID_AUTHD_COUNT			2

int loiter_shm_get(pool *p, unsigned int *conn_count,
  unsigned int *authd_count);
int loiter_shm_incr(pool *p, int field_id, int incr);

#endif /* MOD_LOITER_SHM_H */
