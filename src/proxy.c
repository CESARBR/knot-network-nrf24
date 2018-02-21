/*
 * This file is part of the KNOT Project
 *
 * Copyright (c) 2018, CESAR. All rights reserved.
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdint.h>
#include <unistd.h>
#include <ell/ell.h>

#include "hal/linux_log.h"

#include "dbus.h"
#include "proxy.h"

#define KNOT_DBUS_SERVICE		"br.org.cesar.knot"

static unsigned int watch_id;

static void service_appeared(struct l_dbus *dbus, void *user_data)
{
	hal_log_info("Service appeared");
}

static void service_disappeared(struct l_dbus *dbus, void *user_data)
{
	hal_log_info("Service disappeared");
}

int proxy_start(void)
{
	watch_id = l_dbus_add_service_watch(dbus_get_bus(), KNOT_DBUS_SERVICE,
						service_appeared,
						service_disappeared,
						NULL, NULL);

	return 0;
}

void proxy_stop(void)
{
	l_dbus_remove_watch(dbus_get_bus(), watch_id);
}

int proxy_create(uint32_t id)
{
	return 0;
}

void proxy_remove(uint32_t id)
{
}