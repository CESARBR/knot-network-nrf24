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

#include <errno.h>
#include <stdint.h>
#include <unistd.h>
#include <ell/ell.h>

#include "hal/linux_log.h"

#include "dbus.h"
#include "proxy.h"

#define KNOT_DBUS_SERVICE		"br.org.cesar.knot"
#define KNOT_DBUS_DEVICE		"br.org.cesar.knot.Device1"

static unsigned int watch_id;
static struct l_dbus_client *client;
static proxy_removed_func_t removed_cb;

static void service_appeared(struct l_dbus *dbus, void *user_data)
{
	hal_log_info("Service appeared");
}

static void service_disappeared(struct l_dbus *dbus, void *user_data)
{
	hal_log_info("Service disappeared");
}

static void added(struct l_dbus_proxy *proxy, void *user_data)
{
	const char *interface = l_dbus_proxy_get_interface(proxy);
	const char *path = l_dbus_proxy_get_path(proxy);

	if (strcmp(KNOT_DBUS_DEVICE, interface) != 0)
		return;

	/* Debug purpose only */
	hal_log_info("proxy added: %s %s", path, interface);
}

static void removed(struct l_dbus_proxy *proxy, void *user_data)
{
	const char *interface = l_dbus_proxy_get_interface(proxy);
	const char *path = l_dbus_proxy_get_path(proxy);

	if (strcmp(KNOT_DBUS_DEVICE, interface) != 0)
		return;

	/* Debug purpose only */
	hal_log_info("proxy removed: %s %s", path, interface);
}

static void property_changed(struct l_dbus_proxy *proxy, const char *name,
				struct l_dbus_message *msg, void *user_data)
{
	uint64_t id;
	bool paired;

	/* Track all devices based on Id property */

	l_info("property changed: %s (%s %s)", name,
					l_dbus_proxy_get_path(proxy),
					l_dbus_proxy_get_interface(proxy));
	if (strcmp(name, "Pair"))
		return;

	if (!l_dbus_proxy_get_property(proxy, "Id", "t", &id))
		return;

	if (!l_dbus_message_get_arguments(msg, "b", &paired))
		return;

	if (paired != false)
		return;

	hal_log_info("   Id: %"PRIu64 " Paired:%d", id, paired);
	removed_cb(id);
}

int proxy_start(proxy_removed_func_t func)
{

	if (!func)
		return -EINVAL;

	removed_cb = func;

	watch_id = l_dbus_add_service_watch(dbus_get_bus(), KNOT_DBUS_SERVICE,
						service_appeared,
						service_disappeared,
						NULL, NULL);

	client = l_dbus_client_new(dbus_get_bus(), KNOT_DBUS_SERVICE, "/");
	l_dbus_client_set_proxy_handlers(client, added,
					 removed, property_changed, NULL, NULL);

	return 0;
}

void proxy_stop(void)
{
	l_dbus_client_destroy(client);
	l_dbus_remove_watch(dbus_get_bus(), watch_id);
}

