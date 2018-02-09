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

#include <stdbool.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>

#include "hal/linux_log.h"
#include "hal/nrf24.h"

#include <ell/ell.h>

#include "dbus.h"
#include "device.h"

struct nrf24_device {
	struct nrf24_mac addr;
	char *name;
	char *path;
	bool paired;
	bool connected;
};

/* TODO: Missing set name */
static bool device_property_get_name(struct l_dbus *dbus,
				  struct l_dbus_message *msg,
				  struct l_dbus_message_builder *builder,
				  void *user_data)
{
	struct nrf24_device *device= user_data;

	l_dbus_message_builder_append_basic(builder, 's', device->name);
	hal_log_info("%s GetProperty(Name = %s)", device->path, device->name);

	return true;
}

static bool device_property_get_address(struct l_dbus *dbus,
				  struct l_dbus_message *msg,
				  struct l_dbus_message_builder *builder,
				  void *user_data)
{
	struct nrf24_device *device= user_data;
	char str[24];

	nrf24_mac2str(&device->addr, str);

	l_dbus_message_builder_append_basic(builder, 's', str);
	hal_log_info("%s GetProperty(Address = %s)", device->path, str);

	return true;
}

/* TODO: Missing connection tracking  */
static bool device_property_get_connected(struct l_dbus *dbus,
				     struct l_dbus_message *msg,
				     struct l_dbus_message_builder *builder,
				     void *user_data)
{
	struct nrf24_device *device= user_data;

	/* TODO: missing implementation */

	l_dbus_message_builder_append_basic(builder, 'b', &device->connected);
	hal_log_info("%s GetProperty(Powered = %d)",
		     device->path, device->connected);

	return true;
}

/* TODO: Missing to store the device when set_paired is called */

static bool device_property_get_paired(struct l_dbus *dbus,
				     struct l_dbus_message *msg,
				     struct l_dbus_message_builder *builder,
				     void *user_data)
{
	struct nrf24_device *device= user_data;

	l_dbus_message_builder_append_basic(builder, 'b', &device->paired);
	hal_log_info("%s GetProperty(Paired = %d)",
		     device->path, device->paired);

	return true;
}

static void device_setup_interface(struct l_dbus_interface *interface)
{
	if (!l_dbus_interface_property(interface, "Name", 0, "s",
				       device_property_get_name,
				       NULL))
		hal_log_error("Can't add 'Name' property");

	if (!l_dbus_interface_property(interface, "Address", 0, "s",
				       device_property_get_address,
				       NULL))
		hal_log_error("Can't add 'Address' property");

	if (!l_dbus_interface_property(interface, "Connected", 0, "b",
				       device_property_get_connected,
				       NULL))
		hal_log_error("Can't add 'Connected' property");

	if (!l_dbus_interface_property(interface, "Paired", 0, "b",
				       device_property_get_paired,
				       NULL))
		hal_log_error("Can't add 'Paired' property");
}

struct nrf24_device *device_create(const char *adapter_path,
				   const struct nrf24_mac *addr,
				   const char *name, bool paired)
{
	struct nrf24_device *device;
	char device_path[24 + strlen(adapter_path) + 1];
	char mac_str[24];
	int i, len;

	device = l_new(struct nrf24_device, 1);
	device->name = l_strdup(name);
	device->addr = *addr;
	device->paired = paired;
	device->connected = false;

	memset(mac_str, 0, sizeof(mac_str));

	strcpy(device_path, adapter_path);
	len = snprintf(device_path, sizeof(device_path), "%s/", adapter_path);

	nrf24_mac2str(addr, &device_path[len]);

	/* Replace ':' by '_' */
	for (i = len; i < (len + 24); i++) {
		if (device_path[i] == ':')
			device_path[i] = '_';
	}

	device->path = l_strdup(device_path);
	if (!l_dbus_object_add_interface(dbus_get_bus(),
					 device_path,
					 DEVICE_INTERFACE,
					 device))
	    hal_log_error("dbus: unable to add %s to %s",
			  DEVICE_INTERFACE, device_path);

	if (!l_dbus_object_add_interface(dbus_get_bus(),
					 device_path,
					 L_DBUS_INTERFACE_PROPERTIES,
					 device))
	    hal_log_error("dbus: unable to add %s to %s",
			  L_DBUS_INTERFACE_PROPERTIES, device_path);

	return device;
}

void device_destroy(struct nrf24_device *device)
{
	l_dbus_object_remove_interface(dbus_get_bus(),
				       device->path,
				       DEVICE_INTERFACE);
	l_dbus_object_remove_interface(dbus_get_bus(),
				       device->path,
				       L_DBUS_INTERFACE_PROPERTIES);
	l_free(device->name);
	l_free(device->path);
	l_free(device);
}

void device_get_address(const struct nrf24_device *device,
			struct nrf24_mac *addr)
{
	memcpy(addr, &device->addr, sizeof(*addr));
}

int device_start(void)
{
	/* nRF24 Device (device) object */
	if (!l_dbus_register_interface(dbus_get_bus(),
				       DEVICE_INTERFACE,
				       device_setup_interface,
				       NULL, false)) {
		hal_log_error("dbus: unable to register %s", DEVICE_INTERFACE);
		return -EINVAL;
	}

	return 0;
}

void device_stop(void)
{
	l_dbus_unregister_interface(dbus_get_bus(),
				    DEVICE_INTERFACE);
}
