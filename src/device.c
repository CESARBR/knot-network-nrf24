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
#include "storage.h"
#include "settings.h"

struct nrf24_device {
	struct nrf24_mac addr;
	int refs;
	uint32_t last_seen;
	uint64_t id;
	char *name;
	char *dpath;		/* Device object path */
	char *apath;		/* Adapter object path */
	bool paired;
	bool connected;
	device_forget_cb_t forget_cb;
	void *user_data;
	struct l_dbus_message *msg;
};

static void device_free(struct nrf24_device *device)
{
	if (device->msg)
		l_dbus_message_unref(device->msg);

	l_free(device->name);
	l_free(device->dpath);
	l_free(device->apath);
	l_free(device);
}

static struct nrf24_device *device_ref(struct nrf24_device *device)
{
	if (unlikely(!device))
		return NULL;

	__sync_fetch_and_add(&device->refs, 1);

	return device;
}

static void device_unref(struct nrf24_device *device)
{
	if (unlikely(!device))
		return;

	if (__sync_sub_and_fetch(&device->refs, 1))
		return;

	device_free(device);
}

static struct l_dbus_message *method_pair(struct l_dbus *dbus,
						struct l_dbus_message *msg,
						void *user_data)
{
	struct nrf24_device *device = user_data;
	char mac_str[24];

	if (device->paired)
		return dbus_error_already_exists(msg, "Already paired");

	if (device->msg)
		return dbus_error_busy(msg);

	device->msg = l_dbus_message_ref(msg);
	device->paired = true;

	l_dbus_property_changed(dbus_get_bus(), device->dpath,
				DEVICE_INTERFACE,"Paired");

	/* TODO: Pair() will be asynchronous ... */
	l_dbus_message_unref(device->msg);
	device->msg = NULL;

	if (nrf24_mac2str(&device->addr, mac_str) != 0)
		return dbus_error_invalid_args(msg);

	store_device(mac_str, device->id, device->name);

	return l_dbus_message_new_method_return(msg);
}

static struct l_dbus_message *method_forget(struct l_dbus *dbus,
						struct l_dbus_message *msg,
						void *user_data)
{
	struct nrf24_device *device = user_data;

	if (!device->paired)
		return dbus_error_not_available(msg);

	if (device->msg)
		return dbus_error_busy(msg);

	device->msg = l_dbus_message_ref(msg);
	device->paired = false;

	device->forget_cb(device, device->user_data);

	/* TODO: Forget() will be asynchronous ... */
	l_dbus_message_unref(device->msg);
	device->msg = NULL;

	return l_dbus_message_new_method_return(msg);
}

static struct l_dbus_message *property_set_name(struct l_dbus *dbus,
					 struct l_dbus_message *msg,
					 struct l_dbus_message_iter *new_value,
					 l_dbus_property_complete_cb_t complete,
					 void *user_data)
{
	struct nrf24_device *device = user_data;
	const char *name;
	char mac_str[24];

	if (!l_dbus_message_iter_get_variant(new_value, "s", &name))
		return dbus_error_invalid_args(msg);

	l_free(device->name);
	device->name = l_strdup(name);
	nrf24_mac2str(&device->addr, mac_str);
	storage_write_key_string(settings.nodes_path, mac_str, "Name", name);
	hal_log_info("%s SetProperty(Name = %s)", device->dpath, device->name);

	return l_dbus_message_new_method_return(msg);
}
static bool property_get_name(struct l_dbus *dbus,
				  struct l_dbus_message *msg,
				  struct l_dbus_message_builder *builder,
				  void *user_data)
{
	struct nrf24_device *device = user_data;

	l_dbus_message_builder_append_basic(builder, 's', device->name);
	hal_log_info("%s GetProperty(Name = %s)", device->dpath, device->name);

	return true;
}

static bool property_get_id(struct l_dbus *dbus,
				  struct l_dbus_message *msg,
				  struct l_dbus_message_builder *builder,
				  void *user_data)
{
	struct nrf24_device *device = user_data;

	l_dbus_message_builder_append_basic(builder, 't', &device->id);
	hal_log_info("%s GetProperty(Id = %"PRIu64")",
		     device->dpath, device->id);

	return true;
}

static bool property_get_adapter(struct l_dbus *dbus,
				  struct l_dbus_message *msg,
				  struct l_dbus_message_builder *builder,
				  void *user_data)
{
	struct nrf24_device *device = user_data;

	l_dbus_message_builder_append_basic(builder, 'o', device->apath);
	hal_log_info("%s GetProperty(Adapter = %s)",
		     device->dpath, device->apath);

	return true;
}

static bool property_get_address(struct l_dbus *dbus,
				  struct l_dbus_message *msg,
				  struct l_dbus_message_builder *builder,
				  void *user_data)
{
	struct nrf24_device *device = user_data;
	char str[24];

	nrf24_mac2str(&device->addr, str);

	l_dbus_message_builder_append_basic(builder, 's', str);
	hal_log_info("%s GetProperty(Address = %s)", device->dpath, str);

	return true;
}

static bool property_get_connected(struct l_dbus *dbus,
				     struct l_dbus_message *msg,
				     struct l_dbus_message_builder *builder,
				     void *user_data)
{
	struct nrf24_device *device = user_data;

	l_dbus_message_builder_append_basic(builder, 'b', &device->connected);
	hal_log_info("%s GetProperty(Powered = %d)",
		     device->dpath, device->connected);

	return true;
}

static bool property_get_paired(struct l_dbus *dbus,
				     struct l_dbus_message *msg,
				     struct l_dbus_message_builder *builder,
				     void *user_data)
{
	struct nrf24_device *device = user_data;

	l_dbus_message_builder_append_basic(builder, 'b', &device->paired);
	hal_log_info("%s GetProperty(Paired = %d)",
		     device->dpath, device->paired);

	return true;
}

static void device_setup_interface(struct l_dbus_interface *interface)
{
	l_dbus_interface_method(interface, "Pair", 0,
				method_pair, "", "", "");

	l_dbus_interface_method(interface, "Forget", 0,
				method_forget, "", "", "");

	if (!l_dbus_interface_property(interface, "Name", 0, "s",
				       property_get_name,
				       property_set_name))
		hal_log_error("Can't add 'Name' property");

	if (!l_dbus_interface_property(interface, "Id", 0, "t",
				       property_get_id,
				       NULL))
		hal_log_error("Can't add 'Id' property");

	if (!l_dbus_interface_property(interface, "Adapter", 0, "o",
				       property_get_adapter,
				       NULL))
		hal_log_error("Can't add 'Adapter' property");

	if (!l_dbus_interface_property(interface, "Address", 0, "s",
				       property_get_address,
				       NULL))
		hal_log_error("Can't add 'Address' property");

	if (!l_dbus_interface_property(interface, "Connected", 0, "b",
				       property_get_connected,
				       NULL))
		hal_log_error("Can't add 'Connected' property");

	if (!l_dbus_interface_property(interface, "Paired", 0, "b",
				       property_get_paired,
				       NULL))
		hal_log_error("Can't add 'Paired' property");
}

struct nrf24_device *device_create(const char *adapter_path,
				   const struct nrf24_mac *addr,
				   uint64_t id, const char *name, bool paired,
				   device_forget_cb_t forget_cb,
				   void *user_data)
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
	device->id = id;
	device->forget_cb = forget_cb;
	device->user_data = user_data;

	memset(mac_str, 0, sizeof(mac_str));

	strcpy(device_path, adapter_path);
	len = snprintf(device_path, sizeof(device_path), "%s/", adapter_path);

	nrf24_mac2str(addr, &device_path[len]);

	/* Replace ':' by '_' */
	for (i = len; i < (len + 24); i++) {
		if (device_path[i] == ':')
			device_path[i] = '_';
	}

	device->apath = l_strdup(adapter_path);
	device->dpath = l_strdup(device_path);

	if (!l_dbus_register_object(dbus_get_bus(),
				    device_path,
				    device_ref(device),
				    (l_dbus_destroy_func_t) device_unref,
				    DEVICE_INTERFACE, device,
				    L_DBUS_INTERFACE_PROPERTIES, device,
				    NULL))
		goto dev_reg_fail;

	return device_ref(device);

dev_reg_fail:
	device_free(device);

	return NULL;
}

void device_destroy(struct nrf24_device *device)
{
	l_dbus_unregister_object(dbus_get_bus(), device->dpath);

	device_unref(device);
}

void device_get_address(const struct nrf24_device *device,
			struct nrf24_mac *addr)
{
	memcpy(addr, &device->addr, sizeof(*addr));
}

const char *device_get_path(const struct nrf24_device *device)
{
	return device->dpath;
}

bool device_is_paired(const struct nrf24_device *device)
{
	return device->paired;
}

void device_set_connected(struct nrf24_device *device, bool connected)
{
	if (device->connected == connected)
		return;

	device->connected = connected;
	l_dbus_property_changed(dbus_get_bus(), device->dpath,
				DEVICE_INTERFACE,"Connected");
}

uint32_t device_get_last_seen(struct nrf24_device *device)
{
	return device->last_seen;
}

void device_set_last_seen(struct nrf24_device *device, uint32_t time_seen)
{
	device->last_seen = time_seen;
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
