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
struct nrf24_device;

typedef void (*device_forget_cb_t) (struct nrf24_device *device,
					void *user_data);
int device_start(void);
void device_stop(void);

void device_get_address(const struct nrf24_device *device,
			struct nrf24_mac *addr);
const char *device_get_path(const struct nrf24_device *device);
bool device_is_paired(const struct nrf24_device *device);
void device_set_connected(struct nrf24_device *device, bool connected);
struct nrf24_device *device_create(const char *adapter_path,
				   const struct nrf24_mac *addr,
				   const char *id, const char *name, bool paired,
				   device_forget_cb_t forget_cb,
				   void *user_data);
uint32_t device_get_last_seen(struct nrf24_device *device);
void device_set_last_seen(struct nrf24_device *device, uint32_t time_seen);
void device_destroy(struct nrf24_device *device);
