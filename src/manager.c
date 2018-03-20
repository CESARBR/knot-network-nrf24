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

#include "hal/nrf24.h"
#include "hal/time.h"
#include "hal/linux_log.h"

#include "storage.h"
#include "adapter.h"
#include "dbus.h"
#include "manager.h"
#include "settings.h"

int manager_start(void)
{
	int cfg_channel = 76, cfg_dbm = 0;
	struct nrf24_mac mac = {.address.uint64 = 0};
	char *mac_str;

	mac_str = storage_read_key_string(settings.config_path, "Radio", "mac");
	if (mac_str != NULL)
		nrf24_str2mac(mac_str, &mac);
	else
		mac_str = l_new(char, 24);

	/* Command line arguments have higher priority */
	if (mac.address.uint64 == 0) {
		hal_getrandom(&mac, sizeof(mac));
		nrf24_mac2str(&mac, mac_str);
		storage_write_key_string(settings.config_path, "Radio", "mac",
					 mac_str);
	}

	l_free(mac_str);

	/*
	 * Priority order: 1) command line 2) config file.
	 * If the user does not provide channel at command line (or channel is
	 * invalid), switch to channel informed at config file. 76 is the
	 * default vale if channel in not informed in the config file.
	 */
	if (settings.channel < 0 || settings.channel > 125)
		settings.channel = cfg_channel;

	/*
	 * Use TX Power from configuration file if it has not been passed
	 * through cmd line. -255 means invalid: not informed by user.
	 */
	if (settings.dbm == -255)
		settings.dbm = cfg_dbm;

	dbus_start();

	/* TODO: Missing error handling */
	return adapter_start(&mac);
}

void manager_stop(void)
{
	adapter_stop();
	dbus_stop();
}
