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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include <glib.h>

#include "hal/linux_log.h"
#include "settings.h"
#include "manager.h"

#define CHANNEL_DEFAULT NRF24_CH_MIN

static GMainLoop *main_loop;

static void sig_term(int sig)
{
	g_main_loop_quit(main_loop);
}

int main(int argc, char *argv[])
{
	struct settings settings;
	int err, retval = 0;

	if (!settings_parse(argc, argv, &settings))
		return EXIT_FAILURE;

	signal(SIGTERM, sig_term);
	signal(SIGINT, sig_term);
	signal(SIGPIPE, SIG_IGN);

	main_loop = g_main_loop_new(NULL, FALSE);

	hal_log_init("nrfd", settings.detach);
	hal_log_info("KNOT HAL nrfd");

	if (settings.host)
		hal_log_error("Development mode: %s:%u", settings.host, settings.port);

	err = manager_start(settings.config_path, settings.host, settings.port,
							settings.spi, settings.channel, settings.dbm, settings.nodes_path);
	if (err < 0) {
		hal_log_error("manager_start(): %s(%d)", strerror(-err), -err);
		retval = EXIT_FAILURE;
		goto fail_manager_start;
	}

	/* Set user id to nobody */
	if (setuid(65534) != 0) {
		err = errno;
		hal_log_error("Set uid to nobody failed. %s(%d).", strerror(err), err);
		retval = EXIT_FAILURE;
		goto fail_setuid;
	}

	if (settings.detach) {
		if (daemon(0, 0)) {
			hal_log_error("Can't start daemon!");
			retval = EXIT_FAILURE;
			goto fail_detach;
		}
	}

	g_main_loop_run(main_loop);

fail_detach:
fail_setuid:
	manager_stop();

fail_manager_start:
	hal_log_error("exiting ...");
	hal_log_close();

	g_main_loop_unref(main_loop);

	return retval;
}
