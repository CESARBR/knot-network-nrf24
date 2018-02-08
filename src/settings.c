/*
 * Copyright (c) 2018, CESAR.
 * All rights reserved.
 *
 * This software may be modified and distributed under the terms
 * of the BSD license. See the LICENSE file for details.
 *
 */

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <getopt.h>

#include "settings.h"

static const char *config_path = "/etc/knot/gatewayConfig.json";
static const char *nodes_path = "/etc/knot/keys.json";
static const char *host = NULL;
static unsigned int port = 8081;
static const char *spi = "/dev/spidev0.0";
static int channel = -1;
static int dbm = -255;
static bool detach = true;
static bool ell = false;
static bool help = false;

static void usage(void)
{
	printf("nrfd - nRF24l01 daemon\n"
		"Usage:\n");
	printf("\tnrfd [options]\n");
	printf("Options:\n"
		"\t-e, --ell          Use ELL instead of glib\n"
		"\t-c, --config       Configuration file path\n"
		"\t-f, --nodes        Known nodes file path\n"
		"\t-h, --host         Host to forward KNoT\n"
		"\t-p, --port         Remote port\n"
		"\t-s, --spi          SPI device path\n"
		"\t-C, --channel      Broadcast channel\n"
		"\t-t, --tx           TX power: transmition signal strength in dBm\n"
		"\t-n, --nodetach     Logging in foreground\n"
		"\t-H, --help         Show help options\n");
}

static const struct option main_options[] = {
	{ "ell",		no_argument,		NULL, 'e' },
	{ "config",		required_argument,	NULL, 'c' },
	{ "nodes",		required_argument,	NULL, 'f' },
	{ "host",		required_argument,	NULL, 'h' },
	{ "port",		required_argument,	NULL, 'p' },
	{ "spi",		required_argument,	NULL, 's' },
	{ "channel",		required_argument,	NULL, 'C' },
	{ "tx",			required_argument,	NULL, 't' },
	{ "nodetach",		no_argument,		NULL, 'n' },
	{ "help",		no_argument,		NULL, 'H' },
	{ }
};


static int parse_args(int argc, char *argv[], struct settings *settings)
{
	int ret = EXIT_FAILURE;
	int opt;

	for (;;) {
		opt = getopt_long(argc, argv, "ec:f:h:p:s:C:t:nH", main_options, NULL);
		if (opt < 0)
			break;

		switch (opt) {
		case 'e':
			settings->ell = true;
			break;
		case 'c':
			settings->config_path = optarg;
			break;
		case 'f':
			settings->nodes_path = optarg;
			break;
		case 'h':
			settings->host = optarg;
			break;
		case 'p':
			settings->port = atoi(optarg);
			break;
		case 'i':
			settings->spi = optarg;
			break;
		case 'C':
			settings->channel = atoi(optarg);
			break;
		case 't':
			settings->dbm = atoi(optarg);
			break;
		case 'n':
			settings->detach = false;
			break;
		case 'H':
			usage();
			settings->help = true;
			return EXIT_SUCCESS;
		default:
			return EXIT_FAILURE;
		}
	}

	if (argc - optind > 0) {
		fprintf(stderr, "Invalid command line parameters\n");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

static int is_valid_config_file(const char *config_path)
{
	struct stat sb;

	if (stat(config_path, &sb) == -1) {
		fprintf(stderr, "%s: %s(%d)\n", config_path, strerror(errno), errno);
		return EXIT_FAILURE;
	}

	if ((sb.st_mode & S_IFMT) != S_IFREG) {
		fprintf(stderr, "%s is not a regular file!\n", config_path);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

static int is_valid_nodes_file(const char *nodes_path)
{
	if (!nodes_path) {
		fprintf(stderr, "Missing KNOT known nodes file!\n");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int settings_parse(int argc, char *argv[], struct settings *settings)
{
	settings->config_path = config_path;
	settings->nodes_path = nodes_path;
	settings->host = host;
	settings->port = port;
	settings->spi = spi;
	settings->channel = channel;
	settings->dbm = dbm;
	settings->detach = detach;
	settings->ell = ell;
	settings->help = help;

	if (!parse_args(argc, argv, settings))
		return EXIT_FAILURE;

	return is_valid_config_file(settings->config_path)
		&& is_valid_nodes_file(settings->nodes_path);
}
