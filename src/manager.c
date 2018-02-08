/*
 * Copyright (c) 2016, CESAR.
 * All rights reserved.
 *
 * This software may be modified and distributed under the terms
 * of the BSD license. See the LICENSE file for details.
 *
 */

#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <glib.h>
#include <ell/ell.h>
#include <gio/gio.h>
#include <json-c/json.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "hal/nrf24.h"
#include "hal/comm.h"
#include "hal/time.h"

#include "hal/linux_log.h"
#include "manager.h"

#define KNOTD_UNIX_ADDRESS		"knot"
#define MAC_ADDRESS_SIZE		24
#define BCAST_TIMEOUT			10000

#ifndef MIN
#define MIN(a,b)			(((a) < (b)) ? (a) : (b))
#endif

static int mgmtfd;
static guint mgmtwatch;
static struct in_addr inet_address;
static int tcp_port;

struct l_dbus *g_dbus = NULL;

static struct adapter {
	struct nrf24_mac mac;

	/* File with struct keys */
	gchar *keys_pathname;
	gboolean powered;
	/* Struct with the known peers */
	struct {
		struct nrf24_mac addr;
		guint registration_id;
		gchar *alias;
		gboolean status;
	} known_peers[MAX_PEERS];
	guint known_peers_size;
} adapter;

struct peer {
	uint64_t mac;
	int8_t socket_fd; /* HAL comm socket */
	int8_t ksock; /* KNoT raw socket: Unix socket or TCP */
	guint kwatch; /* KNoT raw socket watch */
};

static struct peer peers[MAX_PEERS] = {
	{.socket_fd = -1},
	{.socket_fd = -1},
	{.socket_fd = -1},
	{.socket_fd = -1},
	{.socket_fd = -1}
};

struct beacon {
	char *name;
	unsigned long last_beacon;
};

static GHashTable *peer_bcast_table;
static uint8_t count_clients;

static void beacon_free(void *user_data)
{
	struct beacon *peer = user_data;

	g_free(peer->name);
	g_free(peer);
}

static int write_file(const gchar *addr, const gchar *key, const gchar *name)
{
	int array_len;
	int i;
	int err = -EINVAL;
	json_object *jobj, *jobj2;
	json_object *obj_keys, *obj_array, *obj_tmp, *obj_mac;

	/* Load nodes' info from json file */
	jobj = json_object_from_file(adapter.keys_pathname);
	if (!jobj)
		return -EINVAL;

	if (!json_object_object_get_ex(jobj, "keys", &obj_keys))
		goto failure;

	array_len = json_object_array_length(obj_keys);
	/*
	 * If name and key are NULL it means to remove element
	 * If only name is NULL, update some element
	 * Otherwise add some element to file
	 */
	if (name == NULL && key == NULL) {
		jobj2 = json_object_new_object();
		obj_array = json_object_new_array();
		for (i = 0; i < array_len; i++) {
			obj_tmp = json_object_array_get_idx(obj_keys, i);
			if (!json_object_object_get_ex(obj_tmp, "mac",
								&obj_mac))
				goto failure;

		/* Parse mac address string into struct nrf24_mac known_peers */
			if (g_strcmp0(json_object_get_string(obj_mac), addr)
									!= 0)
				json_object_array_add(obj_array,
						json_object_get(obj_tmp));
		}
		json_object_object_add(jobj2, "keys", obj_array);
		json_object_to_file(adapter.keys_pathname, jobj2);
		json_object_put(jobj2);
	} else if (name == NULL) {
	/* TODO update key of some mac (depends on adding keys to file) */
	} else {
		obj_tmp = json_object_new_object();
		json_object_object_add(obj_tmp, "name",
						json_object_new_string(name));
		json_object_object_add(obj_tmp, "mac",
						json_object_new_string(addr));
		json_object_array_add(obj_keys, obj_tmp);
		json_object_to_file(adapter.keys_pathname, jobj);
	}

	err = 0;
failure:
	json_object_put(jobj);
	return err;
}

static int peers_to_json(struct json_object *peers_bcast_json)
{
	GHashTableIter iter;
	gpointer key, value;
	struct json_object *jobj;

	g_hash_table_iter_init (&iter, peer_bcast_table);

	while (g_hash_table_iter_next (&iter, &key, &value)) {
		struct beacon *peer = value;

		jobj = json_object_new_object();
		if (peer == NULL)
			continue;

		json_object_object_add(jobj, "name",
				       json_object_new_string(peer->name));
		json_object_object_add(jobj, "mac",
					json_object_new_string((char *) key));
		json_object_object_add(jobj, "last_beacon",
				json_object_new_int(peer->last_beacon));

		json_object_array_add(peers_bcast_json, jobj);
	}

	return 0;
}

static void dbus_disconnect_callback(void *user_data)
{
	hal_log_info("D-Bus disconnected");
}

static void dbus_request_name_callback(struct l_dbus *dbus, bool success,
					bool queued, void *user_data)
{
	if (!success)
		hal_log_error("Name request failed");
}

static void dbus_ready_callback(void *user_data)
{
	l_dbus_name_acquire(g_dbus, "org.cesar.knot.nrf", false, false, true,
			    dbus_request_name_callback, NULL);

	if (!l_dbus_object_manager_enable(g_dbus))
		hal_log_error("Unable to register the ObjectManager");
}

static void dbus_start(void)
{
	g_dbus = l_dbus_new_default(L_DBUS_SYSTEM_BUS);

	l_dbus_set_ready_handler(g_dbus, dbus_ready_callback,
				 g_dbus, NULL);
	l_dbus_set_disconnect_handler(g_dbus, dbus_disconnect_callback,
				      NULL, NULL);
}

static void dbus_stop(void)
{
	uint8_t i;

	for (i = 0; i < MAX_PEERS; i++) {
		if (adapter.known_peers[i].addr.address.uint64 != 0)
			g_free(adapter.known_peers[i].alias);
	}

	g_free(adapter.keys_pathname);
}

/* Check if peer is on list of known peers */
static int8_t check_permission(struct nrf24_mac mac)
{
	uint8_t i;

	for (i = 0; i < MAX_PEERS; i++) {
		if (mac.address.uint64 ==
				adapter.known_peers[i].addr.address.uint64)
			return 0;
	}

	return -EPERM;
}

/* Get peer position in vector of peers */
static int8_t get_peer(struct nrf24_mac mac)
{
	int8_t i;

	for (i = 0; i < MAX_PEERS; i++)
		if (peers[i].socket_fd != -1 &&
			peers[i].mac == mac.address.uint64)
			return i;

	return -EINVAL;
}

/* Get free position in vector for peers */
static int8_t get_peer_index(void)
{
	int8_t i;

	for (i = 0; i < MAX_PEERS; i++)
		if (peers[i].socket_fd == -1)
			return i;

	return -EUSERS;
}

static int unix_connect(void)
{
	struct sockaddr_un addr;
	int sock;

	sock = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (sock < 0)
		return -errno;

	/* Represents unix socket from nrfd to knotd */
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path + 1, KNOTD_UNIX_ADDRESS,
					strlen(KNOTD_UNIX_ADDRESS));

	if (connect(sock, (struct sockaddr *) &addr, sizeof(addr)) == -1)
		return -errno;

	return sock;
}

static int tcp_init(const char *host)
{
	struct hostent *hostent;		/* Host information */
	int err;

	hostent = gethostbyname(host);
	if (hostent == NULL) {
		err = errno;
		hal_log_error("gethostbyname(): %s(%d)", strerror(err), err);
		return -err;
	}

	inet_address.s_addr = *((unsigned long *) hostent-> h_addr_list[0]);

	return 0;
}

static int tcp_connect(void)
{
	struct sockaddr_in server;
	int err, sock, enable = 1;

	sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock < 0) {
		err = errno;
		hal_log_error("socket(): %s(%d)", strerror(err), err);
		return -err;
	}

	memset(&server, 0, sizeof(server));
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = inet_address.s_addr;
	server.sin_port = htons(tcp_port);

	if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &enable,
						sizeof(enable)) == -1) {
		err = errno;
		hal_log_error("tcp setsockopt(iTCP_NODELAY): %s(%d)",
							strerror(err), err);
		close(sock);
		return -err;
	}

	err = connect(sock, (struct sockaddr *) &server, sizeof(server));
	if (err < 0)
		return -errno;

	return sock;
}

static void kwatch_io_destroy(gpointer user_data)
{
	struct peer *p = (struct peer *) user_data;

	hal_comm_close(p->socket_fd);
	close(p->ksock);
	p->socket_fd = -1;
	p->kwatch = 0;
	count_clients--;
}

static gboolean kwatch_io_read(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	struct peer *p = (struct peer *) user_data;
	GError *gerr = NULL;
	GIOStatus status;
	char buffer[128];
	size_t rx;
	ssize_t tx;

	if (cond & (G_IO_ERR | G_IO_HUP | G_IO_NVAL))
		return FALSE;

	/* Reading data from knotd */
	status = g_io_channel_read_chars(io, buffer, sizeof(buffer),
								&rx, &gerr);
	if (status != G_IO_STATUS_NORMAL) {
		hal_log_error("glib read(): %s", gerr->message);
		g_error_free(gerr);
		return FALSE;
	}

	/* Send data to thing */
	/* TODO: put data in list for transmission */

	tx = hal_comm_write(p->socket_fd, buffer, rx);
	if (tx < 0)
		hal_log_error("hal_comm_write(): %zd", tx);

	return TRUE;
}

static int8_t evt_presence(struct mgmt_nrf24_header *mhdr, ssize_t rbytes)
{
	GIOCondition cond = G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL;
	GIOChannel *io;
	int8_t position;
	uint8_t i;
	int sock, nsk;
	char mac_str[MAC_ADDRESS_SIZE];
	struct beacon *peer;
	struct mgmt_evt_nrf24_bcast_presence *evt_pre =
			(struct mgmt_evt_nrf24_bcast_presence *) mhdr->payload;
	ssize_t name_len;

	nrf24_mac2str(&evt_pre->mac, mac_str);
	peer = g_hash_table_lookup(peer_bcast_table, mac_str);
	if (peer != NULL) {
		peer->last_beacon = hal_time_ms();
		goto done;
	}
	peer = g_try_new0(struct beacon, 1);
	if (peer == NULL)
		return -ENOMEM;
	/*
	 * Print every MAC sending presence in order to ease the discover of
	 * things trying to connect to the gw.
	 */
	peer->last_beacon = hal_time_ms();
	/*
	 * Calculating the size of the name correctly: rbytes contains the
	 * amount of data received and this contains two structures:
	 * mgmt_nrf24_header & mgmt_evt_nrf24_bcast_presence.
	 */
	name_len = rbytes - sizeof(*mhdr) - sizeof(*evt_pre);

	/* Creating a UTF-8 copy of the name */
	peer->name = g_utf8_make_valid((const char *) evt_pre->name, name_len);
	if (!peer->name)
		peer->name = g_strdup("unknown");

	hal_log_info("Thing sending presence. MAC = %s Name = %s",
						mac_str, peer->name);
	/*
	 * MAC and device name will be printed only once, but the last presence
	 * time is updated. Every time a user refresh the list in the webui
	 * we will discard devices that broadcasted
	 */
	g_hash_table_insert(peer_bcast_table, g_strdup(mac_str), peer);
done:
	/* Check if peer is allowed to connect */
	if (check_permission(evt_pre->mac) < 0)
		return -EPERM;

	if (count_clients >= MAX_PEERS)
		return -EUSERS; /* MAX PEERS */

	/* Check if this peer is already allocated */
	position = get_peer(evt_pre->mac);
	/* If this is a new peer */
	if (position < 0) {
		/* Get free peers position */
		position = get_peer_index();
		if (position < 0)
			return position;

		/* Radio socket: nRF24 */
		nsk = hal_comm_socket(HAL_COMM_PF_NRF24, HAL_COMM_PROTO_RAW);
		if (nsk < 0) {
			hal_log_error("hal_comm_socket(nRF24): %s(%d)",
							strerror(nsk), nsk);
			return nsk;
		}

		/* Upper layer socket: knotd */
		if (inet_address.s_addr)
			sock = tcp_connect();
		else
			sock = unix_connect();

		if (sock < 0) {
			hal_log_error("connect(): %s(%d)", strerror(sock), sock);
			hal_comm_close(nsk);
			return sock;
		}

		peers[position].ksock = sock;
		peers[position].socket_fd = nsk;

		/* Set mac value for this position */
		peers[position].mac =
				evt_pre->mac.address.uint64;

		/* Watch knotd socket */
		io = g_io_channel_unix_new(peers[position].ksock);
		g_io_channel_set_flags(io, G_IO_FLAG_NONBLOCK, NULL);
		g_io_channel_set_close_on_unref(io, TRUE);
		g_io_channel_set_encoding(io, NULL, NULL);
		g_io_channel_set_buffered(io, FALSE);

		peers[position].kwatch = g_io_add_watch_full(io,
							G_PRIORITY_DEFAULT,
							cond,
							kwatch_io_read,
							&peers[position],
							kwatch_io_destroy);
		g_io_channel_unref(io);

		count_clients++;

		for (i = 0; i < MAX_PEERS; i++) {
			if (evt_pre->mac.address.uint64 ==
				adapter.known_peers[i].addr.address.uint64) {
				adapter.known_peers[i].status = TRUE;
				break;
			}
		}
		/* Remove device when the connection is established */
		g_hash_table_remove(peer_bcast_table, mac_str);
	}

	/* Send Connect */
	return hal_comm_connect(peers[position].socket_fd,
			&evt_pre->mac.address.uint64);
}

static int8_t evt_disconnected(struct mgmt_nrf24_header *mhdr)
{
	char mac_str[MAC_ADDRESS_SIZE];
	int8_t position;

	struct mgmt_evt_nrf24_disconnected *evt_disc =
			(struct mgmt_evt_nrf24_disconnected *) mhdr->payload;

	nrf24_mac2str(&evt_disc->mac, mac_str);
	hal_log_info("Peer disconnected(%s)", mac_str);

	if (count_clients == 0)
		return -EINVAL;

	position = get_peer(evt_disc->mac);
	if (position < 0)
		return position;

	g_source_remove(peers[position].kwatch);
	return 0;
}

/* Read RAW from Clients */
static int8_t clients_read(void)
{
	uint8_t buffer[256];
	int rx, err, i;
	static struct peer *p = peers;

	if (count_clients == 0)
		return 0;

	/* Handles clients found at a time */
	for (i = MAX_PEERS; i != 0; --i) {
		if (p->socket_fd != -1) {
			rx = hal_comm_read(p->socket_fd, &buffer, sizeof(buffer));
			if (rx > 0) {
				if (write(p->ksock, buffer, rx) < 0) {
					err = errno;
					hal_log_error("write to knotd: %s(%d)",
						      strerror(err), err);
				}
			}
			i = 1; /* LOOP breaking */
		}
		if (++p == (peers + MAX_PEERS))
			p = peers;
	}

	return 0;
}

static int8_t mgmt_read(void)
{
	uint8_t buffer[256];
	struct mgmt_nrf24_header *mhdr = (struct mgmt_nrf24_header *) buffer;
	ssize_t rbytes;

	memset(buffer, 0x00, sizeof(buffer));
	rbytes = hal_comm_read(mgmtfd, buffer, sizeof(buffer));

	/* mgmt on bad state? */
	if (rbytes < 0 && rbytes != -EAGAIN)
		return rbytes;

	/* Nothing to read? */
	if (rbytes == -EAGAIN)
		return rbytes;

	/* Return/ignore if it is not an event? */
	if (!(mhdr->opcode & 0x0200))
		return -EPROTO;

	switch (mhdr->opcode) {

	case MGMT_EVT_NRF24_BCAST_PRESENCE:
		evt_presence(mhdr, rbytes);
		break;

	case MGMT_EVT_NRF24_BCAST_SETUP:
		break;

	case MGMT_EVT_NRF24_BCAST_BEACON:
		break;

	case MGMT_EVT_NRF24_DISCONNECTED:
		evt_disconnected(mhdr);
		break;
	}

	return 0;
}

static gboolean read_idle(gpointer user_data)
{
	mgmt_read();
	clients_read();

	return TRUE;
}

static int radio_init(const char *spi, uint8_t channel, uint8_t rfpwr,
						const struct nrf24_mac *mac)
{
	const struct nrf24_config config = {
			.mac = *mac,
			.channel = channel,
			.name = "nrf0" };
	int err;

	err = hal_comm_init("NRF0", &config);
	if (err < 0) {
		hal_log_error("Cannot init NRF0 radio. (%d)", err);
		return err;
	}

	mgmtfd = hal_comm_socket(HAL_COMM_PF_NRF24, HAL_COMM_PROTO_MGMT);
	if (mgmtfd < 0) {
		hal_log_error("Cannot create socket for radio (%d)", mgmtfd);
		goto done;
	}

	mgmtwatch = g_idle_add(read_idle, NULL);
	hal_log_info("Radio initialized");

	return 0;
done:
	hal_comm_deinit();

	return mgmtfd;
}

static void close_clients(void)
{
	int i;

	for (i = 0; i < MAX_PEERS; i++) {
		if (peers[i].socket_fd != -1)
			g_source_remove(peers[i].kwatch);
	}
}

static void radio_stop(void)
{
	close_clients();
	hal_comm_close(mgmtfd);
	if (mgmtwatch)
		g_source_remove(mgmtwatch);
	hal_comm_deinit();
}

static char *load_config(const char *file)
{
	char *buffer;
	int length;
	FILE *fl = fopen(file, "r");

	if (fl == NULL) {
		hal_log_error("No such file available: %s", file);
		return NULL;
	}

	fseek(fl, 0, SEEK_END);
	length = ftell(fl);
	fseek(fl, 0, SEEK_SET);

	buffer = (char *) malloc((length+1)*sizeof(char));
	if (buffer) {
		fread(buffer, length, 1, fl);
		buffer[length] = '\0';
	}
	fclose(fl);

	return buffer;
}

/* Set TX Power from dBm to values defined at nRF24 datasheet */
static uint8_t dbm_int2rfpwr(int dbm)
{
	switch (dbm) {

	case 0:
		return NRF24_PWR_0DBM;

	case -6:
		return NRF24_PWR_6DBM;

	case -12:
		return NRF24_PWR_12DBM;

	case -18:
		return NRF24_PWR_18DBM;
	}

	/* Return default value when dBm value is invalid */
	return NRF24_PWR_0DBM;
}

static int gen_save_mac(const char *config, const char *file,
							struct nrf24_mac *mac)
{
	json_object *jobj, *obj_radio, *obj_tmp;

	int err = -EINVAL;

	jobj = json_tokener_parse(config);
	if (jobj == NULL)
		return -EINVAL;

	if (!json_object_object_get_ex(jobj, "radio", &obj_radio))
		goto done;

	if (json_object_object_get_ex(obj_radio,  "mac", &obj_tmp)) {

			char mac_string[MAC_ADDRESS_SIZE];
			mac->address.uint64 = 0;

			hal_getrandom(mac->address.b, sizeof(*mac));

			err = nrf24_mac2str(mac, mac_string);
			if (err == -1)
				goto done;

			json_object_object_add(obj_radio, "mac",
					json_object_new_string(mac_string));

			json_object_to_file((char *) file, jobj);
	}

	/* Success */
	err = 0;

done:
	/* Free mem used in json parse: */
	json_object_put(jobj);
	return err;
}

/*
 * TODO: Get "host", "spi" and "port"
 * parameters when/if implemented
 * in the json configuration file
 */
static int parse_config(const char *config, int *channel, int *dbm,
							struct nrf24_mac *mac)
{
	json_object *jobj, *obj_radio, *obj_tmp;

	int err = -EINVAL;

	jobj = json_tokener_parse(config);
	if (jobj == NULL)
		return -EINVAL;

	if (!json_object_object_get_ex(jobj, "radio", &obj_radio))
		goto done;

	if (json_object_object_get_ex(obj_radio, "channel", &obj_tmp))
		*channel = json_object_get_int(obj_tmp);

	if (json_object_object_get_ex(obj_radio,  "TxPower", &obj_tmp))
		*dbm = json_object_get_int(obj_tmp);

	if (json_object_object_get_ex(obj_radio,  "mac", &obj_tmp)) {
		if (json_object_get_string(obj_tmp) != NULL) {
			err =
			nrf24_str2mac(json_object_get_string(obj_tmp), mac);
			if (err == -1)
				goto done;
		}
	}

	/* Success */
	err = 0;

done:
	/* Free mem used in json parse: */
	json_object_put(jobj);
	return err;
}

/*
 * Reads the keys.json file to create the list of allowed peers.
 * If the file does not exist or is in the wrong format, a new one (empty)
 * is created.
 */
static int parse_nodes(const char *nodes_file)
{
	int array_len;
	int i;
	int err = -EINVAL;
	json_object *jobj;
	json_object *obj_keys, *obj_nodes, *obj_tmp;
	FILE *fp;

	/* Load nodes' info from json file */
	jobj = json_object_from_file(nodes_file);
	if (!jobj) {
		fp = fopen(nodes_file, "w");
		if (!fp) {
			hal_log_error("Could not create file %s", nodes_file);
			goto done;
		}
		fprintf(fp, "{\"keys\":[]}");
		fclose(fp);
		err = 0;
		goto done;
	}

	if (!json_object_object_get_ex(jobj, "keys", &obj_keys)){
		fp = fopen(nodes_file, "w");
		if (!fp){
			hal_log_error("Could not write file %s", nodes_file);
			goto done;
		}
		fprintf(fp, "{\"keys\":[]}");
		fclose(fp);
		err = 0;
		goto done;
	}

	/*
	 * Gets only up to MAX_PEERS nodes.
	 */
	array_len = json_object_array_length(obj_keys);
	if (array_len > MAX_PEERS) {
		hal_log_error("Too many nodes at %s", nodes_file);
		array_len = MAX_PEERS;
	}

	for (i = 0; i < array_len; i++) {
		obj_nodes = json_object_array_get_idx(obj_keys, i);
		if (!json_object_object_get_ex(obj_nodes, "mac", &obj_tmp))
			goto done;

		/* Parse mac address string into struct nrf24_mac known_peers */
		if (nrf24_str2mac(json_object_get_string(obj_tmp),
					&adapter.known_peers[i].addr) < 0)
			goto done;
		adapter.known_peers_size++;

		if (!json_object_object_get_ex(obj_nodes, "name", &obj_tmp))
			goto done;

		/* Set the name of the peer registered */
		adapter.known_peers[i].alias =
				g_strdup(json_object_get_string(obj_tmp));
		adapter.known_peers[i].status = FALSE;
	}

	err = 0;
done:
	/* Free mem used to parse json */
	json_object_put(jobj);
	return err;
}

static gboolean check_timeout(gpointer key, gpointer value, gpointer user_data)
{
	struct beacon *peer = value;

	/* If it returns true the key/value is removed */
	if (hal_timeout(hal_time_ms(), peer->last_beacon,
							BCAST_TIMEOUT) > 0) {
		hal_log_info("Peer %s timedout.", (char *) key);
		return TRUE;
	}

	return FALSE;
}

static gboolean timeout_iterator(gpointer user_data)
{
	g_hash_table_foreach_remove(peer_bcast_table, check_timeout, NULL);

	return TRUE;
}

int manager_start(const char *file, const char *host, int port,
					const char *spi, int channel, int dbm,
					const char *nodes_file)
{
	int cfg_channel = 76, cfg_dbm = 0;
	char *json_str;
	struct nrf24_mac mac = {.address.uint64 = 0};
	int err = -1;

	/* Command line arguments have higher priority */
	json_str = load_config(file);
	if (json_str == NULL) {
		hal_log_error("load_config()");
		return err;
	}

	/* TODO: Add name to config file */
	err = parse_config(json_str, &cfg_channel, &cfg_dbm, &mac);
	if (err < 0) {
		hal_log_error("parse_config(): %d", err);
		free(json_str);
		return err;
	}

	memset(&adapter, 0, sizeof(struct adapter));
	/* Parse nodes info from nodes_file and writes it to known_peers */
	err = parse_nodes(nodes_file);
	if (err < 0) {
		hal_log_error("parse_nodes(): %d", err);
		free(json_str);
		return err;
	}

	if (mac.address.uint64 == 0)
		err = gen_save_mac(json_str, file, &mac);

	free(json_str);
	adapter.keys_pathname = g_strdup(nodes_file);
	adapter.mac = mac;
	adapter.powered = TRUE;

	if (err < 0) {
		hal_log_error("Invalid configuration file(%d): %s", err, file);
		return err;
	}

	/*
	 * Priority order: 1) command line 2) config file.
	 * If the user does not provide channel at command line (or channel is
	 * invalid), switch to channel informed at config file. 76 is the
	 * default vale if channel in not informed in the config file.
	 */
	if (channel < 0 || channel > 125)
		channel = cfg_channel;

	/*
	 * Use TX Power from configuration file if it has not been passed
	 * through cmd line. -255 means invalid: not informed by user.
	 */
	if (dbm == -255)
		dbm = cfg_dbm;

	/* Start server dbus */
	dbus_start();

	/* TCP development mode: RPi(nrfd) connected to Linux(knotd) */
	if (host) {
		memset(&inet_address, 0, sizeof(inet_address));
		err = tcp_init(host);
		if (err < 0)
			return err;

		tcp_port = port;
	}

	err = radio_init(spi, channel, dbm_int2rfpwr(dbm),
						(const struct nrf24_mac*) &mac);
	if (err < 0)
		return err;

	peer_bcast_table = g_hash_table_new_full(g_str_hash, g_str_equal,
							g_free, beacon_free);
	g_timeout_add_seconds(5, timeout_iterator, NULL);

	return 0;
}

void manager_stop(void)
{
	dbus_stop();
	radio_stop();
	g_hash_table_destroy(peer_bcast_table);
}
