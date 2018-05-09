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

#include <stdlib.h>
#include <inttypes.h>
#include <errno.h>
#include <netdb.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>

#include <ell/ell.h>

#include "hal/linux_log.h"
#include "hal/time.h"
#include "hal/comm.h"
#include "hal/nrf24.h"

#include "dbus.h"
#include "storage.h"
#include "device.h"
#include "adapter.h"
#include "settings.h"

#define MAX_PEERS			5
#define BCAST_TIMEOUT			10000
#define KNOTD_UNIX_ADDRESS		"knot"

struct nrf24_adapter {
	struct nrf24_mac addr;
	char *path;			/* Object path */
	bool powered;

	struct l_hashmap *offline_list;	/* Disconnected devices */
	struct l_hashmap *paging_list;	/* Paging/connecting devices */
	struct l_hashmap *online_list;	/* Connected devices */
	struct l_queue *idle_list;	/* Connection mapping */
};

struct idle_pipe {
	struct nrf24_mac addr;	/* Peer/Device address */
	struct l_idle *idle;	/* Polling idle for radio data */
	int rxsock;		/* nRF24 HAL COMM socket */
	int txsock;		/* knotd/upperlayer socket */
	uint32_t timestamp;	/* Timestamp of the last received data */
};

static struct nrf24_adapter adapter; /* Supports only one local adapter */
static struct l_idle *mgmt_idle;
static struct l_timeout *mgmt_timeout;
static struct in_addr inet_address;
static int tcp_port;
static int mgmtfd;

static bool pipe_match_addr(const void *a, const void *b)
{
	const struct idle_pipe *pipe = a;
	const struct nrf24_mac *addr = b;
	int ret = memcmp(&pipe->addr, addr, sizeof(pipe->addr));

	return (ret ? false : true);
}

static bool pipe_match_rxsock(const void *a, const void *b)
{
	const struct idle_pipe *pipe = a;
	const int rxsock = L_PTR_TO_INT(b);

	return (pipe->rxsock == rxsock ? true : false);
}

static unsigned int nrf24_mac_hash(const void *p)
{
	const struct nrf24_mac *addr = p;
	uint32_t most = addr->address.uint64 >> 32;
	uint32_t less = addr->address.uint64;

	return (most | less);
}

static int nrf24_mac_compare(const void *a, const void *b)
{
	const struct nrf24_mac *mac1 = a; /* user informed */
	const struct nrf24_mac *mac2 = b; /* hashmap key */

	return memcmp(mac1, mac2, sizeof(struct nrf24_mac));
}

static void *nrf24_dup(const void *a)
{
	return l_memdup(a, sizeof(struct nrf24_mac));
}

static void nrf24_destroy(void *a)
{
	l_free(a);
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


static void io_destroy(void *user_data)
{
	int nrf24sk = L_PTR_TO_INT(user_data);
	struct nrf24_device *device;
	struct nrf24_mac addr;

	/* Handling knotd initiated disconnection */
	device = l_hashmap_remove(adapter.online_list, user_data);
	if (!device)
		return;

	device_get_address(device, &addr);
	device_set_connected(device, false);

	l_hashmap_insert(adapter.offline_list, &addr, device);

	hal_comm_close(nrf24sk);
}

static bool io_read(struct l_io *io, void *user_data)
{
	int txsock = L_PTR_TO_INT(user_data); /* Radio */
	char buffer[128];
	ssize_t rx;
	ssize_t tx;
	int rxsock; /* knotd */
	int err;

	/* Reading data from knotd */
	rxsock = l_io_get_fd(io);
	rx = read(rxsock, buffer, sizeof(buffer));
	if (rx < 0) {
		err = errno;
		hal_log_error("read(): %s (%d)", strerror(err), err);
		return true;
	}

	/* Sendind data to thing */
	/* TODO: put data in list for transmission */

	tx = hal_comm_write(txsock, buffer, rx);
	if (tx < 0)
		hal_log_error("hal_comm_write(): %zd", tx);

	return true;
}

static void remove_pipe_oneshot(void *user_data)
{
	struct l_idle *idle = user_data;
	/* Calls radio_idle_destroy */
	l_idle_remove(idle);
}

static void pipe_destroy(void *user_data)
{
	struct idle_pipe *pipe = user_data;

	if (pipe->rxsock)
		hal_comm_close(pipe->rxsock);

	if (pipe->txsock)
		close(pipe->txsock);

	l_free(pipe);
}

static void radio_idle_destroy(void *user_data)
{
	l_queue_remove(adapter.idle_list, user_data);
	pipe_destroy(user_data);
}

static void radio_idle_read(struct l_idle *idle, void *user_data)
{
	struct idle_pipe *pipe = user_data;
	struct nrf24_device *device;
	uint8_t buffer[256];
	int rx, err;
	uint32_t timestamp = hal_time_ms();
	bool online;

	rx = hal_comm_read(pipe->rxsock, &buffer, sizeof(buffer));
	if (rx <= 0) {
		if (hal_timeout(timestamp, pipe->timestamp, 500) > 0) {
			/* Connection attempt failed */
			online = false;
			goto done;
		} else
			return;
	}

	pipe->timestamp = timestamp;
	if (write(pipe->txsock, buffer, rx) < 0) {
		err = errno;
		hal_log_error("write to knotd: %s(%d)",
			      strerror(err), err);
	}
	/*
	 * FIXME: MGMT should be extended to notify connection
	 * complete event for host initiated connection.
	 */
	online = true;
done:
	device = l_hashmap_remove(adapter.paging_list, &pipe->addr);
	if (!device)
		return;

	if (online) {
		l_hashmap_insert(adapter.online_list,
				 L_INT_TO_PTR(pipe->rxsock), device);
		device_set_connected(device, true);
	} else {
		l_hashmap_insert(adapter.offline_list, &pipe->addr, device);
		l_idle_oneshot(remove_pipe_oneshot, pipe->idle, NULL);
	}
}

static bool offline_foreach(const void *key, void *value, void *user_data)
{
	struct nrf24_device *device = value;
	uint32_t ctime = L_PTR_TO_UINT(user_data);
	struct nrf24_mac addr;
	char str[24];

	if (device_is_paired(device))
		return false;

	if (hal_timeout(ctime, device_get_last_seen(value), 7000) == 0)
		return false;

	device_get_address(device, &addr);
	nrf24_mac2str(&addr, str);
	hal_log_info("Destroying %p %s", device, str);
	device_destroy(device);

	return true;
}

static bool paging_foreach(const void *key, void *value, void *user_data)
{
	const struct nrf24_mac *addr = key;
	struct nrf24_device *device1 = value;
	struct nrf24_device *device2 = user_data;
	struct idle_pipe *pipe;

	if (device1 != device2)
		return false;

	pipe = l_queue_remove_if(adapter.idle_list, pipe_match_addr, addr);
	if (!pipe)
		return false;

	l_idle_oneshot(remove_pipe_oneshot, pipe->idle, NULL);

	return true;
}

static bool online_foreach(const void *key, void *value, void *user_data)
{
	const int *rxsock = key;
	struct nrf24_device *device1 = value;
	struct nrf24_device *device2 = user_data;
	struct idle_pipe *pipe;

	if (device1 != device2)
		return false;

	pipe = l_queue_remove_if(adapter.idle_list, pipe_match_rxsock, rxsock);
	if (!pipe)
		return false;

	l_idle_oneshot(remove_pipe_oneshot, pipe->idle, NULL);

	return true;
}

static void remove_device_oneshot(void *user_data)
{
	struct nrf24_device *device = user_data;
	/*
	 * Never call at the same loop
	 * FIXME: Find better approach. Device object
	 * should not be unregistered at the same loop.
	 */
	device_destroy(device);
}

static void forget_cb(struct nrf24_device *device, void *user_data)
{
	struct nrf24_adapter *adapter = user_data;
	struct nrf24_mac addr;
	char mac_str[24];

	device_get_address(device, &addr);

	if (!l_hashmap_remove(adapter->offline_list, &addr))
		if (!l_hashmap_foreach_remove(adapter->paging_list,
					      paging_foreach, device))
			if (!l_hashmap_foreach_remove(adapter->online_list,
						      online_foreach, device))
				return;

	nrf24_mac2str(&addr, mac_str);
	storage_remove_group(settings.nodes_path, mac_str);
	l_idle_oneshot(remove_device_oneshot, device, NULL);
}

static void evt_disconnected(struct mgmt_nrf24_header *mhdr)
{
	struct nrf24_device *device;
	struct idle_pipe *pipe;
	char mac_str[24];
	struct mgmt_evt_nrf24_disconnected *evt =
		(struct mgmt_evt_nrf24_disconnected *) mhdr->payload;

	nrf24_mac2str(&evt->mac, mac_str);

	hal_log_info("Peer disconnected(%s)", mac_str);

	pipe = l_queue_remove_if(adapter.idle_list, pipe_match_addr, &evt->mac);
	if (!pipe)
		return;

	/* Move from online to offline */
	device = l_hashmap_remove(adapter.online_list,
				  L_INT_TO_PTR(pipe->rxsock));
	/* Remove & destroy idle */
	l_idle_remove(pipe->idle);

	if (!device) {
		/* Connection might be in progress */
		device = l_hashmap_remove(adapter.paging_list, &evt->mac);
		if (!device)
			return;
	}

	l_hashmap_insert(adapter.offline_list, &evt->mac, device);
	device_set_connected(device, false);
}

static int8_t evt_presence(struct mgmt_nrf24_header *mhdr, ssize_t rbytes)
{
	struct l_io *io;
	int sock, nsk;
	char mac_str[24];
	const char *end;
	char *name;
	char id[17];
	struct nrf24_device *device;
	struct idle_pipe *pipe;
	struct mgmt_evt_nrf24_bcast_presence *evt =
			(struct mgmt_evt_nrf24_bcast_presence *) mhdr->payload;
	ssize_t name_len;

	/*
	 * Paired device: Read from storage, connect automatically.
	 * Unknown device: Register/Create the device and wait the user
	 * to trigger 'Pair' method.
	 */
	if (l_hashmap_size(adapter.online_list) == MAX_PEERS)
		return -EUSERS; /* MAX PEERS: No room for more connection */

	/* Connection in progress or quick remote initiated disconnection ? */
	pipe = l_queue_find(adapter.idle_list, pipe_match_addr, &evt->mac);
	if (pipe) {
		nsk = pipe->rxsock;
		goto connect_again;
	}

	/* Register not paired/unknown devices */
	device = l_hashmap_lookup(adapter.offline_list, &evt->mac);
	if (!device) {
		/*
		 * Calculating the size of the name correctly: rbytes contains the
		 * amount of data received and this contains two structures:
		 * mgmt_nrf24_header & mgmt_evt_nrf24_bcast_presence.
		 */
		name_len = rbytes - sizeof(*mhdr) - sizeof(*evt);

		/* Creating a UTF-8 copy of the name */
		if (l_utf8_validate(evt->name, name_len, &end) == false)
			return 0;

		name = l_strndup(evt->name, name_len);
		snprintf(id, 17, "%016"PRIx64, evt->id);
		device = device_create(adapter.path,
				       &evt->mac, id, name, false,
				       forget_cb, &adapter);

		l_free(name);

		if (!device) {
			nrf24_mac2str(&evt->mac, mac_str);
			hal_log_error("Can't create device %s", mac_str);
			return -EAGAIN;
		}

		device_set_last_seen(device, hal_time_ms());
		l_hashmap_insert(adapter.offline_list, &evt->mac, device);

		return 0;
	}

	device_set_last_seen(device, hal_time_ms());

	/* Paired/Known device? */
	if (!device_is_paired(device))
		return 0;

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

	/* Monitor traffic from knotd */
	io = l_io_new(sock);
	l_io_set_close_on_destroy(io, true);
	l_io_set_read_handler(io, io_read, L_INT_TO_PTR(nsk), io_destroy);

	/* Monitor traffic from radio */
	pipe = l_new(struct idle_pipe, 1);
	pipe->rxsock = nsk; /* Radio */
	pipe->txsock = sock; /* knotd */
	pipe->addr = evt->mac;
	pipe->timestamp = hal_time_ms();
	pipe->idle = l_idle_create(radio_idle_read, pipe,
				   radio_idle_destroy);
	l_queue_push_head(adapter.idle_list, pipe);

	l_hashmap_remove(adapter.offline_list, &evt->mac);
	l_hashmap_insert(adapter.paging_list, &evt->mac, device);

connect_again:
	nrf24_mac2str(&evt->mac, mac_str);
	hal_log_info("Conneting to %s", mac_str);

	return hal_comm_connect(nsk, &evt->mac.address.uint64);
}

static void mgmt_idle_read(struct l_idle *idle, void *user_data)
{
	uint8_t buffer[256];
	struct mgmt_nrf24_header *mhdr = (struct mgmt_nrf24_header *) buffer;
	ssize_t rbytes;

	memset(buffer, 0x00, sizeof(buffer));
	rbytes = hal_comm_read(mgmtfd, buffer, sizeof(buffer));

	/* mgmt on bad state? */
	if (rbytes < 0 && rbytes != -EAGAIN)
		return;

	/* Nothing to read? */
	if (rbytes == -EAGAIN)
		return;

	/* Return/ignore if it is not an event? */
	if (!(mhdr->opcode & 0x0200))
		return;

	switch (mhdr->opcode) {

	case MGMT_EVT_NRF24_BCAST_PRESENCE:
		evt_presence(mhdr, rbytes);
		break;

	case MGMT_EVT_NRF24_BCAST_SETUP:
		break;

	case MGMT_EVT_NRF24_BCAST_BEACON:
		break;

	case MGMT_EVT_NRF24_CONNECTED:
		/* TODO: Set device connected */
		break;
	case MGMT_EVT_NRF24_DISCONNECTED:
		evt_disconnected(mhdr);
		break;
	}
}

static void mgmt_timeout_cb(struct l_timeout *timeout, void *user_data)
{
	uint32_t timestamp = hal_time_ms();

	l_hashmap_foreach_remove(adapter.offline_list,
					    offline_foreach,
					    L_UINT_TO_PTR(timestamp));

	l_timeout_modify(mgmt_timeout, 5);
}

static int radio_init(uint8_t channel, const struct nrf24_mac *addr)
{
	const struct nrf24_config config = {
			.mac = *addr,
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
		err = mgmtfd;
		hal_log_error("Cannot create socket for radio (%d)", err);
		goto done;
	}

	mgmt_idle = l_idle_create(mgmt_idle_read, NULL, NULL);
	mgmt_timeout = l_timeout_create(5, mgmt_timeout_cb, NULL, NULL);
	hal_log_info("Radio initialized");

	return 0;
done:
	hal_comm_deinit();

	return err;
}

static void radio_stop(void)
{
	/* TODO: disconnect clients */
	hal_comm_close(mgmtfd);
	if (mgmt_idle)
		l_idle_remove(mgmt_idle);
	if (mgmt_timeout)
		l_timeout_remove(mgmt_timeout);

	hal_comm_deinit();
}

static struct l_dbus_message *method_add_device(struct l_dbus *dbus,
						struct l_dbus_message *msg,
						void *user_data)
{
	struct l_dbus_message_iter dict;
	struct l_dbus_message_iter value;
	struct nrf24_adapter *adapter = user_data;
	struct nrf24_device *device;
	struct nrf24_mac addr;
	const char *mac_str = NULL;
	const char *name = NULL;
	const char *id = NULL;
	char *key;

	if (!l_dbus_message_get_arguments(msg, "a{sv}", &dict))
		return dbus_error_invalid_args(msg);

	while (l_dbus_message_iter_next_entry(&dict, &key, &value)) {
		if (strcmp(key, "Address") == 0)
			l_dbus_message_iter_next_entry(&value, &mac_str);
		else if (strcmp(key, "Name") == 0)
			l_dbus_message_iter_next_entry(&value, &name);
		else if (strcmp(key, "Id") == 0)
			l_dbus_message_iter_next_entry(&value, &id);
		else
			return dbus_error_invalid_args(msg);
	}

	if (!mac_str || !name || !id)
		return dbus_error_invalid_args(msg);

	if (nrf24_str2mac(mac_str, &addr) != 0)
		return dbus_error_invalid_args(msg);

	device = device_create(adapter->path, &addr, id, name, true,
			       forget_cb, adapter);
	if (!device)
		return dbus_error_invalid_args(msg);

	store_device(mac_str, id, name);

	l_hashmap_insert(adapter->offline_list, &addr, device);

	return l_dbus_message_new_method_return(msg);
}

static bool property_get_powered(struct l_dbus *dbus,
				     struct l_dbus_message *msg,
				     struct l_dbus_message_builder *builder,
				     void *user_data)
{
	struct nrf24_adapter *adapter = user_data;

	l_dbus_message_builder_append_basic(builder, 'b', &adapter->powered);
	hal_log_info("%s GetProperty(Powered = %d)",
		     adapter->path, adapter->powered);

	return true;
}

static bool property_get_address(struct l_dbus *dbus,
				  struct l_dbus_message *msg,
				  struct l_dbus_message_builder *builder,
				  void *user_data)
{
	struct nrf24_adapter *adapter = user_data;
	char str[24];

	nrf24_mac2str(&adapter->addr, str);

	l_dbus_message_builder_append_basic(builder, 's', str);
	hal_log_info("%s GetProperty(Address = %s)", adapter->path, str);

	return true;
}

static void adapter_setup_interface(struct l_dbus_interface *interface)
{

	l_dbus_interface_method(interface, "AddDevice", 0,
				method_add_device, "", "a{sv}", "dict");

	if (!l_dbus_interface_property(interface, "Powered", 0, "b",
				       property_get_powered,
				       NULL))
		hal_log_error("Can't add 'Powered' property");

	if (!l_dbus_interface_property(interface, "Address", 0, "s",
				       property_get_address,
				       NULL))
		hal_log_error("Can't add 'Address' property");
}

static void register_device(const char *mac, const char *id,
				const char *name, void *user_data)
{
	struct nrf24_adapter *adapter = user_data;
	struct nrf24_device *device;
	struct nrf24_mac addr;

	nrf24_str2mac(mac, &addr);

	/* Registering paired devices */
	device = device_create(adapter->path, &addr, id, name, true, forget_cb,
			       adapter);
	if (!device)
		return;

	l_hashmap_insert(adapter->offline_list, &addr, device);
}

int adapter_start(const struct nrf24_mac *mac)
{
	const char *path = "/nrf0";
	int ret;

	/*  TCP development mode: RPi(nrfd) connected to Linux(knotd) */
	if (settings.host) {
		memset(&inet_address, 0, sizeof(inet_address));
		ret = tcp_init(settings.host);
		if (ret < 0)
			return ret;

		tcp_port = settings.port;
	}

	ret = radio_init(settings.channel, mac);
	if (ret < 0)
		return ret;

	memset(&adapter, 0, sizeof(struct nrf24_adapter));
	adapter.idle_list = l_queue_new();
	adapter.online_list = l_hashmap_new();
	adapter.offline_list = l_hashmap_new();
	adapter.paging_list = l_hashmap_new();
	l_hashmap_set_hash_function(adapter.offline_list, nrf24_mac_hash);
	l_hashmap_set_hash_function(adapter.paging_list, nrf24_mac_hash);
	l_hashmap_set_compare_function(adapter.offline_list, nrf24_mac_compare);
	l_hashmap_set_compare_function(adapter.paging_list, nrf24_mac_compare);
	l_hashmap_set_key_copy_function(adapter.offline_list, nrf24_dup);
	l_hashmap_set_key_copy_function(adapter.paging_list, nrf24_dup);
	l_hashmap_set_key_free_function(adapter.offline_list, nrf24_destroy);
	l_hashmap_set_key_free_function(adapter.paging_list, nrf24_destroy);

	adapter.path = l_strdup(path);
	adapter.addr = *mac;
	adapter.powered = true;

	/* nRF24 Adapter object */
	if (!l_dbus_register_interface(dbus_get_bus(),
				       ADAPTER_INTERFACE,
				       adapter_setup_interface,
				       NULL, false))
		hal_log_error("dbus: unable to register %s", ADAPTER_INTERFACE);

	if (!l_dbus_object_add_interface(dbus_get_bus(),
					 path,
					 ADAPTER_INTERFACE,
					 &adapter))
	    hal_log_error("dbus: unable to add %s to %s",
					ADAPTER_INTERFACE, path);

	if (!l_dbus_object_add_interface(dbus_get_bus(),
					 path,
					 L_DBUS_INTERFACE_PROPERTIES,
					 &adapter))
	    hal_log_error("dbus: unable to add %s to %s",
					L_DBUS_INTERFACE_PROPERTIES, path);

	/* Register device interface */
	device_start();

	storage_foreach_nrf24_keys(settings.nodes_path,
				   register_device, &adapter);

	return 0;
}

void adapter_stop(void)
{

	l_dbus_unregister_interface(dbus_get_bus(),
				    ADAPTER_INTERFACE);

	radio_stop();

	l_free(adapter.path);

	device_stop();

	l_queue_destroy(adapter.idle_list, pipe_destroy);

	l_hashmap_destroy(adapter.offline_list,
			(l_hashmap_destroy_func_t ) device_destroy);
	l_hashmap_destroy(adapter.paging_list,
			(l_hashmap_destroy_func_t ) device_destroy);
	l_hashmap_destroy(adapter.online_list,
			(l_hashmap_destroy_func_t ) device_destroy);
}
