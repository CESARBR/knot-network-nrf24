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
#include <string.h>
#include <errno.h>
#include <json-c/json.h>

#include "storage.h"

static char *load_config(const char *pathname)
{
	char *buffer;
	int length;
	FILE *fl = fopen(pathname, "r");

	if (fl == NULL)
		return NULL;

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

int storage_config_write_keyword(const char *pathname, const char *group,
				 const char *key, const char *value)
{
	json_object *jobj, *obj_group;

	jobj = json_tokener_parse(pathname);
	if (jobj == NULL)
		return -EINVAL;

	if (!json_object_object_get_ex(jobj, group, &obj_group))
		goto done;

	json_object_object_add(obj_group, key, json_object_new_string(value));

	json_object_to_file((char *) pathname, jobj);

done:
	/* Free mem used in json parse: */
	json_object_put(jobj);

	return 0;
}

int storage_config_load(const char *pathname, int *channel, int *dbm, char *mac)
{
	json_object *jobj, *obj_group, *obj_tmp;
	const char *str;
	char *config;
	int err = -EINVAL;

	config = load_config(pathname);
	if (!config)
	       return -EIO;

	jobj = json_tokener_parse(config);

	free(config);

	if (jobj == NULL)
		return -EINVAL;

	if (!json_object_object_get_ex(jobj, "radio", &obj_group))
		goto done;

	if (json_object_object_get_ex(obj_group, "channel", &obj_tmp))
		*channel = json_object_get_int(obj_tmp);

	if (json_object_object_get_ex(obj_group,  "TxPower", &obj_tmp))
		*dbm = json_object_get_int(obj_tmp);

	if (json_object_object_get_ex(obj_group,  "mac", &obj_tmp)) {
		if (json_object_get_string(obj_tmp) != NULL) {
			str = json_object_get_string(obj_tmp);

			/* Assuming that mac has enough space */
			strcpy(mac, str);
		}
	}

	/* Success */
	err = 0;

done:
	/* Free mem used in json parse: */
	json_object_put(jobj);

	return err;
}

void storage_foreach(const char *pathname,
				storage_foreach_func_t func, void *user_data)
{
	int array_len;
	int i;
	json_object *jobj;
	json_object *obj_keys, *obj_nodes, *obj_tmp;
	FILE *fp;
	const char *addr;
	const char *name;

	/* Load nodes' info from json file */
	jobj = json_object_from_file(pathname);
	if (!jobj) {
		fp = fopen(pathname, "w");
		if (!fp)
			goto done;

		fprintf(fp, "{\"keys\":[]}");
		fclose(fp);
		goto done;
	}

	if (!json_object_object_get_ex(jobj, "keys", &obj_keys)){
		fp = fopen(pathname, "w");
		if (!fp)
			goto done;

		fprintf(fp, "{\"keys\":[]}");
		fclose(fp);
		goto done;
	}

	array_len = json_object_array_length(obj_keys);

	for (i = 0; i < array_len; i++) {
		obj_nodes = json_object_array_get_idx(obj_keys, i);
		if (!json_object_object_get_ex(obj_nodes, "mac", &obj_tmp))
			goto done;

		addr = json_object_get_string(obj_tmp);
		if (!addr)
			goto done;

		if (!json_object_object_get_ex(obj_nodes, "name", &obj_tmp))
			goto done;

		name = json_object_get_string(obj_tmp);
		if (!name)
			goto done;

		func(addr, name, user_data);

	}

done:
	/* Free mem used to parse json */
	json_object_put(jobj);
}

int storage_write(const char *pathname, const char *addr,
		       const char *key, const char *name)
{
	int array_len;
	int i;
	int err = -EINVAL;
	json_object *jobj, *jobj2;
	json_object *obj_keys, *obj_array, *obj_tmp, *obj_mac;

	/* Load nodes' info from json file */
	jobj = json_object_from_file(pathname);
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
			if (strcmp(json_object_get_string(obj_mac), addr) != 0)
				json_object_array_add(obj_array,
						json_object_get(obj_tmp));
		}
		json_object_object_add(jobj2, "keys", obj_array);
		json_object_to_file(pathname, jobj2);
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
		json_object_to_file(pathname, jobj);
	}

	err = 0;
failure:
	json_object_put(jobj);
	return err;
}
