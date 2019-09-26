/* Bluez-Alsa SPA plugin
 *
 * Copyright © 2018 Wim Taymans
 * Copyright © 2019 Collabora Ltd.
 *    @author George Kiagiadakis <george.kiagiadakis@collabora.com>
 *
 * SPDX-License-Identifier: MIT
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include "defs.h"

struct impl {
	/* object */
	struct spa_handle handle;
	struct spa_monitor monitor;

	/* support */
	struct spa_log *log;
	struct spa_dbus *dbus;
	struct spa_dbus_connection *dbus_connection;
	DBusConnection *conn;

	/* monitor */
	struct spa_callbacks callbacks;
	uint32_t next_id;
	struct spa_list pcm_list;
};

static struct spa_bluealsa_pcm *find_pcm(struct impl *this, const char *path)
{
	struct spa_bluealsa_pcm *pcm;
	spa_list_for_each(pcm, &this->pcm_list, link) {
		if (!strncmp(path, pcm->ba_pcm.pcm_path, sizeof(pcm->ba_pcm.pcm_path)))
			return pcm;
	}
	return NULL;
}

static int add_pcm(struct impl *this, DBusMessageIter *iter)
{
	DBusError err = DBUS_ERROR_INIT;
	struct spa_bluealsa_pcm *pcm;
	struct spa_monitor_object_info info;
	struct spa_dict_item items[10];
	uint32_t n_items = 0;
	char name[128] = {0};
	char addr[19] = {0};
	char pcmptr[32] = {0};
	int i;

	pcm = calloc(1, sizeof (struct spa_bluealsa_pcm));
	if (!pcm) {
		spa_log_error(this->log, "No memory");
		return -ENOMEM;
	}

	if (!bluealsa_dbus_message_iter_get_pcm(iter, &err, &pcm->ba_pcm)) {
		spa_log_error(this->log, "Get PCM error: %s", err.message);
		dbus_error_free(&err);
		free(pcm);
		return -EIO;
	}

	pcm->id = this->next_id++;
	spa_list_append(&this->pcm_list, &pcm->link);

	ba2str(&pcm->ba_pcm.addr, addr);
	strncpy(name, pcm->ba_pcm.pcm_path + 1, 126);
	for (i = 0; i < 128 && name[i] != '\0'; i++)
		if (name[i] == '/')
			name[i] = '_';

	info = SPA_MONITOR_OBJECT_INFO_INIT();
	info.type = SPA_TYPE_INTERFACE_Device;
	info.factory_name = SPA_NAME_API_BLUEALSA_DEVICE;
	info.change_mask = SPA_MONITOR_OBJECT_CHANGE_MASK_FLAGS |
		SPA_MONITOR_OBJECT_CHANGE_MASK_PROPS;
	info.flags = 0;

	items[n_items++] = SPA_DICT_ITEM_INIT(SPA_KEY_DEVICE_API, "bluealsa");
	items[n_items++] = SPA_DICT_ITEM_INIT(SPA_KEY_DEVICE_NAME, name);
	items[n_items++] = SPA_DICT_ITEM_INIT(SPA_KEY_API_BLUEZ5_PATH, pcm->ba_pcm.device_path);
	items[n_items++] = SPA_DICT_ITEM_INIT(SPA_KEY_API_BLUEZ5_ADDRESS, addr);
	items[n_items++] = SPA_DICT_ITEM_INIT(SPA_KEY_API_BLUEALSA_PCM_PATH, pcm->ba_pcm.pcm_path);
	snprintf(pcmptr, sizeof(pcmptr), "pointer:%p", pcm);
	items[n_items++] = SPA_DICT_ITEM_INIT(SPA_KEY_API_BLUEALSA_PCM_POINTER, pcmptr);
	items[n_items++] = SPA_DICT_ITEM_INIT(SPA_KEY_API_BLUEALSA_PCM_PROFILE,
						spa_bluealsa_pcm_profile_name(pcm));

	info.props = &SPA_DICT_INIT(items, n_items);

	spa_monitor_call_object_info(&this->callbacks, pcm->id, &info);
}

static void remove_pcm(struct impl *this, struct spa_bluealsa_pcm *pcm)
{
	if (this->callbacks.funcs)
		spa_monitor_call_object_info(&this->callbacks, pcm->id, NULL);
	spa_list_remove(&pcm->link);
	free(pcm);
}

static void remove_all_pcms(struct impl *this)
{
	struct spa_bluealsa_pcm *pcm, *tmp;
	spa_list_for_each_safe(pcm, tmp, &this->pcm_list, link) {
		remove_pcm(this, pcm);
	}
}

/* reimpl of bluealsa_dbus_get_pcms() */
static void get_pcms_reply(DBusPendingCall *pending, void *user_data)
{
	struct impl *this = user_data;
	DBusMessage *r;
	DBusMessageIter it[3];

	r = dbus_pending_call_steal_reply(pending);
	if (r == NULL)
		return;

	if (dbus_message_is_error(r, DBUS_ERROR_UNKNOWN_METHOD)) {
		spa_log_warn(this->log, "Bluealsa Manager GetPCMs not available");
		goto finish;
	}

	if (dbus_message_get_type(r) == DBUS_MESSAGE_TYPE_ERROR) {
		spa_log_error(this->log, "GetPCMs() failed: %s",
				dbus_message_get_error_name(r));
		goto finish;
	}

	if (!dbus_message_iter_init(r, &it[0]) ||
	    strcmp(dbus_message_get_signature(r), "a{oa{sv}}") != 0) {
		spa_log_error(this->log, "GetPCMs() invalid signature");
		goto finish;
	}

	for (dbus_message_iter_recurse(&it[0], &it[1]);
		dbus_message_iter_get_arg_type(&it[1]) != DBUS_TYPE_INVALID;
		dbus_message_iter_next(&it[1])) {

		dbus_message_iter_recurse(&it[1], &it[2]);
		if (add_pcm(this, &it[2]) < 0)
			goto finish;
	}

      finish:
	dbus_message_unref(r);
	dbus_pending_call_unref(pending);
	return;
}

/* reimpl of bluealsa_dbus_get_pcms() */
static void get_pcms(struct impl *this)
{
	DBusMessage *m;
	DBusPendingCall *call;

	m = dbus_message_new_method_call(BLUEALSA_SERVICE,
					 "/org/bluealsa",
					 BLUEALSA_INTERFACE_MANAGER,
					 "GetPCMs");

	dbus_connection_send_with_reply(this->conn, m, &call, -1);
	dbus_pending_call_set_notify(call, get_pcms_reply, this, NULL);
	dbus_message_unref(m);
}

static DBusHandlerResult filter_cb(DBusConnection *bus, DBusMessage *m, void *user_data)
{
	struct impl *this = user_data;
	struct spa_bluealsa_pcm *pcm;
	DBusMessageIter iter;
	const char *path, *interface;

	if (dbus_message_is_signal(m, "org.freedesktop.DBus", "NameOwnerChanged")) {
		/* cleanup old PCMs */
		remove_all_pcms(this);

	} else if (dbus_message_is_signal(m, BLUEALSA_INTERFACE_MANAGER, "PCMAdded")) {
		if (!dbus_message_iter_init(m, &iter) ) {
			spa_log_error(this->log, "PCMAdded: Invalid signal signature");
			goto fail;
		}

		if (add_pcm(this, &iter) < 0) {
			goto fail;
		}

	} else if (dbus_message_is_signal(m, BLUEALSA_INTERFACE_MANAGER, "PCMRemoved")) {
		if (!dbus_message_iter_init(m, &iter) ||
				dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_OBJECT_PATH) {
			spa_log_error(this->log, "PCMRemoved: Invalid signal signature");
			goto fail;
		}

		dbus_message_iter_get_basic(&iter, &path);
		if (!(pcm = find_pcm(this, path)))
			goto fail;

		remove_pcm(this, pcm);

	} else if (dbus_message_is_signal(m, DBUS_INTERFACE_PROPERTIES, "PropertiesChanged")) {
		path = dbus_message_get_path(m);

		if (!(pcm = find_pcm(this, path)))
			goto fail;
		if (!dbus_message_iter_init(m, &iter) ||
				dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING) {
			spa_log_error(this->log, "PropertiesChanged: Invalid signal signature");
			goto fail;
		}
		dbus_message_iter_get_basic(&iter, &interface);
		dbus_message_iter_next(&iter);
		if (!bluealsa_dbus_message_iter_get_pcm_props(&iter, NULL, &pcm->ba_pcm))
			goto fail;

		/* notify the device */
		if (pcm->callbacks.funcs) {
			const struct spa_bluealsa_pcm_events *e = pcm->callbacks.funcs;
			if (e->properties_changed)
				e->properties_changed(pcm->callbacks.data);
		}
	}

fail:
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static int setup_filters(struct impl *this, bool enable)
{
	DBusError err = DBUS_ERROR_INIT;

	if (enable && !dbus_connection_add_filter(this->conn, filter_cb, this, NULL)) {
		spa_log_error(this->log, "failed to add filter function");
		goto fail;
	} else if (!enable) {
		dbus_connection_remove_filter(this->conn, filter_cb, this);
	}

	void (*func)(DBusConnection *, const char *, DBusError *) =
		enable ? dbus_bus_add_match : dbus_bus_remove_match;

	func(this->conn,
		"type='signal',sender='org.freedesktop.DBus',"
		"interface='org.freedesktop.DBus',member='NameOwnerChanged',"
		"arg0='" BLUEALSA_SERVICE "'", &err);
	if (dbus_error_is_set(&err))
		goto fail;

	func(this->conn,
		"type='signal',sender='" BLUEALSA_SERVICE "',"
		"interface='" BLUEALSA_INTERFACE_MANAGER "',member='PCMAdded',", &err);
	if (dbus_error_is_set(&err))
		goto fail;

	func(this->conn,
		"type='signal',sender='" BLUEALSA_SERVICE "',"
		"interface='" BLUEALSA_INTERFACE_MANAGER "',member='PCMRemoved',", &err);
	if (dbus_error_is_set(&err))
		goto fail;

	func(this->conn,
		"type='signal',sender='" BLUEALSA_SERVICE "',"
		"interface='org.freedesktop.DBus.Properties',member='PropertiesChanged',"
		"arg0='" BLUEALSA_INTERFACE_PCM "'", &err);
	if (dbus_error_is_set(&err))
		goto fail;

	return 0;

fail:
	spa_log_error(this->log, "failed to %s match rule: %s",
				enable ? "add" : "remove", err.message);
	dbus_error_free(&err);
	return -EIO;
}

static int
impl_monitor_set_callbacks(void *object,
			   const struct spa_monitor_callbacks *callbacks,
			   void *data)
{
	struct impl *this = object;
	bool had_callbacks;

	spa_return_val_if_fail(this != NULL, -EINVAL);

	had_callbacks = (this->callbacks.funcs != NULL);
	this->callbacks = SPA_CALLBACKS_INIT(callbacks, data);

	if (callbacks && !had_callbacks) {
		int ret;
		if ((ret = setup_filters(this, true)) < 0)
			return ret;
		get_pcms(this);
	} else if (!callbacks && had_callbacks) {
		setup_filters(this, false);
		remove_all_pcms(this);
	} else if (callbacks && had_callbacks) {
		return -EINVAL;
	}

	return 0;
}

static const struct spa_monitor_methods impl_monitor = {
	SPA_VERSION_MONITOR_METHODS,
	.set_callbacks = impl_monitor_set_callbacks,
};

static int impl_get_interface(struct spa_handle *handle, uint32_t type, void **interface)
{
	struct impl *this;

	spa_return_val_if_fail(handle != NULL, -EINVAL);
	spa_return_val_if_fail(interface != NULL, -EINVAL);

	this = (struct impl *) handle;

	if (type == SPA_TYPE_INTERFACE_Monitor)
		*interface = &this->monitor;
	else
		return -ENOENT;

	return 0;
}

static int impl_clear(struct spa_handle *handle)
{
	return impl_monitor_set_callbacks(handle, NULL, NULL);
}

static size_t
impl_get_size(const struct spa_handle_factory *factory,
	      const struct spa_dict *params)
{
	return sizeof(struct impl);
}

static int
impl_init(const struct spa_handle_factory *factory,
	  struct spa_handle *handle,
	  const struct spa_dict *info,
	  const struct spa_support *support,
	  uint32_t n_support)
{
	struct impl *this;
	uint32_t i;

	spa_return_val_if_fail(factory != NULL, -EINVAL);
	spa_return_val_if_fail(handle != NULL, -EINVAL);

	handle->get_interface = impl_get_interface;
	handle->clear = impl_clear;

	this = (struct impl *) handle;

	this->monitor.iface = SPA_INTERFACE_INIT(
			SPA_TYPE_INTERFACE_Monitor,
			SPA_VERSION_MONITOR,
			&impl_monitor, this);

	for (i = 0; i < n_support; i++) {
		switch (support[i].type) {
		case SPA_TYPE_INTERFACE_Log:
			this->log = support[i].data;
			break;
		case SPA_TYPE_INTERFACE_DBus:
			this->dbus = support[i].data;
			break;
		}
	}

	if (this->dbus == NULL) {
		spa_log_error(this->log, "a dbus is needed");
		return -EINVAL;
	}

	this->dbus_connection = spa_dbus_get_connection(this->dbus, DBUS_BUS_SYSTEM);
	if (this->dbus_connection == NULL) {
		spa_log_error(this->log, "no dbus connection");
		return -EIO;
	}

	this->conn = spa_dbus_connection_get(this->dbus_connection);

	spa_list_init(&this->pcm_list);

	return 0;
}

static const struct spa_interface_info impl_interfaces[] = {
	{SPA_TYPE_INTERFACE_Monitor,},
};

static int
impl_enum_interface_info(const struct spa_handle_factory *factory,
			 const struct spa_interface_info **info,
			 uint32_t *index)
{
	spa_return_val_if_fail(factory != NULL, -EINVAL);
	spa_return_val_if_fail(info != NULL, -EINVAL);
	spa_return_val_if_fail(index != NULL, -EINVAL);

	if (*index >= SPA_N_ELEMENTS(impl_interfaces))
		return 0;

	*info = &impl_interfaces[(*index)++];

	return 1;
}

static const struct spa_dict_item handle_info_items[] = {
	{ SPA_KEY_FACTORY_AUTHOR, "George Kiagiadakis <george.kiagiadakis@collabora.com>" },
	{ SPA_KEY_FACTORY_DESCRIPTION, "Monitor that exposes bluez-alsa PCM objects as devices" },
};

static const struct spa_dict handle_info = SPA_DICT_INIT_ARRAY(handle_info_items);

const struct spa_handle_factory spa_bluealsa_monitor_factory = {
	SPA_VERSION_HANDLE_FACTORY,
	SPA_NAME_API_BLUEALSA_MONITOR,
	&handle_info,
	impl_get_size,
	impl_init,
	impl_enum_interface_info,
};
