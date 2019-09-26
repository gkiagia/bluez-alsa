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

#define ID_SOURCE 0
#define ID_SINK 1

struct impl {
	/* object */
	struct spa_handle handle;
	struct spa_device device;

	/* support */
	struct spa_log *log;

	/* device */
	struct spa_bluealsa_pcm *pcm;
	struct spa_hook_list hooks;
	bool has_node[2];
};

static void emit_nodes(struct impl *this)
{
	struct spa_bluealsa_pcm *pcm = this->pcm;
	struct spa_device_object_info info;
	struct spa_dict_item items[10];
	uint32_t n_items = 0;
	char alsa_dev[128] = {0};
	char addr[19] = {0};

	ba2str(&pcm->ba_pcm.addr, addr);

	/* api.alsa */
	snprintf(alsa_dev, sizeof(alsa_dev), "bluealsa:DEV=%s,PROFILE=%s", addr,
			spa_bluealsa_pcm_profile_name(pcm));
	items[n_items++] = SPA_DICT_ITEM_INIT(SPA_KEY_API_ALSA_PATH, alsa_dev);

	/* api.bluez5 */
	items[n_items++] = SPA_DICT_ITEM_INIT(SPA_KEY_API_BLUEZ5_PATH, pcm->ba_pcm.device_path);
	items[n_items++] = SPA_DICT_ITEM_INIT(SPA_KEY_API_BLUEZ5_ADDRESS, addr);

	/* api.bluealsa */
	items[n_items++] = SPA_DICT_ITEM_INIT(SPA_KEY_API_BLUEALSA_PCM_PATH, pcm->ba_pcm.pcm_path);
	items[n_items++] = SPA_DICT_ITEM_INIT(SPA_KEY_API_BLUEALSA_PCM_PROFILE,
						spa_bluealsa_pcm_profile_name(pcm));

	info = SPA_DEVICE_OBJECT_INFO_INIT();
	info.type = SPA_TYPE_INTERFACE_Node;
	info.change_mask = SPA_DEVICE_OBJECT_CHANGE_MASK_PROPS;
	info.props = &SPA_DICT_INIT(items, n_items);

	/* a sink in bluealsa is a source in pipewire and vice versa */
	if (pcm->ba_pcm.flags & BA_PCM_FLAG_SINK && !this->has_node[ID_SOURCE]) {
		info.factory_name = SPA_NAME_API_ALSA_PCM_SOURCE;
		spa_device_emit_object_info(&this->hooks, ID_SOURCE, &info);
	} else if (!(pcm->ba_pcm.flags & BA_PCM_FLAG_SINK) && this->has_node[ID_SOURCE]) {
		spa_device_emit_object_info(&this->hooks, ID_SOURCE, NULL);
	}

	if (pcm->ba_pcm.flags & BA_PCM_FLAG_SOURCE && !this->has_node[ID_SINK]) {
		info.factory_name = SPA_NAME_API_ALSA_PCM_SINK;
		spa_device_emit_object_info(&this->hooks, ID_SINK, &info);
	} else if (!(pcm->ba_pcm.flags & BA_PCM_FLAG_SOURCE) && this->has_node[ID_SINK]) {
		spa_device_emit_object_info(&this->hooks, ID_SINK, NULL);
	}
}

static void pcm_properties_changed(void *object)
{
	struct impl *this = object;
	emit_nodes(this);
}

static const struct spa_bluealsa_pcm_events pcm_events = {
	.properties_changed = pcm_properties_changed,
};

static const struct spa_dict_item info_items[] = {
	{ SPA_KEY_DEVICE_API, "bluealsa" },
	{ SPA_KEY_MEDIA_CLASS, "Audio/Device" },
};

static int impl_add_listener(void *object,
			struct spa_hook *listener,
			const struct spa_device_events *events,
			void *data)
{
	struct impl *this = object;
	struct spa_hook_list save;

	spa_return_val_if_fail(this != NULL, -EINVAL);
	spa_return_val_if_fail(events != NULL, -EINVAL);

	spa_hook_list_isolate(&this->hooks, &save, listener, events, data);

	if (events->info) {
		struct spa_device_info info;

		info = SPA_DEVICE_INFO_INIT();

		info.change_mask = SPA_DEVICE_CHANGE_MASK_PROPS;
		info.props = &SPA_DICT_INIT_ARRAY(info_items);

		info.change_mask |= SPA_DEVICE_CHANGE_MASK_PARAMS;
		info.n_params = 0;
		info.params = NULL;

		spa_device_emit_info(&this->hooks, &info);
	}

	if (events->object_info)
		emit_nodes(this);

	spa_hook_list_join(&this->hooks, &save);

	return 0;
}

static int impl_sync(void *object, int seq)
{
	struct impl *this = object;

	spa_return_val_if_fail(this != NULL, -EINVAL);

	spa_device_emit_result(&this->hooks, seq, 0, 0, NULL);

	return 0;
}

static int impl_enum_params(void *object, int seq,
			    uint32_t id, uint32_t start, uint32_t num,
			    const struct spa_pod *filter)
{
	return -ENOTSUP;
}

static int impl_set_param(void *object,
			  uint32_t id, uint32_t flags,
			  const struct spa_pod *param)
{
	return -ENOTSUP;
}

static const struct spa_device_methods impl_device = {
	SPA_VERSION_DEVICE_METHODS,
	.add_listener = impl_add_listener,
	.sync = impl_sync,
	.enum_params = impl_enum_params,
	.set_param = impl_set_param,
};

static int impl_get_interface(struct spa_handle *handle, uint32_t type, void **interface)
{
	struct impl *this;

	spa_return_val_if_fail(handle != NULL, -EINVAL);
	spa_return_val_if_fail(interface != NULL, -EINVAL);

	this = (struct impl *) handle;

	if (type == SPA_TYPE_INTERFACE_Device)
		*interface = &this->device;
	else
		return -ENOENT;

	return 0;
}

static int impl_clear(struct spa_handle *handle)
{
	struct impl *this;
	struct spa_hook *hook, *tmp;

	spa_return_val_if_fail(handle != NULL, -EINVAL);

	this = (struct impl *) handle;

	if (this->has_node[ID_SOURCE])
		spa_device_emit_object_info(&this->hooks, ID_SOURCE, NULL);
	if (this->has_node[ID_SINK])
		spa_device_emit_object_info(&this->hooks, ID_SINK, NULL);

	spa_list_for_each_safe(hook, tmp, &this->hooks.list, link)
		spa_hook_remove(hook);

	this->pcm->callbacks = SPA_CALLBACKS_INIT(NULL, NULL);

	return 0;
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

	this->device.iface = SPA_INTERFACE_INIT(
			SPA_TYPE_INTERFACE_Device,
			SPA_VERSION_DEVICE,
			&impl_device, this);

	for (i = 0; i < n_support; i++) {
		switch (support[i].type) {
		case SPA_TYPE_INTERFACE_Log:
			this->log = support[i].data;
			break;
		}
	}

	spa_hook_list_init(&this->hooks);

	for (i = 0; info && i < info->n_items; i++) {
		if (strcmp(info->items[i].key, SPA_KEY_API_BLUEALSA_PCM_POINTER) == 0)
			sscanf(info->items[i].value, "pointer:%p", &this->pcm);
	}
	if (this->pcm == NULL) {
		spa_log_error(this->log, "a pcm is needed");
		return -EINVAL;
	}

	this->pcm->callbacks = SPA_CALLBACKS_INIT(&pcm_events, this);

	return 0;
}

static const struct spa_interface_info impl_interfaces[] = {
	{SPA_TYPE_INTERFACE_Device,},
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
	{ SPA_KEY_FACTORY_DESCRIPTION, "A bluez-alsa device" },
	{ SPA_KEY_FACTORY_USAGE, SPA_KEY_API_BLUEALSA_PCM_POINTER"=<pointer>" },
};

static const struct spa_dict handle_info = SPA_DICT_INIT_ARRAY(handle_info_items);

const struct spa_handle_factory spa_bluealsa_device_factory = {
	SPA_VERSION_HANDLE_FACTORY,
	SPA_NAME_API_BLUEALSA_DEVICE,
	&handle_info,
	impl_get_size,
	impl_init,
	impl_enum_interface_info,
};
