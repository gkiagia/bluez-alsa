/* Bluez-Alsa SPA plugin
 *
 * Copyright © 2019 Collabora Ltd.
 *    @author George Kiagiadakis <george.kiagiadakis@collabora.com>
 *
 * SPDX-License-Identifier: MIT
 */

#include <errno.h>
#include <stdio.h>

#include <spa/support/plugin.h>

extern const struct spa_handle_factory spa_bluealsa_monitor_factory;
extern const struct spa_handle_factory spa_bluealsa_device_factory;

SPA_EXPORT
int spa_handle_factory_enum(const struct spa_handle_factory **factory,
	uint32_t *index)
{
	spa_return_val_if_fail(factory != NULL, -EINVAL);
	spa_return_val_if_fail(index != NULL, -EINVAL);

	switch (*index) {
	case 0:
		*factory = &spa_bluealsa_monitor_factory;
		break;
	case 1:
		*factory = &spa_bluealsa_device_factory;
		break;
	default:
		return 0;
	}
	(*index)++;
	return 1;
}
