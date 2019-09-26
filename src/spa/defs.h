/* Bluez-Alsa SPA plugin
 *
 * Copyright © 2018 Wim Taymans
 * Copyright © 2019 Collabora Ltd.
 *    @author George Kiagiadakis <george.kiagiadakis@collabora.com>
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef SPA_BLUEALSA_DEFS_H
#define SPA_BLUEALSA_DEFS_H

#include <errno.h>
#include <stddef.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <fcntl.h>

#include <dbus/dbus.h>

#include <spa/support/log.h>
#include <spa/support/loop.h>
#include <spa/support/dbus.h>
#include <spa/monitor/device.h>
#include <spa/monitor/monitor.h>
#include <spa/monitor/utils.h>
#include <spa/utils/hook.h>
#include <spa/utils/type.h>
#include <spa/utils/keys.h>
#include <spa/utils/names.h>

#include "shared/dbus-client.h"

#define SPA_NAME_API_BLUEALSA_MONITOR "api.bluealsa.monitor"
#define SPA_NAME_API_BLUEALSA_DEVICE "api.bluealsa.device"

#define SPA_KEY_API_BLUEALSA_PCM_PATH "api.bluealsa.pcm.path"
#define SPA_KEY_API_BLUEALSA_PCM_POINTER "api.bluealsa.pcm.pointer"
#define SPA_KEY_API_BLUEALSA_PCM_PROFILE "api.bluealsa.pcm.profile"

struct spa_bluealsa_pcm {
	struct spa_list link;
	uint32_t id;
	struct ba_pcm ba_pcm;
	struct spa_callbacks callbacks;
};

/* callbacks called by the monitor to notify the device */
struct spa_bluealsa_pcm_events {
	void (*properties_changed) (void *object);
};

static inline const char *spa_bluealsa_pcm_profile_name(struct spa_bluealsa_pcm *pcm)
{
	if (pcm->ba_pcm.flags & BA_PCM_FLAG_PROFILE_A2DP)
		return "a2dp";
	else if (pcm->ba_pcm.flags & BA_PCM_FLAG_PROFILE_SCO)
		return "sco";
	else
		return "unknown";
}

#endif
