spa_bluealsa_LTLIBRARIES = libspa-bluealsa.la

libspa_bluealsa_la_SOURCES = \
	../shared/dbus-client.c \
	device.c \
	monitor.c \
	plugin.c

spa_bluealsadir = @SPA_PLUGIN_DIR@/bluealsa

AM_CFLAGS = \
	-I$(top_srcdir)/src \
	@BLUEZ_CFLAGS@ \
	@DBUS1_CFLAGS@ \
	@SPA_CFLAGS@

AM_LDFLAGS = -module -avoid-version

libspa_bluealsa_la_LIBADD = \
	@BLUEZ_LIBS@ \
	@DBUS1_LIBS@
