AM_CFLAGS = -I$(top_srcdir)/include $(GLOBAL_CFLAGS) $(libplist_CFLAGS) $(libimobiledevice_CFLAGS) $(libimobiledevice_glue_CFLAGS) $(libgeneral_CFLAGS)
AM_CXXFLAGS = $(AM_CFLAGS) $(GLOBAL_CXXFLAGS)
AM_LDFLAGS = $(libplist_LIBS) $(libimobiledevice_LIBS) $(libimobiledevice_glue_LIBS) $(libgeneral_LIBS)

lib_LTLIBRARIES = libidevicebackup.la

libidevicebackup_la_CFLAGS = $(AM_CFLAGS)
libidevicebackup_la_CXXFLAGS = $(AM_CXXFLAGS)
libidevicebackup_la_LDFLAGS = $(AM_LDFLAGS)
libidevicebackup_la_SOURCES =	libidevicebackup.cpp \
								IBKPexception.cpp
