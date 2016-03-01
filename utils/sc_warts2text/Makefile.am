AUTOMAKE_OPTIONS = subdir-objects

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/scamper

bin_PROGRAMS = sc_warts2text

sc_warts2text_SOURCES = \
	sc_warts2text.c \
	../../utils.c \
	../../mjl_splaytree.c

sc_warts2text_LDADD = ../../scamper/libscamperfile.la

dist_man_MANS = sc_warts2text.1

CLEANFILES = *~ *.core
