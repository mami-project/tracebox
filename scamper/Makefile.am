# $Id: Makefile.am,v 1.23 2013/08/04 19:51:31 mjl Exp $

AUTOMAKE_OPTIONS = subdir-objects

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/scamper

bin_PROGRAMS = scamper

lib_LTLIBRARIES = libscamperfile.la

libscamperfile_la_LDFLAGS = -version-info 0:0:0

libscamperfile_la_SOURCES = \
	../mjl_splaytree.c \
	../utils.c \
	scamper_file.c \
	scamper_file_arts.c \
	scamper_file_warts.c \
	scamper_file_text.c \
	scamper_addr.c \
	scamper_list.c \
	scamper_icmpext.c \
	trace/scamper_trace.c \
	trace/scamper_trace_warts.c \
	trace/scamper_trace_text.c \
	trace/scamper_trace_json.c \
	ping/scamper_ping.c \
	ping/scamper_ping_warts.c \
	ping/scamper_ping_text.c \
	ping/scamper_ping_json.c \
	tracelb/scamper_tracelb.c \
	tracelb/scamper_tracelb_warts.c \
	tracelb/scamper_tracelb_text.c \
	dealias/scamper_dealias.c \
	dealias/scamper_dealias_warts.c \
	dealias/scamper_dealias_text.c \
	dealias/scamper_dealias_json.c \
	sting/scamper_sting.c \
	sting/scamper_sting_warts.c \
	sting/scamper_sting_text.c \
	neighbourdisc/scamper_neighbourdisc.c \
	neighbourdisc/scamper_neighbourdisc_warts.c \
	tbit/scamper_tbit.c \
	tbit/scamper_tbit_warts.c \
	tbit/scamper_tbit_text.c \
	tracebox/scamper_tracebox.c \
	tracebox/scamper_tracebox_warts.c \
	tracebox/scamper_tracebox_text.c \
	tracebox/scamper_tracebox_json.c \
	sniff/scamper_sniff.c \
	sniff/scamper_sniff_warts.c

scamper_SOURCES = \
	../mjl_list.c \
	../mjl_heap.c \
	../mjl_splaytree.c \
	../utils.c \
	scamper.c \
	scamper_osinfo.c \
	scamper_addr.c \
	scamper_list.c \
	scamper_debug.c \
	scamper_udp4.c \
	scamper_udp6.c \
	scamper_icmp4.c \
	scamper_icmp6.c \
	scamper_icmp_resp.c \
	scamper_icmpext.c \
	scamper_tcp4.c \
	scamper_tcp6.c \
	scamper_ip6.c \
	scamper_ip4.c \
	scamper_if.c \
	scamper_rtsock.c \
	scamper_dl.c \
	scamper_addr2mac.c \
	scamper_fds.c \
	scamper_linepoll.c \
	scamper_writebuf.c \
	scamper_dlhdr.c \
	scamper_privsep.c \
	scamper_getsrc.c \
	scamper_control.c \
	scamper_firewall.c \
	scamper_outfiles.c \
	scamper_probe.c \
	scamper_task.c \
	scamper_queue.c \
	scamper_cyclemon.c \
	scamper_options.c \
	scamper_file.c \
	scamper_file_arts.c \
	scamper_file_warts.c \
	scamper_file_text.c \
	scamper_sources.c \
	scamper_source_cmdline.c \
	scamper_source_control.c \
	scamper_source_file.c \
	scamper_source_tsps.c \
	trace/scamper_trace.c \
	trace/scamper_trace_warts.c \
	trace/scamper_trace_text.c \
	trace/scamper_trace_json.c \
	trace/scamper_trace_do.c \
	ping/scamper_ping.c \
	ping/scamper_ping_warts.c \
	ping/scamper_ping_text.c \
	ping/scamper_ping_json.c \
	ping/scamper_ping_do.c \
	tracelb/scamper_tracelb.c \
	tracelb/scamper_tracelb_warts.c \
	tracelb/scamper_tracelb_text.c \
	tracelb/scamper_tracelb_do.c \
	dealias/scamper_dealias.c \
	dealias/scamper_dealias_warts.c \
	dealias/scamper_dealias_text.c \
	dealias/scamper_dealias_json.c \
	dealias/scamper_dealias_do.c \
	sting/scamper_sting.c \
	sting/scamper_sting_warts.c \
	sting/scamper_sting_text.c \
	sting/scamper_sting_do.c \
	neighbourdisc/scamper_neighbourdisc.c \
	neighbourdisc/scamper_neighbourdisc_warts.c \
	neighbourdisc/scamper_neighbourdisc_do.c \
	tbit/scamper_tbit.c \
	tbit/scamper_tbit_warts.c \
	tbit/scamper_tbit_text.c \
	tbit/scamper_tbit_do.c \
	tracebox/scamper_tracebox.c \
	tracebox/scamper_tracebox_warts.c \
	tracebox/scamper_tracebox_text.c \
	tracebox/scamper_tracebox_do.c \
	tracebox/scamper_tracebox_json.c \
	sniff/scamper_sniff.c \
	sniff/scamper_sniff_warts.c \
	sniff/scamper_sniff_do.c

scamper_CFLAGS = $(AM_CFLAGS)

include_HEADERS = \
	../mjl_list.h \
	../mjl_heap.h \
	../mjl_splaytree.h \
	../utils.h \
	../internal.h \
   scamper.h \
	scamper_osinfo.h \
	scamper_addr.h \
	scamper_list.h \
	scamper_debug.h \
	scamper_udp4.h \
	scamper_udp6.h \
	scamper_icmp4.h \
	scamper_icmp6.h \
	scamper_icmp_resp.h \
	scamper_icmpext.h \
	scamper_tcp4.h \
	scamper_tcp6.h \
	scamper_ip6.h \
	scamper_ip4.h \
	scamper_if.h \
	scamper_rtsock.h \
	scamper_dl.h \
	scamper_addr2mac.h \
	scamper_fds.h \
	scamper_linepoll.h \
	scamper_writebuf.h \
	scamper_dlhdr.h \
	scamper_privsep.h \
	scamper_getsrc.h \
	scamper_control.h \
	scamper_firewall.h \
	scamper_outfiles.h \
	scamper_probe.h \
	scamper_task.h \
	scamper_queue.h \
	scamper_cyclemon.h \
	scamper_options.h \
	scamper_file.h \
	scamper_file_arts.h \
	scamper_file_warts.h \
	scamper_file_text.h \
	scamper_sources.h \
	scamper_source_cmdline.h \
	scamper_source_control.h \
	scamper_source_file.h \
	scamper_source_tsps.h \
	trace/scamper_trace.h \
	trace/scamper_trace_warts.h \
	trace/scamper_trace_text.h \
	trace/scamper_trace_json.h \
	trace/scamper_trace_do.h \
	ping/scamper_ping.h \
	ping/scamper_ping_warts.h \
	ping/scamper_ping_text.h \
	ping/scamper_ping_json.h \
	ping/scamper_ping_do.h \
	tracelb/scamper_tracelb.h \
	tracelb/scamper_tracelb_warts.h \
	tracelb/scamper_tracelb_text.h \
	tracelb/scamper_tracelb_do.h \
	dealias/scamper_dealias.h \
	dealias/scamper_dealias_warts.h \
	dealias/scamper_dealias_text.h \
	dealias/scamper_dealias_json.h \
	dealias/scamper_dealias_do.h \
	sting/scamper_sting.h \
	sting/scamper_sting_warts.h \
	sting/scamper_sting_text.h \
	sting/scamper_sting_do.h \
	neighbourdisc/scamper_neighbourdisc.h \
	neighbourdisc/scamper_neighbourdisc_warts.h \
	neighbourdisc/scamper_neighbourdisc_do.h \
	tbit/scamper_tbit.h \
	tbit/scamper_tbit_warts.h \
	tbit/scamper_tbit_text.h \
	tbit/scamper_tbit_do.h \
	tracebox/scamper_tracebox.h \
	tracebox/scamper_tracebox_warts.h \
	tracebox/scamper_tracebox_text.h \
	tracebox/scamper_tracebox_do.h \
	tracebox/scamper_tracebox_json.h \
	sniff/scamper_sniff.h \
	sniff/scamper_sniff_warts.h \
	sniff/scamper_sniff_do.h

dist_man_MANS = \
	scamper.1 \
	libscamperfile.3 \
	warts.5

CLEANFILES = *~ *.core scamper.1.html \
	trace/*~ ping/*~ tracelb/*~ dealias/*~ sting/*~ \
	neighbourdisc/*~ tbit/*~ tracebox/*~ sniff/*~
