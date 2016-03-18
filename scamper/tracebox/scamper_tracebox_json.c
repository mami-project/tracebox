/*
 * scamper_tracebox_json.c
 *
 * Copyright (C) 2003-2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
 * Copyright (C) 2011-2013 Internap Network Services Corporation
 * Copyright (C) 2013      The Regents of the University of California
 * Authors: Brian Hammond, Matthew Luckie, K.Edeline
 *
 * $Id: scamper_tracebox_json.c,v 1.4 2013/07/31 17:42:42 mjl Exp $
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#ifndef lint
static const char rcsid[] =
  "$Id: scamper_tracebox_json.c,v 1.4 2013/07/31 17:42:42 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_addr.h"
#include "scamper_list.h"
#include "scamper_tracebox.h"
#include "scamper_file.h"
#include "scamper_tracebox_json.h"
#include "utils.h"

static char *fields_tostr(scamper_tracebox_hop_field_t **fields, uint8_t field_count) {
   char buf[1024];
   size_t off = 0;
   uint8_t i, j, len;
   scamper_tracebox_hop_field_t *field;

   string_concat(buf, sizeof(buf), &off, "[");
   for (i=0; i < field_count; i++) {
      field = fields[i];
      if (i > 0) string_concat(buf, sizeof(buf), &off, ", ");

      if (field->is_opt) {
         const char *name = scamper_tracebox_tcp_options[field->name]; 
         len = field->value_len;
         string_concat(buf, sizeof(buf), &off, 
            "{\"name\":\"TCP::Options::%s\", \"value\":\"", name);
      } else {
         const char *name = scamper_tracebox_fields[field->name];
         len  = scamper_tracebox_fields_size[field->name];
         string_concat(buf, sizeof(buf), &off, "{\"name\":\"%s\", \"value\":\"", 
              name);
      }


      for (j=0; j < len; j++)
         string_concat(buf, sizeof(buf), &off, "%.2x", field->value[j]);
      string_concat(buf, sizeof(buf), &off, "\"}");
      
   }
   string_concat(buf, sizeof(buf), &off, "]");
   return strdup(buf);
}

static char *hop_tostr(scamper_tracebox_hop_t *hop)
{
   char buf[4096], tmp[128];
   char *buf_modif, *buf_add, *buf_del;
   size_t off = 0;

   if (hop->hop_addr != NULL) {

      string_concat(buf, sizeof(buf), &off,	"{\"addr\":\"%s\"",
	      scamper_addr_tostr(hop->hop_addr, tmp, sizeof(tmp)));
      string_concat(buf, sizeof(buf), &off,
	      ", \"probe_ttl\":%u, \"icmp_size\":%u", 
	      hop->hop_probe_ttl, hop->hop_quoted_size);
      string_concat(buf, sizeof(buf), &off, ", \"rtt\":%s",
	      timeval_tostr(&hop->hop_rtt, tmp, sizeof(tmp)));
   } else {

      string_concat(buf, sizeof(buf), &off,	"{\"addr\":\"*\"");
      string_concat(buf, sizeof(buf), &off,
	      ", \"probe_ttl\":%u, \"icmp_size\":%u", 
	      hop->hop_probe_ttl, 0);
      string_concat(buf, sizeof(buf), &off, ", \"rtt\":0");
   }

   buf_modif = fields_tostr(hop->modifications, hop->modifications_count);
   string_concat(buf, sizeof(buf), &off, ", \"modifications\":");
   string_concat(buf, sizeof(buf), &off, buf_modif);
   buf_add = fields_tostr(hop->additions, hop->additions_count);
   string_concat(buf, sizeof(buf), &off, ", \"additions\":");
   string_concat(buf, sizeof(buf), &off, buf_add);
   buf_del = fields_tostr(hop->deletions, hop->deletions_count);
   string_concat(buf, sizeof(buf), &off, ", \"deletions\":");
   string_concat(buf, sizeof(buf), &off, buf_del);

   string_concat(buf, sizeof(buf), &off, "}");

   free(buf_modif); 
   free(buf_add); 
   free(buf_del);
   
   return strdup(buf);
}

static char *header_tostr(const scamper_tracebox_t *tracebox)
{
  char buf[2048], tmp[64];
  const char *ptr;
  size_t off = 0;
  time_t tt = tracebox->start.tv_sec;

  string_concat(buf, sizeof(buf), &off, 
      "\"version\":\"0.1\",\"type\":\"tracebox\"");
  string_concat(buf, sizeof(buf), &off, ", \"userid\":%u", tracebox->userid);
  if (tracebox->raw_packet) {
     string_concat(buf, sizeof(buf), &off, ", \"method\":\"raw\"");
  } else {
     string_concat(buf, sizeof(buf), &off, ", \"method\":\"%s-", 
                     tracebox->ipv6 ? "ip6" : "ip4");
     string_concat(buf, sizeof(buf), &off, "%s\"", 
                     tracebox->udp ? "udp" : "tcp");
  }

  string_concat(buf, sizeof(buf), &off, ", \"probe\":\"%s\"", 
               (tracebox->probe != NULL) ? tracebox->probe : "default");
  string_concat(buf, sizeof(buf), &off, ", \"src\":\"%s\"",
		scamper_addr_tostr(tracebox->src, tmp, sizeof(tmp)));
  string_concat(buf, sizeof(buf), &off, ", \"dst\":\"%s\"",
		scamper_addr_tostr(tracebox->dst, tmp, sizeof(tmp)));
  string_concat(buf, sizeof(buf), &off, ", \"sport\":%u, \"dport\":%u",
	  tracebox->sport, tracebox->dport);
  string_concat(buf, sizeof(buf), &off,
		", \"result\":\"%s\"",
		scamper_tracebox_res2str(tracebox, tmp, sizeof(tmp)));
  strftime(tmp, sizeof(tmp), "%Y-%m-%d %H:%M:%S", localtime(&tt));
  string_concat(buf, sizeof(buf), &off,
		", \"start\":{\"sec\":%u, \"usec\":%u, \"ftime\":\"%s\"}",
		tracebox->start.tv_sec, tracebox->start.tv_usec, tmp);
  string_concat(buf, sizeof(buf), &off,
		", \"attempts\":%u, \"hoplimit\":%u, \"wait\":%u",
		TRACEBOX_SINGLE_HOP_MAX_REPLAYS, TRACEBOX_MAX_HOPS, 
      TRACEBOX_TIMEOUT_DEFAULT);

  string_concat(buf, sizeof(buf), &off,	
      ", \"ip_ect\":%u, \"ip_ce\":%u",
		tracebox->ect, tracebox->ce);
  string_concat(buf, sizeof(buf), &off,	
      ", \"ip_dscp\":%u, \"ip_id\":%u, \"ip_id_value\":%u",
		tracebox->dscp, tracebox->ipid, tracebox->ipid_value);
  string_concat(buf, sizeof(buf), &off,	
      ", \"tcp_flags\":%u, \"tcp_ece\":%u",
		tracebox->flags, tracebox->ece);
  string_concat(buf, sizeof(buf), &off,	
      ", \"tcp_seq\":%u, \"tcp_ack\":%u, \"tcp_win\":%u",
		tracebox->seq, 0, TRACEBOX_DEFAULT_TCPWIN);

  string_concat(buf, sizeof(buf), &off,	
      ", \"tcp_opt_mss\":%u, \"tcp_opt_wscale\":%u",
		tracebox->mss, tracebox->wscale);

  string_concat(buf, sizeof(buf), &off,	
      ", \"tcp_opt_sackp\":%u, \"tcp_opt_sack\":%u",
		tracebox->sackp, tracebox->sack);
  string_concat(buf, sizeof(buf), &off,	
      ", \"tcp_opt_sack_sle\":%u, \"tcp_opt_sack_sre\":%u",
		tracebox->sack_sle, tracebox->sack_sre);

  string_concat(buf, sizeof(buf), &off,	
      ", \"tcp_opt_mp_capable\":%u, \"tcp_opt_mp_join\":%u",
		tracebox->mpcapable, tracebox->mpjoin);
  string_concat(buf, sizeof(buf), &off,	
        ", \"tcp_opt_mp_capable_h_skey\":%u, \"tcp_opt_mp_capable_l_skey;\":%u",
		tracebox->h_skey, tracebox->l_skey);
  string_concat(buf, sizeof(buf), &off,	
      ", \"tcp_opt_mp_join_rec_token\":%u, \"tcp_opt_mp_join_send_rnum;\":%u",
		tracebox->rec_token, tracebox->send_rnum);

  string_concat(buf, sizeof(buf), &off,	
      ", \"tcp_opt_ts\":%u, \"tcp_opt_tsval\":%u, \"tcp_opt_tsecr\":%u",
		tracebox->ts, tracebox->tsval, tracebox->tsecr);

  return strdup(buf);
}

int scamper_file_json_tracebox_write(const scamper_file_t *sf,
				  const scamper_tracebox_t *tracebox) {
   scamper_tracebox_hop_t *hop;
   int fd = scamper_file_getfd(sf);
   size_t wc, len, off = 0;
   off_t foff = 0;
   char *str = NULL, *header = NULL, **hops = NULL;
   int hopc, i, j, rc = -1;

   if(fd != STDOUT_FILENO && (foff = lseek(fd, 0, SEEK_CUR)) == -1)
      return -1;

   if((header = header_tostr(tracebox)) == NULL)
      goto cleanup;
   len = strlen(header);
   
   hopc = tracebox->hop_count;
   if (hopc > 0) {
      len += 11; // , "hops":[] 
      if ((hops = malloc_zero(sizeof(char *) * hopc)) == NULL)
         goto cleanup;
      for (i=0, j=0; i<tracebox->hop_count; i++) {
         hop = tracebox->hops[i];
         if (j > 0) len++; // , 
         if ((hops[j] = hop_tostr(hop)) == NULL)
            goto cleanup;
         len += strlen(hops[j]);
         j++;
      }
   }
   len += 4; // {}\n\0 
   
   if ((str = malloc(len)) == NULL)
      goto cleanup;

   string_concat(str, len, &off, "{%s", header);
   if (hopc > 0) {
      string_concat(str, len, &off, ", \"hops\":[");
      for (j=0; j<hopc; j++) {
         if (j > 0) string_concat(str, len, &off, ",");
         string_concat(str, len, &off, "%s", hops[j]);
      }
      string_concat(str, len, &off, "]");
   }
   string_concat(str, len, &off, "}\n");
   assert(off+1 == len);

   if (write_wrap(fd, str, &wc, off) != 0) {
      if (fd != STDOUT_FILENO) {
         if(ftruncate(fd, foff) != 0)
            goto cleanup;
      }
      goto cleanup;
   }

   rc = 0; /* we succeeded */

cleanup:
   if(hops != NULL) {
      for(i=0; i<hopc; i++)
         if(hops[i] != NULL)
            free(hops[i]);
         free(hops);
   }
   if(header != NULL) free(header);
   if(str != NULL) free(str);

   return rc;
}
