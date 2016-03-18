/*
 * scamper_file_text_tracebox.c
 *
 *
 *
 * @author: K.Edeline
 */

#ifndef lint
static const char rcsid[] =
  "$Id";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include <string.h>

#include "scamper_addr.h"
#include "scamper_list.h"
#include "scamper_file.h"
#include "scamper_tracebox.h"
#include "scamper_tracebox_text.h"
#include "utils.h"

static char * scamper_tracebox_icmp2text(const scamper_tracebox_t *tracebox, const uint8_t code,char *buf, size_t bufsize, size_t *soff) {
   char *c;
   if (!tracebox->ipv6) {
      string_concat(buf, bufsize, soff, " icmp ");

      switch (code) {
         case ICMP_UNREACH_NET:           c = "net";           break;
         case ICMP_UNREACH_HOST:          c = "host";          break;
         case ICMP_UNREACH_PROTOCOL:      c = "protocol";      break;
         case ICMP_UNREACH_PORT:          c = "port";          break;
         case ICMP_UNREACH_SRCFAIL:       c = "src-rt failed"; break;
         case ICMP_UNREACH_NET_UNKNOWN:   c = "net unknown";   break;
         case ICMP_UNREACH_HOST_UNKNOWN:  c = "host unknown";  break;
         case ICMP_UNREACH_ISOLATED:      c = "isolated";      break;
         case ICMP_UNREACH_NET_PROHIB:    c = "net prohib";    break;
         case ICMP_UNREACH_HOST_PROHIB:   c = "host prohib";   break;
         case ICMP_UNREACH_TOSNET:        c = "tos net";       break;
         case ICMP_UNREACH_TOSHOST:       c = "tos host";      break;
         case ICMP_UNREACH_FILTER_PROHIB: c = "admin prohib";  break;
         default:                         c = "unknown";       break;
      }
   } else {
      string_concat(buf, bufsize, soff, " icmp6 ");
      switch (code) {
         case ICMP6_DST_UNREACH_NOROUTE:     c = "no route";     break;
         case ICMP6_DST_UNREACH_ADMIN:       c = "admin prohib"; break;
         case ICMP6_DST_UNREACH_BEYONDSCOPE: c = "beyond scope"; break;
         case ICMP6_DST_UNREACH_ADDR:        c = "addr";         break;
         case ICMP6_DST_UNREACH_NOPORT:      c = "port";         break;
         default:                            c = "unknown";      break;
      }
   }
   string_concat(buf, bufsize, soff, " %s", c);
}

static void scamper_file_text_tracebox_write_fields(const scamper_tracebox_t *tracebox, 
                                                   scamper_tracebox_hop_field_t **fields, 
                                                   uint8_t field_count, char* prefix, 
                                                   char *buf, size_t bufsize, size_t *soff) {
   scamper_tracebox_hop_field_t *field;
   int i, j;
   uint8_t len;

   for (i=0; i < field_count; i++) {
      field = fields[i];
      string_concat(buf, bufsize, soff, " %s", prefix);
      if (field->is_opt) {
         const char *name = scamper_tracebox_tcp_options[field->name]; 
         len = field->value_len;
         string_concat(buf, bufsize, soff, "TCP::Options::%s", name);
      } else {
         const char *name = scamper_tracebox_fields[field->name];
         len  = scamper_tracebox_fields_size[field->name];
         string_concat(buf, bufsize, soff, "%s", name);
      }

      /* write field value */
      if (tracebox->print_values) {
         string_concat(buf, bufsize, soff, "(");
         for (j=0; j < len; j++)
            string_concat(buf, bufsize, soff, "%.2x", field->value[j]);
         string_concat(buf, bufsize, soff, ")");
      }
      
   }
   return;
}

static int scamper_file_text_tracebox_write_standard(const scamper_tracebox_t *tracebox, 
      char *buf, size_t bufsize, size_t *soff) {

   scamper_tracebox_hop_t *hop;
   int i;
   char tmp[128];

   static char *q4[] = {
    "( 0/40)",               
    "(20/40)",
    "(28/40)",
    "(40/40)",
    ""
   };
   static char *q6[] = {
    "( 0/60)",               
    "(40/60)",
    "(48/60)",
    "(60/60)",
    ""
   };

   for (i=0; i<tracebox->hop_count; i++) {
      hop = tracebox->hops[i];
      
      string_concat(buf, bufsize, soff, " %2d:", i+1);
      if (hop->hop_addr == NULL) {
         string_concat(buf, bufsize, soff, " *\n");
         continue;
      } 

      if (tracebox->ipv6) {
         string_concat(buf, bufsize, soff, " %s ", 
               scamper_addr_tostr(hop->hop_addr, tmp, sizeof(tmp)));
      } else {
         string_concat(buf, bufsize, soff, " %-15s", 
               scamper_addr_tostr(hop->hop_addr, tmp, sizeof(tmp)));
      }

      if (tracebox->icmp_quote_type)
         string_concat(buf, bufsize, soff, " %s", 
             tracebox->ipv6 ? q6[hop->hop_quoted_size] : q4[hop->hop_quoted_size]);
      if (tracebox->rtt) 
         string_concat(buf, bufsize, soff, " (%s ms)", timeval_tostr(&hop->hop_rtt, tmp, sizeof(tmp)));


       scamper_file_text_tracebox_write_fields(tracebox,
            hop->modifications, 
           hop->modifications_count, "", buf, bufsize, soff);
       scamper_file_text_tracebox_write_fields(tracebox, hop->deletions, 
           hop->deletions_count, "-", buf, bufsize, soff);
       scamper_file_text_tracebox_write_fields(tracebox, hop->additions, 
           hop->additions_count, "+", buf, bufsize, soff);

       string_concat(buf, bufsize, soff, "\n");
   }

   return 0;
}

static char *last_observed_value(uint8_t *dlens, char **addrs, 
                                 uint8_t index, uint8_t field) {
   int i;
   uint8_t min_type;

   if      (field>=14) min_type = SCAMPER_TRACEBOX_ANSWER_ONLY_L3;
   else if (field>=7)  min_type = SCAMPER_TRACEBOX_ANSWER_8B; 
   else                min_type = SCAMPER_TRACEBOX_ANSWER_FULL;

   for(i=index; i>=0; i--) {
      if (dlens[i] >= min_type) 
         return addrs[i];
   }

   return "you";
}

static int scamper_file_text_tracebox_write_proxy(const scamper_tracebox_t *tracebox,char *buf, size_t bufsize, size_t *soff) {

  if (tracebox->result != SCAMPER_TRACEBOX_RESULT_SUCCESS) return 1;

  scamper_tracebox_pkt_t *pkt; 
  uint32_t i;
  uint8_t proto = 0, ttl = 0, last_ttl = 0, v, tcp_ttl = 0, udp_ttl = 0, loop = 0;

  for(i=0; i<tracebox->pktc; i++) {
    pkt = tracebox->pkts[i];
    v = 0;

    if(((pkt->data[0] & 0xf0) >> 4) == 4) {
      v = 4;
      proto = pkt->data[9];
      ttl=pkt->data[8];
    } else if(((pkt->data[0] & 0xf0) >> 4) == 6) {
      v = 6;
      proto = pkt->data[6];
      ttl= pkt->data[7];   
    } else continue;

    if(proto == IPPROTO_TCP) {
      if (pkt->dir == SCAMPER_TRACEBOX_PKT_DIR_TX) 
	tcp_ttl=ttl;

    } else if (proto == IPPROTO_UDP) {

      if (pkt->dir == SCAMPER_TRACEBOX_PKT_DIR_TX) 
	udp_ttl=ttl;         
    } 
  }

  if (tcp_ttl<udp_ttl)
    string_concat(buf, bufsize, soff, " There is a proxy between you and the destination.\n"); 
  else
    string_concat(buf, bufsize, soff, " No proxy between you and the destination was detected.\n");  

  return 0;
}

static int scamper_file_text_tracebox_write_statefull(
      const scamper_tracebox_t *tracebox, char *buf, 
      size_t bufsize, size_t *soff, char* dst) {

   if (tracebox->result == SCAMPER_TRACEBOX_RESULT_SUCCESS) 
      return 1;

   scamper_tracebox_pkt_t *pkt; 
   uint32_t i;
   uint8_t proto = 0, ttl = 0, last_ttl = 0, v;
   uint8_t srv_ttl = 0, loop = 0, retries = 0;

   for (i=0; i<tracebox->pktc; i++) {
      pkt = tracebox->pkts[i];v = 0;

      if (((pkt->data[0] & 0xf0) >> 4) == 4) {
         v = 4;
         proto = pkt->data[9];
         ttl=pkt->data[8];
      } else if (((pkt->data[0] & 0xf0) >> 4) == 6) {
         v = 6;
         proto = pkt->data[6];
         ttl= pkt->data[7];   
      } else continue;

      if (proto == IPPROTO_TCP) {
         if (last_ttl > ttl) { 
            if (loop == 0) srv_ttl=last_ttl;
            loop++;
            retries=0;
         } else if (last_ttl == ttl) 
            retries++;
         else retries=0;

         /* early MB */
         if (retries == 3) { 
            loop++;      
            retries=0;
         }

         if (pkt->dir == SCAMPER_TRACEBOX_PKT_DIR_RX) {

            if (loop == 2) {
               if (ttl == srv_ttl) {
                  string_concat(buf, bufsize, soff, 
                     " There is no statefull middlebox between you and the destination.\n"); 
                  return 0;
               } 

            } else if (loop == 4) {
               if (ttl == srv_ttl) {
                  string_concat(buf, bufsize, soff, 
                     " There is a statefull middlebox between you and the destination.\n");
                  return 0;
               }
            } 
         }
         last_ttl=ttl;
      }
   }

   return 0;
}

int scamper_file_text_tracebox_write(const scamper_file_t *sf,
				     const scamper_tracebox_t *tracebox) { 

   const int bufsize = 131072;
   char buf[bufsize];
   char src[64], dst[64], tmp[256];
   int fd = scamper_file_getfd(sf);
   size_t soff = 0;

   string_concat(buf, sizeof(buf), &soff,
	   "tracebox %s mode from %s to %s\n result: %s\n", 
      scamper_tracebox_modes[tracebox->printmode],
	   scamper_addr_tostr(tracebox->src, src, sizeof(src)),
	   scamper_addr_tostr(tracebox->dst, dst, sizeof(dst)),
	   scamper_tracebox_res2str(tracebox, tmp, sizeof(tmp)));

   switch (tracebox->printmode) {
      case TRACEBOX_PRINT_MODE_PROXY:
         scamper_file_text_tracebox_write_proxy(tracebox,buf,bufsize,&soff);
         break;                               
      case TRACEBOX_PRINT_MODE_STATEFULL:  
         scamper_file_text_tracebox_write_statefull(tracebox,buf,bufsize,&soff,dst);
         break;                                                  
      case TRACEBOX_PRINT_MODE_STANDARD:           
      default:
         scamper_file_text_tracebox_write_standard(tracebox,buf,bufsize,&soff);
         break;
   }
   write_wrap(fd, buf, NULL, soff);
   return 0;
}

