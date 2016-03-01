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


static char * compute_differences(const scamper_tracebox_t *tracebox, 
                                  const uint8_t *pkt1, const uint8_t *pkt2, 
                                  const uint8_t type, const uint8_t network,
                                  const uint8_t transport);

static void compare_fields(const scamper_tracebox_t *tracebox,
                           unsigned int start, unsigned int end, 
                           uint8_t **ppkt1, uint8_t **ppkt2, size_t bufsize, 
                           size_t *soff, char *buf);


static int scamper_file_text_tracebox_write_standard(const scamper_tracebox_t *tracebox,char *buf, size_t bufsize, size_t *soff) {

   scamper_tracebox_pkt_t *pkt, *prev_pkt = NULL; 

   char addr[64], *cmp_result;
   struct timeval diff;
   uint32_t i, seq, ack, off;
   uint16_t len;
   uint8_t proto, flags, type, iphlen, tcphlen, *ptr, ttl, v, prev_query = 0, synacked = 0;
   int frag, ip_start, trans_start, dlen, counter = 1;
  
   for(i=0; i<tracebox->pktc; i++) {
      pkt = tracebox->pkts[i];
      off = 0; v = 0;

      /* IPv4 */
      if(((pkt->data[0] & 0xf0) >> 4) == 4) {
         v = 4;
         iphlen = (pkt->data[0] & 0xf) * 4;
	      len    = bytes_ntohs(pkt->data+2);
         ttl    = pkt->data[8];
	      proto  = pkt->data[9];
	      off     = (bytes_ntohs(pkt->data+6) & 0x1fff) * 8;

	     scamper_addr_t *tmp_addr = scamper_addr_alloc(SCAMPER_ADDR_TYPE_IPV4, pkt->data+12);
	     scamper_addr_tostr(tmp_addr, addr, sizeof(addr));
	     scamper_addr_free(tmp_addr);

      /* IPv6 */
      } else if(((pkt->data[0] & 0xf0) >> 4) == 6) {
         v = 6;
	      iphlen = 40;
	      len    = bytes_ntohs(pkt->data+4) + iphlen;
	      proto  = pkt->data[6];
         ttl    = pkt->data[7];   

	      scamper_addr_t *tmp_addr = scamper_addr_alloc(SCAMPER_ADDR_TYPE_IPV6, pkt->data+8);
         scamper_addr_tostr(tmp_addr, addr, sizeof(addr));
	      scamper_addr_free(tmp_addr);

      } else {
	      string_concat(buf, bufsize, soff, " erroneous packet\n");
	      return;
      }

      if (synacked) {
	      string_concat(buf, bufsize, soff, " capture error\n");
	      return;
      }

      if(proto == IPPROTO_TCP) {
	      flags   = pkt->data[iphlen+13];
	      tcphlen = ((pkt->data[iphlen+12] & 0xf0) >> 4) * 4;

         /* SYN flag on */
	      if(flags & 0x02) {
            /* ACK flag on */
	         if((flags & 0x10) && pkt->dir == SCAMPER_TRACEBOX_PKT_DIR_RX) {
	            if (!prev_query) {
		            string_concat(buf, bufsize, soff, " bad server behavior\n");
		            continue;
	            }
                      
	            cmp_result = compute_differences(tracebox, prev_pkt->data, pkt->data,
					             SCAMPER_TRACEBOX_ANSWER_SYNACK, v, proto);
	            string_concat(buf, bufsize, soff, " %-15s", addr);
	            if (tracebox->rtt) 
		            string_concat(buf, bufsize, soff, " RTT:%.4f",
			            (((pkt->tv.tv_sec - prev_pkt->tv.tv_sec)*1000000L+pkt->tv.tv_usec) - prev_pkt->tv.tv_usec)/1000.0);
	            if (cmp_result) {
		            string_concat(buf, bufsize, soff, cmp_result);
		            free(cmp_result);
	            }
	            synacked=1;
            } else if (pkt->dir == SCAMPER_TRACEBOX_PKT_DIR_TX) {//SYN

               if (prev_query) {
		            string_concat(buf, bufsize, soff, " *\n");
		            counter++;
	            }
	            string_concat(buf, bufsize, soff, " %2d:", counter);
	            prev_pkt = pkt;

	            prev_query=1;
	            continue;
            }  else {
	            string_concat(buf, bufsize, soff, " erroneous packet\n");
	            return;
	         }
         } else if(flags & 0x01) {
            string_concat(buf, bufsize, soff, " %-15s TCP FIN", addr);
         } else if(flags & 0x04) {
            string_concat(buf, bufsize, soff, " %-15s TCP RST", addr);
         } else {
            string_concat(buf, bufsize, soff, " %-15s erroneous packet\n", addr);
            return;
         }

      } else if(proto == IPPROTO_ICMP) {
	      if (!prev_query) continue;
	      prev_query=0;

	      uint8_t icmp_type = pkt->data[iphlen];
	      uint8_t icmp_code = pkt->data[iphlen+1];
	      ip_start    = iphlen+8;
	      trans_start = ip_start+20;
	      dlen        = len-ip_start;

         if (icmp_type == 11 && icmp_code == 0) {
	         string_concat(buf, bufsize, soff, " %-15s ", addr);

            /* get size of quoted packet */
            char *quote_size;
            if (len-ip_start <= 0) {
               type = SCAMPER_TRACEBOX_ANSWER_EMPTY;
               quote_size = "(0/40)";
	         } else if (len-trans_start <= 0) {
	            type = SCAMPER_TRACEBOX_ANSWER_ONLY_L3;
               quote_size = "(20/40)";
	         } else if (len-trans_start == 8) {
	            type = SCAMPER_TRACEBOX_ANSWER_8B;
               quote_size = "(28/40)";
	         } else {
	            type = SCAMPER_TRACEBOX_ANSWER_FULL;
               quote_size = "(40/40)";
	         }

            if (tracebox->icmp_quote_type)
               string_concat(buf, bufsize, soff, "%-6s", quote_size);
            if (tracebox->rtt) 
	            string_concat(buf, bufsize, soff, " RTT:%.4f",
			     (((pkt->tv.tv_sec - prev_pkt->tv.tv_sec)*1000000L+pkt->tv.tv_usec) - prev_pkt->tv.tv_usec)/1000.0);

	         cmp_result = compute_differences(tracebox, prev_pkt->data, 
                                             &(pkt->data[ip_start]),
					                              type, v, tracebox->udp ? 
                                             IPPROTO_UDP : IPPROTO_TCP);
            if (cmp_result) {
               string_concat(buf, bufsize, soff, cmp_result);
               free(cmp_result);
            }
         } else if (icmp_type == 3) { // dest unreachable
            string_concat(buf, bufsize, soff, "Destination unreachable\n");
         } else {
	         string_concat(buf, bufsize, soff, " erroneous packet\n");
	         return;
         }

      } else if (proto == IPPROTO_UDP) {
                      
	      if (prev_query) {
	         string_concat(buf, bufsize, soff, " *\n");
	         counter++;
	      }
	      string_concat(buf, bufsize, soff, " %2d:", counter);

	      prev_pkt = pkt;
	      prev_query=(pkt->dir == SCAMPER_TRACEBOX_PKT_DIR_TX);

	      continue;
      } else if(proto == IPPROTO_ICMPV6) {

	      if (!prev_query) continue;
	      prev_query=0;

	      uint8_t type = pkt->data[iphlen];
	      uint8_t code = pkt->data[iphlen+1];
	      ip_start    = iphlen+8;
	      trans_start = ip_start+40;
	      dlen        = len-ip_start;

	      if (type == 3 && code == 0) { //hop limit exceeded in transit
	         string_concat(buf, bufsize, soff, " %s ", addr);

	         /* get size of quoted packet */
            char *quote_size;
            if (len-ip_start <= 0) {
               type = SCAMPER_TRACEBOX_ANSWER_EMPTY;
               quote_size = "(0/60)";
	         } else if (len-trans_start <= 0) {
	            type = SCAMPER_TRACEBOX_ANSWER_ONLY_L3;
               quote_size = "(40/60)";
	         } else if (len-trans_start == 8) {
	            type = SCAMPER_TRACEBOX_ANSWER_8B;
               quote_size = "(48/60)";
	         } else {
	            type = SCAMPER_TRACEBOX_ANSWER_FULL;
               quote_size = "(60/60)";
	         }

            if (tracebox->icmp_quote_type)
               string_concat(buf, bufsize, soff, "%-6s", quote_size);
	         if (tracebox->rtt) 
	            string_concat(buf, bufsize, soff, " RTT:%.4f",
			        (((pkt->tv.tv_sec - prev_pkt->tv.tv_sec)*
                    1000000L+pkt->tv.tv_usec) - prev_pkt->tv.tv_usec)/1000.0);

	         cmp_result = compute_differences(tracebox, prev_pkt->data, 
                                            &(pkt->data[ip_start]),
					                             type, v, tracebox->udp ? 
                                            IPPROTO_UDP : IPPROTO_TCP);
	         if (cmp_result) {
	            string_concat(buf, bufsize, soff, cmp_result);
	            free(cmp_result);
	         }

	      } else if (type == 1) { // dest unreachable
	         string_concat(buf, bufsize, soff, " dest-unreachable\n");
         } else {
            string_concat(buf, bufsize, soff, " erroneous packet\n");
	         return;
         }

      }  else {
         string_concat(buf, bufsize, soff, " erroneous packet\n");
	      return;
      }

      string_concat(buf, bufsize, soff, "\n");
      counter++;
      prev_pkt = pkt;
   }

  /* if no answer for last query */
   if (tracebox->result == SCAMPER_TRACEBOX_RESULT_TIMEOUT)
      string_concat(buf, bufsize, soff, " *\n");

   return 0;
}

static void free_array(uint8_t **ppkt, int len) {
   if (!ppkt) return;

   int i;
   for (i=0; i<len; i++) {
      if (ppkt[i]) 
         free(ppkt[i]);
   }
   free(ppkt);
}

/* return the address of the last router that did include the specified field in the icmp ttl expired
 *
 */
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

char *compute_differences(const scamper_tracebox_t *tracebox, 
      const uint8_t *pkt1, const uint8_t *pkt2, const uint8_t type, 
      const uint8_t network, const uint8_t transport) {

   size_t bufsize = 20480, soff = 0;
   char *buf = malloc(bufsize*sizeof(char));
   unsigned int transoff;// + ip_opt*4;
   uint8_t **ppkt1 = parse_packet(network, transport, type, pkt1);
   uint8_t **ppkt2 = parse_packet(network, transport, type, pkt2);

   /* Look for new IP opt */
   if (network == 4) {
      transoff = 20;
      if (ppkt1[24][0] != ppkt2[24][0]) 
         string_concat(buf, bufsize, &soff, " warning: IPHeaderLength changed\n");
   } else if (network == 6) {
      transoff = 40;
      if ((ppkt1[27][0] != ppkt2[27][0]) || (ppkt1[27][1] != ppkt2[27][1])) 
         string_concat(buf, bufsize, &soff, " warning: IPv6Length changed\n");
   } 

   /* Compare each fields */
   switch (type) {

      /* 7 Bottom Non-optional TCP fields */
      case SCAMPER_TRACEBOX_ANSWER_FULL:
         compare_fields(tracebox, 0, 7, ppkt1, ppkt2, bufsize, &soff, buf);

      /* Parse TCP options for full quote and SYN/ACKs */
      case SCAMPER_TRACEBOX_ANSWER_SYNACK:
         if (!tracebox->udp) {
            int optoff = transoff+20;
            uint8_t tcp_opt = ((pkt1[transoff+12]& 0xf0) >> 4)-5 ;
            uint8_t tcp_opt2 = ((pkt2[transoff+12]& 0xf0) >> 4)-5 ;
            int nb_bytes = tcp_opt * 4, nb_bytes2 = tcp_opt2 * 4;

            uint8_t **diff = compare_tcp_opt(pkt1+optoff, pkt2+optoff, nb_bytes, nb_bytes2);
            if ((diff[0][0] || diff[0][1]) || diff[0][2]) {
	            uint8_t index;
	            for (index=0;index<diff[0][0];index++) 
	               string_concat(buf, bufsize, &soff, "  TCP::Options::%s",
                                scamper_tracebox_tcp_options[diff[1][index]]);
	            for (index=0;index<diff[0][1];index++) 
	               string_concat(buf, bufsize, &soff, "  -TCP::Options::%s",
                                scamper_tracebox_tcp_options[diff[2][index]]);
	            for (index=0;index<diff[0][2];index++) 
	               string_concat(buf, bufsize, &soff, "  +TCP::Options::%s",
                                scamper_tracebox_tcp_options[diff[3][index]]);
            }
            free_array(diff, 4);
         } // end not udp 
         if (type == SCAMPER_TRACEBOX_ANSWER_SYNACK) 
            break;

      /* TCP Ports&Seqnum or UDP fields */
      case SCAMPER_TRACEBOX_ANSWER_8B:
         compare_fields(tracebox, 7, 14, ppkt1, ppkt2, bufsize, &soff, buf);

      /* IP header */
      case SCAMPER_TRACEBOX_ANSWER_ONLY_L3:
         compare_fields(tracebox, 14, 36, ppkt1, ppkt2, bufsize, &soff, buf);
  
      case SCAMPER_TRACEBOX_ANSWER_EMPTY:
         break;  
   }

   free_array(ppkt1, scamper_tracebox_fields_len);  
   free_array(ppkt2, scamper_tracebox_fields_len);
   if (!soff) free(buf);
   return !soff ? NULL : buf;
}

static void compare_fields(const scamper_tracebox_t *tracebox,
                    unsigned int start, unsigned int end, 
                    uint8_t **ppkt1, uint8_t **ppkt2, size_t bufsize, 
                    size_t *soff, char *buf) {
   int i, j, k;
   for (i=start; i<end; i++) {
      for (j=0; j<scamper_tracebox_fields_size[i]; j++) {

         if (ppkt1[i][j] != ppkt2[i][j]) {
            if (tracebox->print_values) {
               string_concat(buf, bufsize, soff, " %s(",
                             scamper_tracebox_fields[i]);
               for (k=0; k<scamper_tracebox_fields_size[i]; k++)
                  string_concat(buf, bufsize, soff, "%x", ppkt2[i][k]);
               string_concat(buf, bufsize, soff, ")");
            } else {
               string_concat(buf, bufsize, soff, " %s",
                             scamper_tracebox_fields[i]);
            }      
            break;
         }
      }
   }
}
