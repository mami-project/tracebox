/*
 * scamper_tracebox.c
 *
 *
 *
 * @author: K.Edeline
 */

#ifndef lint
static const char rcsid[] =
  "$Id: scamper_tracebox.c,v 1.24 2013/08/07 21:30:02 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_addr.h"
#include "scamper_list.h"
#include "scamper_tracebox.h"
#include "utils.h"


const char *scamper_tracebox_modes[] = {
   "standard",
    NULL,
   "full-icmp",
    NULL, 
   "proxy",
   "statefull",
    NULL,
};

const int scamper_tracebox_modes_len = 7;

/*
 * max tcp options type number
 */
const int scamper_tracebox_tcp_options_max = 30;
const char *scamper_tracebox_tcp_options[] = {
   "EOL",
   "NOP",
   "MSS",
   "WSOPT-WindowScale",
   "SACKPermitted",
   "SACK",
   "Echo",
   "EchoReply",
   "TSOPT-TimeStampOption",
   "PartialOrderConnectionPermitted",
   "PartialOrderServiceProfile",
   "CC",
   "CC.NEW",
   "CC.ECHO",
   "TCPAlternateChecksumRequest",
   "TCPAlternateChecksumData",
   "Skeeter",
   "Bubba",
   "TrailerChecksumOption",
   "MD5SignatureOption",
   "SCPSCapabilities",
   "SelectiveNegativeAck",
   "RecordBoundaries",
   "CorruptionExperienced",
   "SNAP",
   NULL,	
   "TCPCompressionFilter",
   "Quick-StartResponse",
   "UserTimeoutOption",
   "TCPAuthenticationOption",
   "MultipathTCP",
};

const int scamper_tracebox_fields_len = 37;
const char *scamper_tracebox_fields[] = {
   "TCP::AckNumber", 
   "TCP::Offset",
   "TCP::Reserved",
   "TCP::Flags",
   "TCP::Window",
   "TCP::Checksum",
   "TCP::UrgentPtr",
   "TCP::SPort",
   "TCP::DPort",
   "TCP::SeqNumber",
   "UDP::SPort",     /* 10 */
   "UDP::DPort",
   "UDP::Length",
   "UDP::Checksum",
   "IPv6::Version",
   "IPv6::DiffServicesCP", /* 15 */
   "IPv6::ECN",
   "IPv6::FlowLabel",
   "IPv6::PayloadLength",
   "IPv6::NextHeader",
   "IPv6::HopLimit", /* 20 */
   "IPv6::SourceAddr",
   "IPv6::DestAddr",
   "IP::Version",
   "IP::IHL",
   "IP::DiffServicesCP", /* 25 */
   "IP::ECN",
   "IP::Length",
   "IP::ID",
   "IP::Flags",   
   "IP::FragmentOffset",	/* 30 */
   "IP::TTL",
   "IP::Protocol",
   "IP::Checksum",
   "IP::SourceAddr",
   "IP::DestAddr",
   "TCP::Options",
};

uint8_t scamper_tracebox_fields_size[] = {
   4,//"TCP::AckNumber", 
   1,//"TCP::Offset",
   1,//"TCP::Reserved",
   1,//"TCP::Flags",
   2,//"TCP::Window",
   2,//"TCP::Checksum", 
   2,//"TCP::UrgentPtr",
   2,//"TCP::SPort",
   2,//"TCP::DPort",
   4,//"TCP::SeqNumber",
   2,//"UDP::SPort",     /* 10 */
   2,//"UDP::DPort",
   2,//"UDP::Length",
   2,//"UDP::Checksum",
   1,//"IPv6::Version",
   1,//"IPv6::DiffServicesCP",
   1,//"IPv6::ECN",
   3,//"IPv6::FlowLabel",
   2,//"IPv6::PayloadLength",
   1,//"IPv6::NextHeader",
   1,//"IPv6::HopLimit", /* 20 */
   16,//"IPv6::SourceAddr",
   16,//"IPv6::DestAddr",
   1,//"IP::Version",
   1,//"IP::IHL",
   1,//"IP::DiffServicesCP",
   1,//"IP::ECN",
   2,//"IP::Length",
   2,//"IP::ID",
   1,//"IP::Flags",   
   2,//"IP::FragmentOffset",	/* 30 */
   1,//"IP::TTL",
   1,//"IP::Protocol",
   2,//"IP::Checksum",
   4,//"IP::SourceAddr",
   4,//"IP::DestAddr",
   255, // TCP::OPTIONS /!
};

const int scamper_tracebox_tcp_fields_len = 10;
const char *scamper_tracebox_tcp_fields[] = {
   "TCP::AckNumber",
   "TCP::Offset",
   "TCP::Reserved",
   "TCP::Flags",
   "TCP::Window",
   "TCP::Checksum",
   "TCP::UrgentPtr",
   "TCP::SPort",
   "TCP::DPort",
   "TCP::SeqNumber",
};

const int scamper_tracebox_udp_fields_len = 4;
const char *scamper_tracebox_udp_fields[] = {
   " UDP::SPort",
   " UDP::DPort",
   " UDP::Length",
   " UDP::Checksum",
};

const int scamper_tracebox_ipv6_fields_len = 9;
const char *scamper_tracebox_ipv6_fields[] = {
   " IPv6::Version",
   " IPv6::DiffServicesCP",
   " IPv6::ECN",
   " IPv6::FlowLabel",
   " IPv6::PayloadLength",
   " IPv6::NextHeader",
   " IPv6::HopLimit",
   " IPv6::SourceAddr",
   " IPv6::DestAddr",
};

const int scamper_tracebox_ipv4_fields_len = 13;
const char *scamper_tracebox_ipv4_fields[] = {
   "IP::Version",
   "IP::IHL",
   "IP::DiffServicesCP",
   "IP::ECN",
   "IP::Length",
   "IP::ID",
   "IP::Flags",   
   "IP::FragmentOffset",	
   "IP::TTL",
   "IP::Protocol",
   "IP::Checksum",
   "IP::SourceAddr",
   "IP::DestAddr",
};

int scamper_tracebox_pkt_iplen(const scamper_tracebox_pkt_t *pkt) {
   uint8_t v = pkt->data[0] >> 4;
   int rc = -1;

   if (v == 4)
      rc = bytes_ntohs(pkt->data+2);
   else if (v == 6)
      rc = bytes_ntohs(pkt->data+4) + 40;
   return rc;
}

int scamper_tracebox_pkt_iph(const scamper_tracebox_pkt_t *pkt,
			     uint8_t *proto, uint8_t *iphlen, uint16_t *iplen) {
  uint8_t v = pkt->data[0] >> 4;

   if (v == 4) {
      *iphlen = (pkt->data[0] & 0xf) * 4;
      *iplen  = bytes_ntohs(pkt->data+2);
      *proto  = pkt->data[9];
      return 0;
   }

   if (v == 6) {
      *iphlen = 40;
      *iplen = bytes_ntohs(pkt->data+4) + 40;
      *proto = pkt->data[6];
      for (;;) {
         switch(*proto) {
         case IPPROTO_HOPOPTS:
         case IPPROTO_DSTOPTS:
         case IPPROTO_ROUTING:
            *proto = pkt->data[*iphlen];
            *iphlen += (pkt->data[(*iphlen)+1] * 8) + 8;
            continue;
         case IPPROTO_FRAGMENT:
            *proto = pkt->data[*iphlen];
            if ((bytes_ntohs(pkt->data+(*iphlen)+2) & 0xfff8) != 0) 
               return -1;
            if ((pkt->data[(*iphlen)+3] & 0x1) != 0) 
               return -1;
            *iphlen += 8;
            continue;
         }
	     break;
      }
      return 0;
   }
   return -1;
}

char *scamper_tracebox_res2str(const scamper_tracebox_t *tracebox, 
                               char *buf, size_t len) {
   static char *t[] = {
    "none",                /* 0 */
    "tcp-noconn",
    "tcp-rst",
    "tcp-error",
    "sys-error",
    "aborted",
    "destination-unreachable",
    "halted",
    "tcp-badopt",
    "tcp-fin",
    "tcp-zerowin",         /* 10 */
    "icmp-ttlexp",
    "success",
    "timeouted",
   };

   if(tracebox->result > sizeof(t) / sizeof(char *) || 
         t[tracebox->result] == NULL) {
      snprintf(buf, len, "%d", tracebox->result);
      return buf;
   }

   return t[tracebox->result];
}

scamper_tracebox_pkt_t *scamper_tracebox_pkt_alloc(uint8_t dir, 
            uint8_t *data, uint16_t len, struct timeval *tv) {

   scamper_tracebox_pkt_t *pkt;
   if((pkt = malloc_zero(sizeof(scamper_tracebox_pkt_t))) == NULL)
    goto err;

   pkt->dir = dir;
   if(len != 0 && data != NULL) {
      if((pkt->data = memdup(data, len)) == NULL)
         goto err;
      pkt->len = len;
   }

   if(tv != NULL) timeval_cpy(&pkt->tv, tv);
   return pkt;

err:
   free(pkt);
   return NULL;
}

void scamper_tracebox_pkt_free(scamper_tracebox_pkt_t *pkt) {
   if(pkt == NULL)
      return;
   if(pkt->data != NULL) 
      free(pkt->data);
   free(pkt);
   return;
}

int scamper_tracebox_pkts_alloc(scamper_tracebox_t *tracebox, uint32_t count) {
   size_t size = count * sizeof(scamper_tracebox_pkt_t *);
   if((tracebox->pkts = (scamper_tracebox_pkt_t **)malloc_zero(size)) == NULL)
      return -1;
   return 0;
}

int scamper_tracebox_record_pkt(scamper_tracebox_t *tracebox, 
                                scamper_tracebox_pkt_t *pkt) {
   size_t len = (tracebox->pktc + 1) * sizeof(scamper_tracebox_pkt_t *);

   /* Add a new element to the pkts array */
   if(realloc_wrap((void**)&tracebox->pkts, len) != 0)
      return -1;

   tracebox->pkts[tracebox->pktc++] = pkt;
   return 0;
}

int scamper_tracebox_hops_alloc(scamper_tracebox_t *tracebox, const int hops) {
   scamper_tracebox_hop_t **h;
   size_t size, i;
   size = sizeof(scamper_tracebox_hop_t *) * hops;

   h = (scamper_tracebox_hop_t **)malloc_zero(size);
   for (i=0; i<hops; i++) {
      h[i] = scamper_tracebox_hop_alloc();
   }

   if(h != NULL) {
      tracebox->hops = h;
      return 0;
   }

   return -1;
}

static scamper_tracebox_hop_field_t *scamper_tracebox_hop_field_alloc(uint8_t field_name, 
                                                                        uint8_t *field_value, 
                                                                        uint8_t field_value_len) {
   scamper_tracebox_hop_field_t *hop_field;
   size_t field_size = sizeof(scamper_tracebox_hop_field_t);
   if ((hop_field = (scamper_tracebox_hop_field_t *)malloc(field_size)) == NULL) {
      return NULL;
   }
   if ((hop_field->value = (uint8_t *)memdup(field_value, field_value_len)) == NULL) {
      return NULL;
   } 

   hop_field->name      = field_name;
   hop_field->value_len = field_value_len;

   return hop_field;
}

static scamper_tracebox_hop_field_t **
scamper_tracebox_hop_fields_alloc(scamper_tracebox_hop_field_t ***fields,
                                  const int fields_count, 
                                  uint8_t hop_field_name, 
                                  uint8_t *hop_field_value,
                                  uint8_t opt) {

   scamper_tracebox_hop_field_t *field;
   uint8_t field_len = 1;

   if (opt) {  
      if (hop_field_value[0] > 0x01)
         field_len  = hop_field_value[1];
   } else field_len = scamper_tracebox_fields_size[hop_field_name];
   field = scamper_tracebox_hop_field_alloc(hop_field_name, hop_field_value, field_len);
   field->is_opt = opt;

   scamper_tracebox_hop_field_t **f;
   size_t size;
   size = sizeof(scamper_tracebox_hop_field_t*) * (fields_count+1);
   
   if(fields_count == 0) {
      f = (scamper_tracebox_hop_field_t **)malloc_zero(size);
   } else {
      f = (scamper_tracebox_hop_field_t **)realloc(*fields, size);
   }

   f[fields_count] = field;
   *fields = f;
   
   return f;
}

void scamper_tracebox_hop_field_free(scamper_tracebox_hop_field_t *hop_field) {
   if (hop_field != NULL) {
      free(hop_field->value);
      free(hop_field);
   }
}

void scamper_tracebox_hop_free(scamper_tracebox_hop_t *hop) {
   if(hop != NULL) {

      if (hop->hop_addr != NULL)
         scamper_addr_free(hop->hop_addr);

      uint8_t i;
      for (i=0; i<hop->modifications_count; i++)
         scamper_tracebox_hop_field_free(hop->modifications[i]);
      for (i=0; i<hop->additions_count; i++)
         scamper_tracebox_hop_field_free(hop->additions[i]);
      for (i=0; i<hop->deletions_count; i++)
         scamper_tracebox_hop_field_free(hop->deletions[i]);

      if (hop->modifications != NULL)
         free(hop->modifications);
      if (hop->additions != NULL)
         free(hop->additions);
      if (hop->deletions != NULL)
         free(hop->deletions);

      free(hop);
   }
}

scamper_tracebox_hop_t *scamper_tracebox_hop_alloc() {
   scamper_tracebox_hop_t *hop;

   if ((hop = malloc_zero(sizeof(struct scamper_tracebox_hop))) == NULL) {
      return NULL;
   }

   return hop;
}

int scamper_tracebox_hop_count(const scamper_tracebox_t *tracebox)
{
   scamper_tracebox_hop_t *hop;
   int hops = 0;
   uint8_t i;

   for(i=0; i<tracebox->hop_count; i++) {
         hops++;
   }

   return hops;
}

void scamper_tracebox_free(scamper_tracebox_t *tracebox) {
   uint32_t i;
   if(tracebox == NULL)
      return;

  /* free hop records */
   if(tracebox->hops != NULL) {
      scamper_tracebox_hop_t *hop;
      for(i=0; i<TRACEBOX_MAX_HOPS; i++) {
         hop = tracebox->hops[i];
         scamper_tracebox_hop_free(hop);
      }
      free(tracebox->hops);
   }

   if(tracebox->probe) free(tracebox->probe);
   if(tracebox->raw_packet) free(tracebox->raw_packet);

   if(tracebox->src != NULL)   scamper_addr_free(tracebox->src);
   if(tracebox->dst != NULL)   scamper_addr_free(tracebox->dst);
   if(tracebox->list != NULL)  scamper_list_free(tracebox->list);
   if(tracebox->cycle != NULL) scamper_cycle_free(tracebox->cycle);

   /* Free the recorded packets */
   if(tracebox->pkts != NULL) {
      for(i=0; i<tracebox->pktc; i++)
         scamper_tracebox_pkt_free(tracebox->pkts[i]);
      free(tracebox->pkts);
   }

   free(tracebox);
   return;
}

scamper_tracebox_t *scamper_tracebox_alloc(void) {
   return (scamper_tracebox_t *)malloc_zero(sizeof(scamper_tracebox_t));
}

static void compare_fields(const scamper_tracebox_t *tracebox,
                    int hop_index,
                    unsigned int start, unsigned int end, 
                    uint8_t **ppkt1, uint8_t **ppkt2) {
   int i, j, k;
   for (i=start; i<end; i++) {
      for (j=0; j<scamper_tracebox_fields_size[i]; j++) {

         if (ppkt1[i][j] != ppkt2[i][j]) {
            scamper_tracebox_hop_fields_alloc(&tracebox->hops[hop_index]->modifications, 
                                        tracebox->hops[hop_index]->modifications_count++,  
                                        i, ppkt2[i], 0);
            break;
         }
      }
   }
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

/** 
 * compare_tcp_opt
 * optlist1 : last observed (sent or received) options
 * optlist2 : received options
 *
 **/
static void compare_tcp_opt(scamper_tracebox_hop_t *hop,
                          uint8_t *optlist1, uint8_t *optlist2, 
                          uint8_t llen1, uint8_t llen2) {
   int i, len1, len2;
   int j = 0, found = 0, modified = 0, off_index = 0;
   uint8_t opt_list[TRACEBOX_MAX_TCP_OPTIONS], opt_count = 0;
   memset(opt_list, 0, TRACEBOX_MAX_TCP_OPTIONS);
   opt_count = 0; i = 0;
        
   while (i<llen1) {
      uint8_t type1 = optlist1[i];
      switch (type1) {
         case 0x00:  case 0x01:
            i++; break;
         /* Available TCP opts */
         case 0x02:case 0x03:case 0x04:case 0x05:case 0x06:case 0x07: 
         case 0x08:case 0x09:case 0x0a:case 0x0b:case 0x0c:case 0x0d:
         case 0x0e:case 0x0f:case 0x10:case 0x11:case 0x12:case 0x13:
         case 0x14:case 0x15:case 0x16:case 0x17:case 0x18:case 0x19:
         case 0x1b:case 0x1c:case 0x1d:case 0x1e:
            j = 0;found = 0; modified = 0;
            len1 = optlist1[i+1];
            opt_list[opt_count++] = type1;

            while (j<llen2) {
               uint8_t type2 = optlist2[j];
               switch (type2) {
                  case 0x00:case 0x01:
                     j++; break;
                  case 0x02:case 0x03:case 0x04:case 0x05:case 0x06:case 0x07: 
                  case 0x08:case 0x09:case 0x0a:case 0x0b:case 0x0c:case 0x0d:
                  case 0x0e:case 0x0f:                    case 0x12:case 0x13:
                  case 0x14:case 0x15:case 0x16:case 0x17:case 0x18:case 0x19:
                            case 0x1b:case 0x1c:case 0x1d:case 0x1e:
                     len2 = optlist2[j+1];
                     if (!len2) len2++;
                     /* same tcpopt found */
                     if (type2 == type1) {
                        int k = 0; 
                        found = 1;
                        /* diff length => diff content */
                        if (len1 != len2) modified = 1; 
                        else {
                           for (k=0; k<len1; k++) {
                              if (optlist1[i+k] != optlist2[j+k]) {
                                 modified = 1;
                                 scamper_tracebox_hop_fields_alloc(&hop->modifications, 
                                        hop->modifications_count++,  
                                        type1, 
                                        optlist2+j, 1);
                                 break;
                              }
                           }
                           /* Check if we reached the end of this opt. */
                           if (k == len1) { 
                              modified = 0;
                              j = llen2;
                           } 
                        }                    
                     } 
                     j+=len2; break;
                  default:
                     j++; break;             
               }
            } 

            /* save stripped option */
            if (!found)   {
               scamper_tracebox_hop_fields_alloc(&hop->deletions, 
                                                 hop->deletions_count++,  
                                                 type1, 
                                                 optlist1+i, 1);
            }
            i+=len1;
            break;
         default:
            i++;  break;             
      }  
   } 

   /* Added options */ 
   j = 0;
   while (j<llen2) {
      uint8_t type2 = optlist2[j];
      switch (type2) {
         case 0x00:case 0x01:
            j++; break;
         case 0x02:case 0x03:case 0x04:case 0x05:case 0x06:case 0x07: 
         case 0x08:case 0x09:case 0x0a:case 0x0b:case 0x0c:case 0x0d:
         case 0x0e:case 0x0f:                    case 0x12:case 0x13:
         case 0x14:case 0x15:case 0x16:case 0x17:case 0x18:case 0x19:
                   case 0x1b:case 0x1c:case 0x1d:case 0x1e:
            found = 0;
            len2  = optlist2[j+1];
            if (!len2) len2++;
            for (i=0; i<opt_count; i++) {
               if (opt_list[i] == type2) 
                  found = 1;
            }
            if (!found) {
               scamper_tracebox_hop_fields_alloc(&hop->additions, 
                                  hop->additions_count++,  
                                  type2, 
                                  optlist2+j, 1);
            }  
            j+=len2; break;
         default:
            j++; break;             
      }
   }
        
   return;
}

static void compute_differences(const scamper_tracebox_t *tracebox, 
      int hop_index,
      uint8_t *pkt1, uint8_t *pkt2, const uint8_t type, 
      const uint8_t network, const uint8_t transport) {

   unsigned int transoff;
   uint8_t **ppkt1 = parse_packet(network, transport, type, pkt1);
   uint8_t **ppkt2 = parse_packet(network, transport, type, pkt2);

   /* Look for new IP opt */
   if      (network == 4) transoff = 20;
   else if (network == 6) transoff = 40;

   /* Compare each fields */
   switch (type) {

      /* 7 Bottom Non-optional TCP fields */
      case SCAMPER_TRACEBOX_ANSWER_FULL:
         compare_fields(tracebox, hop_index, 0, 7, ppkt1, ppkt2);

      /* Parse TCP options for full quote and SYN/ACKs */
      case SCAMPER_TRACEBOX_ANSWER_SYNACK:
         if (!tracebox->udp) {
            int optoff = transoff+20, optind = 0;
            uint8_t tcp_opt  = ((pkt1[transoff+12]& 0xf0) >> 4)-5 ;
            uint8_t tcp_opt2 = ((pkt2[transoff+12]& 0xf0) >> 4)-5 ;
            int nb_bytes = tcp_opt * 4, nb_bytes2 = tcp_opt2 * 4;

            uint8_t *opt1_off = pkt1+optoff, *opt2_off = pkt2+optoff;
            compare_tcp_opt(tracebox->hops[hop_index],
                              opt1_off, opt2_off, 
                              nb_bytes, nb_bytes2);
          
         } 
         if (type == SCAMPER_TRACEBOX_ANSWER_SYNACK) 
            break;

      /* TCP Ports&Seqnum or UDP fields */
      case SCAMPER_TRACEBOX_ANSWER_8B:
         compare_fields(tracebox, hop_index, 7, 14, ppkt1, ppkt2);

      /* IP header */
      case SCAMPER_TRACEBOX_ANSWER_ONLY_L3:
         compare_fields(tracebox, hop_index, 14, 36, ppkt1, ppkt2);
  
      case SCAMPER_TRACEBOX_ANSWER_EMPTY:
         break;  
   }

   free_array(ppkt1, scamper_tracebox_fields_len);  
   free_array(ppkt2, scamper_tracebox_fields_len);
   return;
}

static void parse_meta(scamper_tracebox_t *tracebox, scamper_tracebox_pkt_t *pkt, 
                       uint8_t v, uint8_t proto, uint8_t iphlen) {
   /* populate option fields */
   if (v == 6) {
      struct ip6_hdr ip_hdr = *(struct ip6_hdr*)pkt->data;

      tracebox->ipid_value   = ntohl(ip_hdr.ip6_flow) & 0xfffff;
      tracebox->ect          = ntohl(ip_hdr.ip6_flow) & 0x200000 >> 25;
      tracebox->ce           = ntohl(ip_hdr.ip6_flow) & 0x100000 >> 24;
      tracebox->dscp         = ntohl(ip_hdr.ip6_flow) & 0xfc00000 >> 20;
   } else if (v == 4) {
      struct ip ip_hdr = *(struct ip*)pkt->data;

      tracebox->ipid_value   = ntohs(ip_hdr.ip_id);
      tracebox->ect          = (ip_hdr.ip_tos & 0x02) >> 1;
      tracebox->ce           =  ip_hdr.ip_tos & 0x01;
      tracebox->dscp         = (ip_hdr.ip_tos & 0xfc) >> 2;
      
   }

   if (proto == IPPROTO_TCP) {
      
      struct tcphdr tcp_hdr = *(struct tcphdr*)(pkt->data + iphlen);
      tracebox->seq          = ntohl(tcp_hdr.th_seq);
      tracebox->flags        = tcp_hdr.th_flags;
      tracebox->ece          = (tcp_hdr.th_flags & 0x80) >> 7;  

      typedef struct {
        uint8_t kind;
        uint8_t size;
      } tcp_option_t;
      uint8_t* opt = ( pkt->data + iphlen + sizeof(struct tcphdr));
      uint8_t subtype;
      while( *opt != 0 ) {
         
         tcp_option_t _opt = *(tcp_option_t*)opt;
         switch (_opt.kind) {
            case 1: // NOP 
               ++opt;  // NOP is one byte;
               break;
            case 2: // MSS 2
               tracebox->mss = ntohs(*(uint16_t*)(opt + 2));
               opt += (_opt.size <= 0) ? 1 :  _opt.size;
               break;
            case 3: // wscale 1
               tracebox->wscale = *(uint8_t*)(opt + 2);
               opt += (_opt.size <= 0) ? 1 :  _opt.size;
               break;
            case 4: // sack permitted
               tracebox->sackp = 1;
               opt += (_opt.size <= 0) ? 1 :  _opt.size;
               break;
            case 5: // sack 8
               tracebox->sack = 1;
               tracebox->sack_sle     = ntohl(*(uint32_t*)(opt + 2));
               tracebox->sack_sre     = ntohl(*(uint32_t*)(opt + 6));
               opt += (_opt.size <= 0) ? 1 :  _opt.size;
               break;
            case 8: // timestamp 10
               tracebox->ts           = 1;
               tracebox->tsval        = ntohl(*(uint32_t*)(opt + 2));
               tracebox->tsecr        = ntohl(*(uint32_t*)(opt + 6));
               opt += (_opt.size <= 0) ? 1 :  _opt.size;
               break;
            case 30: // mptcp
               subtype = (*(uint8_t*)(opt + 2) >> 4);
               if (subtype == 0) {
                  tracebox->mpcapable = 1;
                  tracebox->h_skey    = ntohl(*(uint32_t*)(opt + 2));
                  tracebox->l_skey    = ntohl(*(uint32_t*)(opt + 6));
               } else if (subtype == 1) {
                  tracebox->mpjoin    = 1;
                  tracebox->rec_token = ntohl(*(uint32_t*)(opt + 2));
                  tracebox->send_rnum = ntohl(*(uint32_t*)(opt + 6));
               }
               opt += (_opt.size <= 0) ? 1 :  _opt.size;
               break;
            default:
               opt += (_opt.size <= 0) ? 1 :  _opt.size;
               break;
         }
      }
   }

}

int scamper_tracebox_pkts2hops(scamper_tracebox_t *tracebox, uint8_t parse_header) {

   scamper_tracebox_pkt_t *pkt, *prev_pkt = NULL; 
   scamper_addr_t *addr;
   uint32_t i, off;
   uint16_t len;
   uint8_t proto, flags, type, iphlen, ttl, v;
   uint8_t prev_query = 0, synacked = 0, header_parsed = 0;
   int frag, ip_start, trans_start, dlen, counter = 0;

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
	      off    = (bytes_ntohs(pkt->data+6) & 0x1fff) * 8;

	      addr = scamper_addr_alloc(SCAMPER_ADDR_TYPE_IPV4, pkt->data+12);

      /* IPv6 */
      } else if(((pkt->data[0] & 0xf0) >> 4) == 6) {
         v = 6;
	      iphlen = 40;
	      len    = bytes_ntohs(pkt->data+4) + iphlen;
	      proto  = pkt->data[6];
         ttl    = pkt->data[7];   

	      addr = scamper_addr_alloc(SCAMPER_ADDR_TYPE_IPV6, pkt->data+8);
      } else {
         tracebox->result = SCAMPER_TRACEBOX_RESULT_ERROR;
	      goto err;
      }

      if (synacked) {
	      tracebox->result = SCAMPER_TRACEBOX_RESULT_ERROR;
	      goto err;
      }

      if (parse_header && !header_parsed && pkt->dir == SCAMPER_TRACEBOX_PKT_DIR_TX) {
         parse_meta(tracebox, pkt, v, proto, iphlen);
         header_parsed = 1; 
      }

      if(proto == IPPROTO_TCP) {
	      flags   = pkt->data[iphlen+13];

         /* SYN flag on */
	      if(flags & 0x02) {
            /* ACK flag on */
	         if((flags & 0x10) && pkt->dir == SCAMPER_TRACEBOX_PKT_DIR_RX) {
	            if (!prev_query) {
		            tracebox->result =SCAMPER_TRACEBOX_RESULT_TCP_ERROR;
		            continue;
	            }
                      
	            compute_differences(tracebox, counter, prev_pkt->data, pkt->data,
					             SCAMPER_TRACEBOX_ANSWER_SYNACK, v, proto);
               tracebox->hops[counter]->hop_addr = addr;
               tracebox->hops[counter]->hop_quoted_size = SCAMPER_TRACEBOX_ANSWER_SYNACK;
               timeval_diff_tv(&tracebox->hops[counter]->hop_rtt, &prev_pkt->tv, &pkt->tv);

	            synacked = 1;

            } else if (pkt->dir == SCAMPER_TRACEBOX_PKT_DIR_TX) {

               if (prev_query) {
                  tracebox->hops[counter]->hop_addr = NULL;
		            counter++;
                  tracebox->hop_count++;
	            }

               tracebox->hops[counter]->hop_probe_ttl = ttl;
               scamper_addr_free(addr);

	            prev_pkt = pkt;
               prev_query=1;

	            continue;
            }  else {
	            tracebox->result = SCAMPER_TRACEBOX_RESULT_ERROR;
	            goto err;
	         }
         } else if(flags & 0x01) {
            tracebox->hops[counter]->hop_addr = addr;
            tracebox->result = SCAMPER_TRACEBOX_RESULT_TCP_FIN;
         } else if(flags & 0x04) {
            tracebox->hops[counter]->hop_addr = addr;
            tracebox->result = SCAMPER_TRACEBOX_RESULT_TCP_RST;
         } else {
            tracebox->hops[counter]->hop_addr = addr;
            tracebox->result = SCAMPER_TRACEBOX_RESULT_TCP_ERROR;
            goto succ;
         }

      } else if(proto == IPPROTO_ICMP) {
	      if (!prev_query) continue;
	      prev_query=0;

	      uint8_t icmp_type = pkt->data[iphlen];
	      uint8_t icmp_code = pkt->data[iphlen+1];
	      ip_start    = iphlen+8;
	      trans_start = ip_start+20;
	      dlen        = len-ip_start;
         tracebox->hops[counter]->hop_addr = addr;

         if (icmp_type == ICMP_TIMXCEED && icmp_code == ICMP_TIMXCEED_INTRANS) {
            /* get size of quoted packet */
            if (len-ip_start <= 0)
               type = SCAMPER_TRACEBOX_ANSWER_EMPTY;
	         else if (len-trans_start <= 0)
	            type = SCAMPER_TRACEBOX_ANSWER_ONLY_L3;
	         else if (len-trans_start == 8)
	            type = SCAMPER_TRACEBOX_ANSWER_8B;
	         else 
	            type = SCAMPER_TRACEBOX_ANSWER_FULL;

            tracebox->hops[counter]->hop_quoted_size = type;
            timeval_diff_tv(&tracebox->hops[counter]->hop_rtt, &prev_pkt->tv, &pkt->tv);
	         compute_differences(tracebox, counter, prev_pkt->data, 
                                             &(pkt->data[ip_start]),
					                              type, v, tracebox->udp ? 
                                             IPPROTO_UDP : IPPROTO_TCP);
         } else if (icmp_type == ICMP_UNREACH) {
            tracebox->result = SCAMPER_TRACEBOX_RESULT_DEST_UNREACHABLE;
         } else {
	         tracebox->result = SCAMPER_TRACEBOX_RESULT_ERROR;
	         goto err;
         }

      } else if (proto == IPPROTO_UDP) {
                      
	      if (prev_query) {

            tracebox->hops[counter]->hop_addr = NULL;
	         counter++;
            tracebox->hop_count++;
	      }
         tracebox->hops[counter]->hop_probe_ttl = ttl;
         scamper_addr_free(addr);

	      prev_pkt = pkt;
	      prev_query=(pkt->dir == SCAMPER_TRACEBOX_PKT_DIR_TX);

	      continue;
      } else if(proto == IPPROTO_ICMPV6) {

	      if (!prev_query) continue;
	      prev_query=0;

	      uint8_t icmp_type = pkt->data[iphlen];
	      uint8_t icmp_code = pkt->data[iphlen+1];
	      ip_start    = iphlen+8;
	      trans_start = ip_start+40;
	      dlen        = len-ip_start;
         tracebox->hops[counter]->hop_addr = addr;

	      if (icmp_type == ICMP6_TIME_EXCEEDED && icmp_code == ICMP6_TIME_EXCEED_TRANSIT) {

	         /* get size of quoted packet */
            if (len-ip_start <= 0) 
               type = SCAMPER_TRACEBOX_ANSWER_EMPTY;
	         else if (len-trans_start <= 0) 
	            type = SCAMPER_TRACEBOX_ANSWER_ONLY_L3;
	         else if (len-trans_start == 8) 
	            type = SCAMPER_TRACEBOX_ANSWER_8B;
	         else 
	            type = SCAMPER_TRACEBOX_ANSWER_FULL;
	         
            tracebox->hops[counter]->hop_quoted_size = type;
            timeval_diff_tv(&tracebox->hops[counter]->hop_rtt, &prev_pkt->tv, &pkt->tv);

	         compute_differences(tracebox, counter, prev_pkt->data, 
                                            &(pkt->data[ip_start]),
					                             type, v, tracebox->udp ? 
                                            IPPROTO_UDP : IPPROTO_TCP);
	      } else if (icmp_type == ICMP6_DST_UNREACH) { 
            tracebox->result = SCAMPER_TRACEBOX_RESULT_DEST_UNREACHABLE;
         } else {
            tracebox->result = SCAMPER_TRACEBOX_RESULT_ERROR;
	         goto err;
         }

      }  else {
         tracebox->result = SCAMPER_TRACEBOX_RESULT_ERROR;
	      goto err;
      }

      counter++;
      tracebox->hop_count++;
      prev_pkt = pkt;
   }

  /* if no answer for last query */
   if (tracebox->result == SCAMPER_TRACEBOX_RESULT_TIMEOUT) { 
      tracebox->hops[counter]->hop_addr = NULL;
   }
succ:
   return 0;
err:
   return -1;
}

uint8_t **parse_packet(const uint8_t network, const uint8_t transport, 
                       const uint8_t type, const uint8_t *pkt) {
   int transoff   = (network == 4) ? 20 : 40;
   uint8_t **ppkt = malloc_zero(scamper_tracebox_fields_len * sizeof(uint8_t*)), i;
   for (i=0; i<scamper_tracebox_fields_len-1; i++)
      ppkt[i] = malloc_zero(scamper_tracebox_fields_size[i] * sizeof(uint8_t));
   ppkt[scamper_tracebox_fields_len-1] = NULL;

   switch (type)  {
      /* Parse last transport bytes */
      case SCAMPER_TRACEBOX_ANSWER_FULL:
         if (transport == IPPROTO_TCP) {
            for(i=8; i<12; i++) ppkt[0][i-8] = pkt[transoff];
            ppkt[1][0] = (pkt[transoff+12] & 0xf0) >> 4; 
            ppkt[2][0] = pkt[transoff+12] & 0x0f;        
            ppkt[3][0] = pkt[transoff+13];
            ppkt[4][0] = pkt[transoff+14]; ppkt[4][1] = pkt[transoff+15];
            ppkt[5][0] = pkt[transoff+16]; ppkt[5][1] = pkt[transoff+17];
            ppkt[6][0] = pkt[transoff+18]; ppkt[6][1] = pkt[transoff+19];

            /* Copy TCP options bytes */
            uint8_t tcp_opt_bytes = (ppkt[1][0]-5) * 4;
            scamper_tracebox_fields_size
               [scamper_tracebox_fields_len-1] = tcp_opt_bytes;
            if (tcp_opt_bytes > 0) {
               int optoff = transoff+20;
               ppkt[scamper_tracebox_fields_len-1] = calloc(tcp_opt_bytes,
                                                            sizeof(uint8_t));
               for(i=0; i<tcp_opt_bytes; i++) 
                  ppkt[scamper_tracebox_fields_len-1][i] = pkt[optoff+i];
            }
         }     

      /* Parse 8 first transport bytes (TCP or UDP) */
      case SCAMPER_TRACEBOX_ANSWER_8B:
         if (transport == IPPROTO_TCP) {
            ppkt[7][0] = pkt[transoff];  ppkt[7][1] = pkt[transoff+1];
            ppkt[8][0] = pkt[transoff+2];ppkt[8][1] = pkt[transoff+3];
            for(i=4;i<8;i++) ppkt[9][i-4] = pkt[transoff+i];
         } else if (transport == IPPROTO_UDP) {
            ppkt[10][0] = pkt[transoff];  ppkt[10][1] = pkt[transoff+1];
            ppkt[11][0] = pkt[transoff+2];ppkt[11][1] = pkt[transoff+3];
            ppkt[12][0] = pkt[transoff+4];ppkt[12][1] = pkt[transoff+5];
            ppkt[13][0] = pkt[transoff+6];ppkt[13][1] = pkt[transoff+7];     
         }  

      /* Parse network layer */
      case SCAMPER_TRACEBOX_ANSWER_ONLY_L3:
         if (network == 4) {
            ppkt[23][0] = (pkt[0] & 0xf0) >> 4;
            ppkt[24][0] =  pkt[0] & 0x0f;
            ppkt[25][0] = (pkt[1] & 0xfc) >> 2;
            ppkt[26][0] =  pkt[1] & 0x03;   
            ppkt[27][0] =  pkt[2]; ppkt[27][1] = pkt[3];
            ppkt[28][0] =  pkt[4]; ppkt[28][1] = pkt[5];
            ppkt[29][0] = (pkt[6] & 0xe0) >> 5;   
            ppkt[30][0] =  pkt[6] & 0x1f; 
            ppkt[30][1] =  pkt[7];  
            ppkt[31][0] =  pkt[8];   
            ppkt[32][0] =  pkt[9];  
            ppkt[33][0] =  pkt[10]; ppkt[33][1] = pkt[11];  
            for(i=12;i<16;i++) ppkt[34][i-12] = pkt[i];
            for(i=16;i<20;i++) ppkt[35][i-16] = pkt[i]; 
         } else if (network == 6) {
            ppkt[14][0] = (pkt[0] & 0xf0) >> 4;
            ppkt[15][0] =((pkt[0] & 0x0f)<<2) | ((pkt[1] & 0xc0)>>6);
            ppkt[16][0] = (pkt[1] & 0x30)>>4;
            ppkt[17][0] =  pkt[1] & 0x0f;
            ppkt[17][1] =  pkt[2]; ppkt[17][2] = pkt[3];
            ppkt[18][0] =  pkt[4]; ppkt[18][1] = pkt[5];
            ppkt[19][0] =  pkt[6];
            ppkt[20][0] =  pkt[7];
            for(i=8;i<24;i++)  ppkt[21][i-8] = pkt[i];
            for(i=24;i<40;i++) ppkt[22][i-24] = pkt[i];
         }
      default:
         break;         
   }

   return ppkt;
}

static void print_ppkt_subarray(uint8_t **ppkt, int beg, int end) {
  int i, j;
  for (i=beg;i<end;i++) {
    printf("   %s ",scamper_tracebox_fields[i]);
    for (j=0;j<scamper_tracebox_fields_size[i];j++) {
      printf("%02x", ppkt[i][j]);
    }
    printf("\n");
  }
}

static void print_ppkt_tcp_opts(const uint8_t *optlist, uint8_t llen) {
  uint8_t **diff = malloc_zero(4*sizeof(uint8_t*));
  int i=0, j, len;
        
  while (i<llen) {
    uint8_t type = optlist[i];
    switch (type) {
      case 0x00:
      case 0x01:
         i++;    
         printf("   %s\n",scamper_tracebox_tcp_options[type]);
         if (type == 0x00) return;
         break;
      case 0x02:case 0x03:case 0x04:case 0x05:case 0x06:case 0x07: 
      case 0x08:case 0x09:case 0x0a:case 0x0b:case 0x0c:case 0x0d:
      case 0x0e:case 0x0f:case 0x10:case 0x11:case 0x12:case 0x13:
      case 0x14:case 0x15:case 0x16:case 0x17:case 0x18:case 0x19:
      case 0x1b:case 0x1c:case 0x1d:case 0x1e:
         len = optlist[i+1];
         printf("   TCP::Options::%s ",scamper_tracebox_tcp_options[type]);
         printf("len: %d ",len);
         if (i+len > i+2)
             printf("content: ");
         
         for (j=i+2;j<i+len;j++) {
           printf("%02x",optlist[j]);
         }
         printf("\n");

         if (len == 0) return;
         i+=len;
         break;
        default:
           i++;
           break;             

       }  
    } 
  return;
}

void pprint_packet(const uint8_t network, const uint8_t transport, const uint8_t type, const uint8_t *pkt) {
    uint8_t **ppkt = parse_packet(network, transport, type, pkt);
    int i,j;
    
    if (type == SCAMPER_TRACEBOX_ANSWER_EMPTY)
      return; 

    if (network == 4) 
      print_ppkt_subarray(ppkt, 23,36);
    else if (network == 6) 
      print_ppkt_subarray(ppkt, 14,23);  

    if (type != SCAMPER_TRACEBOX_ANSWER_ONLY_L3) {
        if (transport == IPPROTO_TCP) 
          print_ppkt_subarray(ppkt, 7,10);
        else if (transport == IPPROTO_UDP) 
          print_ppkt_subarray(ppkt, 10,14);

        if (type == SCAMPER_TRACEBOX_ANSWER_FULL && transport == IPPROTO_TCP) {
           print_ppkt_subarray(ppkt, 0,7);  
           print_ppkt_tcp_opts(ppkt[scamper_tracebox_fields_len-1], (ppkt[1][0]-5)*4);
        }
    }

    if (!ppkt) return;
    for (i=0;i<scamper_tracebox_fields_len;i++) {
      if (ppkt[i]) free(ppkt[i]);
    }
    free(ppkt);
    return;
}

