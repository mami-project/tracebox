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

/* Free the tracebox object. */
void scamper_tracebox_free(scamper_tracebox_t *tracebox) {
   uint32_t i;

   if(tracebox == NULL)
      return;

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

static void print_ppkt_subarray(uint8_t **ppkt, int beg, int end) {
   /* print subarray [beg; end [ */ 
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
  uint8_t **diff = malloc(4*sizeof(uint8_t*));
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
    default://should never happen
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
    print_ppkt_subarray(ppkt, 23, 36);
  else if (network == 6) 
    print_ppkt_subarray(ppkt, 14, 23);  

  if (type != SCAMPER_TRACEBOX_ANSWER_ONLY_L3) {
    if (transport == IPPROTO_TCP) 
      print_ppkt_subarray(ppkt, 7, 10);
    else if (transport == IPPROTO_UDP) 
      print_ppkt_subarray(ppkt, 10, 14);

    if (type == SCAMPER_TRACEBOX_ANSWER_FULL && transport == IPPROTO_TCP) {
      print_ppkt_subarray(ppkt, 0, 7);  
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

uint8_t **parse_packet(const uint8_t network, const uint8_t transport, 
                       const uint8_t type, const uint8_t *pkt) {
   int transoff   = (network == 4) ? 20 : 40;
   uint8_t **ppkt = malloc(scamper_tracebox_fields_len * sizeof(uint8_t*)), i;
   for (i=0; i<scamper_tracebox_fields_len-1; i++)
      ppkt[i] = calloc(scamper_tracebox_fields_size[i], sizeof(uint8_t));
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

/** 
 * compare_tcp_opt
 * optlist1 : previous last received (or sent) value
 * optlist2 : received value
 *
 * returns [[len1,len2,len3],[modified options list], [removed options list], [added options list]]
 **/
uint8_t **compare_tcp_opt(const uint8_t *optlist1, const uint8_t *optlist2, 
                          uint8_t llen1, uint8_t llen2) {
   int i, len1, len2;
   int j = 0, found = 0, modified = 0;

   uint8_t **diff = malloc(4*sizeof(uint8_t*));
   diff[0] = calloc(3,1);
   for (i=1; i<4; i++) 
      diff[i] = calloc(TRACEBOX_MAX_TCP_OPTIONS,1);

   uint8_t opt_list[TRACEBOX_MAX_TCP_OPTIONS], opt_count = 0;
   for (opt_count=0; opt_count<TRACEBOX_MAX_TCP_OPTIONS; opt_count++)
      opt_list[opt_count] = 0;
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

            /* save result */
            if (!found)   diff[2][diff[0][1]++] = type1;
            if (modified) diff[1][diff[0][0]++] = type1;

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
            if (!found) diff[3][diff[0][2]++] = type2;

            j+=len2; break;
         default:
            j++; break;             
      }
   } // end loop 2 bis
        
   return diff;
}


