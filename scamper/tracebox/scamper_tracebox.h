/*
 * scamper_tracebox.h
 *
 *
 *
 * @author: K.Edeline
 */

#ifndef __SCAMPER_TRACEBOX_H
#define __SCAMPER_TRACEBOX_H

#define SCAMPER_TRACEBOX_APP_DEFAULT             1

/* generic tracebox results */
#define SCAMPER_TRACEBOX_RESULT_NONE             0 /* no result */
#define SCAMPER_TRACEBOX_RESULT_TCP_NOCONN       1 /* no connection */
#define SCAMPER_TRACEBOX_RESULT_TCP_RST          2 /* Early reset */
#define SCAMPER_TRACEBOX_RESULT_TCP_ERROR        3 /* TCP Error */
#define SCAMPER_TRACEBOX_RESULT_ERROR            4 /* System error */
#define SCAMPER_TRACEBOX_RESULT_ABORTED          5 /* Test aborted */
#define SCAMPER_TRACEBOX_RESULT_DEST_UNREACHABLE 6 /* no connection: rst rx */
#define SCAMPER_TRACEBOX_RESULT_HALTED           7 /* halted */
#define SCAMPER_TRACEBOX_RESULT_TCP_BADOPT       8 /* bad TCP option */
#define SCAMPER_TRACEBOX_RESULT_TCP_FIN          9 /* early fin */
#define SCAMPER_TRACEBOX_RESULT_ICMP_TTL_EXP     11
#define SCAMPER_TRACEBOX_RESULT_SUCCESS          12
#define SCAMPER_TRACEBOX_RESULT_TIMEOUT          13

/* direction of recorded packet */
#define SCAMPER_TRACEBOX_PKT_DIR_TX              1
#define SCAMPER_TRACEBOX_PKT_DIR_RX              2

/* router answer */
#define SCAMPER_TRACEBOX_ANSWER_EMPTY		  0
#define SCAMPER_TRACEBOX_ANSWER_ONLY_L3	  1
#define SCAMPER_TRACEBOX_ANSWER_8B		     2
#define SCAMPER_TRACEBOX_ANSWER_FULL		  3
#define SCAMPER_TRACEBOX_ANSWER_SYNACK      4 

/* Default parameters value */
#define TRACEBOX_RETX_DEFAULT           3
#define TRACEBOX_TIMEOUT_DEFAULT        3000
#define TRACEBOX_TIMEOUT_LONG           70000
#define TRACEBOX_SINGLE_HOP_MAX_REPLAYS 3
#define TRACEBOX_TOTAL_MAX_REPLAYS   	 5
#define TRACEBOX_MAX_HOPS               128
#define TRACEBOX_DEFAULT_MSS		       1460
#define TRACEBOX_DEFAULT_WSCALE		    14
#define TRACEBOX_DEFAULT_TCPWIN         65535

#define TRACEBOX_PRINT_MODE_STANDARD           0x0
#define TRACEBOX_PRINT_MODE_FRAGS              0x1                 
#define TRACEBOX_PRINT_MODE_PROXY              0x4
#define TRACEBOX_PRINT_MODE_STATEFULL          0x5  
#define TRACEBOX_PRINT_MODE_SIMPLIFIED_OUTPUT  0x6 

#define TRACEBOX_MAX_TCP_OPTIONS 64

extern const char *scamper_tracebox_modes[];
extern const int scamper_tracebox_modes_len;

extern const int scamper_tracebox_tcp_options_max;
extern const char *scamper_tracebox_tcp_options[];

extern const int scamper_tracebox_fields_len;
extern const char *scamper_tracebox_fields[];

extern uint8_t scamper_tracebox_fields_size[];

extern const int scamper_tracebox_tcp_fields_len;
extern const char *scamper_tracebox_tcp_fields[];

extern const int scamper_tracebox_udp_fields_len;
extern const char *scamper_tracebox_udp_fields[];

extern const int scamper_tracebox_ipv6_fields_len;
extern const char *scamper_tracebox_ipv6_fields[];

extern const int scamper_tracebox_ipv4_fields_len;
extern const char *scamper_tracebox_ipv4_fields[];

typedef struct scamper_tracebox_pkt {
  struct timeval       tv;
  uint8_t              dir;
  uint16_t             len;
  uint8_t             *data;
} scamper_tracebox_pkt_t;

typedef struct scamper_tracebox_hop_field {
   uint8_t name;
   uint8_t *value;  
   uint8_t value_len;
   uint8_t is_opt;

} scamper_tracebox_hop_field_t;

typedef struct scamper_tracebox_hop
{
   /* the address of the hop that responded */
   scamper_addr_t              *hop_addr;

   /* time elapsed between sending the probe and receiving this resp */
   struct timeval               hop_rtt;
   uint16_t                     hop_quoted_size;
   uint8_t                      hop_probe_ttl;

   /* modifications */
   scamper_tracebox_hop_field_t **modifications;
   uint8_t modifications_count;
   scamper_tracebox_hop_field_t **additions;
   uint8_t additions_count;
   scamper_tracebox_hop_field_t **deletions;
   uint8_t deletions_count;

} scamper_tracebox_hop_t;

/*
 * scamper_tracebox
 *
 * parameters and results of a measurement conducted with tracebox.
 */
typedef struct scamper_tracebox
{
  scamper_list_t      *list;
  scamper_cycle_t     *cycle;
  uint32_t             userid;

  /* hops array, number of valid hops specified by hop_count */
  scamper_tracebox_hop_t  **hops;
  uint16_t               hop_count;

  scamper_addr_t      *src;
  scamper_addr_t      *dst;
  uint16_t             sport;
  uint16_t             dport;
  uint32_t		        seq;
  
  uint8_t   udp;
  uint8_t   ipv6;
  char     *probe; 

  /* Arguments */
  char     *raw_packet;
  uint8_t   printmode;
  uint8_t   rtt;
  uint8_t   icmp_quote_type;
  uint8_t   print_values;

  /* options */
  uint8_t ect, ece, ce, dscp, mpcapable;
  uint8_t mpjoin, sackp, ts, ipid, sack;
  uint8_t ao, md5, aokeyid, aornextkeyid;
  uint8_t flags;
  uint32_t ipid_value, mss, wscale, sack_sle;
  uint32_t sack_sre, tsval, tsecr, rec_token;
  uint32_t send_rnum, h_skey, l_skey;
  uint32_t md5digest[4], aomac[4];

  struct timeval       start;

  /* proxy options */
  uint16_t secondary_dport; 
  uint8_t srv_ttl;

  /* outcome of test */
  uint16_t             result;

  /* packets collected as part of this test */
  scamper_tracebox_pkt_t **pkts;
  uint32_t             pktc;

  /* debug  */
  char* misc;
  uint32_t miscl;

} scamper_tracebox_t;

scamper_tracebox_t *scamper_tracebox_alloc(void);
void scamper_tracebox_free(scamper_tracebox_t *tracebox);

char *scamper_tracebox_res2str(const scamper_tracebox_t *tracebox, char *buf, size_t len);
int scamper_tracebox_pkts2hops(scamper_tracebox_t *tracebox, uint8_t parse_header);

scamper_tracebox_pkt_t *scamper_tracebox_pkt_alloc(uint8_t dir, uint8_t *data,
					   uint16_t len, struct timeval *tv);
void scamper_tracebox_pkt_free(scamper_tracebox_pkt_t *pkt);

int scamper_tracebox_pkts_alloc(scamper_tracebox_t *tracebox, uint32_t count);
int scamper_tracebox_record_pkt(scamper_tracebox_t *tracebox, scamper_tracebox_pkt_t *pkt);

int scamper_tracebox_hops_alloc(scamper_tracebox_t *tracebox, const int hops);
void scamper_tracebox_hop_field_free(scamper_tracebox_hop_field_t *hop_field);
scamper_tracebox_hop_t *scamper_tracebox_hop_alloc(void);
void scamper_tracebox_hop_free(scamper_tracebox_hop_t *hop);
int scamper_tracebox_hop_count(const scamper_tracebox_t *tracebox);

uint8_t **parse_packet(const uint8_t network, const uint8_t transport, const uint8_t type, const uint8_t *pkt);

void pprint_packet(const uint8_t network, const uint8_t transport, const uint8_t type, const uint8_t *pkt);

#endif /* __SCAMPER_TRACEBOX_H */
