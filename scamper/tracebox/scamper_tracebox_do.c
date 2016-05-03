/*
 * scamper_do_tracebox.c
 *
 *
 *
 * @author: K.Edeline
 */

#ifndef lint
static const char rcsid[] =
  "$Id: scamper_tracebox_do.c,v 1.102 2014/04/22 21:55:29 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "scamper.h"
#include "scamper_addr.h"
#include "scamper_list.h"
#include "scamper_task.h"
#include "scamper_dl.h"
#include "scamper_fds.h"
#include "scamper_dlhdr.h"
#include "scamper_firewall.h"
#include "scamper_rtsock.h"
#include "scamper_if.h"
#include "scamper_probe.h"
#include "scamper_getsrc.h"
#include "scamper_tcp4.h"
#include "scamper_ip4.h"
#include "scamper_ip6.h"
#include "scamper_tcp6.h"
#include "scamper_queue.h"
#include "scamper_file.h"
#include "scamper_options.h"
#include "scamper_debug.h"
#include "utils.h"
#include "mjl_list.h"
#include "scamper_tracebox.h"
#include "scamper_tracebox_do.h"
#include "scamper_tracebox_text.h"

typedef struct tracebox_options
{
  uint8_t   udp;
  uint8_t   ipv6;
  uint8_t   rtt;
  uint8_t   icmp_quote_type;
  uint16_t  dport;
  uint16_t  secondary_dport;
  char      *probe;
  char      *raw_packet;
  int 	   printmode;
  uint8_t   print_values;

  uint8_t   app;
} tracebox_options_t;

#define tp_len   un.tcp.len
#define tp_flags un.tcp.flags
#define tp_sackb un.tcp.sackb
#define tp_seq   un.tcp.seq
#define tp_ack   un.tcp.ack
#define tp_sack  un.tcp.sack

typedef struct tracebox_state
{

  uint16_t                  last_ttl;
  uint8_t                   replaying;  
  uint8_t                   timeout_count;
  uint8_t                   loop;

#ifndef _WIN32
  scamper_fd_t               *rtsock;
#endif

  scamper_fd_t               *dl;
  scamper_fd_t               *raw;    
  scamper_fd_t               *probe;    

  scamper_dlhdr_t            *dlhdr;
  scamper_route_t            *route;
  uint8_t                     mode;
  uint8_t                     attempt;
  uint16_t                    flags;
  struct timeval              timeout;
  uint16_t                    ipid;

  slist_t                    *tx;

} tracebox_state_t;

#define pmtud_ptb_data        un.pmtud.ptb_data
#define pmtud_ptb_datalen     un.pmtud.ptb_datalen
#define pmtud_ptb_c           un.pmtud.ptb_c
#define sackr_rx              un.sackr.rx
#define sackr_x               un.sackr.x
#define sackr_flags           un.sackr.flags
#define sackr_timeout         un.sackr.timeout
#define ecn_flags             un.ecn.flags

/* The callback functions registered with the tracebox task */
static scamper_task_funcs_t tracebox_funcs;

/* Address cache used to avoid reallocating the same address multiple times */
extern scamper_addrcache_t *addrcache;

/* Options that tracebox supports */
#define TRACEBOX_OPT_DPORT                 1
#define TRACEBOX_OPT_IPV6                  3
#define TRACEBOX_OPT_UDP                   4
#define TRACEBOX_OPT_MAXHOPS               5
#define TRACEBOX_OPT_PROBE                 6
#define TRACEBOX_OPT_RTT                   7
#define TRACEBOX_OPT_ICMP_QUOTE_TYPE       8
#define TRACEBOX_OPT_PROXY                 13
#define TRACEBOX_OPT_STATEFULL             14
#define TRACEBOX_OPT_PROXY_SECONDARY_DPORT 15
#define TRACEBOX_OPT_PRINT_VALUES          16
#define TRACEBOX_OPT_RAW_PACKET            17

/* types of tracebox probe packets */
#define TRACEBOX_PROBE_TYPE_TCP 1
#define TRACEBOX_PROBE_TYPE_UDP 2

static const scamper_option_in_t opts[] = {
  {'6', "ipv6", TRACEBOX_OPT_IPV6,              SCAMPER_OPTION_TYPE_NULL},
  {'d', "dport", TRACEBOX_OPT_DPORT,             SCAMPER_OPTION_TYPE_NUM},
  {'p', "probe", TRACEBOX_OPT_PROBE,             SCAMPER_OPTION_TYPE_STR},
  {'w', "raw-packet", TRACEBOX_OPT_RAW_PACKET,   SCAMPER_OPTION_TYPE_STR},
  {'u', "udp", TRACEBOX_OPT_UDP,               SCAMPER_OPTION_TYPE_NULL},
  {'r', "rtt", TRACEBOX_OPT_RTT,             SCAMPER_OPTION_TYPE_NULL},
  {'v', "values", TRACEBOX_OPT_PRINT_VALUES,             SCAMPER_OPTION_TYPE_NULL},
  {'t', "icmp-quote-type", TRACEBOX_OPT_ICMP_QUOTE_TYPE,               SCAMPER_OPTION_TYPE_NULL},
  {'\0', "proxy", TRACEBOX_OPT_PROXY,             SCAMPER_OPTION_TYPE_NULL}, 
  {'\0', "proxy-secondary-dport", TRACEBOX_OPT_PROXY_SECONDARY_DPORT,             SCAMPER_OPTION_TYPE_NUM},     
  {'\0', "statefull", TRACEBOX_OPT_STATEFULL,         SCAMPER_OPTION_TYPE_NULL},
};
static const int opts_cnt = SCAMPER_OPTION_COUNT(opts);

static const uint8_t MODE_RTSOCK    =  1; /* waiting for rtsock */
static const uint8_t MODE_DLHDR     =  2; /* waiting for dlhdr to use */
static const uint8_t MODE_PROXY     =  3;
static const uint8_t MODE_DONE      =  4; /* test finished */
static const uint8_t MODE_SYN       =  5; 

const char *scamper_do_tracebox_usage(void)
{
  return "tracebox [-6urt] [-p probe] [-r raw-packet] [-d dport] [--stateful] [--proxy] [--proxy-secondary-dport]";
}

static scamper_tracebox_t *tracebox_getdata(const scamper_task_t *task)
{
  return scamper_task_getdata(task);
}

static tracebox_state_t *tracebox_getstate(const scamper_task_t *task)
{
  return scamper_task_getstate(task);
}

static void tracebox_queue(scamper_task_t *task)
{
  tracebox_state_t *state = tracebox_getstate(task);

  if(slist_count(state->tx) > 0)
    scamper_task_queue_probe(task);
  else if(state->mode == MODE_DONE)
    scamper_task_queue_done(task, 0);
  else
    scamper_task_queue_wait_tv(task, &state->timeout);

  return;
}

/*
 * tracebox_result:
 *
 * record the result, and then begin to gracefully end the connection.
 */
static void tracebox_result(scamper_task_t *task, uint8_t result)
{
  scamper_tracebox_t *tracebox = tracebox_getdata(task);
  tracebox_state_t *state = tracebox_getstate(task);
  char buf[16], addr[64];
  int d = 0;
  switch(result) {
  case SCAMPER_TRACEBOX_RESULT_SUCCESS:
  case SCAMPER_TRACEBOX_RESULT_NONE:
  case SCAMPER_TRACEBOX_RESULT_TCP_NOCONN:
  case SCAMPER_TRACEBOX_RESULT_DEST_UNREACHABLE:
  case SCAMPER_TRACEBOX_RESULT_TCP_ERROR:
  case SCAMPER_TRACEBOX_RESULT_TCP_RST:
  case SCAMPER_TRACEBOX_RESULT_TCP_BADOPT:
  case SCAMPER_TRACEBOX_RESULT_TCP_FIN:
  case SCAMPER_TRACEBOX_RESULT_ERROR:
  case SCAMPER_TRACEBOX_RESULT_ABORTED:
  case SCAMPER_TRACEBOX_RESULT_TIMEOUT:
  case SCAMPER_TRACEBOX_RESULT_HALTED:
    d = 1;
    break;
  default:
    break;
  }
   
  if(tracebox->result == SCAMPER_TRACEBOX_RESULT_NONE) {
    tracebox->result = result;
    scamper_addr_tostr(tracebox->dst, addr, sizeof(addr));
    scamper_debug(__func__, "%s %s", addr,
		  scamper_tracebox_res2str(tracebox, buf, sizeof(buf)));
  }
   
  if(d == 1){
    state->mode = MODE_DONE;
    scamper_task_queue_done(task, 0);
  }
   
  return;
}

static void tracebox_handleerror(scamper_task_t *task, int error)
{
  scamper_tracebox_t *tracebox = tracebox_getdata(task);
  tracebox_state_t *state = tracebox_getstate(task);
  tracebox->result = SCAMPER_TRACEBOX_RESULT_ERROR;
  if(state != NULL) state->mode = MODE_DONE;
  scamper_task_queue_done(task, 0);
  return;
}

/*
 * dl_syn:
 *
 * 
 */
static void dl_syn(scamper_task_t *task, scamper_dl_rec_t *dl)
{
  scamper_tracebox_t *tracebox = tracebox_getdata(task);
  tracebox_state_t *state = tracebox_getstate(task);  

  if(SCAMPER_DL_IS_ICMP(dl)) {
    if (SCAMPER_DL_IS_ICMP_TTL_EXP(dl)) {
      slist_tail_push(state->tx, NULL);    
    } else if (SCAMPER_DL_IS_ICMP_UNREACH(dl))
      scamper_debug(__func__,"unreachable");
    else if (SCAMPER_DL_IS_ICMP_PACKET_TOO_BIG(dl))
      scamper_debug(__func__,"packet too big") ;
  }

  //measurement loops
  else if (tracebox->printmode == TRACEBOX_PRINT_MODE_PROXY && state->loop == 0) {
    slist_tail_push(state->tx, NULL);
    //state->loop++;      
  } else if (tracebox->printmode == TRACEBOX_PRINT_MODE_STATEFULL && state->loop < 5) {
    slist_tail_push(state->tx, NULL);
    //state->loop++;
  }

  tracebox_queue(task);
  return;

 err:
  tracebox_handleerror(task, errno);
  return;
}

static void dl_proxy(scamper_task_t *task, scamper_dl_rec_t *dl)
{
  scamper_tracebox_t *tracebox = tracebox_getdata(task);
  tracebox_state_t *state = tracebox_getstate(task);

  if(SCAMPER_DL_IS_ICMP(dl)) {
    if (SCAMPER_DL_IS_ICMP_TTL_EXP(dl)) {
      slist_tail_push(state->tx, NULL);
    } else if (SCAMPER_DL_IS_ICMP_UNREACH(dl))
      scamper_debug(__func__,"dest-unreachable");
    else if (SCAMPER_DL_IS_ICMP_PACKET_TOO_BIG(dl))
      scamper_debug(__func__,"packet too big") ;

  }
  tracebox_queue(task);
  return;

 err:
  tracebox_handleerror(task, errno);
  return;
}

static void reset_timeout_counters(tracebox_state_t *state) {
  state->replaying     = 0;
  state->timeout_count = 0;
  state->attempt       = 0;
}

static void timeout_rt(scamper_task_t *task)
{
  tracebox_result(task, SCAMPER_TRACEBOX_RESULT_ERROR);
  return;
}

static void timeout_dlhdr(scamper_task_t *task)
{
  tracebox_result(task, SCAMPER_TRACEBOX_RESULT_ERROR);
  return;
}

static void timeout_syn(scamper_task_t *task)
{
  scamper_tracebox_t *tracebox = tracebox_getdata(task);
  tracebox_state_t *state = tracebox_getstate(task);
  
  state->timeout_count++;

  if(state->timeout_count >= TRACEBOX_TOTAL_MAX_REPLAYS) {
    tracebox_result(task, SCAMPER_TRACEBOX_RESULT_TIMEOUT);
    return;
  }

  if (state->attempt < TRACEBOX_SINGLE_HOP_MAX_REPLAYS) {
    state->last_ttl--;
    state->replaying = 1;
  } else if (state->attempt == TRACEBOX_SINGLE_HOP_MAX_REPLAYS) {
    if (tracebox->printmode == TRACEBOX_PRINT_MODE_STATEFULL && state->loop == 2) {
      tracebox->seq       += 10;
      state->last_ttl      = 0;
      reset_timeout_counters(state);
      state->loop          = 3;
    }
    state->replaying = 0;
    state->attempt   = 0;
    scamper_debug(__func__," max replay for single hops");
  }

  return;
}

static void timeout_proxy(scamper_task_t *task)
{
  scamper_tracebox_t *tracebox = tracebox_getdata(task);
  tracebox_state_t *state = tracebox_getstate(task);
  
  state->timeout_count++;

  if(state->timeout_count >= TRACEBOX_TOTAL_MAX_REPLAYS) {
    tracebox_result(task, SCAMPER_TRACEBOX_RESULT_TIMEOUT);
    return;
  }

  if (state->attempt < TRACEBOX_SINGLE_HOP_MAX_REPLAYS) {
    state->last_ttl--;
    state->replaying = 1;
  } else if (state->attempt == TRACEBOX_SINGLE_HOP_MAX_REPLAYS) {
    state->replaying = 0;
    state->attempt   = 0;
    scamper_debug(__func__,"max replay for single hops: skipping...");
  }

  return;
}

/*
 * do_tracebox_handle_dl
 *
 * for each packet received, check that the addresses and ports make sense.
 */
static void do_tracebox_handle_dl(scamper_task_t *task, scamper_dl_rec_t *dl)
{
  
  static void (* const func[])(scamper_task_t *, scamper_dl_rec_t *) =
    {
      NULL,
      NULL,          /* MODE_RTSOCK */
      NULL,          /* MODE_DLHDR */
      dl_proxy,          /* MODE_PROXY */
      NULL,          /* MODE_DONE */
      dl_syn,        /* MODE_SYN */
    };

  scamper_tracebox_t *tracebox = tracebox_getdata(task);
  tracebox_state_t *state = tracebox_getstate(task);
  scamper_tracebox_pkt_t *pkt = NULL;
  scamper_dl_rec_t *newp = NULL;
  int more = 0;
  char addr[64];

  /* avoid double register of packets on FreeBSD */
  if (!scamper_addr_raw_cmp(tracebox->src, dl->dl_ip_src)) {
     pkt = scamper_tracebox_pkt_alloc(SCAMPER_TRACEBOX_PKT_DIR_TX, dl->dl_net_raw,
				   dl->dl_ip_size, &dl->dl_tv);
     if(pkt == NULL || scamper_tracebox_record_pkt(tracebox, pkt) != 0) {
       if(pkt != NULL) scamper_tracebox_pkt_free(pkt);
       goto err;
     }
    return;
  }
  /* reset timeout and replay watchers */
  reset_timeout_counters(state);
  
  if(SCAMPER_DL_IS_ICMP(dl)) {
    
    if (SCAMPER_DL_IS_ICMP_TTL_EXP(dl)) {

      if (SCAMPER_DL_IS_IPV4(dl)) {
        scamper_addr_t *a=scamper_addr_alloc(SCAMPER_ADDR_TYPE_IPV4,dl->dl_ip_src);
        scamper_addr_tostr(a,addr,sizeof(addr));
        scamper_addr_free(a);
      } else if (SCAMPER_DL_IS_IPV6(dl)) {
	      scamper_addr_t *a=scamper_addr_alloc(SCAMPER_ADDR_TYPE_IPV6,dl->dl_ip_src);
	      scamper_addr_tostr(a,addr,sizeof(addr));
	      scamper_addr_free(a);
      } else strcpy(addr,"unknown transport");
      scamper_debug(__func__,"rx: icmp ttl exp from %s",addr);

      if (tracebox->printmode == TRACEBOX_PRINT_MODE_STATEFULL && state->loop == 1 
	  &&  state->last_ttl == tracebox->srv_ttl - 1) {
        tracebox->seq       -= 10;
        state->last_ttl      = 0;
        reset_timeout_counters(state);
        state->loop++;  
      }
      more = 1;
    } else if (SCAMPER_DL_IS_ICMP_UNREACH(dl)) {
      scamper_debug(__func__,"rx: icmp unreach");
      tracebox_result(task, SCAMPER_TRACEBOX_RESULT_DEST_UNREACHABLE);
    } else if (SCAMPER_DL_IS_ICMP_PACKET_TOO_BIG(dl)) {
      scamper_debug(__func__,"rx: icmp packet too big");
      tracebox_result(task, SCAMPER_TRACEBOX_RESULT_DEST_UNREACHABLE);
    }
  } else if (SCAMPER_DL_IS_TCP(dl)) {
    if (SCAMPER_DL_IS_TCP_SYNACK(dl)) {
      scamper_debug(__func__,"rx: tcp syn ack");
       
    } else if ((dl->dl_tcp_flags & TH_RST) != 0)
      scamper_debug(__func__,"rx: tcp rst");

  } else if (SCAMPER_DL_IS_UDP(dl)) scamper_debug(__func__,"rx: udp dgram");

  pkt = scamper_tracebox_pkt_alloc(SCAMPER_TRACEBOX_PKT_DIR_RX, dl->dl_net_raw,
				   dl->dl_ip_size, &dl->dl_tv);
  if(pkt == NULL || scamper_tracebox_record_pkt(tracebox, pkt) != 0) {
    if(pkt != NULL) scamper_tracebox_pkt_free(pkt);
    goto err;
  }
  
  /* test server is reached */
  if (!scamper_addr_raw_cmp(tracebox->dst, dl->dl_ip_src)) {
    if (tracebox->printmode == TRACEBOX_PRINT_MODE_PROXY && state->loop == 0) {
      
      tracebox->udp        = 1;
      state->last_ttl      = 0;
      reset_timeout_counters(state);
      if (tracebox->secondary_dport != 0)
        tracebox->dport    = tracebox->secondary_dport;
      more = 1;
      state->loop++;
    } else if (tracebox->printmode == TRACEBOX_PRINT_MODE_STATEFULL 
               && state->loop < 4 && state->loop != 2) {
      tracebox->seq       -= 10;
      tracebox->srv_ttl    = state->last_ttl;
      state->last_ttl      = 0;
      reset_timeout_counters(state);
      more = 1;
      state->loop++;
    } else {
      tracebox_result(task, SCAMPER_TRACEBOX_RESULT_SUCCESS);
      goto done;
    }
  }
  // prevent looping
  if (state->last_ttl >= TRACEBOX_MAX_HOPS) {
    
    tracebox_result(task, SCAMPER_TRACEBOX_RESULT_ABORTED);
    goto done;
  }

  if(func[state->mode] == NULL)
    goto done;
  if (more) func[state->mode](task, dl);
 
done:
  return;
  
err:
  tracebox_handleerror(task, errno);
  return;
}

static void do_tracebox_handle_timeout(scamper_task_t *task)
{ 
  /* Array of timeout functions */
  static void (* const func[])(scamper_task_t *) =
    {
      NULL,
      timeout_rt,         /* MODE_RTSOCK */
      timeout_dlhdr,      /* MODE_DLHDR */
      timeout_proxy,               /* MODE_PROXY */
      NULL,               /* MODE_DONE */
      timeout_syn,        /* MODE_SYN */

    };
  tracebox_state_t *state = tracebox_getstate(task);

  /* Call the appropriate timeout function */
  if(func[state->mode] != NULL)
    func[state->mode](task);

  return;
}

static void tracebox_handle_dlhdr(scamper_dlhdr_t *dlhdr)
{  
  scamper_task_t *task = dlhdr->param;
  tracebox_state_t *state = tracebox_getstate(task);

  if(dlhdr->error != 0)
    {
      scamper_task_queue_done(task, 0);
      return;
    }

  state->mode = MODE_SYN;
  scamper_task_queue_probe(task);
  return;
}

static void tracebox_handle_rt(scamper_route_t *rt)
{
  scamper_task_t *task = rt->param;
  scamper_tracebox_t *tracebox = tracebox_getdata(task);
  tracebox_state_t *state      = tracebox_getstate(task);
  scamper_dl_t *dl;
  uint16_t mtu;
  
  if(state->mode != MODE_RTSOCK || state->route != rt)
    goto done;

#ifndef _WIN32
  if(state->rtsock != NULL)
    {
      scamper_fd_free(state->rtsock);
      state->rtsock = NULL;
    }
#endif

  if(rt->error != 0 || rt->ifindex < 0)
    {
      printerror(errno, strerror, __func__, "could not get ifindex");
      tracebox_handleerror(task, errno);
      goto done;
    }

  /*
   * scamper needs the datalink to transmit packets; try and get a
   * datalink on the ifindex specified.
   */
   if((state->dl = scamper_fd_dl(rt->ifindex)) == NULL)
    {
      scamper_debug(__func__, "could not get dl for %d", rt->ifindex);
      tracebox_handleerror(task, errno);
      goto done;
    }

   dl = scamper_fd_dl_get(state->dl);
   if (state->raw == NULL && 
         tracebox->udp == 0 && scamper_dl_tx_type(dl) == SCAMPER_DL_TX_UNSUPPORTED) { 
      if  (tracebox->ipv6 == 0)
         state->raw = scamper_fd_ip4();
    }

  /*
   * determine the underlying framing to use with each probe packet that will
   * be sent on the datalink.
   */
  state->mode = MODE_DLHDR;
  if((state->dlhdr = scamper_dlhdr_alloc()) == NULL) {
      tracebox_handleerror(task, errno);
      goto done;
  }
  
  state->dlhdr->dst = scamper_addr_use(tracebox->dst);
  state->dlhdr->gw = rt->gw != NULL ? scamper_addr_use(rt->gw) : NULL;
  state->dlhdr->ifindex = rt->ifindex;
  state->dlhdr->txtype = scamper_dl_tx_type(dl);
  state->dlhdr->param = task;
  state->dlhdr->cb = tracebox_handle_dlhdr;
  if(scamper_dlhdr_get(state->dlhdr) != 0)
    {
      tracebox_handleerror(task, errno);
      goto done;
    }

  if(state->raw != NULL)
    {
      state->attempt = 0;
	   state->mode = MODE_SYN;
      scamper_task_queue_probe(task);
      return;
    }

  if(state->mode == MODE_DLHDR && 
     scamper_task_queue_isdone(task) == 0);
    
done:
    scamper_route_free(rt);
  if(state->route == rt)
    state->route = NULL;
  return;
}

static void do_tracebox_write(scamper_file_t *sf, scamper_task_t *task) {
   scamper_tracebox_t *tracebox = tracebox_getdata(task);
   scamper_tracebox_pkts2hops(tracebox, 0);
   scamper_file_write_tracebox(sf, tracebox);
   return;
}

static void tracebox_state_free(scamper_task_t *task) {  
   scamper_tracebox_t *tracebox = tracebox_getdata(task);
   tracebox_state_t *state = tracebox_getstate(task);
   int i;

   if(state == NULL)
      return;
   assert(tracebox != NULL);

   #ifndef _WIN32
   if(state->rtsock != NULL)
      scamper_fd_free(state->rtsock);
   #endif

   if(state->raw != NULL)        
      scamper_fd_free(state->raw);

   if(state->dl != NULL)
      scamper_fd_free(state->dl);

   if(state->probe != NULL)      
      scamper_fd_free(state->probe);

   if(state->dlhdr != NULL)
      scamper_dlhdr_free(state->dlhdr);

   if(state->route != NULL)
      scamper_route_free(state->route);

   if(state->tx != NULL) {
      slist_free(state->tx);
   }

   free(state);
   return;
}

static int tracebox_state_alloc(scamper_task_t *task)
{ 
  scamper_tracebox_t *tracebox = tracebox_getdata(task);
  tracebox_state_t *state;
  uint16_t seq;

  if((state = malloc_zero(sizeof(tracebox_state_t))) == NULL)
    {
      printerror(errno, strerror, __func__, "could not malloc state");
      goto err;
    }

  scamper_task_setstate(task, state);

  if((state->tx = slist_alloc()) == NULL)
    {
      printerror(errno, strerror, __func__, "could not create tx list");
      goto err;
    }

  /*
   * generate a random 16 bit sequence number so we don't have to deal
   * with sequence number wrapping for now.
   */
  if(random_u16(&seq) != 0)
    {
      printerror(errno, strerror, __func__, "could not get random isn");
      goto err;
    }

#ifndef _WIN32
  if((state->rtsock = scamper_fd_rtsock()) == NULL)
    {
      printerror(errno, strerror, __func__, "could not get rtsock");
      goto err;
    }
#endif

   if(scamper_tracebox_hops_alloc(tracebox, TRACEBOX_MAX_HOPS) != 0) {
     printerror(errno, strerror, __func__, "could not malloc hops");
     goto err;
   }

   state->mode = MODE_RTSOCK;
   state->last_ttl = 0;
   reset_timeout_counters(state);
   state->raw   = NULL;
   state->probe = NULL;
   if((scamper_option_rawtcp() != 0 || scamper_option_planetlab() != 0) && 
      state->raw == NULL) {

      if (tracebox->ipv6 == 0) {
         state->raw = scamper_fd_ip4();
      } else {
         state->probe = scamper_fd_tcp6(NULL, tracebox->sport);
      }

   }

  return 0;
 err:
  return -1;
}

static void do_tracebox_halt(scamper_task_t *task) {
   tracebox_result(task, SCAMPER_TRACEBOX_RESULT_HALTED);
   return;
}

static void do_tracebox_free(scamper_task_t *task) {  
   scamper_tracebox_t *tracebox = tracebox_getdata(task);
   if(tracebox == NULL)
      return;
   tracebox_state_free(task);
   scamper_tracebox_free(tracebox);
   return;
}

static scamper_probe_t build_probe_from_raw(scamper_task_t *task, scamper_probe_t probe, uint8_t update_ttl, char *raw_packet) {
  scamper_tracebox_t *tracebox = tracebox_getdata(task);
  tracebox_state_t *state = tracebox_getstate(task);

  /* Common to all probes */
  if (state->raw != NULL) {
    probe.pr_fd   = scamper_fd_fd_get(state->raw);
  } else {
    probe.pr_fd     = -1;
    probe.pr_dl     = scamper_fd_dl_get(state->dl);
    probe.pr_dl_buf = state->dlhdr->buf;
    probe.pr_dl_len = state->dlhdr->len;
  }
  probe.pr_no_trans = (uint8_t)1;
  probe.pr_ip_src = tracebox->src;
  probe.pr_ip_dst = tracebox->dst;
  probe.pr_ip_proto = IPPROTO_TCP;
  if (update_ttl) state->last_ttl++;
  probe.pr_ip_ttl = state->last_ttl;
  
  if (tracebox->ect) 
    probe.pr_ip_tos |= 0x02; // ECN Capable Transport ECT(0)
  if (tracebox->ce) 
    probe.pr_ip_tos |= 0x01; // Congestion Encountered — CE
 
  if (tracebox->dscp)
    probe.pr_ip_tos |= tracebox->dscp;

  /* IP Version dependent options */
  if(tracebox->dst->type == SCAMPER_ADDR_TYPE_IPV4) {
    if (tracebox->ipid) {
      probe.pr_ip_id = tracebox->ipid_value;
    }

  } else if (tracebox->dst->type == SCAMPER_ADDR_TYPE_IPV6) {
    if (tracebox->ipid) 
      probe.pr_ip_flow = tracebox->ipid_value;
  }

  probe.pr_len=strlen(raw_packet)/2;
  probe.pr_data=malloc_zero(probe.pr_len);

  int i, value;
  char tmp[3] = { 0 };
  for (i=0; i<probe.pr_len; i++) {
    memcpy(tmp, raw_packet+2*i, 2);
    probe.pr_data[i]=(unsigned char)strtol(tmp, NULL, 16);
  }
  
  return probe;
}

static scamper_probe_t build_probe(scamper_task_t *task, scamper_probe_t probe, 
                                   uint8_t update_ttl) {

  scamper_tracebox_t *tracebox = tracebox_getdata(task);
  tracebox_state_t *state = tracebox_getstate(task);

  /* Common to all probes */
  if (state->raw != NULL) {
     probe.pr_fd = scamper_fd_fd_get(state->raw);
  } else if (state->probe != NULL) {
     probe.pr_fd = scamper_fd_fd_get(state->probe);
      
  } else {
     probe.pr_fd     = -1;
     probe.pr_dl     = scamper_fd_dl_get(state->dl);
     probe.pr_dl_buf = state->dlhdr->buf;
     probe.pr_dl_len = state->dlhdr->len;
  }
  probe.pr_ip_src = tracebox->src;
  probe.pr_ip_dst = tracebox->dst;

  if (update_ttl) state->last_ttl++;
  probe.pr_ip_ttl = state->last_ttl;
  

  if (tracebox->ect) 
    probe.pr_ip_tos |= 0x02; // ECN Capable Transport ECT(0)
  if (tracebox->ce) 
    probe.pr_ip_tos |= 0x01; // Congestion Encountered — CE
 
  if (tracebox->dscp)
    probe.pr_ip_tos |= tracebox->dscp;

  /* IP Version dependent options */
  if(tracebox->dst->type == SCAMPER_ADDR_TYPE_IPV4) {
    if (tracebox->ipid) {
      probe.pr_ip_id = tracebox->ipid_value;
    } else probe.pr_ip_id = 0;
    //probe.pr_ip_off = IP_DF;//donot fragment flag
  } else if (tracebox->dst->type == SCAMPER_ADDR_TYPE_IPV6) {
    if (tracebox->ipid) 
      probe.pr_ip_flow = tracebox->ipid_value;
    else probe.pr_ip_flow = 0;
  }

  /* Transport type dependent options */
  if (tracebox->udp) {
    probe.pr_ip_proto  = IPPROTO_UDP;  
    probe.pr_udp_sport = tracebox->sport;
    probe.pr_udp_dport = tracebox->dport;
  } else { 
    probe.pr_ip_proto   = IPPROTO_TCP;
    probe.pr_tcp_sport  = tracebox->sport;
    probe.pr_tcp_dport  = tracebox->dport;
    probe.pr_tcp_flags |= tracebox->flags;
    probe.pr_tcp_seq    = tracebox->seq;
    probe.pr_tcp_win    = TRACEBOX_DEFAULT_TCPWIN;	
   
    if (tracebox->mss)
      probe.pr_tcp_mss   = tracebox->mss;
    if (tracebox->wscale)
      probe.pr_tcp_wscale = tracebox->wscale;

    if (tracebox->mpcapable) {
      probe.pr_tcp_mpcapable  = tracebox->h_skey; 
      probe.pr_tcp_mpcapable2 = tracebox->l_skey;
    }
    if (tracebox->mpjoin) {
      probe.pr_tcp_mpjoin  = tracebox->rec_token; 
      probe.pr_tcp_mpjoin2 = tracebox->send_rnum;
    }
    if (tracebox->sack) {
      probe.pr_tcp_sackb = 1;
      probe.pr_tcp_sack[0] = tracebox->sack_sle;
      probe.pr_tcp_sack[1] = tracebox->sack_sre;
    }
    if (tracebox->sackp)
      probe.pr_tcp_opts |= SCAMPER_PROBE_TCPOPT_SACK;
    if (tracebox->ts) {
      probe.pr_tcp_opts |= SCAMPER_PROBE_TCPOPT_TS;
      probe.pr_tcp_tsval = tracebox->tsval;
      probe.pr_tcp_tsecr = tracebox->tsecr;
    }
    if (tracebox->ece) probe.pr_tcp_flags |= (TH_ECE|TH_CWR);
    if (tracebox->md5) {
      probe.pr_tcp_md5=1;
      int i;
      for (i=0;i<4;i++)
        probe.pr_tcp_md5digest[i]=tracebox->md5digest[i];
    }
    if (tracebox->ao) {
      probe.pr_tcp_auth=1;
      probe.pr_tcp_authkeyid=tracebox->aokeyid;
      probe.pr_tcp_authrnextkeyid=tracebox->aornextkeyid;
      int i;
      for (i=0;i<4;i++)
        probe.pr_tcp_authmac[i]=tracebox->aomac[i];
    }
  }
  
  return probe;
}

static void do_tracebox_probe(scamper_task_t *task)
{
  scamper_tracebox_t     *tracebox = tracebox_getdata(task);
  tracebox_state_t       *state = tracebox_getstate(task);
  scamper_tracebox_pkt_t *pkt;
  scamper_probe_t     probe;
  int                 wait, rc;

  assert(tracebox != NULL);
  assert(tracebox->dst != NULL);
  assert(tracebox->dst->type == SCAMPER_ADDR_TYPE_IPV4 ||
	 tracebox->dst->type == SCAMPER_ADDR_TYPE_IPV6);

  if(state == NULL)
    {
      /* Fill in the test start time */
      gettimeofday_wrap(&tracebox->start);

      /* Allocate space to store task state */
      if(tracebox_state_alloc(task) != 0)
	goto err;

      state = tracebox_getstate(task);
    }

  if(state->mode == MODE_RTSOCK)
    {
      state->route = scamper_route_alloc(tracebox->dst, task, tracebox_handle_rt);
      if(state->route == NULL) 
	     goto err;

#ifndef _WIN32
      if(scamper_rtsock_getroute(state->rtsock, state->route) != 0)
	goto err;
#else
      if(scamper_rtsock_getroute(state->route) != 0)
	goto err;
#endif

      if(scamper_task_queue_isdone(task))
	      return;

      scamper_task_queue_wait(task, 1000);
      return;

    }

  memset(&probe, 0, sizeof(probe));
  if (tracebox->raw_packet)
    probe = build_probe_from_raw(task, probe, 1, tracebox->raw_packet);
  else probe = build_probe(task, probe, 1);

  wait = TRACEBOX_TIMEOUT_DEFAULT;
  slist_head_pop(state->tx);

  /* Send the probe */
  if(scamper_probe(&probe) != 0) {
      errno = probe.pr_errno;
      printerror(errno, strerror, __func__, "could not send probe");
      goto err;
    }

  if (state->raw == NULL) {
     pkt = scamper_tracebox_pkt_alloc(SCAMPER_TRACEBOX_PKT_DIR_TX, 
                      probe.pr_tx_raw, probe.pr_tx_rawlen, &probe.pr_tx);
      if (pkt == NULL || scamper_tracebox_record_pkt(tracebox, pkt) != 0) {
         if (pkt != NULL) scamper_tracebox_pkt_free(pkt);
         printerror(errno, strerror, __func__, "could not record packet");
         goto err;
      }
   }

  state->attempt++;
  if(wait > 0)
    timeval_add_ms(&state->timeout, &probe.pr_tx, wait);

  tracebox_queue(task);
  return;

 err:
  tracebox_handleerror(task, errno);
  return;
}

static int tracebox_arg_param_validate(int optid, char *param, long *out) {
   long tmp;

   switch (optid) {

      case TRACEBOX_OPT_PROXY_SECONDARY_DPORT:
      case TRACEBOX_OPT_DPORT:
         if (string_tolong(param, &tmp) != 0 || tmp < 0 || tmp > 65535)
            goto err;
         break;
      case TRACEBOX_OPT_PROXY:
      case TRACEBOX_OPT_IPV6:        
      case TRACEBOX_OPT_UDP:                             
      case TRACEBOX_OPT_STATEFULL:                  
      case TRACEBOX_OPT_ICMP_QUOTE_TYPE:
      case TRACEBOX_OPT_RTT:          
      case TRACEBOX_OPT_PRINT_VALUES:     
         tmp=0; break; 
      case TRACEBOX_OPT_PROBE: 
      case TRACEBOX_OPT_RAW_PACKET:
         break;
      default:
         return -1;
    }

   /* valid parameter */
   if (out != NULL)
      *out = tmp;
   return 0;

err:
   return -1;
}

int scamper_do_tracebox_arg_validate(int argc, char *argv[], int *stop) {

   return scamper_options_validate(opts, opts_cnt, argc, argv, stop,
				                       tracebox_arg_param_validate);
}

static int tracebox_app_default(scamper_tracebox_t *tracebox, 
                                tracebox_options_t *o) {
   if (tracebox->dport == 0) tracebox->dport = 80; 

   /* random seq number common to all probe */
   if (!tracebox->udp) {
      random_u32(&tracebox->seq);
      tracebox->flags |= TH_SYN;
   }

   if (tracebox->ipid && !tracebox->ipid_value) 
      random_u32(&tracebox->ipid_value);

   if (tracebox->ts) {
      struct timeval tv;	      
      gettimeofday_wrap(&tv);
      tracebox->tsval = (tv.tv_sec) * 1000 + tv.tv_usec/1000.0;
      tracebox->tsecr = (tv.tv_sec) * 1000 + tv.tv_usec/1000.0;
   }

   if (tracebox->dscp == 1) {
      random_u8(&tracebox->dscp);
      tracebox->dscp &= 0xfc;
   }

   if (tracebox->sack) {
      random_u32(&tracebox->sack_sle);
      random_u32(&tracebox->sack_sre);
   }

   if (tracebox->mpjoin) {
      random_u32(&tracebox->rec_token);
      random_u32(&tracebox->send_rnum);
   }

   if (tracebox->mpcapable) {
      random_u32(&tracebox->h_skey);
      random_u32(&tracebox->l_skey);
   }

   if (tracebox->md5) {
      int i;
      for (i=0; i<4; i++)
         random_u32(&(tracebox->md5digest[i]));
   }

   if (tracebox->ao) {
      random_u8(&tracebox->aokeyid);
      random_u8(&tracebox->aornextkeyid);
      int i;
      for (i=0; i<4; i++)
         random_u32(&(tracebox->aomac[i]));
   }

   /* check for mode inconsistensies */
   if (tracebox->printmode == TRACEBOX_PRINT_MODE_PROXY) {
      tracebox->udp = 0;
   }

   if (tracebox->printmode == TRACEBOX_PRINT_MODE_STATEFULL) {
      tracebox->udp  = 0;
      tracebox->seq += 20;
   }

   return 0;
}

static void parse_probe(scamper_tracebox_t *tracebox) {

   char *token, *p, *probe;
   uint32_t subtoken;
   const char * delimiter = "/";

   for (p = tracebox->probe; *p; p++) 
      *p = tolower(*p);
   probe = strdup(tracebox->probe);
   token = strtok(probe, delimiter); 

   while (token) {
      /* Protocols */
      if (strcasestr(token, "ipv6")) 
         tracebox->ipv6 = 1;
      else if (strcasestr(token, "ip") && !strcasestr(token, "ipid")) 
         tracebox->ipv6 = 0;
      else if (strcasestr(token, "tcp")) { 
         if (sscanf(token, "tcp(%d)", &subtoken) == 1) 
            tracebox->flags = subtoken;
         else tracebox->flags |= TH_SYN;
            tracebox->udp = 0;
      } else if (strcasestr(token, "udp"))  
         tracebox->udp = 1;

      /* IP */
      else if (strcasestr(token, "ipid")) { 
         tracebox->ipid       = 1;
         if (sscanf(token, "ipid(%d)", &subtoken) == 1) 
            tracebox->ipid_value   = subtoken;
         else tracebox->ipid_value = 0;
      } else if (strcasestr(token, "ect"))  
         tracebox->ect  = 1;
      else if (strcasestr(token, "ece"))  
         tracebox->ece  = 1;
      else if (strcasestr(token, "ce"))   
         tracebox->ce   = 1;

      else if (strcasestr(token, "dscp")) { 
         if (sscanf(token, "dscp(%d)", &subtoken)== 1) {
            tracebox->dscp = subtoken;
            tracebox->dscp <<= 2;
         } else tracebox->dscp = 1;
      }  

      /* TCP options */
      else if (strcasestr(token, "mss")) { 
         if (sscanf(token, "mss(%d)", &subtoken)== 1) 
            tracebox->mss = subtoken;
         else tracebox->mss = TRACEBOX_DEFAULT_MSS;
      } else if (strcasestr(token, "wscale") || 
                 strcasestr(token, "windowscale")) { 
         if (sscanf(token, "wscale(%d)", &subtoken) == 1 || 
             sscanf(token, "windowscale(%d)", &subtoken) == 1) 
           tracebox->wscale = subtoken;
         else tracebox->wscale = TRACEBOX_DEFAULT_WSCALE;
      }  
       
      else if (strcasestr(token, "mpcapable")) 
         tracebox->mpcapable = 1;
      else if (strcasestr(token, "mpjoin"))    
         tracebox->mpjoin    = 1;
      else if (strcasestr(token, "sackp"))     
         tracebox->sackp     = 1;
      else if (strcasestr(token,"sack") && !strcasestr(token, "sackp"))      
         tracebox->sack      = 1;
      else if (strcasestr(token, "ts") || 
              strcasestr(token, "timestamp") ||
              strcasestr(token, "tstamp")) 
         tracebox->ts = 1;
      else if (strcasestr(token, "md5")) 
         tracebox->md5 = 1;
      else if (strcasestr(token, "ao") || strcasestr(token, "auth") ||
               strcasestr(token, "tcpao"))
         tracebox->ao = 1;

      token = strtok(NULL, delimiter); 
   }
   free(probe);
}

/*
 * scamper_do_tracebox_alloc
 *
 * Given a string representing a tracebox task, parse the parameters and assemble
 * a tracebox. Return the tracebox structure so that it is all ready to go.
 */
void *scamper_do_tracebox_alloc(char *str) {

   static int (* const app_func[])(scamper_tracebox_t *, 
                                   tracebox_options_t *) = {
      NULL,
      tracebox_app_default,
   };

   scamper_option_out_t *opts_out = NULL, *opt;
   scamper_tracebox_t *tracebox = NULL;
   tracebox_options_t o;
   uint16_t sport  = scamper_sport_default();
   uint32_t userid = 0;
   char *addr;
   long tmp = 0;
   int af;

   memset(&o, 0, sizeof(o));
   /* Parse the options */
   if (scamper_options_parse(str, opts, opts_cnt, &opts_out, &addr) != 0) {
      scamper_debug(__func__, "could not parse options");
      goto err;
   }

   /* If there is no IP address after the options string, then stop now */
   if (addr == NULL) {
      scamper_debug(__func__, "no address parameter");
      goto err;
   }

   /* Parse the options, do preliminary sanity checks */
   for (opt = opts_out; opt != NULL; opt = opt->next) {

      if (opt->type != SCAMPER_OPTION_TYPE_NULL &&
	         tracebox_arg_param_validate(opt->id, opt->str, &tmp) != 0) {
	      scamper_debug(__func__, "validation of optid %d failed", opt->id);
	      goto err;
	   }

      switch (opt->id) {
	      case TRACEBOX_OPT_DPORT:
	         o.dport = (uint16_t)tmp;
	         break;
	      case TRACEBOX_OPT_IPV6: 
	         o.ipv6 = (uint8_t)1;
	         break;       
	      case TRACEBOX_OPT_UDP:         
	         o.udp = (uint8_t)1;
	         break;     
	      case TRACEBOX_OPT_RTT:         
	         o.rtt = (uint8_t)1;
	         break; 
	      case TRACEBOX_OPT_ICMP_QUOTE_TYPE:         
	         o.icmp_quote_type = (uint8_t)1;
	         break; 
	      case TRACEBOX_OPT_PRINT_VALUES:
	         o.print_values = (uint8_t)1;
	         break;
	      case TRACEBOX_OPT_PROXY_SECONDARY_DPORT:
	         o.secondary_dport=(uint16_t)tmp;
	         break;      
	      case TRACEBOX_OPT_PROBE:  
	         o.probe = opt->str;
	         break;
	      case TRACEBOX_OPT_RAW_PACKET:
	         o.raw_packet = opt->str;
	         break;                   
	      case TRACEBOX_OPT_PROXY:  
	         o.printmode = TRACEBOX_PRINT_MODE_PROXY;
	         break;
	      case TRACEBOX_OPT_STATEFULL:
	         o.printmode = TRACEBOX_PRINT_MODE_STATEFULL;
	         break;                    
      }
   }

   scamper_options_free(opts_out); opts_out = NULL;

   if ((tracebox = scamper_tracebox_alloc()) == NULL) {
      printerror(errno, strerror, __func__, "could not alloc tracebox");
      goto err;
   }

   if ((tracebox->dst = scamper_addrcache_resolve(addrcache,AF_UNSPEC,addr)) == NULL) {
      printerror(EFAULT, strerror, __func__, "could not resolve %s", addr);
      goto err;
   }

   tracebox->sport           = sport;
   tracebox->dport           = o.dport;
   tracebox->udp             = o.udp;
   tracebox->ipv6            = o.ipv6;
   tracebox->rtt             = o.rtt;
   tracebox->print_values    = o.print_values;
   tracebox->icmp_quote_type = o.icmp_quote_type;
   tracebox->printmode       = o.printmode;
   tracebox->secondary_dport = o.secondary_dport;

   if (o.probe) 
      tracebox->probe = strdup(o.probe); 
   if (o.raw_packet)
      tracebox->raw_packet = strdup(o.raw_packet);
   if(o.app == 0) 
      o.app = SCAMPER_TRACEBOX_APP_DEFAULT;
   if (tracebox->probe != NULL) 
      parse_probe(tracebox);

   if(app_func[SCAMPER_TRACEBOX_APP_DEFAULT] != NULL && 
         app_func[SCAMPER_TRACEBOX_APP_DEFAULT](tracebox, &o) != 0)
      goto err;

   return tracebox;

err:
   if(tracebox != NULL) scamper_tracebox_free(tracebox);
   if(opts_out != NULL) scamper_options_free(opts_out);
   return NULL;
}



void scamper_do_tracebox_free(void *data)
{ 
  scamper_tracebox_t *tracebox = (scamper_tracebox_t *)data;
  scamper_tracebox_free(tracebox);
  return;
}

scamper_task_t *scamper_do_tracebox_alloctask(void *data, 
         scamper_list_t *list, scamper_cycle_t *cycle) {  

   scamper_tracebox_t *tracebox = (scamper_tracebox_t *)data;
   scamper_task_sig_t *sig = NULL;
   scamper_task_t *task = NULL;

   /* allocate a task structure and store the tracebox with it */
   if ((task = scamper_task_alloc(data, &tracebox_funcs)) == NULL)
      goto err;

   /* declare the signature of the tracebox task */
   if ((sig = scamper_task_sig_alloc(SCAMPER_TASK_SIG_TYPE_TX_IP)) == NULL)
      goto err;
   sig->sig_tx_ip_dst = scamper_addr_use(tracebox->dst);
   if (tracebox->src == NULL && (tracebox->src = scamper_getsrc(tracebox->dst, 0)) == NULL)
      goto err;
   sig->sig_tx_ip_src = scamper_addr_use(tracebox->src);
   if (scamper_task_sig_add(task, sig) != 0)
      goto err;
   sig = NULL;

   /* associate the list and cycle with the tracebox */
   tracebox->list  = scamper_list_use(list);
   tracebox->cycle = scamper_cycle_use(cycle);

   return task;

 err:
   if (sig != NULL) scamper_task_sig_free(sig);
   if (task != NULL) {
      scamper_task_setdatanull(task);
      scamper_task_free(task);
   }
   return NULL;
}

void scamper_do_tracebox_cleanup(void) {
   return;
}

int scamper_do_tracebox_init(void) {
   tracebox_funcs.probe          = do_tracebox_probe;
   tracebox_funcs.handle_icmp    = NULL;
   tracebox_funcs.handle_dl      = do_tracebox_handle_dl;
   tracebox_funcs.handle_timeout = do_tracebox_handle_timeout;
   tracebox_funcs.write          = do_tracebox_write;
   tracebox_funcs.task_free      = do_tracebox_free;
   tracebox_funcs.halt           = do_tracebox_halt;

   return 0;
}

