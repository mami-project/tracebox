/*
 * scamper_dealias_json.c
 *
 * Copyright (c) 2013 The Regents of the University of California
 * Copyright (c) 2013 Matthew Luckie
 * Author: Matthew Luckie
 *
 * $Id: scamper_dealias_json.c,v 1.4 2013/08/14 18:21:33 mjl Exp $
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
  "$Id: scamper_dealias_json.c,v 1.4 2013/08/14 18:21:33 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_addr.h"
#include "scamper_list.h"
#include "scamper_dealias.h"
#include "scamper_file.h"
#include "scamper_dealias_json.h"

#include "utils.h"

static char *dealias_header_tostr(const scamper_dealias_t *dealias)
{
  scamper_dealias_mercator_t *mc;
  scamper_dealias_ally_t *ally;
  scamper_dealias_radargun_t *rg;
  scamper_dealias_prefixscan_t *pf;
  scamper_dealias_bump_t *bump;
  char buf[512], tmp[64];
  size_t off = 0;
  uint16_t u16;

  string_concat(buf, sizeof(buf), &off,
		"{\"version\":\"0.1\", \"type\":\"dealias\", \"method\":\"%s\"",
		scamper_dealias_method_tostr(dealias, tmp, sizeof(tmp)));
  string_concat(buf, sizeof(buf), &off, ", \"userid\":%u, \"result\":\"%s\"",
		dealias->userid,
		scamper_dealias_result_tostr(dealias, tmp, sizeof(tmp)));
  string_concat(buf, sizeof(buf), &off, ", \"start\":{\"sec\":%u, \"usec\":%u}",
		dealias->start.tv_sec, dealias->start.tv_usec);

  if(SCAMPER_DEALIAS_METHOD_IS_MERCATOR(dealias))
    {
      mc = dealias->data;
      string_concat(buf, sizeof(buf), &off,
		    ", \"attempts\":%u, \"wait_timeout\":%u",
		    mc->attempts, mc->wait_timeout);
    }
  else if(SCAMPER_DEALIAS_METHOD_IS_ALLY(dealias))
    {
      ally = dealias->data;
      string_concat(buf, sizeof(buf), &off,
		    ", \"wait_probe\":%u, \"wait_timeout\":%u",
		    ally->wait_probe, ally->wait_timeout);
      string_concat(buf, sizeof(buf), &off, ", \"attempts\":%u, \"fudge\":%u",
		    ally->attempts, ally->fudge);
      /* XXX: flags */
    }
  else if(SCAMPER_DEALIAS_METHOD_IS_RADARGUN(dealias))
    {
      rg = dealias->data;
      string_concat(buf, sizeof(buf), &off, ", \"attempts\":%u, \"wait_probe\":%u",
		    rg->attempts, rg->wait_probe);
      string_concat(buf, sizeof(buf), &off, ", \"wait_round\":%u, \"wait_timeout\":%u",
		    rg->wait_round, rg->wait_timeout);
      /* XXX: flags */
    }
  else if(SCAMPER_DEALIAS_METHOD_IS_PREFIXSCAN(dealias))
    {
      pf = dealias->data;
      string_concat(buf, sizeof(buf), &off, ", \"a\":\"%s\"",
		    scamper_addr_tostr(pf->a, tmp, sizeof(tmp)));
      string_concat(buf, sizeof(buf), &off, ", \"b\":\"%s/%u\"",
		    scamper_addr_tostr(pf->b, tmp, sizeof(tmp)), pf->prefix);
      if(pf->ab != NULL)
	string_concat(buf, sizeof(buf), &off, ", \"ab\":\"%s/%u\"",
		      scamper_addr_tostr(pf->ab, tmp, sizeof(tmp)),
		      scamper_addr_prefixhosts(pf->b, pf->ab));
      if(pf->xc > 0)
	{
	  string_concat(buf, sizeof(buf), &off, ", \"xs\":[\"%s\"",
			scamper_addr_tostr(pf->xs[0], tmp, sizeof(tmp)));
	  for(u16=1; u16 < pf->xc; u16++)
	    string_concat(buf, sizeof(buf), &off, ", \"%s\"",
			  scamper_addr_tostr(pf->xs[u16], tmp, sizeof(tmp)));
	  string_concat(buf, sizeof(buf), &off, "]");
	}
      string_concat(buf, sizeof(buf), &off,
		    ", \"attempts\":%u, \"replyc\":%u, \"fudge\":%u",
		    pf->attempts, pf->replyc, pf->fudge);
      string_concat(buf, sizeof(buf), &off,
		    ", \"wait_probe\":%u, \"wait_timeout\":%u",
		    pf->wait_probe, pf->wait_timeout);
      /* XXX: flags */
    }
  else if(SCAMPER_DEALIAS_METHOD_IS_BUMP(dealias))
    {
      bump = dealias->data;
      string_concat(buf, sizeof(buf), &off,
		    ", \"wait_probe\":%u, \"bump_limit\":%u, \"attempts\":%u",
		    bump->wait_probe, bump->bump_limit, bump->attempts);
    }

  return strdup(buf);
}

static char *dealias_probedef_tostr(const scamper_dealias_probedef_t *def)
{
  char buf[256], tmp[64];
  size_t off = 0;
  string_concat(buf, sizeof(buf), &off, "{\"id\":%u, \"src\":\"%s\"",
		def->id, scamper_addr_tostr(def->src, tmp, sizeof(tmp)));
  string_concat(buf, sizeof(buf), &off, ", \"dst\":\"%s\", \"ttl\":%u, \"size\":%u",
		scamper_addr_tostr(def->dst, tmp, sizeof(tmp)), def->ttl, def->size);
  string_concat(buf, sizeof(buf), &off, ", \"method\":\"%s\"",
		scamper_dealias_probedef_method_tostr(def, tmp, sizeof(tmp)));
  if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_ICMP(def))
    string_concat(buf, sizeof(buf), &off, ", \"icmp_id\":%u, \"icmp_csum\":%u",
		  def->un.icmp.id, def->un.icmp.csum);
  else if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_UDP(def))
    string_concat(buf, sizeof(buf), &off, ", \"udp_sport\":%u, \"udp_dport\":%u",
		  def->un.udp.sport, def->un.udp.dport);
  else if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_TCP(def))
    string_concat(buf, sizeof(buf), &off,
		  ", \"tcp_sport\":%u, \"tcp_dport\":%u, \"tcp_flags\":%u",
		  def->un.tcp.sport, def->un.tcp.dport, def->un.tcp.flags);
  if(def->mtu > 0)
    string_concat(buf, sizeof(buf), &off, ", \"mtu\":%u", def->mtu);
  string_concat(buf, sizeof(buf), &off, "}");
  return strdup(buf);
}

static int dealias_probedefs_get(const scamper_dealias_t *dealias,
				 scamper_dealias_probedef_t **defs, int *defc)
{
  scamper_dealias_mercator_t *mc;
  scamper_dealias_ally_t *ally;
  scamper_dealias_radargun_t *rg;
  scamper_dealias_prefixscan_t *pf;
  scamper_dealias_bump_t *bump;

  switch(dealias->method)
    {
    case SCAMPER_DEALIAS_METHOD_MERCATOR:
      mc = dealias->data;
      *defs = &mc->probedef; *defc = 1;
      break;

    case SCAMPER_DEALIAS_METHOD_ALLY:
      ally = dealias->data;
      *defs = ally->probedefs; *defc = 2;
      break;

    case SCAMPER_DEALIAS_METHOD_RADARGUN:
      rg = dealias->data;
      *defs = rg->probedefs; *defc = rg->probedefc;
      break;

    case SCAMPER_DEALIAS_METHOD_PREFIXSCAN:
      pf = dealias->data;
      *defs = pf->probedefs; *defc = pf->probedefc;
      break;

    case SCAMPER_DEALIAS_METHOD_BUMP:
      bump = dealias->data;
      *defs = bump->probedefs; *defc = 2;
      break;

    default:
      return -1;
    }

  return 0;
}

static char *dealias_reply_tostr(const scamper_dealias_reply_t *reply)
{
  char buf[256], tmp[64];
  size_t off = 0;
  string_concat(buf, sizeof(buf), &off,
		"{\"src\":\"%s\", \"rx\":{\"sec\":%u, \"usec\":%u}, \"ttl\":%u",
		scamper_addr_tostr(reply->src, tmp, sizeof(tmp)),
		reply->rx.tv_sec, reply->rx.tv_usec, reply->ttl);
  if(SCAMPER_ADDR_TYPE_IS_IPV4(reply->src))
    string_concat(buf, sizeof(buf), &off, ", \"ipid\": %u", reply->ipid);
  else if(reply->flags & SCAMPER_DEALIAS_REPLY_FLAG_IPID32)
    string_concat(buf, sizeof(buf), &off, ", \"ipid\": %u", reply->ipid32);
  string_concat(buf, sizeof(buf), &off, ", \"proto\":%u", reply->proto);

  if(SCAMPER_DEALIAS_REPLY_IS_ICMP(reply))
    {
      string_concat(buf, sizeof(buf), &off, ", \"icmp_type\":%u, \"icmp_code\":%u",
		    reply->icmp_type, reply->icmp_code);

      if(SCAMPER_DEALIAS_REPLY_IS_ICMP_UNREACH(reply) ||
	 SCAMPER_DEALIAS_REPLY_IS_ICMP_TTL_EXP(reply))
	string_concat(buf, sizeof(buf), &off,
		      ", \"icmp_q_ttl\":%u",reply->icmp_q_ip_ttl);
    }
  else if(SCAMPER_DEALIAS_REPLY_IS_TCP(reply))
    {
      string_concat(buf, sizeof(buf), &off, ", \"tcp_flags\":%u", reply->tcp_flags);
    }

  string_concat(buf, sizeof(buf), &off, "}");
  return strdup(buf);
}

static char *dealias_probe_tostr(const scamper_dealias_probe_t *probe)
{
  char header[256], **replies = NULL, *rc = NULL, *str = NULL;
  size_t len, wc = 0, header_len = 0, *reply_lens = NULL;
  int i;

  string_concat(header, sizeof(header), &header_len,
		"{\"probedef_id\":%u, \"seq\":%u, \"tx\":{\"sec\":%u, \"usec\":%u}",
		probe->def->id, probe->seq, probe->tx.tv_sec, probe->tx.tv_usec);
  if(SCAMPER_ADDR_TYPE_IS_IPV4(probe->def->dst))
    string_concat(header, sizeof(header), &header_len, ", \"ipid\":%u", probe->ipid);
  string_concat(header, sizeof(header), &header_len, ", \"replies\":[");
  len = header_len;
  if(probe->replyc > 0)
    {
      if((replies = malloc_zero(sizeof(char *) * probe->replyc)) == NULL ||
	 (reply_lens = malloc_zero(sizeof(size_t) * probe->replyc)) == NULL)
	goto done;
      for(i=0; i<probe->replyc; i++)
	{
	  if(i > 0) len += 2; /* , */
	  if((replies[i] = dealias_reply_tostr(probe->replies[i])) == NULL)
	    goto done;
	  reply_lens[i] = strlen(replies[i]);
	  len += reply_lens[i];
	}
    }
  len += 3; /* ]}\0 */

  if((str = malloc(len)) == NULL)
    goto done;
  memcpy(str, header, header_len); wc += header_len;
  if(probe->replyc > 0)
    {
      for(i=0; i<probe->replyc; i++)
	{
	  if(i > 0)
	    {
	      memcpy(str+wc, ", ", 2);
	      wc += 2;
	    }
	  memcpy(str+wc, replies[i], reply_lens[i]);
	  wc += reply_lens[i];
	}
    }
  memcpy(str+wc, "]}\0", 3); wc += 3;
  assert(wc == len);

  rc = str;

 done:
  if(rc == NULL && str != NULL)
    free(str);
  if(replies != NULL) {
    for(i=0; i<probe->replyc; i++)
      if(replies[i] != NULL)
	free(replies[i]);
    free(replies);
  }
  if(reply_lens != NULL)
    free(reply_lens);
  return rc;
}

int scamper_file_json_dealias_write(const scamper_file_t *sf,
				    const scamper_dealias_t *dealias)
{
  int       fd          = scamper_file_getfd(sf);
  off_t     off         = 0;
  char     *str         = NULL;
  size_t    len         = 0;
  size_t    wc          = 0;
  char     *header      = NULL;
  size_t    header_len  = 0;
  char    **pds         = NULL;
  size_t   *pd_lens     = NULL;
  char    **prs         = NULL;
  size_t   *pr_lens     = NULL;
  int       i, rc       = -1;

  scamper_dealias_probedef_t *defs; int defc;

  /* get current position incase trunction is required */
  if(fd != 1 && (off = lseek(fd, 0, SEEK_CUR)) == -1)
    return -1;

  /* get the header string */
  if((header = dealias_header_tostr(dealias)) == NULL)
    goto cleanup;
  len = (header_len = strlen(header));
  len += 2; /* }\n" */

  /* get the probedef strings */
  if(dealias_probedefs_get(dealias, &defs, &defc) != 0 ||
     (pds = malloc_zero(sizeof(char *) * defc)) == NULL ||
     (pd_lens = malloc_zero(sizeof(size_t) * defc)) == NULL)
    goto cleanup;
  len += 16; /* , "probedefs":[] */
  for(i=0; i<defc; i++)
    {
      if(i > 0) len += 2; /* , */
      pds[i] = dealias_probedef_tostr(&defs[i]);
      pd_lens[i] = strlen(pds[i]);
      len += pd_lens[i];
    }

  /* get the probe strings */
  len += 13; /* , "probes":[] */
  if(dealias->probec > 0)
    {
      if((prs = malloc_zero(sizeof(char *) * dealias->probec)) == NULL ||
	 (pr_lens = malloc_zero(sizeof(size_t) * dealias->probec)) == NULL)
	goto cleanup;

      for(i=0; i<dealias->probec; i++)
	{
	  if(i > 0) len += 2; /* , */
	  if((prs[i] = dealias_probe_tostr(dealias->probes[i])) == NULL)
	    goto cleanup;
	  pr_lens[i] = strlen(prs[i]);
	  len += pr_lens[i];
	}
    }

  if((str = malloc(len)) == NULL)
    goto cleanup;
  memcpy(str+wc, header, header_len); wc += header_len;
  memcpy(str+wc, ", \"probedefs\":[", 15); wc += 15;
  for(i=0; i<defc; i++)
    {
      if(i > 0)
	{
	  memcpy(str+wc, ", ", 2);
	  wc += 2;
	}
      memcpy(str+wc, pds[i], pd_lens[i]);
      wc += pd_lens[i];
    }
  memcpy(str+wc, "]", 1); wc++;
  memcpy(str+wc, ", \"probes\":[", 12); wc += 12;
  if(dealias->probec > 0)
    {
      for(i=0; i<dealias->probec; i++)
	{
	  if(i > 0 )
	    {
	      memcpy(str+wc, ", ", 2);
	      wc += 2;
	    }
	  memcpy(str+wc, prs[i], pr_lens[i]);
	  wc += pr_lens[i];
	}
    }
  memcpy(str+wc, "]", 1); wc++;
  memcpy(str+wc, "}\n", 2); wc += 2;

  assert(wc == len);

  /*
   * try and write the string to disk.  if it fails, then truncate the
   * write and fail
   */
  if(write_wrap(fd, str, &wc, len) != 0)
    {
      if(fd != 1)
	{
	  if(ftruncate(fd, off) != 0)
	    goto cleanup;
	}
      goto cleanup;
    }
  rc = 0; /* we succeeded */

 cleanup:
  if(str != NULL) free(str);
  if(header != NULL) free(header);
  if(pd_lens != NULL) free(pd_lens);
  if(pr_lens != NULL) free(pr_lens);
  if(pds != NULL)
    {
      for(i=0; i<defc; i++)
	if(pds[i] != NULL)
	  free(pds[i]);
      free(pds);
    }
  if(prs != NULL)
    {
      for(i=0; i<dealias->probec; i++)
	if(prs[i] != NULL)
	  free(prs[i]);
      free(prs);
    }
  return rc;
}
