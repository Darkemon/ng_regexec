/*-
 * Author: Krasotin Artem
 * 
 */
 
/*
 * REGEXEC NETGRAPH NODE TYPE
 *  
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/ctype.h>
#include <sys/queue.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <netgraph/ng_message.h>
#include <netgraph/netgraph.h>
#include <netgraph/ng_parse.h>

#include "regex.h"
#include "ng_regexec.h"

#ifdef NG_SEPARATE_MALLOC
MALLOC_DEFINE(M_NETGRAPH_REGEXEC, "netgraph_regexec", "netgraph regexec node");
#else
#define M_NETGRAPH_REGEXEC M_NETGRAPH
#endif

#define ERROUT(x)	do { error = (x); goto done; } while (0)

#define OFFSETOF(s, e) ((char *)&((s *)0)->e - (char *)((s *)0)) 

#define REGEXP_MATCH() {                                                        \
  switch(hdr->ip.ip_p) {                                                        \
    case IPPROTO_TCP:                                                           \
      hip->stats.matchTcp++;                                                    \
      break;                                                                    \
    case IPPROTO_UDP:                                                           \
      hip->stats.matchUdp++;                                                    \
      break;                                                                    \
  }                                                                             \
                                                                                \
  /* Create log dgram. */                                                       \
  if (nip->h_log != NULL) {                                                     \
    m_log = m_getcl(M_DONTWAIT, MT_DATA, M_PKTHDR);                             \
    if (m_log != NULL) {                                                        \
      item_log = ng_package_data(m_log, NG_NOFLAGS);                            \
      if (item_log != NULL) {                                                   \
        strlcpy(log_dgram.pat_name, p_name, strlen(p_name)+1);                  \
        /* Fill mbuf. */                                                        \
        bcopy(&log_dgram, mtod(m_log, struct export_log_dgram *),               \
          sizeof(struct ng_regexec_log_dgram));                                 \
        m_log->m_len = m_log->m_pkthdr.len =                                    \
          sizeof(struct ng_regexec_log_dgram);                                  \
      }                                                                         \
      else                                                                      \
        m_freem(m_log);                                                         \
      }                                                                         \
    }                                                                           \
                                                                                \
  matched = 1;                                                                  \
  break;                                                                        \
}

struct ng_regexec_entry {
	STAILQ_ENTRY(ng_regexec_entry) p_link;
  char      *p_name;
  char      *p_pattern;
  regex_t   regexp;
};

struct hooks_list_entry {
	STAILQ_ENTRY(hooks_list_entry) p_link;
  struct ng_regexec_entry *pattern;
};

STAILQ_HEAD(ng_regexec_list_head, ng_regexec_entry);
STAILQ_HEAD(hooks_list_head, hooks_list_entry);

struct ng_regexec_hookinfo {
  hook_p     h_match;               /* matching hook pointer */
  hook_p     h_nomatch;             /* non-matching hook pointer */
  struct ng_regexec_hooks    *hooks;
  struct ng_regexec_hookstat  stats;
  struct hooks_list_head regexp_ref_list_head;
};
typedef struct ng_regexec_hookinfo *hinfo_p;

struct ng_regexec_nodeinfo {
  hook_p h_log;
  struct ng_regexec_list_head regexp_list_head;
};
typedef struct ng_regexec_nodeinfo *ninfo_p;

/* Netgraph methods. */
static ng_constructor_t ng_regexec_constructor;
static ng_rcvmsg_t      ng_regexec_rcvmsg;
static ng_newhook_t     ng_regexec_newhook;
static ng_rcvdata_t     ng_regexec_rcvdata;
static ng_shutdown_t    ng_regexec_shutdown;
static ng_disconnect_t  ng_regexec_disconnect;

static int ng_regexec_pattern_array_getLength(const struct ng_parse_type *type,
                                      const u_char *start, const u_char *buf);

static int 
ng_regexec_pattern_array_getLength(const struct ng_parse_type *type,
                                      const u_char *start, const u_char *buf)
{
  const struct ng_regexec_hooks *h;

  h = (const struct ng_regexec_hooks *)
    (buf - OFFSETOF(struct ng_regexec_hooks, pat));
  return h->pat_len;
}

/* Parse type for struct ng_regexec_hooks */
static const struct ng_parse_array_info ng_regexec_pattern_array_info = {
  &ng_parse_uint16_type,
  &ng_regexec_pattern_array_getLength
};
static const struct ng_parse_type ng_regexec_pattern_array_type = {
  &ng_parse_array_type,
  &ng_regexec_pattern_array_info
};
static const struct ng_parse_struct_field ng_regexec_hooks_type_fields[]
  = NG_REGEXEC_HOOKS_TYPE_INFO(ng_regexec_pattern_array_type);
static const struct ng_parse_type ng_regexec_hooks_type = {
  &ng_parse_struct_type,
  &ng_regexec_hooks_type_fields
};

/* Parse type for struct ng_regexec_name */
static const struct ng_parse_struct_field ng_regexec_name_type_fields[]
  = NG_REGEXEC_NAME_TYPE_INFO();
static const struct ng_parse_type ng_regexec_name_type = {
  &ng_parse_struct_type,
  &ng_regexec_name_type_fields
};

/* Parse type for struct ng_regexec_hookstat. */
static const struct ng_parse_struct_field ng_regexec_hookstat_type_fields[]
  = NG_REGEXEC_HOOKSTAT_TYPE_INFO;
static const struct ng_parse_type ng_regexec_hookstat_type = {
  &ng_parse_struct_type,
  &ng_regexec_hookstat_type_fields
};

/* List of commands and how to convert arguments to/from ASCII. */
static const struct ng_cmdlist ng_regexec_cmdlist[] = {
  {
    NGM_REGEXEC_COOKIE,
    NGM_REGEXEC_SHOW,
    "show",
    &ng_parse_uint16_type,
    NULL
  },
  {
    NGM_REGEXEC_COOKIE,
    NGM_REGEXEC_SHOWALL,
    "showall",
    NULL,
    NULL
  },
  {
    NGM_REGEXEC_COOKIE,
    NGM_REGEXEC_SET_HOOKS,
    "sethooks",
    &ng_regexec_hooks_type,
    NULL
  },
  {
    NGM_REGEXEC_COOKIE,
    NGM_REGEXEC_GET_HOOKS,
    "gethooks",
    &ng_parse_hookbuf_type,
    &ng_regexec_hooks_type
  },
  {
    NGM_REGEXEC_COOKIE,
    NGM_REGEXEC_ADD_PATTERN,
    "addpattern",
    &ng_parse_string_type,
    NULL
  },
  {
    NGM_REGEXEC_COOKIE,
    NGM_REGEXEC_DEL_PATTERN,
    "delpattern",
    &ng_parse_uint16_type,
    NULL
  },
  {
    NGM_REGEXEC_COOKIE,
    NGM_REGEXEC_SET_NAME,
    "setname",
    &ng_regexec_name_type,
    NULL
  },
  {
    NGM_REGEXEC_COOKIE,
    NGM_REGEXEC_GET_STATS,
    "getstats",
    &ng_parse_hookbuf_type,
    &ng_regexec_hookstat_type
  },
  {
    NGM_REGEXEC_COOKIE,
    NGM_REGEXEC_CLR_STATS,
    "clrstats",
    &ng_parse_hookbuf_type,
    NULL
  },
  {
    NGM_REGEXEC_COOKIE,
    NGM_REGEXEC_GETCLR_STATS,
    "getclrstats",
    &ng_parse_hookbuf_type,
    &ng_regexec_hookstat_type
  },
  { 0 }
};

/* Netgraph type descriptor. */
static struct ng_type typestruct = {
  .version     = NG_ABI_VERSION,
  .name        = NG_REGEXEC_NODE_TYPE,
  .constructor = ng_regexec_constructor,
  .rcvmsg      = ng_regexec_rcvmsg,
  .shutdown    = ng_regexec_shutdown,
  .newhook     = ng_regexec_newhook,
  .rcvdata     = ng_regexec_rcvdata,
  .disconnect  = ng_regexec_disconnect,
  .cmdlist     = ng_regexec_cmdlist
};
NETGRAPH_INIT(regexec, &typestruct);

/* Default regexec values for a hook that matches nothing. */
static const struct ng_regexec_hooks ng_regexec_default = {
  { '\0' },    /* to be filled in at hook creation time */
  { '\0' },
  { '\0' },
  0,
  { 0 }
};

/* Internal helper functions. */
static int ng_regexec_sethooks(hook_p hook, const struct ng_regexec_hooks *hp);
static int ng_regexec_addrefs(hook_p hook, void* arg);
static int ng_regexec_remrefs(hook_p hook, void* arg);
static int ng_regexec_delrefs_pattern(hook_p hook, void* arg);
static int ng_regexec_rem_all_pattern_refs(hook_p hook);
static int ng_regexec_del_pattern_id(hook_p hook, uint16_t id);
static struct ng_regexec_entry *
  ng_regexec_find_pattern(node_p node, uint16_t id);
static uint16_t
  ng_regexec_find_id_pattern(node_p node, struct ng_regexec_entry *entry);
static int ng_regexec_hex2dec(char c);
static char *ng_regexec_translate_re(char *re, size_t len);
#ifdef NG_REGEXEC_DEBUG
int find_substr(const char *str, size_t str_len, const char *substr, 
  size_t substr_len);
#endif
int print(const u_char *data, int datalen, char flag);

/*
 * Node constructor.
 */
static int
ng_regexec_constructor(node_p node)
{
  ninfo_p privdata;
  privdata = malloc(sizeof(*privdata), M_NETGRAPH_REGEXEC, M_WAITOK|M_ZERO);
  
  /* Init list. */
  STAILQ_INIT(&privdata->regexp_list_head);
  
  /* M_WAITOK can't return NULL. */
  NG_NODE_SET_PRIVATE(node, privdata);

  return (0);
}


/*
 * Add a hook.
 */
static int
ng_regexec_newhook(node_p node, hook_p hook, const char *name)
{
  ninfo_p nip = NG_NODE_PRIVATE(node);
  hinfo_p hip;
  hook_p  tmp;
  int     error;

  if (strcmp(name, NG_REGEXEC_LOG_HOOK_NAME) == 0) {
    nip->h_log = hook;
    return (0);
  }

  /* Create hook private structure. */
  hip = malloc(sizeof(*hip), M_NETGRAPH_REGEXEC, M_WAITOK | M_ZERO);
  /* M_WAITOK can't return NULL. */
  NG_HOOK_SET_PRIVATE(hook, hip);
  
  /* Init list. */
  STAILQ_INIT(&hip->regexp_ref_list_head);
  
  /* Add our reference into other hooks data. */
  NG_NODE_FOREACH_HOOK(node, ng_regexec_addrefs, hook, tmp);

  /* Attach the default hooks data. */
  if ((error = ng_regexec_sethooks(hook, &ng_regexec_default)) != 0) {
    free(hip, M_NETGRAPH_REGEXEC);
    NG_HOOK_SET_PRIVATE(hook, NULL);
    return (error);
  }

  /* Set hook name */
  strlcpy(hip->hooks->thisHook, name, sizeof(hip->hooks->thisHook));
  return (0);
}


/*
 * Receive a control message.
 */
static int
ng_regexec_rcvmsg(node_p node, item_p item, hook_p lasthook)
{
  struct ng_mesg *msg;
  struct ng_mesg *resp = NULL;
  int error = 0;

  NGI_GET_MSG(item, msg);
  switch (msg->header.typecookie) 
  {
    case NGM_REGEXEC_COOKIE:
      switch (msg->header.cmd) 
      {
        case NGM_REGEXEC_ADD_PATTERN:
        {
          int reg_flags = REG_EXTENDED | REG_ICASE | REG_NOSUB;
          int reg_error = 0;  
          char *pat = (char *)msg->data; 
          ninfo_p nip = NG_NODE_PRIVATE(node);
          
          /* Create new entry of list. */
          struct ng_regexec_entry *entry = malloc(
            sizeof(struct ng_regexec_entry), M_NETGRAPH_REGEXEC, M_WAITOK);
                    
          /* Copy pattern. */
          entry->p_pattern = malloc(strlen(pat)+1, M_NETGRAPH_REGEXEC, M_WAITOK);
          strlcpy(entry->p_pattern, pat, strlen(pat)+1);
          
          pat = ng_regexec_translate_re(entry->p_pattern, 
            strlen(entry->p_pattern));
          
          /* Set default name. */
          entry->p_name = malloc(sizeof(char), M_NETGRAPH_REGEXEC, M_WAITOK);
          entry->p_name[0] = '\0';
          
          /* Compile regexp. */
          if (strlen(pat) > 0) {
            reg_error = regcomp(&entry->regexp, pat, reg_flags);
            if (reg_error != 0) {
              char errmsg[255];
              regerror(reg_error, &entry->regexp, errmsg, sizeof(errmsg));
              uprintf("unable to compile pattern: %s\n", errmsg);
              
              /* Free data. */
              free(entry->p_name, M_NETGRAPH_REGEXEC);
              free(entry->p_pattern, M_NETGRAPH_REGEXEC);
              free(entry, M_NETGRAPH_REGEXEC);
            }
            else {
#ifdef NG_REGEXEC_DEBUG              
              uprintf("Pattern: %s\n", entry->p_pattern);
#endif
              /* Add entry to the list. */
              STAILQ_INSERT_TAIL(&nip->regexp_list_head, entry, p_link);
            }
          }
          free(pat, M_NETGRAPH_REGEXEC);
          break;
        }
        case NGM_REGEXEC_DEL_PATTERN:
        {
          uint16_t *index = (uint16_t *)msg->data;
          ninfo_p nip = NG_NODE_PRIVATE(node);
          hook_p tmp; 
          struct ng_regexec_entry *entry;
         
          if ((entry = ng_regexec_find_pattern(node, *index)) == NULL)
            error = ENOENT;
          else {
            /* Recalculate all hooks info. */
            NG_NODE_FOREACH_HOOK(node, ng_regexec_delrefs_pattern, entry, tmp);
          
            /* Free data. */
            regfree(&entry->regexp);
            free(entry->p_name, M_NETGRAPH_REGEXEC);
            free(entry->p_pattern, M_NETGRAPH_REGEXEC);
            STAILQ_REMOVE(&nip->regexp_list_head, entry, ng_regexec_entry, 
                p_link);
            free(entry, M_NETGRAPH_REGEXEC);
          }
          break;
        }
        case NGM_REGEXEC_SHOW:
        case NGM_REGEXEC_SHOWALL:
        {
          ninfo_p nip = NG_NODE_PRIVATE(node);
          struct ng_regexec_entry *entry1, *entry2;
          uint16_t *index = NULL;
          uint16_t  i = 1;
          
          if (msg->header.cmd == NGM_REGEXEC_SHOW) {
            index = (uint16_t *)msg->data;
            error = ENOENT;
          }
          
          entry1 = STAILQ_FIRST(&nip->regexp_list_head);
          while (entry1 != NULL) 
          {
            if (index == NULL) {
              uprintf("%d. %s\n", i, entry1->p_name);
            }
            else {
              if (i == *index) {
                uprintf("%d. (%s) %s\n", i, entry1->p_name, entry1->p_pattern);
                error = 0;
                break;
              }
            }
            entry2 = STAILQ_NEXT(entry1, p_link);
            entry1 = entry2;
            i++;
          }
          break;
        }
        case NGM_REGEXEC_SET_NAME:
        {
          struct ng_regexec_name *const
            name_info = (struct ng_regexec_name *)msg->data;
  
          size_t name_len = strlen(name_info->name) + 1;
          ninfo_p nip = NG_NODE_PRIVATE(node);
          struct ng_regexec_entry *entry;
          
          /* Sanity check */
          if (msg->header.arglen < sizeof(*name_info))
            ERROUT(EINVAL);
          
          if (name_info->id == 0)
            entry = STAILQ_LAST(&nip->regexp_list_head, ng_regexec_entry, 
              p_link);
          else
            entry = ng_regexec_find_pattern(node, name_info->id);

          if (entry != NULL) {
            free(entry->p_name, M_NETGRAPH_REGEXEC);
            entry->p_name = malloc(name_len, M_NETGRAPH_REGEXEC, M_WAITOK);
            strlcpy(entry->p_name, name_info->name, name_len);
          }
          else
            error = ENOENT;
          break;
        }
        case NGM_REGEXEC_SET_HOOKS:
        {
          struct ng_regexec_hooks *const
            hp = (struct ng_regexec_hooks *)msg->data;
          hook_p hook;

          /* Sanity check */
          if (msg->header.arglen < sizeof(*hp)
              || msg->header.arglen
              != NG_REGEXEC_HOOKS_SIZE(hp->pat_len))
            ERROUT(EINVAL);
          
          /* Find hook */
          if ((hook = ng_findhook(node, hp->thisHook)) == NULL)
            ERROUT(ENOENT);

          /* Set hooks */
          if ((error = ng_regexec_sethooks(hook, hp)) != 0)
            ERROUT(error);
          break;
        }

        case NGM_REGEXEC_GET_HOOKS:
        {
          struct ng_regexec_hooks *hp;
          size_t size;
          hook_p hook;

          /* Sanity check */
          if (msg->header.arglen == 0)
            ERROUT(EINVAL);
          msg->data[msg->header.arglen - 1] = '\0';

          /* Checks is log hook or not. */
          if (strcmp(msg->data, NG_REGEXEC_LOG_HOOK_NAME) == 0)
            ERROUT(EINVAL);

          /* Find hook */
          if ((hook = ng_findhook(node, msg->data)) == NULL)
            ERROUT(ENOENT);

          /* Build response */
          hp = ((hinfo_p)NG_HOOK_PRIVATE(hook))->hooks;
          size = NG_REGEXEC_HOOKS_SIZE(hp->pat_len);
          NG_MKRESPONSE(resp, msg, size, M_WAITOK);
          /* M_WAITOK can't return NULL. */
          bcopy(hp, resp->data, size);
          break;
        }
        
        case NGM_REGEXEC_GET_STATS:
        case NGM_REGEXEC_CLR_STATS:
        case NGM_REGEXEC_GETCLR_STATS:
        {
          struct ng_regexec_hookstat *stats;
          hook_p hook;

          /* Sanity check */
          if (msg->header.arglen == 0)
            ERROUT(EINVAL);
          msg->data[msg->header.arglen - 1] = '\0';

          /* Checks is log hook or not. */
          if (strcmp(msg->data, NG_REGEXEC_LOG_HOOK_NAME) == 0)
            ERROUT(EINVAL);

          /* Find hook */
          if ((hook = ng_findhook(node, msg->data)) == NULL)
            ERROUT(ENOENT);
            
          stats = &((hinfo_p)NG_HOOK_PRIVATE(hook))->stats;

          /* Build response (if desired) */
          if (msg->header.cmd != NGM_REGEXEC_CLR_STATS) {
            NG_MKRESPONSE(resp, msg, sizeof(*stats), M_WAITOK);
            /* M_WAITOK can't return NULL. */
            bcopy(stats, resp->data, sizeof(*stats));
          }

          /* Clear stats (if desired) */
          if (msg->header.cmd != NGM_REGEXEC_GET_STATS)
            bzero(stats, sizeof(*stats));
          break;
		    }

        default:
          error = EINVAL;
          break;
      }
      break;
    default:
      error = EINVAL;
      break;
  }
done:
  NG_RESPOND_MSG(error, node, item, resp);
  NG_FREE_MSG(msg);
  return (error);
}


/*
 * Receive data on a hook
 *
 * Apply the filter, and then drop or forward packet as appropriate.
 */
static int
ng_regexec_rcvdata(hook_p hook, item_p item)
{
  const hinfo_p hip = NG_HOOK_PRIVATE(hook);
  const ninfo_p nip = NG_NODE_PRIVATE(NG_HOOK_NODE(hook));
  int totlen;
  int error = 0;
  int matched = 0;
  hinfo_p dhip;
  hook_p dest;
  u_char *payload = NULL, *data = NULL;
  item_p item_log = NULL;
  struct mbuf *m, *m_log = NULL;
  struct allhdr *hdr;
  struct ng_regexec_log_dgram log_dgram;
  
  m = NGI_M(item);	/* 'item' still owns it.. we are peeking */ 
  totlen = m->m_pkthdr.len;
  
  if (nip->h_log == hook) {
    NG_FREE_ITEM(item);
    return (0);
  }
  
  /* Update stats on incoming hook. */
  hip->stats.recvFrames++; 
  hip->stats.recvOctets += totlen;

  /* Don't call regexec with totlen == 0! */
  if (totlen == 0)
    goto ready;

  //
  // Crashes tcp protocol if pullup to totlen. (why?)
  // Therefore we copy data.
  //
  
  /* Need to put packet in contiguous memory for regexec */
/*  if (m->m_len < totlen) {
    NGI_M(item) = m = m_pullup(m, totlen);
    if (m == NULL) {
      NG_FREE_ITEM(item);
      return (ENOBUFS);
    }
  }
  */
  
  data = malloc(totlen, M_NETGRAPH_REGEXEC, M_NOWAIT);
  if(data == NULL) {
    error = ENOMEM;
    goto ready;
  }
  m_copydata(m, 0, totlen, data);
  
	hdr = (struct allhdr *)data;
  payload = data;

  if ((hdr->ip).ip_v == 4) { 
    log_dgram.ip_src = (hdr->ip).ip_src; 
    log_dgram.ip_dst = (hdr->ip).ip_dst;
  } else {
    bzero(&log_dgram, sizeof(log_dgram));
  }

  switch((hdr->ip).ip_p)
  {
    case IPPROTO_TCP:
    {
      struct tcphdr *tcp = &hdr->nexthdr.tcp;
      payload = (u_char *)((u_char *)tcp + (tcp->th_off * 4));
      totlen = ntohs((hdr->ip).ip_len) -
        (int)((caddr_t)payload - (caddr_t)&hdr->ip);
      
      log_dgram.sport = tcp->th_sport;  
      log_dgram.dport = tcp->th_dport;
      break;
    }
    case IPPROTO_UDP:
    {
      struct udphdr *udp = &hdr->nexthdr.udp;
      totlen = ntohs(udp->uh_ulen) - sizeof(struct udphdr);
      payload = (u_char *)(udp) + sizeof(struct udphdr);
      
      log_dgram.sport = udp->uh_sport;
      log_dgram.dport = udp->uh_dport;
      break;
    }
    case IPPROTO_ICMP:
    {
      /* TODO */
      break;
    }
  }
  
  /* 
   * Run packet through regexec. 
   */
  regmatch_t pmatch;
  pmatch.rm_so = 0;                                    
  pmatch.rm_eo = totlen;
  char *p_name = NULL;
  /* See hooks own patterns. */
  if (hip->hooks->pat_len != 0) {
    if (!STAILQ_EMPTY(&hip->regexp_ref_list_head)) {
      struct hooks_list_entry *entry1, *entry2;
      entry1 = STAILQ_FIRST(&hip->regexp_ref_list_head);
      while (entry1 != NULL) {
        if (regexec(&entry1->pattern->regexp, (char *)payload, 1, &pmatch, 
          REG_STARTEND) == 0)
        {
          p_name = entry1->pattern->p_name;
          REGEXP_MATCH();
        }
        else {
          entry2 = STAILQ_NEXT(entry1, p_link);
          entry1 = entry2; 
        }
      }
    }
  }
  /* See all patterns. */
  else if (!STAILQ_EMPTY(&nip->regexp_list_head)) 
  {
    struct ng_regexec_entry *entry1, *entry2;
    entry1 = STAILQ_FIRST(&nip->regexp_list_head);
    while (entry1 != NULL) {
      if (regexec(&entry1->regexp, (char *)payload, 1, &pmatch, 
        REG_STARTEND) == 0)
      {
        p_name = entry1->p_name;
        REGEXP_MATCH();
      }
      else { 
        entry2 = STAILQ_NEXT(entry1, p_link);
        entry1 = entry2;
      }
    }
  }     
  free(data, M_NETGRAPH_REGEXEC);

ready:
	/* See if we got a match and find destination hook */
  if (matched > 0)
  {
    /* Update stats */
    hip->stats.recvMatchFrames++;
    hip->stats.recvMatchOctets += totlen;

    dest = hip->h_match;
    
    /* Send log dgram. */
    if(item_log != NULL) {
      if (nip->h_log != NULL) {
        NG_FWD_ITEM_HOOK(error, item_log, nip->h_log);
      }
      else
       NG_FREE_ITEM(item_log); 
    }
  } else
    dest = hip->h_nomatch;

  /* Deliver frame out destination hook */
  if (dest == NULL) {
    NG_FREE_ITEM(item);
    return (0);
  }

  dhip = NG_HOOK_PRIVATE(dest);
  dhip->stats.xmitOctets += totlen;
  dhip->stats.xmitFrames++;
  NG_FWD_ITEM_HOOK(error, item, dest);
  return (error);
}


/*
 * Shutdown processing.
 */
static int
ng_regexec_shutdown(node_p node)
{
  const ninfo_p nip = NG_NODE_PRIVATE(node);
  struct ng_regexec_entry *entry;
  
  NG_NODE_SET_PRIVATE(node, NULL);
  /* Clear the list of patterns. */
  while (!STAILQ_EMPTY(&nip->regexp_list_head)) {
    entry = STAILQ_FIRST(&nip->regexp_list_head);
    STAILQ_REMOVE_HEAD(&nip->regexp_list_head, p_link);
    regfree(&entry->regexp);
    free(entry->p_name, M_NETGRAPH_REGEXEC);
    free(entry->p_pattern, M_NETGRAPH_REGEXEC);
    free(entry, M_NETGRAPH_REGEXEC);
  }
  free(nip, M_NETGRAPH_REGEXEC);
  NG_NODE_UNREF(node);
  return (0);
}


/*
 * Hook disconnection.
 *
 * We must check all hooks, since they may reference this one.
 */
static int
ng_regexec_disconnect(hook_p hook)
{
  const node_p node = NG_HOOK_NODE(hook); 
  const ninfo_p nip = NG_NODE_PRIVATE(node);
  const hinfo_p hip = NG_HOOK_PRIVATE(hook);
  hook_p tmp;
  
  if (hook == nip->h_log) {
    nip->h_log = NULL;
    return (0);
  }
  
  KASSERT(hip != NULL, ("%s: null info", __func__));

  /* Remove our reference from other hooks data. */
  NG_NODE_FOREACH_HOOK(node, ng_regexec_remrefs, hook, tmp);

  ng_regexec_rem_all_pattern_refs(hook);
  free(hip->hooks, M_NETGRAPH_REGEXEC);
  free(hip, M_NETGRAPH_REGEXEC);
  if ((NG_NODE_NUMHOOKS(node) == 0) &&
      (NG_NODE_IS_VALID(node))) 
    ng_rmnode_self(node);
  return (0);
}


/************************************************************************
      HELPER STUFF
 ************************************************************************/

/*
 * Set hooks.
 */
static int
ng_regexec_sethooks(hook_p hook, const struct ng_regexec_hooks *hp0)
{
  const hinfo_p hip = NG_HOOK_PRIVATE(hook);
	struct ng_regexec_hooks *hp;
  struct hooks_list_entry *entry_h;
  struct ng_regexec_entry *entry;
	size_t size;
  uint16_t i;

  if (strcmp(hp0->thisHook, NG_REGEXEC_LOG_HOOK_NAME) == 0)
    return (EINVAL);
  if (strcmp(hp0->ifMatch, NG_REGEXEC_LOG_HOOK_NAME) == 0)
    return (EINVAL);
  if (strcmp(hp0->ifNotMatch, NG_REGEXEC_LOG_HOOK_NAME) == 0)
    return (EINVAL);

  // TODO: check unique indexes in 'pat' array.

	/* Make a copy of the program */
	size = NG_REGEXEC_HOOKS_SIZE(hp0->pat_len);
	hp = malloc(size, M_NETGRAPH_REGEXEC, M_WAITOK);
	bcopy(hp0, hp, size); // M_WAITOK can't return NULL.
  
	/* Free previous program, if any, and assign new one */
  if (hip->hooks != NULL)
    free(hip->hooks, M_NETGRAPH_REGEXEC);
  hip->hooks = hp;

  /* Clear the list of references to the patterns. */
  ng_regexec_rem_all_pattern_refs(hook);

  /* Add references to the patterns. */
  for (i=0; i<hip->hooks->pat_len; i++) {
    if (hip->hooks->pat[i] == 0)
      continue;

    entry = ng_regexec_find_pattern(NG_HOOK_NODE(hook), hip->hooks->pat[i]);
    if (entry == NULL) {
      ng_regexec_rem_all_pattern_refs(hook);
      bzero(hip->hooks->pat, hip->hooks->pat_len*sizeof(uint16_t));
      hip->hooks->pat_len = 0;
      return (EINVAL);
    }
    
    entry_h = malloc(sizeof(struct hooks_list_entry), M_NETGRAPH_REGEXEC, 
      M_WAITOK | M_ZERO);
    entry_h->pattern = entry;
    STAILQ_INSERT_TAIL(&hip->regexp_ref_list_head, entry_h, p_link);
  }

  /* Prepare direct references on target hooks. */
  hip->h_match = ng_findhook(NG_HOOK_NODE(hook), hip->hooks->ifMatch);
  hip->h_nomatch = ng_findhook(NG_HOOK_NODE(hook), hip->hooks->ifNotMatch);
  
  return (0);
}

/*
 * Callback functions to be used by NG_NODE_FOREACH_HOOK() macro.
 */
static int
ng_regexec_addrefs(hook_p hook, void* arg)
{
  hinfo_p hip = NG_HOOK_PRIVATE(hook);
  hook_p h = (hook_p)arg;

  /* Specially for 'log' hook. */
  if (hip == NULL)
    return (1);

  if (strcmp(hip->hooks->ifMatch, NG_HOOK_NAME(h)) == 0)
    hip->h_match = h;
  if (strcmp(hip->hooks->ifNotMatch, NG_HOOK_NAME(h)) == 0)
    hip->h_nomatch = h;
  return (1);
}

static int
ng_regexec_remrefs(hook_p hook, void* arg)
{
  hinfo_p hip = NG_HOOK_PRIVATE(hook);
  hook_p h = (hook_p)arg;

  /* Specially for 'log' hook. */
  if (hip == NULL)
    return (1);

  if (hip->h_match == h)
    hip->h_match = NULL;
  if (hip->h_nomatch == h)
    hip->h_nomatch = NULL;
  return (1);
}

static int
ng_regexec_delrefs_pattern(hook_p hook, void* arg)
{
  hinfo_p hip = NG_HOOK_PRIVATE(hook);
  struct ng_regexec_entry *entry = (struct ng_regexec_entry *)arg;
  struct hooks_list_entry *entry_h1, *entry_h2;

  /* Specially for 'log' hook. */
  if (hip == NULL)
    return (1);

  uint16_t pat_id = ng_regexec_find_id_pattern(NG_HOOK_NODE(hook), entry);

  entry_h1 = STAILQ_FIRST(&hip->regexp_ref_list_head);
  while (entry_h1 != NULL) {
    if (entry_h1->pattern == entry) {
      STAILQ_REMOVE(&hip->regexp_ref_list_head, entry_h1, hooks_list_entry, 
          p_link);
      free(entry_h1, M_NETGRAPH_REGEXEC);
      ng_regexec_del_pattern_id(hook, pat_id);
      break;
    }
    else {
      entry_h2 = STAILQ_NEXT(entry_h1, p_link);
      entry_h1 = entry_h2;
    }
  }

  return (1);
}

/*
 * Helpers for patterns manipulations.
 */ 

/* Delete all references to patterns entry. */
static int
ng_regexec_rem_all_pattern_refs(hook_p hook)
{
  struct hooks_list_entry *entry_h;
  hinfo_p hip = NG_HOOK_PRIVATE(hook);
  
  while (!STAILQ_EMPTY(&hip->regexp_ref_list_head)) {
    entry_h = STAILQ_FIRST(&hip->regexp_ref_list_head);
    STAILQ_REMOVE_HEAD(&hip->regexp_ref_list_head, p_link);
    free(entry_h, M_NETGRAPH_REGEXEC);
  }
  return (0);
}

/* Delete pattern id and recalculate other id's. */
static int
ng_regexec_del_pattern_id(hook_p hook, uint16_t id)
{
  int all_zero = 1;
  uint16_t i;
  hinfo_p hip = NG_HOOK_PRIVATE(hook);
  
  if (id == 0)
    return (0);
  
  for (i=0; i<hip->hooks->pat_len; i++) {
    if (hip->hooks->pat[i] >= id) {
      if (hip->hooks->pat[i] == id) {
        hip->hooks->pat[i] = 0;
        continue;
      }
      hip->hooks->pat[i]--;
    }
    
    if (all_zero)
      if (hip->hooks->pat[i] != 0)
        all_zero = 0;
  }
  
  if (all_zero)
    hip->hooks->pat_len = 0;
  
  return (0);
}

/* Find pattern entry by index number. */
static struct ng_regexec_entry *
ng_regexec_find_pattern(node_p node, uint16_t id)
{
  uint16_t i = 1;
  ninfo_p nip = NG_NODE_PRIVATE(node);
  struct ng_regexec_entry *entry1, *entry2;
         
  if (id == 0)
    return (NULL);         
         
  entry1 = STAILQ_FIRST(&nip->regexp_list_head);
  while (entry1 != NULL) {
    if (i == id)
      return (entry1);
    else {
      entry2 = STAILQ_NEXT(entry1, p_link);
      entry1 = entry2;
      i++;
    }
  }
  return (NULL);
}

/* Find pattern entry id by reference to entry. */
static uint16_t
ng_regexec_find_id_pattern(node_p node, struct ng_regexec_entry *entry)
{
  uint16_t i = 1;
  ninfo_p nip = NG_NODE_PRIVATE(node);
  struct ng_regexec_entry *entry1, *entry2;
         
  if (entry == NULL)
    return (0);         
         
  entry1 = STAILQ_FIRST(&nip->regexp_list_head);
  while (entry1 != NULL) {
    if (entry1 == entry)
      return (i);
    else {
      entry2 = STAILQ_NEXT(entry1, p_link);
      entry1 = entry2;
      i++;
    }
  }
  return (0);
}

/*
 * Translate pattern string.
 */ 
static int
ng_regexec_hex2dec(char c) 
{
	switch (c) {
	case '0' ... '9':
		return (c - '0');
	case 'a' ... 'f':
		return (c - 'a' + 10);
	case 'A' ... 'F':
	default:
		return (c - 'A' + 10);
	}
}


static char *
ng_regexec_translate_re(char *str, size_t len)
{
	uint16_t i, j;
  char *re = malloc(strlen(str)+1, M_NETGRAPH_REGEXEC, M_WAITOK|M_ZERO);

	/*
	 * Convert, "in place", hex numbers in the RE to decimal equivalent.
	 * If the result of the conversion is an RE control character, then
	 * prefix it with a '\'.
	 */
	for (i = 0, j = 0; i < len; i++, j++) {
		if (((i + 3) < len) && (str[i] == '\\') && (str[i + 1] == 'x') &&
		    isxdigit(str[i + 2]) && isxdigit(str[i + 3])) 
    {
			re[j++] = '\\';
      re[j] = (ng_regexec_hex2dec(str[i + 2]) * 16) + 
        ng_regexec_hex2dec(str[i + 3]);
			i+=3;
		} else
			re[j] = str[i];
	}
	if (i != 0) {
		re[j] = '\0';
	}
	return (re);
}


#ifdef NG_REGEXEC_DEBUG
int
find_substr(const char *str, size_t str_len, const char *substr, 
  size_t substr_len)
{
  if ((substr_len > str_len) || (substr_len == 0))
    return 0;
  
  size_t i=0;
  
loop:
  while (i<str_len)
  {
    if(str_len-i < substr_len)
      return 0;
    
    for (size_t j=0; j<substr_len; j++)
      if (str[i+j-1] != substr[j]) {
        i++;
        goto loop;
      }
    return 1;
  }
  return 0;
}
#endif

int
print(const u_char *data, int datalen, char flag)
{
  for(int i=0; i<=datalen; i++) {
    switch(flag) {
      case 's':
        printf("%c", data[i]);
        break;
      case 'h':
        printf("%02x ", data[i]);
        break;
    }
  }
  printf("\n");
  return (0);
}
