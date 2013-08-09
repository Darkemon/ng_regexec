/*-
 * Author: Krasotin Artem
 * 
 */
  
#ifndef _NETGRAPH_NG_REGEXEC_H_
#define _NETGRAPH_NG_REGEXEC_H_

/* Node type name and magic cookie. */
#define NG_REGEXEC_NODE_TYPE "regexec"
#define NGM_REGEXEC_COOKIE   1331462403

#define NG_REGEXEC_LOG_HOOK_NAME "log"

/* Hooks info structure for one hook */
struct ng_regexec_hooks {
  char      thisHook[NG_HOOKSIZ];   /* name of hook */
  char      ifMatch[NG_HOOKSIZ];    /* name of match dest hook */
  char      ifNotMatch[NG_HOOKSIZ]; /* name of !match dest hook */
  u_char    pat_len;
  uint16_t  pat[];
};

/* Keep this in sync with the above structures definitions. */
#define NG_REGEXEC_HOOKS_TYPE_INFO(arrtype) {                                   \
  { "thisHook",   &ng_parse_hookbuf_type },                                     \
  { "ifMatch",    &ng_parse_hookbuf_type },                                     \
  { "ifNotMatch", &ng_parse_hookbuf_type },                                     \
  { "pat_len",    &ng_parse_uint8_type   },                                     \
  { "pat",        &arrtype               },                                     \
  { NULL }                                                                      \
}

#define NG_REGEXEC_HOOKS_SIZE(length)                                           \
  (sizeof(struct ng_regexec_hooks) + length*sizeof(uint16_t))

/* Structure for pattern name setting. */
struct ng_regexec_name {
  uint16_t  id;
  char      name[];
};

/* Keep this in sync with the above structures definitions. */
#define NG_REGEXEC_NAME_TYPE_INFO() {                                           \
  { "id",      &ng_parse_uint16_type },                                         \
  { "name",    &ng_parse_string_type },                                         \
  { NULL }                                                                      \
}

/* Statistics structure for one hook. */
struct ng_regexec_hookstat {
  uint64_t	recvFrames;
  uint64_t	recvOctets;
  uint64_t	recvMatchFrames;
  uint64_t	recvMatchOctets;
  uint64_t	xmitFrames;
  uint64_t	xmitOctets;
  uint64_t	matchUdp;
  uint64_t	matchTcp;
};

/* Keep this in sync with the above structures definitions. */
#define NG_REGEXEC_HOOKSTAT_TYPE_INFO	{                                         \
  { "recvFrames",       &ng_parse_uint64_type },                                \
  { "recvOctets",       &ng_parse_uint64_type },                                \
  { "recvMatchFrames",  &ng_parse_uint64_type },                                \
  { "recvMatchOctets",  &ng_parse_uint64_type },                                \
  { "xmitFrames",       &ng_parse_uint64_type },                                \
  { "xmitOctets",       &ng_parse_uint64_type },                                \
  { "matchUdp",         &ng_parse_uint64_type },                                \
  { "matchTcp",         &ng_parse_uint64_type },                                \
  { NULL }                                                                      \
}

/* Netgraph commands. */
enum {
  NGM_REGEXEC_SHOW = 1,
  NGM_REGEXEC_SHOWALL,
  NGM_REGEXEC_SET_HOOKS,       /* supply a struct ng_regexec_hooks */
  NGM_REGEXEC_GET_HOOKS,       /* returns a struct ng_regexec_hooks */
  NGM_REGEXEC_ADD_PATTERN,
  NGM_REGEXEC_DEL_PATTERN,
  NGM_REGEXEC_SET_NAME,        /* supply a struct ng_regexec_name */
  NGM_REGEXEC_GET_STATS,       /* supply name as char[NG_HOOKSIZ] */ 
  NGM_REGEXEC_CLR_STATS,       /* supply name as char[NG_HOOKSIZ] */
  NGM_REGEXEC_GETCLR_STATS     /* supply name as char[NG_HOOKSIZ] */
};

struct allhdr {
  struct ip ip;
  union {
    struct tcphdr tcp;
    struct udphdr udp;
  } nexthdr;
};

struct ng_regexec_log_dgram {
  struct in_addr ip_src, ip_dst;
  u_short sport, dport;
  char pat_name[256];
};

#endif /* _NETGRAPH_NG_REGEXEC_H_ */
