ng_regexec
==========

Description
-----------

FreeBSD netgraph module for determine packet by regexp.

Install
-------

    make
    kldload ./ng_netgraph.ko
    
    
Detail
------

This module checks packets to correspondence with specified patterns. For TCP/UDP packets payload is checked, otherwise whole packet is checked. 
Packet is sent through hook <b>ifMatch</b> if it matches with one of the patterns, and datagram packet is sent through hook <b>log</b> (if this hook is specified) with data about matched packet and pattern. Otherwise packet is sent through hook <b>ifNotMatch</b>. Packet is dropped if correspond destination hook is not specified.

Each node can have any number of the patterns, which are numbered in order from number 1. Each pattern can have the name, this name is used in datagram packet, which is sent through hook <b>log</b>.

In each node may create any number of the hooks, except hook <b>log</b> - it is one always.
Ech node have only one array of the patterns, which is used all hooks of the node.
For each hook output hooks are set for matching and non-matching incoming packets respectively. Also for each hook array with indexes of the patterns is set. In hook own pattern array (array with indexes of the patterns) is used for check packet. The check of packets passes successively by patterns and stops by first match.
If length of the pattern array in hook is zero, packet will be checked by all patterns in node.


Hooks
-----

This node type supports any number of hooks having arbitrary names.


Control messages
------------------

This node type supports the generic control messages, plus the following:

NGM_REGEXEC_SET_HOOKS

This command sets the set of the patterns that will be applied to incoming packet on a hook. The following structure must be supplied as an argument:
	
~~~  
struct ng_regexec_hooks {
  char      thisHook[NG_HOOKSIZ];   /* name of hook */
  char      ifMatch[NG_HOOKSIZ];    /* name of match dest hook */
  char      ifNotMatch[NG_HOOKSIZ]; /* name of !match dest hook */
  u_char    pat_len;
  uint16_t  pat[];
};
~~~

The hook to be updated is specified in thisHook. Matching and non-matching incoming packets are delivered out the hooks named <b>ifMatch</b> and <b>ifNotMatch</b> respectively.


NGM_REGEXEC_GET_HOOKS

This command takes an ASCII string argument, the hook name, and returns the corresponding struct ng_regexec_hooks as shown above.


NGM_REGEXEC_ADD_PATTERN

This command takes an ASCII string, regexp pattern, and adds pattern to the and of patterns array of the node.


NGM_REGEXEC_DEL_PATTERN

This command takes an unsigned integer number, index number of the pattern, and removes correspond pattern. All hooks,  which use removed pattern is updated.


NGM_REGEXEC_SET_NAME

This command adds name to the pattern. The following structure must be supplied as an argument:
~~~
struct ng_regexec_name {
  uint16_t  id;
  char      name[];
};
~~~

The field <i>id</i> is pattern index, <i>name</i> - pattern name (must be NULL-terminated string). The name is assigned to last pattern in the array if the field <i>id</i> equals 0.


NGM_REGEXEC_GET_STATS

This command takes an ASCII string argument, the hook name, and returns the statistics associated with the hook as a struct ng_regexec_hookstat.


NGM_REGEXEC_CLR_STATS

This command takes an ASCII string argument, the hook name, and clears the statistics associated with the hook.


NGM_REGEXEC_GETCLR_STATS

This command is identical to NGM_REGEXEC_GET_STATS, except that the statistics are also atomically cleared.


Shutdown
--------

This node shuts down upon receipt of a NGM_SHUTDOWN control message, or when all hooks have been disconnected.
