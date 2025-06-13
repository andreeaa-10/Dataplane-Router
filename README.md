## Overview
Implemented the dataplane of an IPv4 router in C (≈20 hours), handling packet forwarding, ARP resolution, and ICMP messaging over POSIX sockets.

## Routing Process
1. Receive Ethernet frame and verify it carries an IPv4 packet.  
2. Recalculate and compare IP checksum; drop on mismatch.  
3. Check TTL; if ≤ 1 send ICMP Time Exceeded and drop.  
4. Decrement TTL, update checksum.  
5. Perform Longest Prefix Match in routing table; drop if no route.  
6. Lookup next-hop MAC in ARP cache; if missing queue packet and send ARP request.  
7. Prepend Ethernet header with resolved MAC and forward packet.

## Longest-Prefix Match
- Built a binary trie: each IP bit is a trie level.  
- Functions: `trie_create`, `trie_insert(route, mask)`, `get_best_route(dest_ip)`, `free_trie`.  
- On packet arrival, traverse bit by bit to find the longest matching route.

## ARP Protocol
- ARP cache implemented as a linked list + pending-packet queue.  
- Functions: `add_arp_entry`, `find_arp_entry`, `free_arp_cache`.  
- On cache miss: enqueue packet, broadcast ARP request.  
- On ARP reply: insert MAC into cache, dequeue and forward waiting packets.  
- On ARP request: swap addresses and send ARP reply.

## ICMP Protocol
- Generate **ICMP Time Exceeded** (TTL expired) and **Host Unreachable** (no route).  
- Reply to **ICMP Echo Request** with Echo Reply if destined to router.  
- Build ICMP packets from scratch, recalc IP/ICMP checksums, set Ethernet headers accordingly.

## Challenges
- Endianness conversions between little- and big-endian when parsing headers.  
- Ambiguous ICMP requirements required careful spec reading.  
- ARP request construction and pending-packet queue management were error-prone.

## References
- https://vinesmsuic.github.io/notes-networkingIP-L3/index.html  
- https://en.wikipedia.org/wiki/Address_Resolution_Protocol  
- https://leetcode.com/problems/implement-trie-prefix-tree/description/  
- https://networkdirection.net/articles/network-theory/icmpforipv4/  
