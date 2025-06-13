#include <arpa/inet.h>
#include <string.h>
#include "protocols.h"
#include "queue.h"
#include "lib.h"
#include "list.h"

#define ETHERTYPE_IP		0x0800	
#define ETHERTYPE_ARP       0x0806

//element din coada de pachete
struct queue_packet {
    char *data;              
    size_t len;              
    int interface;           
    uint32_t next_hop;       
};

struct route_table_entry *rtable;
int rtable_len;

//lista pentru cache ul arp
list arp_cache = NULL;

//coada de pachete
queue arp_queue;

//trie pentru lpm
typedef struct Trie {
    struct Trie *children[2];  
    struct route_table_entry *route;  
    int isLeaf;  
} Trie;


Trie* trie_create() {
    Trie *t = malloc(sizeof(Trie));
    t->children[0] = NULL;
	t->children[1] = NULL;
    t->route = NULL;  
    t->isLeaf = 0;  
    return t;
}

void trie_insert(Trie *root, struct route_table_entry *route){
	Trie *temp = root;
	uint32_t ip = ntohl(route->prefix);
    uint32_t mask = ntohl(route->mask);

	for (int i = 0; i < 32; i++) {
        if (!(mask & (1 << (31 - i))))
            break;  
            
        int bit = (ip >> (31 - i)) & 1;
        
        if (temp->children[bit] == NULL) {
            temp->children[bit] = trie_create();
        }
        
        temp = temp->children[bit];
    }
    
    temp->route = route;
    temp->isLeaf = 1;
}

struct route_table_entry* get_best_route(Trie *root, uint32_t dest_ip) {
    Trie *temp = root;
    struct route_table_entry *best_match = NULL;
    
    dest_ip = ntohl(dest_ip);
    
    for (int i = 0; i < 32; i++) {
        if (temp == NULL) {
            break;
        }
        
        if (temp->isLeaf) {
            best_match = temp->route;
        }
        
        int bit = (dest_ip >> (31 - i)) & 1;
        
        temp = temp->children[bit];
    }
    
    return best_match;
}

void free_trie(Trie *node) {
    if (node == NULL) {
        return;
    }
    
    free_trie(node->children[0]);
    free_trie(node->children[1]);
    free(node);
}

//trimitere icmp pentru host_unreachable si time_exceeded
void send_icmp_error(uint8_t type, uint8_t code, size_t interface, char* buf, size_t len) {
    char packet[MAX_PACKET_LEN];

    struct ether_hdr *eth_hdr = (struct ether_hdr *) buf;
    struct ip_hdr *ip_hd = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));

    struct ether_hdr *new_eth_hdr = (struct ether_hdr *) packet;
    struct ip_hdr *new_ip_hd = (struct ip_hdr *)(packet + sizeof(struct ether_hdr));
    struct icmp_hdr *icmp_hd = (struct icmp_hdr *)(packet + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));
    char *icmp_data = (char *)icmp_hd + sizeof(struct icmp_hdr);

    new_eth_hdr->ethr_type = htons(ETHERTYPE_IP);
    get_interface_mac(interface, new_eth_hdr->ethr_shost);
    memcpy(new_eth_hdr->ethr_dhost, eth_hdr->ethr_shost, 6);

    new_ip_hd->ver = 4;
    new_ip_hd->ihl = 5;
    new_ip_hd->tos = 0;
    new_ip_hd->tot_len = htons(sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + 64);
    new_ip_hd->id = htons(0);
    new_ip_hd->frag = htons(0);
    new_ip_hd->ttl = 64;
    new_ip_hd->proto = 1;
    new_ip_hd->source_addr = inet_addr(get_interface_ip(interface));
    new_ip_hd->dest_addr = ip_hd->source_addr;
    new_ip_hd->checksum = 0;
    new_ip_hd->checksum = htons(checksum((uint16_t *)new_ip_hd, sizeof(struct ip_hdr)));

    icmp_hd->mtype = type;
    icmp_hd->mcode = code;
    icmp_hd->check = 0;
    memcpy(icmp_data, ip_hd, 64); 
    icmp_hd->check = htons(checksum((uint16_t *)icmp_hd, sizeof(struct icmp_hdr) + 64));

    int total_len = sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + 64;
    send_to_link(total_len, packet, (size_t)interface); 
}

//trimitere icmp pentru echo reply
void send_icmp_echo_reply(size_t interface, char *buf, size_t len){
    struct ether_hdr *eth_hdr = (struct ether_hdr *) buf;
    struct ip_hdr *ip_hd = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));
    struct icmp_hdr *icmp_hd = (struct icmp_hdr *)(buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));

    uint8_t tmp_mac[6];
    memcpy(tmp_mac, eth_hdr->ethr_shost, 6);
    memcpy(eth_hdr->ethr_shost, eth_hdr->ethr_dhost, 6);
    memcpy(eth_hdr->ethr_dhost, tmp_mac, 6);

    uint32_t tmp_ip = ip_hd->source_addr;
    ip_hd->source_addr = ip_hd->dest_addr;
    ip_hd->dest_addr = tmp_ip;

    icmp_hd->mtype = 0;

    ip_hd->checksum = 0;
    ip_hd->checksum = htons(checksum((uint16_t *)ip_hd, sizeof(struct ip_hdr)));

    icmp_hd->check = 0;
    icmp_hd->check = htons(checksum((uint16_t *)icmp_hd, sizeof(struct icmp_hdr) + 64));

    send_to_link(len, buf, (size_t)interface); 
}

void add_arp_entry(uint32_t ip, uint8_t *mac) {
    struct arp_table_entry *arp_entry = malloc(sizeof(struct arp_table_entry));

    arp_entry->ip = ip;
    memcpy(arp_entry->mac, mac, 6);

    arp_cache = constr(arp_entry, arp_cache); 
}

struct arp_table_entry *find_arp_entry(uint32_t ip) {
    list temp = arp_cache;
    while (temp != NULL) {
        struct arp_table_entry *entry = (struct arp_table_entry *)temp->element;
        if (entry->ip == ip) {
            return entry;
        }
        temp = temp->next;
    }
    return NULL;  
}

void free_arp_cache() {
    while (arp_cache != NULL) {
        struct arp_table_entry *temp = (struct arp_table_entry *)arp_cache->element;
        free(temp); 
        arp_cache = cdr_and_free(arp_cache);  
    }
}

//functie de arp request
void handle_arp_request(size_t len, char *buf, size_t interface) {
    struct ether_hdr *eth_hdr = (struct ether_hdr *)buf;
    struct arp_hdr *arp_hd = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));

    arp_hd->opcode = htons(2);
    memcpy(arp_hd->thwa, arp_hd->shwa, 6);
    get_interface_mac(interface, arp_hd->shwa);
    arp_hd->tprotoa = arp_hd->sprotoa;
    arp_hd->sprotoa = inet_addr(get_interface_ip(interface));

    memcpy(eth_hdr->ethr_dhost, eth_hdr->ethr_shost, 6);
    get_interface_mac(interface, eth_hdr->ethr_shost);

    send_to_link(len, buf, interface);
}

//functie de arp reply
void handle_arp_reply(size_t len, char *buf, size_t interface) {
    struct arp_hdr *arp_hd = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));
    add_arp_entry(arp_hd->sprotoa, arp_hd->shwa);
    queue new_queue = create_queue();
    while (!queue_empty(arp_queue)) {
        struct queue_packet *packet = queue_deq(arp_queue);

        if (packet->next_hop == arp_hd->sprotoa) {
            struct ether_hdr *eth_hdr = (struct ether_hdr *)packet->data;
            get_interface_mac(packet->interface, eth_hdr->ethr_shost);
            memcpy(eth_hdr->ethr_dhost, arp_hd->shwa, 6);

            send_to_link(packet->len, packet->data, packet->interface);
            free(packet->data);
            free(packet);
        } else {
            queue_enq(new_queue, packet);  
        }
    }
    arp_queue = new_queue;
}


int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argv + 2, argc - 2);

	rtable = malloc(sizeof(struct route_table_entry) * 100000);
	DIE(rtable == NULL, "memory");

    arp_queue = create_queue();

	rtable_len = read_rtable(argv[1], rtable);

	Trie *routeTrie = trie_create();
    
    for (int i = 0; i < rtable_len; i++){
        trie_insert(routeTrie, &rtable[i]);
	}

	while (1) {

		size_t interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_hdr *eth_hdr = (struct ether_hdr *) buf;
		struct ip_hdr *ip_hd = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));

        uint32_t interface_ip;
        interface_ip = inet_addr(get_interface_ip(interface));

        //cazul in care primesc un pachet ip
		if (eth_hdr->ethr_type == ntohs(ETHERTYPE_IP)) {

            //daca router-ul meu este destinatia(icmp request)
            if (interface_ip == ip_hd->dest_addr) {
                send_icmp_echo_reply(interface, buf, len);
                continue;
            }

            uint16_t received_checksum = ntohs(ip_hd->checksum);
            ip_hd->checksum = 0;
            uint16_t computed_checksum = checksum((uint16_t *)ip_hd, sizeof(struct ip_hdr));
            if (received_checksum != computed_checksum) {
                continue;
            }

            if(ip_hd->ttl <= 1 && ip_hd->ttl - 1 <= 1){
                send_icmp_error(11, 0, interface, buf, len);
                continue;
            }
            
            ip_hd->ttl--;
            ip_hd->checksum = 0;
            ip_hd->checksum = htons(checksum((uint16_t *)ip_hd, sizeof(struct ip_hdr)));

            struct route_table_entry *best_route = get_best_route(routeTrie, ip_hd->dest_addr);
            
            if(!best_route){
                send_icmp_error(3, 0, interface, buf, len);
                continue;
            }
            
            struct arp_table_entry *arp_entry = find_arp_entry(best_route->next_hop);

            //cazul in  care nu gasesc intrare in cache-ul arp
            if (!arp_entry) {
                struct queue_packet *ip_packet = malloc(sizeof(struct queue_packet));
    
                ip_packet->len = len;
                ip_packet->data = malloc(len);              
                memcpy(ip_packet->data, buf, len);
                ip_packet->interface = best_route->interface;
                ip_packet->next_hop = best_route->next_hop;

                //pun pachetul in coada ca sa ma ocup de el dupa ce primesc arp reply 
                queue_enq(arp_queue, ip_packet);

                //construiesc un pachet arp ca sa-l trimit ca request
                char arp_packet[MAX_PACKET_LEN];
                struct ether_hdr *eth_hdr = (struct ether_hdr *)arp_packet;
                struct arp_hdr *arp_hd = (struct arp_hdr *)(arp_packet + sizeof(struct ether_hdr));

                eth_hdr->ethr_type = htons(ETHERTYPE_ARP);
                get_interface_mac(interface, eth_hdr->ethr_shost);
                eth_hdr->ethr_dhost[0] = 0xFF;
                eth_hdr->ethr_dhost[1] = 0xFF;
                eth_hdr->ethr_dhost[2] = 0xFF;
                eth_hdr->ethr_dhost[3] = 0xFF;
                eth_hdr->ethr_dhost[4] = 0xFF;
                eth_hdr->ethr_dhost[5] = 0xFF;

                arp_hd->hw_type = htons(1);
                arp_hd->proto_type = htons(ETHERTYPE_IP);
                arp_hd->hw_len = 6;
                arp_hd->proto_len = 4;
                arp_hd->opcode = htons(1);
                get_interface_mac(best_route->interface, arp_hd->shwa);
                arp_hd->sprotoa = inet_addr(get_interface_ip(best_route->interface));
                arp_hd->thwa[0] = 0xFF;
                arp_hd->thwa[1] = 0xFF;
                arp_hd->thwa[2] = 0xFF;
                arp_hd->thwa[3] = 0xFF;
                arp_hd->thwa[4] = 0xFF;
                arp_hd->thwa[5] = 0xFF;
                arp_hd->tprotoa =  best_route->next_hop;

                send_to_link(sizeof(struct ether_hdr) + sizeof(struct arp_hdr), arp_packet, best_route->interface);
            }
            else {
                //cazul in care gasesc intrarea in cache-ul arp
                memcpy(eth_hdr->ethr_shost, eth_hdr->ethr_dhost, 6);
                memcpy(eth_hdr->ethr_dhost, arp_entry->mac, 6);

                send_to_link(len, buf, (size_t)best_route->interface);
            }
        }
        //cazul in care primesc un pachet arp
        else if (eth_hdr->ethr_type == ntohs(ETHERTYPE_ARP)){
            struct arp_hdr *arp_hd = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));

            //cazul in care primesc un pachet arp de tip request
            //(urmeaza sa pregatesc un pachet de tip reply pentru a-l receptiona ca reply)
            if (ntohs(arp_hd->opcode) == 1) {
                handle_arp_request(len, buf, interface);
            }
            //cazul in care primesc un pachet de tip reply
            //(ma uit in coada si trimit pachetele pentru care gasesc corespodent in cache)
            else if (ntohs(arp_hd->opcode) == 2) {
                handle_arp_reply(len, buf, interface);
            }
        }
        //pachetul nu este nici ipv4, nici arp
        else 
            continue;
	}
	free(rtable);
	free_trie(routeTrie);
}

