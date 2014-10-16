/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include "sr_send_arp_icmp.h"
/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

    /* Add initialization code here! */


} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);
    printf("*** -> Received packet of length %d \n",len);

    if (len<sizeof(sr_ethernet_hdr_t)){
        printf("ERROR: Invalid Ethernet packet size \n");
        return;
    }
    int r 		=  0;
    uint16_t type 	=  ethertype(packet);
    switch (type){
        case ethertype_ip:
	    printf("IP\n");
            r = sr_ip_pkt(sr,packet,len,interface);
	    if (r<0){
                printf("Problems while dealing with IP Packet --*/\n");
            }
        break;
        case ethertype_arp:
		printf("ARP\n");
            r = sr_arp_pkt(sr,packet,len,interface);
	    if (r<0){
		printf("Problems while dealing with ARP Packet --*/\n");
	    }
        break;
        default:
            printf("ERROR: Ethernet type not supported\n");
        break;
    }

}/* end sr_ForwardPacket */

struct sr_if * find_dst_face_router(struct sr_instance* sr, uint32_t ip_dst){
    struct sr_if * if_router;
    for(if_router = sr->if_list; if_router!=NULL;if_router=if_router->next){
        if(if_router->ip==ip_dst){
            return if_router;
        }
    }
    return NULL;
}


int sr_ip_pkt(struct sr_instance* sr, uint8_t * packet,unsigned int len,char* interface){

        /* checking length */
        if (len < sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)){
            printf("ERROR: Invalid IP packet size \n");
            return -1;
        }

        /*uint8_t * ethernet_hdr_u    =  packet;*/
        uint8_t * ip_hdr_u          =  packet+sizeof(sr_ethernet_hdr_t);
        sr_ethernet_hdr_t *e_hdr    =  (sr_ethernet_hdr_t *) packet;
        sr_ip_hdr_t * ip_hdr        =  (sr_ip_hdr_t *) (ip_hdr_u);
        uint16_t sum_backup         =  ip_hdr->ip_sum;
        ip_hdr->ip_sum              =  0;

        /*checking checksum*/
        if (!cksum((void*)ip_hdr_u,ip_hdr->ip_hl)) {
            printf("ERROR: Invalid IP header checksum\n");
            return -1;
        }

        int r =0;
        ip_hdr->ip_sum              =  sum_backup;
        struct sr_if * if_router    = find_dst_face_router(sr, ip_hdr->ip_dst);

        /* TO ROUTER */
        if (if_router){
            printf("IP: Packet is for this router\n");

            uint8_t protocol     =  ip_protocol(ip_hdr_u);
            sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(ip_hdr_u +sizeof(sr_ip_hdr_t)) ;

            switch (protocol){
                /* ICMP */
                case 1:
                    printf("IP: ICMP packet\n");
                    if (icmp_hdr->icmp_type == icmp_request){
			printf("IP: Sending ICMP REPLY\n");
                        r = sr_send_icmp(sr,packet,interface,0,0);
                    }
                    return r;
                break;
                /* Other protocol */
                default:
		    printf("IP: Other type of protocol received\n");
		    printf("IP: Sending ICMP Port unreachable (type 3, code 3)\n");
                    r = sr_send_icmp(sr,packet,interface,3,3);
                    return r;
                break;

            }
        /*FORWARD*/
        }else{

            printf("IP: Forwarding Packet.......\n ");
            if (ip_hdr->ip_ttl<1){
                printf("ERROR: The TTL Expired - IP Packet\n ");
		printf("IP: Sending Time exceeded (type 11, code 0)\n");
                int r = sr_send_icmp(sr,packet,interface, 11,0);
                return r;
            
            }else{
                struct sr_rt * rt;
                int dst_net_unr = 0; 
                for (rt = sr->routing_table; rt!=NULL;rt=rt->next){
			/*printf("IP HERE\n");
			print_addr_ip_int(ip_hdr->ip_dst);*/
                    if (( ip_hdr->ip_dst & rt->mask.s_addr) == rt->dest.s_addr){
                        dst_net_unr++;
                        struct sr_if *if_router = NULL;
                        if_router = sr_get_interface(sr,rt->interface);
                        memcpy (e_hdr->ether_shost, if_router->addr, ETHER_ADDR_LEN);
                        struct sr_arpentry *entry = sr_arpcache_lookup(&sr->cache,rt->gw.s_addr);
                        
                        if (entry){
                            /*printf("IP: Forwarding packet \n");*/
                            memcpy(e_hdr->ether_dhost,entry->mac,ETHER_ADDR_LEN);
                            ip_hdr->ip_sum = 0;
                            ip_hdr->ip_ttl -= 1;
                            ip_hdr->ip_sum = cksum(ip_hdr,ip_hdr->ip_hl*sizeof(uint32_t));
                            r = sr_send_packet(sr,packet,len,rt->interface);
                            free(entry);
                        }else{
                            /*printf("IP: Adding packet on queue\n ");*/
                            struct sr_arpreq * req = sr_arpcache_queuereq(&sr->cache,rt->gw.s_addr, packet,len,interface);
                            sr_handle_arpreq (sr,req);
                        }
                    }
                }
            	if (dst_net_unr==0){
		    printf("IP: Sending Destination net unreachable (type 3, code 0)\n");
                    int r = sr_send_icmp(sr,packet,interface, 3,0);
                    return r;
            	}
	    }
        }
    return r;
}

int sr_arp_pkt(struct sr_instance* sr, uint8_t * packet/* lent */,  unsigned int len,char* interface/* lent */){
        /* checking length */
        if (len < sizeof(sr_ethernet_hdr_t)+sizeof(sr_icmp_hdr_t)){
            printf("ERROR: Invalid ARP packet size\n ");
            return 0;
        }
        int r                       = 0;
        sr_arp_hdr_t *arp_hdr       = (sr_arp_hdr_t * ) (packet + sizeof(sr_ethernet_hdr_t));
        struct sr_arpreq *req       = NULL;
        struct sr_if * if_router    = find_dst_face_router(sr, arp_hdr->ar_tip);


        /* ARP PACKET REPLY */
        if ( arp_hdr->ar_op == htons( arp_op_reply)){
            /* INSERT IN ARP CACHE IF MESSAGE IS FOR US */
            if (if_router){ 
                printf("ARP: Inserting reply in cache ");
                req = sr_arpcache_insert(&sr->cache,arp_hdr->ar_sha,arp_hdr->ar_sip);
             }else{
                for (req = sr->cache.requests; req != NULL; req = req->next) {
                    if (req->ip == arp_hdr->ar_sip) {
                        break;
                    }
                }
            }
            /* FUNCTION IN ARPCACHE*/
            sr_handle_arp_reqs_pkts(sr,arp_hdr->ar_tha,req,interface);
            sr_arpreq_destroy(&sr->cache, req);
            return r;
        /* ARP PACKET REQUEST*/
        }else{
            if (if_router){
                r = sr_send_arp_rep(sr,packet,interface);
                return r;
            }
        }
    return r;
}
