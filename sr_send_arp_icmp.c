#include "sr_send_arp_icmp.h"

/* ICMPs */
int sr_send_icmp (struct sr_instance *sr, uint8_t * packet,char * interface, uint8_t type, uint8_t code){

    uint8_t * old_ethernet_hdr_u    = packet + sizeof( sr_ethernet_hdr_t);
    uint8_t * old_ip_hdr_u      = old_ethernet_hdr_u + sizeof (sr_ip_hdr_t);

    sr_ethernet_hdr_t * old_ethernet_hdr    = (sr_ethernet_hdr_t*) packet;
    sr_ip_hdr_t * old_ip_hdr        = (sr_ip_hdr_t*) old_ethernet_hdr_u;
    sr_icmp_t0_hdr_t * old_icmp_hdr     = (sr_icmp_t0_hdr_t*) old_ip_hdr_u;

    unsigned int length = sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t);

    switch(type) {
        case 0:
            length          += sizeof(sr_icmp_t0_hdr_t);
            break;
        case 3:
            length          += sizeof(sr_icmp_t3_hdr_t);
            break;
        case 11:
            length          += sizeof(sr_icmp_t11_hdr_t);
            break;            
        default:
            printf("ERROR: ICMP type not supported");
            return -1;
    }
    
    uint8_t * new_packet_u = (uint8_t*)malloc (length);
    uint8_t * until_ethernet = (uint8_t*)(new_packet_u + sizeof(sr_ethernet_hdr_t));
    uint8_t * until_ip = (uint8_t*)(new_packet_u + sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));

    bzero(new_packet_u,length);

    /* ETHERNET HDR */
    sr_ethernet_hdr_t * e_hdr   = (sr_ethernet_hdr_t*) new_packet_u;
    e_hdr->ether_type           = htons(ethertype_ip);
    memcpy(e_hdr->ether_shost,old_ethernet_hdr->ether_dhost,ETHER_ADDR_LEN);
    memcpy(e_hdr->ether_dhost,old_ethernet_hdr->ether_shost,ETHER_ADDR_LEN);

    /* IP HDR*/
    sr_ip_hdr_t * ip_hdr = (sr_ip_hdr_t *) (new_packet_u + sizeof(sr_ethernet_hdr_t));
    ip_hdr->ip_v   = 4;
    ip_hdr->ip_hl  = 5;
    ip_hdr->ip_tos = 0;
    ip_hdr->ip_id  = 0;
    ip_hdr->ip_off = htons(IP_DF);
    ip_hdr->ip_ttl = 255;
    ip_hdr->ip_p   = ip_protocol_icmp;
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_src = old_ip_hdr->ip_dst;
    ip_hdr->ip_dst = old_ip_hdr->ip_src;

    sr_icmp_t0_hdr_t *icmp_t0_hdr = (sr_icmp_t0_hdr_t*)(new_packet_u +sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));
    sr_icmp_t3_hdr_t *icmp_t3_hdr = (sr_icmp_t3_hdr_t*)(new_packet_u +sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));
    sr_icmp_t11_hdr_t *icmp_t11_hdr = (sr_icmp_t11_hdr_t*)(new_packet_u +sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));
    int size_icmp =0;

    switch(type) {
        case 0:
            size_icmp = htons(old_ip_hdr->ip_len)-old_ip_hdr->ip_hl*sizeof(uint32_t);
            icmp_t0_hdr->icmp_type = icmp_reply;
            icmp_t0_hdr->icmp_code = code;
            icmp_t0_hdr->icmp_sum = 0;
            icmp_t0_hdr->identifier = old_icmp_hdr->identifier;
            icmp_t0_hdr->sequence_number = old_icmp_hdr->sequence_number;
            memcpy(icmp_t0_hdr->data,old_icmp_hdr->data,size_icmp - 8);
            icmp_t0_hdr->icmp_sum = cksum((void *)until_ip,size_icmp);
            break;

        case 3:
            size_icmp = sizeof(sr_icmp_t3_hdr_t);
            icmp_t3_hdr->icmp_type = icmp_dst_unr;
            icmp_t3_hdr->icmp_code = code;
            icmp_t3_hdr->icmp_sum = 0;
            memcpy(icmp_t3_hdr->data,old_ethernet_hdr_u,ip_hdr->ip_hl*sizeof(uint32_t) + 8);
            icmp_t3_hdr->icmp_sum = cksum((void*)until_ip, size_icmp);
            break;            

        case 11:
            size_icmp = sizeof(sr_icmp_t11_hdr_t);    
            icmp_t11_hdr->icmp_type = icmp_time_exc;
            icmp_t11_hdr->icmp_code = code;
            icmp_t11_hdr->icmp_sum = 0;
            memcpy(icmp_t11_hdr->data,old_ethernet_hdr_u,ip_hdr->ip_hl*sizeof(uint32_t) + 8);
            icmp_t11_hdr->icmp_sum = cksum(until_ip, size_icmp);
            break;
    }

    int size_ip = ip_hdr->ip_hl*sizeof(uint32_t);
    ip_hdr->ip_len = htons(20 + size_icmp);
    ip_hdr->ip_sum = cksum((void*)until_ethernet,size_ip);
    int r=sr_send_packet(sr,new_packet_u, length,interface);
    free(new_packet_u);
    return r;
}


/* ARPs */

int sr_send_arp_req (struct sr_instance *sr,  struct  sr_arpreq * req){
    int r =0;
    char * interface=NULL;
    struct sr_rt * rt = sr->routing_table;
    for (rt = sr->routing_table; rt!=NULL;rt=rt->next){
	if (( req->ip & rt->mask.s_addr) == rt->dest.s_addr){
	    interface = rt->interface;
	}
    }
    if (interface == NULL) return -1;
    
    struct sr_if * if_router = sr_get_interface(sr,interface);

    /*NEW_PACKET*/
    unsigned int length = sizeof(sr_ethernet_hdr_t)+sizeof(sr_arp_hdr_t);
    uint8_t * new_packet_u = (uint8_t*)malloc (length);
    bzero(new_packet_u,length);

    /* ETHERNET HDR */
    sr_ethernet_hdr_t * e_hdr = (sr_ethernet_hdr_t*) new_packet_u;
    e_hdr->ether_type = htons(ethertype_arp);
    memcpy(e_hdr->ether_shost,if_router->addr,ETHER_ADDR_LEN);
    memset(e_hdr->ether_dhost, 0xff, ETHER_ADDR_LEN);

    /* ARP HDR */
    sr_arp_hdr_t * a_hdr = (sr_arp_hdr_t *) (new_packet_u + sizeof(sr_ethernet_hdr_t));
    a_hdr->ar_hrd = htons(arp_hrd_ethernet);
    a_hdr->ar_pro = htons(ethertype_ip);
    a_hdr->ar_hln = ETHER_ADDR_LEN;
    a_hdr->ar_pln = 4;
    a_hdr->ar_op = htons(arp_op_request);
    a_hdr->ar_sip = if_router->ip;
    a_hdr->ar_tip = req->ip;
    memcpy(a_hdr->ar_sha,if_router->addr,ETHER_ADDR_LEN);
    memset(a_hdr->ar_tha, 0xff, ETHER_ADDR_LEN);
   
    r = sr_send_packet(sr,new_packet_u, length,interface);
    free(new_packet_u);
    return r;
}


int sr_send_arp_rep (struct sr_instance *sr, uint8_t * packet,char * interface){
    int r =0;
    struct sr_if * if_router = sr_get_interface(sr,interface);

    uint8_t * old_ethernet_hdr_u    = packet + sizeof( sr_ethernet_hdr_t);
    sr_ethernet_hdr_t * old_ethernet_hdr    = (sr_ethernet_hdr_t*) packet;
    sr_arp_hdr_t * old_arp_hdr      = (sr_arp_hdr_t*) old_ethernet_hdr_u;

    /*NEW_PACKET*/
    unsigned int length = sizeof(sr_ethernet_hdr_t)+sizeof(sr_arp_hdr_t);
    uint8_t * new_packet_u = (uint8_t*)malloc (length);
    bzero(new_packet_u,length);

    /* ETHERNET HDR */
    sr_ethernet_hdr_t * e_hdr = (sr_ethernet_hdr_t*) new_packet_u;
    e_hdr->ether_type = htons(ethertype_arp);
    memcpy(e_hdr->ether_shost,if_router->addr,ETHER_ADDR_LEN);
    memcpy(e_hdr->ether_dhost,old_ethernet_hdr->ether_shost,ETHER_ADDR_LEN);

    /* ARP HDR */
    sr_arp_hdr_t * a_hdr = (sr_arp_hdr_t *) (new_packet_u + sizeof(sr_ethernet_hdr_t));
    a_hdr->ar_hrd = htons(1);
    a_hdr->ar_pro = htons(ethertype_ip);
    a_hdr->ar_hln = ETHER_ADDR_LEN;
    a_hdr->ar_pln = 4;
    a_hdr->ar_op = htons(arp_op_reply);
    a_hdr->ar_sip = if_router->ip;
    a_hdr->ar_tip = old_arp_hdr->ar_sip;
    memcpy(a_hdr->ar_sha,if_router->addr,ETHER_ADDR_LEN);
    memcpy(a_hdr->ar_tha,old_arp_hdr->ar_sha,ETHER_ADDR_LEN);
    
    r = sr_send_packet(sr,new_packet_u, length,interface);
    free(new_packet_u);
    return r;
}
