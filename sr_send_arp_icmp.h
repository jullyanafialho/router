#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sr_protocol.h"
#include "sr_if.h"
#include "sr_router.h"
#include "sr_rt.h"
#include "sr_utils.h"

int sr_send_icmp (struct sr_instance *sr, uint8_t * packet,char * interface, uint8_t type, uint8_t code);

int sr_send_arp_req (struct sr_instance *sr, struct  sr_arpreq * req);
int sr_send_arp_rep (struct sr_instance *sr, uint8_t * packet,char * interface);