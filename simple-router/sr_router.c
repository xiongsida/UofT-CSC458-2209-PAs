#include <stdio.h>
#include <assert.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance *sr)
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

void sr_handlepacket(struct sr_instance *sr,
                     uint8_t *packet /* lent */,
                     unsigned int len,
                     char *interface /* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n", len);

  /* fill in code here */
  int minlength = sizeof(sr_ethernet_hdr_t);
  if (len < minlength)
  {
    printf("Failed to print ETHERNET header, insufficient length\n");
    return;
  }

  /* I use some code from sr_util */
  uint16_t ethtype = ethertype(packet);
  print_hdr_eth(packet);
  print_hdrs(packet, len);

  if (ethtype == ethertype_ip)
  {
    printf("---------here-get an ip packet-----\n");
    handle_ip(sr, packet, len, interface);
  }
  else if (ethtype == ethertype_arp)
  {

    handle_arp(sr, packet, len, interface);
  }
  else /* illegal ethernet type*/
  {
    printf("Unrecognized Ethernet Type: %d\n", ethtype);
  }

} /* end sr_ForwardPacket */

void handle_ip(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface)
{
  if (len - sizeof(sr_ethernet_hdr_t) < sizeof(sr_ip_hdr_t)) /* illegal length*/
  {
    printf("error, insufficient header  length\n");
    return;
  }
  sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  if (ip_header->ip_v != 4)
  {
    printf("error, not IPV4\n");
    return;
  }

  /* validate ip checksum*/
  uint16_t received_ip_checksum = ip_header->ip_sum;
  ip_header->ip_sum = 0;
  uint16_t calculated_ip_checksum = cksum(ip_header, sizeof(sr_ip_hdr_t)); /* ip header length in bytes*/
  if (calculated_ip_checksum != received_ip_checksum)
  {
    printf("error, invalid IP checksum\n");
    ip_header->ip_sum = received_ip_checksum;
    return;
  }
  ip_header->ip_sum = received_ip_checksum;

  if (ip_header->ip_ttl <= 0)
  {
    return;
  }

  /* figure out if the packet is for the router itself, if it is, then figure out if packet is icmp packet*/
  int is_for_us = is_ip_sent_to_us(sr, ip_header->ip_dst);

  if (is_for_us == 1)
  {
    if (ip_header->ip_p == ip_protocol_icmp)
    {
      if (len < sizeof(sr_icmp_hdr_t) + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t))
      {
        printf("error! Cannot process ICMP packet because it was not long enough.\n");
        return;
      }
      printf("bingo, the router received a packet destined for itself, on the interface: %s.\n", interface);

      sr_icmp_hdr_t *icmp_header = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

      /*/ validate checksum for ICMP package*/
      uint16_t received_icmp_checksum = icmp_header->icmp_sum;
      icmp_header->icmp_sum = 0;
      uint16_t calculated_icmp_checksum = cksum(icmp_header, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
      if (calculated_icmp_checksum != received_icmp_checksum)
      {
        printf("error, invalid icmp checksum\n");
        icmp_header->icmp_sum = received_icmp_checksum;
        return;
      }
      icmp_header->icmp_sum = received_icmp_checksum;

      if (icmp_header->icmp_type != 8) /*if not an ICMP request*/
      {
        printf("error, packet is not an echo request\n");
        return;
      }
      printf("bingo, ready to construct and send icmp echo reply\n");
      construct_send_icmp_packet(sr, packet, len, interface, 0, 0); /*echo*/
    }
    else /*TCP or UDP*/
    {
      printf("get a non-icmp packet, ready to construct and send port unreachable\n");
      construct_send_icmp_packet(sr, packet, len, interface, 3, 3); /*port unreachable*/
    }
  }
  else /*not for this router's interfaces*/
  {
    if (ip_header->ip_ttl <= 1)
    {
      printf("The ttl has expired.\n");
      ip_header->ip_ttl--;
      construct_send_icmp_packet(sr, packet, len, interface, 11, 0); /*time exceeded*/
      return;
    }
    printf("bingo, now let us forward this ip packet that was received on interface %s\n", interface);
    struct sr_rt *next_hop_ip = LPM(sr, ip_header->ip_dst);
    if (!next_hop_ip)
    { /* No match found in routing table */

      printf("LPM was unable to find a match in the routing table. Sending ICMP3\n");
      construct_send_icmp_packet(sr, packet, len, interface, 3, 0); /* net unreachable*/
      return;
    }
    printf("bingo, next hop found, we know which interface to use to forward, ready to alter and forward\n");
    ip_header->ip_ttl--;
    ip_header->ip_sum = 0;
    ip_header->ip_sum = cksum(ip_header, sizeof(sr_ip_hdr_t));
    struct sr_arpentry *next_hop_mac = sr_arpcache_lookup(&(sr->cache), next_hop_ip->gw.s_addr); /* get the next hop, aka the which interface ip to use to send*/
    if (!next_hop_mac)
    { /* No ip-mac pari found in cache*/
      printf("No ARP cache entry was found. Queuing an ARP request\n");
      sr_ethernet_hdr_t *ethernet_header = (sr_ethernet_hdr_t *)packet;
      print_hdr_eth(ethernet_header);
      struct sr_if *output_interface = sr_get_interface(sr, next_hop_ip->interface);
      /* memcpy(ethernet_header->ether_shost, output_interface->addr, ETHER_ADDR_LEN ); */

      struct sr_arpreq *queued_arp_req = sr_arpcache_queuereq(&(sr->cache),
                                                              next_hop_ip->gw.s_addr /*original_ip_header->ip_dst*/,
                                                              packet, len, next_hop_ip->interface);
      /*handle_arpreq(sr, queued_arp_req); /* this function need be implemented in sr_arpcashe.c, there is psudo code in its head file provided by professor*/
      /*the above handle_arpreq function is temperaly commented*/
      handle_arpreq(sr, queued_arp_req);
      return;
    }
    else
    {
      printf("Got next hop mac addr from cache.\n");
    }
    printf("ARP cache entry was found. Putting the packet on interface %s toward next hop.\n", next_hop_ip->interface);

    sr_ethernet_hdr_t *ethernet_header = (sr_ethernet_hdr_t *)packet;
    memcpy(ethernet_header->ether_shost, sr_get_interface(sr, next_hop_ip->interface)->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
    memcpy(ethernet_header->ether_dhost, next_hop_mac->mac, sizeof(uint8_t) * ETHER_ADDR_LEN);

    free(next_hop_mac); /* function sr_arpcache_lookup() says 'You must free the returned structure if it is not NULL.'*/

    sr_send_packet(sr, packet, len, sr_get_interface(sr, next_hop_ip->interface)->name);
    return;
  }
}

void construct_send_icmp_packet(struct sr_instance *sr, uint8_t *packet,
                                unsigned int len, char *interface,
                                uint8_t icmp_type, uint8_t icmp_code)
{
  printf("\n length of packet: %d\n", len);
  printf("here we constrcuct and send icmp packet\n");
  int packet_length = sizeof(sr_icmp_t3_hdr_t) + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);
  if (icmp_type == 0)
  {
    packet_length = len;
  }
  uint8_t *packet_to_send = (uint8_t *)malloc(packet_length);
  memset(packet_to_send, 0, packet_length * sizeof(uint8_t)); /* initial packet with 0*/

  sr_ethernet_hdr_t *ethernet_header_received = (sr_ethernet_hdr_t *)packet;
  sr_ip_hdr_t *ip_header_received = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

  sr_ethernet_hdr_t *ethernet_header_to_send = (sr_ethernet_hdr_t *)packet_to_send;
  sr_ip_hdr_t *ip_header_to_send = (sr_ip_hdr_t *)(packet_to_send + sizeof(sr_ethernet_hdr_t));
  /*for echo replies, we use sr_icmp_hdr,
  for type 3 messages (destination net/host/port unreachable, etc.) we use sr_icmp_t3_hdr,
  but how about time exceed message? */
  printf("start preparing icmp packet to send\n");
  /*icmp*/
  if (icmp_type == 0)
  {
    printf("here we will prepare echo reply's icmp header");
    sr_icmp_hdr_t *icmp_header_to_send = (sr_icmp_hdr_t *)(packet_to_send + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

    memcpy(icmp_header_to_send, (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)), packet_length - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
    printf("\n length of packet: %d\n", packet_length);
    printf("\n length of ethernet: %d\n", sizeof(sr_ethernet_hdr_t));
    printf("\n length of ip: %d\n", sizeof(sr_ip_hdr_t));
    printf("\n length of icmp: %d\n", packet_length - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
    icmp_header_to_send->icmp_code = icmp_code;
    icmp_header_to_send->icmp_type = icmp_type;

    icmp_header_to_send->icmp_sum = 0;
    icmp_header_to_send->icmp_sum = cksum(icmp_header_to_send, packet_length - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
  }
  else
  {
    printf("prepare other reply's icmp header\n");
    sr_icmp_t3_hdr_t *icmp_header_to_send = (sr_icmp_t3_hdr_t *)(packet_to_send + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    /*copy IP Header and following data into icmp header for type 11 or type 3*/
    memcpy(icmp_header_to_send->data, ip_header_received, ICMP_DATA_SIZE); /*RFC 792 says data should be Internet Header + 64 bits of Data Datagram*/
    icmp_header_to_send->icmp_code = icmp_code;
    icmp_header_to_send->icmp_type = icmp_type;
    icmp_header_to_send->next_mtu = 1500; /* set MTU for type 3*/
    icmp_header_to_send->icmp_sum = 0;
    icmp_header_to_send->icmp_sum = cksum(icmp_header_to_send, packet_length - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));

    printf("-------------icmp header to send\n");
    print_hdr_icmp(icmp_header_to_send);
  }

  /*ip*/
  struct sr_if *interface_to_send = sr_get_interface(sr, interface); /*send from the interface that received packet*/  
  uint32_t source_ip = interface_to_send->ip;
  if (icmp_type == 0 || (icmp_type == 3 && icmp_code == 3))
  {
    source_ip = ip_header_received->ip_dst;
  }
  memcpy(ip_header_to_send, ip_header_received, sizeof(sr_ip_hdr_t)); /*copy first in case of some field unchanged*/
  ip_header_to_send->ip_src = source_ip;
  ip_header_to_send->ip_dst = ip_header_received->ip_src;
  ip_header_to_send->ip_ttl = INIT_TTL; /*ttl:255*/
  ip_header_to_send->ip_p = ip_protocol_icmp;
  ip_header_to_send->ip_len = htons(packet_length - sizeof(sr_ethernet_hdr_t)); /*host short*/
  ip_header_to_send->ip_sum = 0;
  ip_header_to_send->ip_sum = cksum(ip_header_to_send, sizeof(sr_ip_hdr_t));
  printf("-----------ip header to send\n");
  print_hdr_ip(ip_header_to_send);

  /*ethernet*/
  memcpy(ethernet_header_to_send->ether_shost, interface_to_send->addr, sizeof(uint8_t) * ETHER_ADDR_LEN); /*MAC address*/
  memcpy(ethernet_header_to_send->ether_dhost, ethernet_header_received->ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
  ethernet_header_to_send->ether_type = htons(ethertype_ip);

  printf("-------------ethernet header to send\n");
  print_hdr_eth(ethernet_header_to_send);

  /* Need to do arp first before sending out icmp packet. */
  struct sr_arpentry *next_hop_mac = sr_arpcache_lookup(&(sr->cache), ip_header_to_send->ip_dst); /* get the next hop, aka the which interface ip to use to send*/
  if (!next_hop_mac)
  { /* No ip-mac pari found in cache*/
    printf("No ARP cache entry was found. Queuing an ARP request\n");
    sr_ethernet_hdr_t *ethernet_header = (sr_ethernet_hdr_t *)packet_to_send;
    print_hdr_eth(ethernet_header);
    /* struct sr_if *output_interface = sr_get_interface(sr, next_hop_ip->interface); */
    /* memcpy(ethernet_header->ether_shost, output_interface->addr, ETHER_ADDR_LEN ); */

    struct sr_arpreq *queued_arp_req = sr_arpcache_queuereq(&(sr->cache),
                                                            ip_header_to_send->ip_dst /*original_ip_header->ip_dst*/,
                                                            packet_to_send, len, interface);
    /*handle_arpreq(sr, queued_arp_req); /* this function need be implemented in sr_arpcashe.c, there is psudo code in its head file provided by professor*/
    /*the above handle_arpreq function is temperaly commented*/
    handle_arpreq(sr, queued_arp_req);
    return;
  }



  sr_send_packet(sr, packet_to_send, packet_length, interface);
  free(packet_to_send);
}

struct sr_rt *LPM(struct sr_instance *sr, uint32_t destination_ip)
{
  /* actually we just need extact match for this assignment, because mask is 255.255.255.255*/
  struct sr_rt *routing_table_node = sr->routing_table;
  struct sr_rt *best_match = NULL;
  while (routing_table_node)
  {
    if ((routing_table_node->dest.s_addr & routing_table_node->mask.s_addr) == (destination_ip & routing_table_node->mask.s_addr))
    {
      if (!best_match || (routing_table_node->mask.s_addr > best_match->mask.s_addr))
      {
        best_match = routing_table_node;
      }
    }
    routing_table_node = routing_table_node->next;
  }
  return best_match;
}

int is_ip_sent_to_us(struct sr_instance *sr, uint32_t dest_ip)
{
  struct sr_if *router_iterface = 0;
  router_iterface = sr->if_list;
  sr_print_if_list(sr);
  while (router_iterface)
  {
    if (ntohl(router_iterface->ip) == ntohl(dest_ip))
    {
      return 1;
    }
    router_iterface = router_iterface->next;
  }
  return 0;
}

void handle_arp(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface)
{

  printf("handle arp\n");
  print_hdrs(packet, len);
  printf("%s\n", interface);

  sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)packet;
  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  if (ntohs(arp_hdr->ar_op) == arp_op_request)
  {
    printf("request\n");
    /* uint8_t *outgoingpacket; */
    printf("interface list:\n");
    sr_print_if_list(sr);
    printf("\n");

    if (!sr->if_list)
    {
      fprintf(stderr, "Interface list is empty.\n");
      exit(1);
    }
    struct sr_if *if_walker = sr->if_list;
    while (if_walker)
    {
      if (if_walker->ip == arp_hdr->ar_tip)
      {
        printf("Found destination on router itself.\n");
        break;
      }
      if_walker = if_walker->next;
    }

    /* Construct new ethernet header. */
    sr_ethernet_hdr_t *new_ehdr = malloc(sizeof(sr_ethernet_hdr_t));
    memcpy(new_ehdr->ether_dhost, ehdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(new_ehdr->ether_shost, if_walker->addr, ETHER_ADDR_LEN);
    new_ehdr->ether_type = ehdr->ether_type;

    /* Construct new arp header. */
    sr_arp_hdr_t *new_arp_hdr = malloc(sizeof(sr_arp_hdr_t));
    memcpy(new_arp_hdr, arp_hdr, sizeof(sr_arp_hdr_t));
    new_arp_hdr->ar_op = htons(arp_op_reply);
    memcpy(new_arp_hdr->ar_sha, if_walker->addr, ETHER_ADDR_LEN);
    new_arp_hdr->ar_sip = if_walker->ip;
    memcpy(new_arp_hdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
    new_arp_hdr->ar_tip = arp_hdr->ar_sip;

    /* Combine ethernet header and arp header. */
    uint8_t *new_packet = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
    memcpy(new_packet, new_ehdr, sizeof(sr_ethernet_hdr_t));
    memcpy(new_packet + sizeof(sr_ethernet_hdr_t), new_arp_hdr, sizeof(sr_arp_hdr_t));
    printf("---------------new packet ------------\n");
    print_hdrs(new_packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
    printf("---------------------------\n");

    /* Send the newly constructed packet. */
    sr_send_packet(sr, new_packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), if_walker->name);
  }
  else if (ntohs(arp_hdr->ar_op) == arp_op_reply)
  {
    printf("we get arp reply\n");
    print_hdrs(packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
    struct sr_arpreq *waiting_req = sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, arp_hdr->ar_sip);
    assert(waiting_req);
    struct sr_packet *req_packet = waiting_req->packets;

    while (req_packet)
    {
      printf("get one packet\n");
      sr_ethernet_hdr_t *ethernet_hdr = (sr_ethernet_hdr_t *)req_packet->buf;
      memcpy(ethernet_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
      memcpy(ethernet_hdr->ether_shost, arp_hdr->ar_tha, ETHER_ADDR_LEN);
      print_hdrs(req_packet->buf, req_packet->len);
      printf("send thorugh %s\n", req_packet->iface);
      sr_send_packet(sr, req_packet->buf, req_packet->len, req_packet->iface);
      req_packet = req_packet->next;
      printf("packet sent\n");
    }

    sr_arpcache_dump(&(sr->cache));
  }
  else
  {
    printf("Wrong arp opcode.");
  }
  printf("\n\n");
}