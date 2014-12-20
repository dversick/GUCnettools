// Add -lpcap
// Values set for ARP request.

//How to use
//Install pcap using # sudo apt-get install libpcap0.8-dev
//gcc -o lsmacs lsmacs.c -lpcap

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>           // close(
#include <string.h>           // strcpy, memset(), and memcpy()
#include <pcap.h>
#include <stdarg.h>
#include <sys/time.h>       /* select */
#include <ifaddrs.h>
#include <netdb.h>            // struct addrinfo
#include <sys/types.h>        // needed for socket(), uint8_t, uint16_t
#include <sys/socket.h>       // needed for socket()
#include <netinet/in.h>       // IPPROTO_RAW, INET_ADDRSTRLEN
#include <netinet/ip.h>       // IP_MAXPACKET (which is 65535)
#include <arpa/inet.h>        // inet_pton() and inet_ntop()
#include <sys/ioctl.h>        // macro ioctl is defined
#include <bits/ioctls.h>      // defines values for argument "request" of ioctl.
#include <net/if.h>           // struct ifreq
#include <linux/if_ether.h>   // ETH_P_ARP = 0x0806
#include <linux/if_packet.h>  // struct sockaddr_ll (see man 7 packet)
#include <net/ethernet.h>

#include <errno.h>            // errno, perror()

#define EXIT_FAILURE 1
#define ARP_ETHERNETG 0x0806
#define ETH_ADDR_LEN    0x06
#define IP_ADDR_LEN   0x04

// Define a struct for ARP header
//Remove one of the next two, make sure is unused
typedef struct _arp_hdr arp_hdr;
struct _arp_hdr {
  uint16_t htype;
  uint16_t ptype;
  uint8_t hlen;
  uint8_t plen;
  uint16_t opcode;
  uint8_t sender_mac[6];
  uint8_t sender_ip[4];
  uint8_t target_mac[6];
  uint8_t target_ip[4];
};

struct arp_header {

  u_int16_t arp_htype;        /* hardware type: ethernet, frame-relay, ... */
  u_int16_t arp_ptype;        /* protocol type: ip, ipx, ... */
  u_char arp_hlen;        /* harware address length: eth-0x06, ... */
  u_char arp_plen;        /* protocol address length: ip-0x04, ... */
  u_int16_t arp_oper;       /* operation: request:0x01, reply:0x02, ... */
  u_char arp_sha[ETH_ADDR_LEN];     /* source hardware address */
  u_char arp_sip[IP_ADDR_LEN];      /* source protocol address */
  u_char arp_dha[ETH_ADDR_LEN];     /* destination hardware address */
  u_char arp_dip[IP_ADDR_LEN];      /* destination protocol address */

};
void *Malloc(size_t);
void *Realloc(void *, size_t);

void
err_sys(const char *fmt,...) {
   va_list ap;
   va_start(ap, fmt);
   va_end(ap);
   exit(EXIT_FAILURE);
}
void
callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet_in);

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[6];    /* destination host address */
        u_char  ether_shost[6];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

// Define some constants.
#define ETH_HDRLEN 14      // Ethernet header length
#define IP4_HDRLEN 20      // IPv4 header length
#define ARP_HDRLEN 28      // ARP header length
#define ARPOP_REQUEST 1    // Taken from <linux/if_arp.h>

// Function prototypes
char *allocate_strmem (int);
uint8_t *allocate_ustrmem (int);
char *make_message(const char *, ...);

struct in_addr bq_addr;
char llmac[18], llip[16];
int
main (int argc, char **argv)
{
  int i, j, status, frame_length, sd, bytes;
  char *interface, *target, *src_ip;
  arp_hdr arphdr;
  uint8_t *src_mac, *dst_mac, *ether_frame;
  struct addrinfo hints, *res;
  struct sockaddr_in *ipv4;
  struct sockaddr_ll device;
  struct ifreq ifr;

  pcap_t *handle;
  int pcap_fd;
  struct bpf_program filter;
  char *filter_string;
  bpf_u_int32 net;
  bpf_u_int32 mask;
  struct pcap_pkthdr header;
  const u_char *packet; 

  // Allocate memory for various arrays.
  src_mac = allocate_ustrmem (6);
  dst_mac = allocate_ustrmem (6);
  ether_frame = allocate_ustrmem (IP_MAXPACKET);
  interface = allocate_strmem (40);
  target = allocate_strmem (40);
  // target1 = allocate_strmem (40);
  src_ip = allocate_strmem (INET_ADDRSTRLEN);

  //Code to get our IP address!!


  struct ifaddrs *ifaddr, *ifa;
   int family, s;
   char host[NI_MAXHOST];

   if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
   }

   for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        family = ifa->ifa_addr->sa_family;

        if (family == AF_INET) {
                s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in),
                                               host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
                if (s != 0) {
                        printf("getnameinfo() failed: %s\n", gai_strerror(s));
                        exit(EXIT_FAILURE);
                }
        }
   }
  //End code to get the IP address
  strcpy (interface, argv[1]);

  // Submit request for a socket descriptor to look up interface.
  // in other words, create a socket, < 0 checks for error (error is given at -1)
  if ((sd = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
    perror ("socket() failed to get socket descriptor for using ioctl() ");
    exit (EXIT_FAILURE);
  }

  // Use ioctl() to look up interface name and get its MAC address.
  memset (&ifr, 0, sizeof (ifr));
  snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
  //SIOCGIFHWADDR used to get the MAC address
  if (ioctl (sd, SIOCGIFHWADDR, &ifr) < 0) {
    perror ("ioctl() failed to get source MAC address ");
    return (EXIT_FAILURE);
  }
  close (sd);

  // Copy source MAC address.
  memcpy (src_mac, ifr.ifr_hwaddr.sa_data, 6 * sizeof (uint8_t));

  // Report source MAC address to stdout.
  // print
  printf ("IP: %s", host);
  printf("\tMAC:");
  for (i=0; i<5; i++) {
    printf ("%02x:", src_mac[i]);
  }
  printf ("%02x\n", src_mac[5]);

  // Find interface index from interface name and store index in
  // struct sockaddr_ll device, which will be used as an argument of sendto().
  memset (&device, 0, sizeof (device));
  if ((device.sll_ifindex = if_nametoindex (interface)) == 0) {
    perror ("if_nametoindex() failed to obtain interface index ");
    exit (EXIT_FAILURE);
  }
  // printf ("Index for interface %s is %i\n", interface, device.sll_ifindex);

  // Set destination MAC address: broadcast address
  memset (dst_mac, 0xff, 6 * sizeof (uint8_t));

  // Source IPv4 address:  you need to fill this out
  strcpy (src_ip, host);

  // Code for pcap sniffing, purely mine lol.

  char errbuf[PCAP_ERRBUF_SIZE];
  //Change me for the network interface
  char *dev = "wlan0";
  
  if(dev == NULL) {
    fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
      return(2);
  }

  if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
     fprintf(stderr, "Can't get netmask for device %s\n", dev);
      net = 0;
      mask = 0;
  }

  bq_addr.s_addr = net & mask;
  int z = 0 ;
  int numberOfOnesInNetAddress = 0;
  while (mask) {
    if (mask & 1)
        numberOfOnesInNetAddress++;

    mask >>= 1;
  }
  int toShiftIPIncrementValue = numberOfOnesInNetAddress;
  numberOfOnesInNetAddress = 32 - numberOfOnesInNetAddress;
  int incrementIPValue = 0b00000000000000000000000000000001;
  while(toShiftIPIncrementValue>0) {
    
    incrementIPValue <<= 1;
    toShiftIPIncrementValue--;
  }

  int numberOfHosts=1;
  int q = 0;
  for(q;q<numberOfOnesInNetAddress;q++){
    numberOfHosts = numberOfHosts * 2;
  }

  handle = pcap_open_live(dev, 64, 1, 0, errbuf);

  if(handle == NULL) {
    fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
  return(2);
  }

  if (pcap_setnonblock(handle, 1, errbuf) == -1){
      error("pcap_setnonblock failed: %s", errbuf);
  }
  //determine the type of link-layer headers the device provides
  //If your program doesn't support the link-layer header type provided by the device
  //then exit
  if (pcap_datalink(handle) != DLT_EN10MB) {
    fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", dev);
    return(2);
  }
  // Missing our ip and mac address, go back to the tutorial


  filter_string=make_message("ether dst %.2x:%.2x:%.2x:%.2x:%.2x:%.2x and "
                                 "(arp or (ether[14:4]=0xaaaa0300 and "
                                 "ether[20:2]=0x0806) or (ether[12:2]=0x8100 "
                                 "and ether[16:2]=0x0806) or "
                                 "(ether[12:2]=0x8100 and "
                                 "ether[18:4]=0xaaaa0300 and "
                                 "ether[24:2]=0x0806))", src_mac[0],src_mac[1],src_mac[2],src_mac[3],src_mac[4],src_mac[5]);
  
  if (pcap_compile(handle, &filter, filter_string, 0, net) == -1) {
  fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_string, pcap_geterr(handle));
  return(2);
  }

  if (pcap_setfilter(handle, &filter) == -1) {
     fprintf(stderr, "Couldn't install filter %s: %s\n", filter_string, pcap_geterr(handle));
     return(2);
   }
  

   if ((pcap_fd=pcap_get_selectable_fd(handle)) == -1)
    error("pcap_get_selectable_fd() fails");
  //Not sure why the +1

  char current[15]="";
  char digit[3];
  // End of my code
  //For loop to go through all the hosts possible in the network
  //and send a request ARP packet to each
  for(i = 1; i < numberOfHosts ; i++ ) {

    bq_addr.s_addr = bq_addr.s_addr + incrementIPValue;
    strcat(current, inet_ntoa(bq_addr));
    memset (&hints, 0, sizeof (struct addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = hints.ai_flags | AI_CANONNAME;

    // Source IP address
    if ((status = inet_pton (AF_INET, src_ip, &arphdr.sender_ip)) != 1) {
      fprintf (stderr, "inet_pton() failed for source IP address.\nError message: %s", strerror (status));
      exit (EXIT_FAILURE);
    }
    // Resolve target using getaddrinfo().
    if ((status = getaddrinfo (current, NULL, &hints, &res)) != 0) {
      fprintf (stderr, "getaddrinfo() failed: %s\n", gai_strerror (status));
      exit (EXIT_FAILURE);
    }
    ipv4 = (struct sockaddr_in *) res->ai_addr;
    memcpy (&arphdr.target_ip, &ipv4->sin_addr, 4 * sizeof (uint8_t));
    freeaddrinfo (res);

    // Fill out sockaddr_ll.
    device.sll_family = AF_PACKET;
    memcpy (device.sll_addr, src_mac, 6 * sizeof (uint8_t));
    device.sll_halen = htons (6);

    // ARP header

    // Hardware type (16 bits): 1 for ethernet
    arphdr.htype = htons (1);

    // Protocol type (16 bits): 2048 for IP
    arphdr.ptype = htons (ETH_P_IP);

    // Hardware address length (8 bits): 6 bytes for MAC address
    arphdr.hlen = 6;

    // Protocol address length (8 bits): 4 bytes for IPv4 address
    arphdr.plen = 4;

    // OpCode: 1 for ARP request
    arphdr.opcode = htons (ARPOP_REQUEST);

    // Sender hardware address (48 bits): MAC address
    memcpy (&arphdr.sender_mac, src_mac, 6 * sizeof (uint8_t));

    // Sender protocol address (32 bits)
    // See getaddrinfo() resolution of src_ip.

    // Target hardware address (48 bits): zero, since we don't know it yet.
    memset (&arphdr.target_mac, 0, 6 * sizeof (uint8_t));

    // Target protocol address (32 bits)
    // See getaddrinfo() resolution of target.

    // Fill out ethernet frame header.

    // Ethernet frame length = ethernet header (MAC + MAC + ethernet type) + ethernet data (ARP header)
    frame_length = 6 + 6 + 2 + ARP_HDRLEN;

    // Destination and Source MAC addresses
    memcpy (ether_frame, dst_mac, 6 * sizeof (uint8_t));
    memcpy (ether_frame + 6, src_mac, 6 * sizeof (uint8_t));

    ether_frame[12] = ETH_P_ARP / 256;
    ether_frame[13] = ETH_P_ARP % 256;

    // Next is ethernet frame data (ARP header).

    // ARP header
    memcpy (ether_frame + ETH_HDRLEN, &arphdr, ARP_HDRLEN * sizeof (uint8_t));

    // Submit request for a raw socket descriptor.
    if ((sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
      perror ("socket() failed ");
      exit (EXIT_FAILURE);
    }

    // Send ethernet frame to current socket.
  
    if ((bytes = sendto(sd, ether_frame, frame_length, 0, (struct sockaddr *) &device, sizeof (device))) <= 0) {
      perror ("sendto() failed");
      exit (EXIT_FAILURE);
    }
    //
    struct timeval tv;
    tv.tv_sec = 1/100;
      tv.tv_usec = 0;
      fd_set fd_wait;
    FD_ZERO(&fd_wait);
     FD_SET(pcap_fd, &fd_wait);
     if(select(pcap_fd, &fd_wait, NULL, NULL, &tv) < 0)
         error("Error occured on Select()");
     
     if ((pcap_dispatch(handle, 2000, callback, NULL)) == -1){
           err_sys("pcap_dispatch: %s\n", pcap_geterr(handle));
    }
    memset(current, 0, sizeof(current));
}
//End for loop
  // Close socket descriptor.
  close (sd);
  // Close pcap sniffing
  pcap_close(handle);
  // Free allocated memory.
  free (src_mac);
  free (dst_mac);
  free (ether_frame);
  free (interface);
  free (target);
  free (src_ip);
  //Terminate program
  return (EXIT_SUCCESS);
}

// Allocate memory for an array of chars.
char *
allocate_strmem (int len)
{
  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_strmem().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = (char *) malloc (len * sizeof (char));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (char));
    return (tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_strmem().\n");
    exit (EXIT_FAILURE);
  }
}

void
callback(u_char *args, const struct pcap_pkthdr *header,
   const u_char *packet_in) {
  const struct arp_header *elarp;
  char destip[16];
  u_char dip[IP_ADDR_LEN];
  char  e_smac[18], e_dmac[18],
    a_sha[18], a_sip[16],
    a_dha[18], a_dip[16]; 
  const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
  // const struct arp_hdr *arp;
  ethernet = (struct sniff_ethernet*)(packet_in);
  //Obtaining the ARP packet
  elarp = (struct arp_header *)(packet_in+14);
  snprintf (destip, 16, "%d.%d.%d.%d",
        elarp->arp_sip[0], elarp->arp_sip[1], elarp->arp_sip[2], elarp->arp_sip[3]);
  printf("IP:%s \t", destip);

  // Load mac address from received ARP packet
  snprintf (e_smac, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
      elarp->arp_sha[0], elarp->arp_sha[1], elarp->arp_sha[2],
      elarp->arp_sha[3], elarp->arp_sha[4], elarp->arp_sha[5]);
  printf("MAC: %s\n", e_smac); 
  return;

}
//Make message
char *
make_message(const char *fmt, ...) {
   int n;
   /* Guess we need no more than 100 bytes. */
   size_t size = 100;
   char *p;
   va_list ap;
   p = Malloc (size);
   while (1) {
      /* Try to print in the allocated space. */
      va_start(ap, fmt);
      n = vsnprintf (p, size, fmt, ap);
      va_end(ap);
      /* If that worked, return the string. */
      if (n > -1 && n < (int) size)
         return p;
      /* Else try again with more space. */
      if (n > -1)    /* glibc 2.1 */
         size = n+1; /* precisely what is needed */
      else           /* glibc 2.0 */
         size *= 2;  /* twice the old size */
      p = Realloc (p, size);
   }
}
//Realloc
void *Realloc(void *ptr, size_t size) {
   void *result;

   result=realloc(ptr, size);

   if (result == NULL)
      err_sys("realloc");

   return result;
}
//Malloc
void *Malloc(size_t size) {
   void *result;

   result = malloc(size);

   if (result == NULL)
      err_sys("malloc");

   return result;
}

// Allocate memory for an array of unsigned chars.
uint8_t *
allocate_ustrmem (int len)
{
  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_ustrmem().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = (uint8_t *) malloc (len * sizeof (uint8_t));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (uint8_t));
    return (tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_ustrmem().\n");
    exit (EXIT_FAILURE);
  }
}