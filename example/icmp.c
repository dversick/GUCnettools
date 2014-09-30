/*
 * Name          : example
 * Synopsis      : example source_ip destination_ip
 * Description   : Very simple ping example for GUC course Local Area Networks
 *                 Based on standard ping
 *                 Sends ICMP packet with payload "GUC network tools"
 * Authors       : Daniel Versick
 * Known Problems: None
 * License       : BSD
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <unistd.h>
#include <arpa/inet.h>

unsigned short checksum(unsigned short *ptr, int nbytes);

int main(int argc, char **argv)
{
	if (argc != 3) 
	{
		printf("synopsis: %s <source IP> <destination IP>\n", argv[0]);
		exit(0);
	}
	
	unsigned long saddr;	// source 32 bit IP address
	unsigned long daddr;	// destination 32 bit IP address
	char payload[] = "GUC network tools";
	int payload_size = sizeof(payload);
	
	saddr = inet_addr(argv[1]);	// calculating 32 bit IP address from text represenation
	daddr = inet_addr(argv[2]);
	
	/* creating raw socket; this operation needs root privileges!!!!!! */
	int sockfd = socket (AF_INET, SOCK_RAW, IPPROTO_RAW);
	
	if (sockfd < 0) 
	{
		perror("could not create socket");
		return (1);
	}
	
	/* calculating total packet size for memory allocation  */
	int packet_size = sizeof (struct iphdr) 
			+ sizeof (struct icmphdr) 
			+ payload_size;

	char *packet = (char *) malloc (packet_size);
	if (!packet) 
	{
		perror("Error: Could not allocate memory.");
		close(sockfd);
		return (1);
	}
	
	/* now assembling the IP and ICMP header */
	struct iphdr *ip = (struct iphdr *) packet;
	struct icmphdr *icmp = (struct icmphdr *) (packet + sizeof (struct iphdr));
	
	memset (packet, 0, packet_size);

	ip->version = 4;
	ip->ihl = 5;
	ip->tos = 0;
	ip->tot_len = htons (packet_size);
	ip->id = rand ();
	ip->frag_off = 0;
	ip->ttl = 255;
	ip->protocol = IPPROTO_ICMP;
	ip->saddr = saddr;
	ip->daddr = daddr;

  	icmp->type = ICMP_ECHO;
	icmp->code = 0;
  	icmp->un.echo.sequence = rand();
  	icmp->un.echo.id = rand();
	
	struct sockaddr_in servaddr;
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = daddr;
	memset(&servaddr.sin_zero, 0, sizeof (servaddr.sin_zero));


	/*
         * Now copying the payload behind the header.
	 * How can we do this better? Copying the payload in every layer of the network hierarchy may not be the best way!
         */	
	memcpy(packet + sizeof(struct iphdr) + sizeof(struct icmphdr), payload, payload_size);
	icmp->checksum = 0;
	icmp->checksum = checksum((unsigned short *)icmp, sizeof(struct icmphdr) + payload_size);

	puts("sending ICMP packet...");
		
	if ( (sendto(sockfd, packet, packet_size, 0, 
		(struct sockaddr*) &servaddr, sizeof (servaddr))) < 1) 
		{
			perror("Sending failed!\n");
		}
		
	free(packet);
	close(sockfd);
	
	return (0);
}

/*
	Function for calculating checksum
*/
unsigned short checksum(unsigned short *ptr, int nbytes)
{
	register long sum;
	u_short oddbyte;
	register u_short answer;

	sum = 0;
	while (nbytes > 1) {
		sum += *ptr++;
		nbytes -= 2;
	}

	if (nbytes == 1) {
		oddbyte = 0;
		*((u_char *) & oddbyte) = *(u_char *) ptr;
		sum += oddbyte;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	answer = ~sum;

	return (answer);
}

