#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#include "raw.h"

#define PROTO_UDP	17
#define DST_PORT	54321

char bcast_mac[6] =	{0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
char dst_mac[6] =	{0x00, 0x00, 0x00, 0x22, 0x22, 0x22};
char src_mac[6] =	{0x00, 0x00, 0x00, 0x33, 0x33, 0x33};

union eth_buffer buffer_u;

int main(int argc, char *argv[])
{
	struct ifreq ifopts;
	char ifName[IFNAMSIZ];
	int sockfd, numbytes;
	char *p;
	
	/* Get interface name */
	if (argc > 1)
		strcpy(ifName, argv[1]);
	else
		strcpy(ifName, DEFAULT_IF);

	/* Open RAW socket */
	if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1)
		perror("socket");
	
	/* Set interface to promiscuous mode */
	strncpy(ifopts.ifr_name, ifName, IFNAMSIZ-1);
	ioctl(sockfd, SIOCGIFFLAGS, &ifopts);
	ifopts.ifr_flags |= IFF_PROMISC;
	ioctl(sockfd, SIOCSIFFLAGS, &ifopts);

	/* End of configuration. Now we can receive data using raw sockets. */

	char* app;
	//struct application* app;
	while (1){
		numbytes = recvfrom(sockfd, buffer_u.raw_data, ETH_LEN, 0, NULL, NULL);
		if (buffer_u.cooked_data.ethernet.eth_type == ntohs(ETH_P_IP) && buffer_u.cooked_data.payload.ip.proto == PROTO_UDP && buffer_u.cooked_data.payload.udp.udphdr.dst_port == ntohs(DST_PORT)){
			printf("IP packet, %d bytes - src ip: %d.%d.%d.%d dst ip: %d.%d.%d.%d proto: %d\n",
				numbytes,
				buffer_u.cooked_data.payload.ip.src[0], buffer_u.cooked_data.payload.ip.src[1],
				buffer_u.cooked_data.payload.ip.src[2], buffer_u.cooked_data.payload.ip.src[3],
				buffer_u.cooked_data.payload.ip.dst[0], buffer_u.cooked_data.payload.ip.dst[1],
				buffer_u.cooked_data.payload.ip.dst[2], buffer_u.cooked_data.payload.ip.dst[3],
				buffer_u.cooked_data.payload.ip.proto
			);
				p = (char *)&buffer_u.cooked_data.payload.udp.udphdr + ntohs(buffer_u.cooked_data.payload.udp.udphdr.udp_len);
				*p = '\0';
				printf("src port: %d dst port: %d size: %d msg: %s \n", 
				ntohs(buffer_u.cooked_data.payload.udp.udphdr.src_port), ntohs(buffer_u.cooked_data.payload.udp.udphdr.dst_port),
				ntohs(buffer_u.cooked_data.payload.udp.udphdr.udp_len), (char *)&buffer_u.cooked_data.payload.udp.udphdr + sizeof(struct udp_hdr)
				); 
				app = &buffer_u.cooked_data.payload.udp.udphdr + sizeof(struct udp_hdr);	
				printf("%c %c %c %c \n", app[0], app[1], app[2], app[3]);

				//printf("id %d \n", app->id);
				//printf("id : %d , controle %d, padd %d, data: %s , chk %d\n", app->id, app->controle, app->padd, app->data, app->app_chksum);

			continue;
		}
	}

	return 0;
}
