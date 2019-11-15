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
#include <stdbool.h>
#include "raw.h"
#include "checksum.h"

char this_mac[6];
char bcast_mac[6] =	{0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
char dst_mac[6] =	{0x00, 0x00, 0x00, 0x22, 0x22, 0x22};
char src_mac[6] =	{0x00, 0x00, 0x00, 0x33, 0x33, 0x33};

union eth_buffer buffer_u;

uint32_t ipchksum(uint8_t *packet)
{
	uint32_t sum=0;
	uint16_t i;

	for(i = 0; i < 20; i += 2)
		sum += ((uint32_t)packet[i] << 8) | (uint32_t)packet[i + 1];
	while (sum & 0xffff0000)
		sum = (sum & 0xffff) + (sum >> 16);
	return sum;
}

int main(int argc, char *argv[])
{
	struct ifreq if_idx, if_mac, ifopts;
	char ifName[IFNAMSIZ];
	struct sockaddr_ll socket_address;
	int sockfd, numbytes;
	//uint8_t msg[] = "hello world!! =)";
	struct application app;
	FILE * file;
	int size;
	bool run = true;


	/* Get interface name */
	if (argc > 1)
		strcpy(ifName, argv[1]);
	else
	{
		printf("Interface não especificada!/n");
		return -1;
	}

	/*Get file */
	if(argc > 2)
	{
		file = fopen (argv[2], "r");
		if(file == NULL)
		{
			printf("Erro ao abrir arquivo!\n");
			return 1;
		}
		printf("Arquivo aberto!\n");
	}
	else
	{
		printf("Arquivo não especificado!\n");
		return 1;
	}


	/* Open RAW socket */
	if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1)
		perror("socket");


	/* Get the index of the interface */
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, ifName, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
		perror("SIOCGIFINDEX");
	socket_address.sll_ifindex = if_idx.ifr_ifindex;
	socket_address.sll_halen = ETH_ALEN;

	/* Get the MAC address of the interface */
	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, ifName, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0)
		perror("SIOCGIFHWADDR");
	memcpy(this_mac, if_mac.ifr_hwaddr.sa_data, 6);

	/* End of configuration. Now we can send data using raw sockets. */

	/* Fill the Ethernet frame header */
	memcpy(buffer_u.cooked_data.ethernet.dst_addr, bcast_mac, 6);
	memcpy(buffer_u.cooked_data.ethernet.src_addr, src_mac, 6);
	buffer_u.cooked_data.ethernet.eth_type = htons(ETH_P_IP);

	/* Fill IP header data. Fill all fields and a zeroed CRC field, then update the CRC! */
	buffer_u.cooked_data.payload.ip.ver = 0x45;
	buffer_u.cooked_data.payload.ip.tos = 0x00;
	buffer_u.cooked_data.payload.ip.len = htons(sizeof(struct ip_hdr) + sizeof(struct udp_hdr) + sizeof(struct application));
	buffer_u.cooked_data.payload.ip.id = htons(0x00);
	buffer_u.cooked_data.payload.ip.off = htons(0x00);
	buffer_u.cooked_data.payload.ip.ttl = 50;
	buffer_u.cooked_data.payload.ip.proto = 17; //0xff;
	buffer_u.cooked_data.payload.ip.sum = htons(0x0000);

	buffer_u.cooked_data.payload.ip.src[0] = 192;
	buffer_u.cooked_data.payload.ip.src[1] = 168;
	buffer_u.cooked_data.payload.ip.src[2] = 0;
	buffer_u.cooked_data.payload.ip.src[3] = 24;
	buffer_u.cooked_data.payload.ip.dst[0] = 192;
	buffer_u.cooked_data.payload.ip.dst[1] = 168;
	buffer_u.cooked_data.payload.ip.dst[2] = 0;
	buffer_u.cooked_data.payload.ip.dst[3] = 24;
	buffer_u.cooked_data.payload.ip.sum = htons((~ipchksum((uint8_t *)&buffer_u.cooked_data.payload.ip) & 0xffff));

	/* Fill UDP header */
	buffer_u.cooked_data.payload.udp.udphdr.src_port = htons(555);
	buffer_u.cooked_data.payload.udp.udphdr.dst_port = htons(54321);
	buffer_u.cooked_data.payload.udp.udphdr.udp_len = htons(sizeof(struct udp_hdr) + sizeof(struct application));
	buffer_u.cooked_data.payload.udp.udphdr.udp_chksum = 0;

	app.id = 0;
	app.controle = 0;
	app.controle |= START;

	size = sizeof(argv[2]) + 1;
	
	if(size >= 512)
	{
		printf("Nome do arquivo maior que o tamanho máximo!\n");
		return -1;
	}
	
	if(size < 512){
		app.controle |= PADDING;
		size = 512 - size;
		if(size > 256)
		{
			app.controle |= PADDING_256;
			size -= 256;
		}
		app.padd = size;
		memset(app.data, 0x00, 512*sizeof(uint8_t));
	}

	memcpy(&app.data, argv[2], sizeof(argv[2]) + 1);
	app.app_chksum = in_cksum(&app, sizeof(app.id) + sizeof(app.controle) + sizeof(app.padd) + sizeof(app.data));
	app.data[sizeof(app.data)] = '\0';

	printf("id : %d , controle %d, padd %d, data: %s , chk %d\n", app.id, app.controle, app.padd, app.data, app.app_chksum);

	/* Fill UDP payload */
	memcpy(buffer_u.raw_data + sizeof(struct eth_hdr) + sizeof(struct ip_hdr) + sizeof(struct udp_hdr), &app, sizeof(struct application));

	/* Send it.. */
	memcpy(socket_address.sll_addr, dst_mac, 6);
	if (sendto(sockfd, buffer_u.raw_data, sizeof(struct eth_hdr) + sizeof(struct ip_hdr) + sizeof(struct udp_hdr) + sizeof(struct application), 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
		printf("Send failed\n");

	return 0;
}