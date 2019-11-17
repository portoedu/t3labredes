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
#include <time.h>
#include <math.h>

#define PROTO_UDP	17
#define SRC_PORT	54322
#define DEF_TIMEOUT 1

char this_mac[6];
char dst_mac[6] =	{0x08, 0x00, 0x27, 0x12, 0x38, 0x8e};
union eth_buffer buffer_u;
union eth_buffer buffer_rec;

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
	struct application app;
	FILE * file;
	int size;
	bool run = true;
	short id = 0;
	char *p;
	uint16_t ack;
	time_t inicio, fim;
	int expoente = 0;
	int ack_expected;
	int num_acks;
	int dup_ack = 0;


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
	memcpy(buffer_u.cooked_data.ethernet.dst_addr, dst_mac, 6);
	memcpy(buffer_u.cooked_data.ethernet.src_addr, this_mac, 6);
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
	buffer_u.cooked_data.payload.udp.udphdr.src_port = htons(SRC_PORT);
	buffer_u.cooked_data.payload.udp.udphdr.dst_port = htons(54321);
	buffer_u.cooked_data.payload.udp.udphdr.udp_len = htons(sizeof(struct udp_hdr) + sizeof(struct application));
	buffer_u.cooked_data.payload.udp.udphdr.udp_chksum = 0;

	app.id = id;
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
	app.app_chksum = htons(in_cksum((short *)&app, sizeof(app.id) + sizeof(app.controle) + sizeof(app.padd) + sizeof(app.data)));

	printf("Iniciando envio-> id : %d , controle %d, padd %d, Nome: %s , chk %d\n", app.id, app.controle, app.padd, app.data, app.app_chksum);

	/* Fill UDP payload */
	memcpy(buffer_u.raw_data + sizeof(struct eth_hdr) + sizeof(struct ip_hdr) + sizeof(struct udp_hdr), &app, sizeof(struct application));

	resendStart:
	/* Send it.. */
	memcpy(socket_address.sll_addr, dst_mac, 6);
	if (sendto(sockfd, buffer_u.raw_data, sizeof(struct eth_hdr) + sizeof(struct ip_hdr) + sizeof(struct udp_hdr) + sizeof(struct application), 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
		printf("Send failed\n");

	inicio = time(NULL);
	fim = time(NULL);

	do{
		fim = time(NULL);

		if(( fim - inicio ) > DEF_TIMEOUT)
		{
			printf("Timeout: %ld, reenviando!\n", (fim - inicio));
			goto resendStart;
		}

		numbytes = recvfrom(sockfd, buffer_rec.raw_data, ETH_LEN, 0, NULL, NULL);
	}while(buffer_rec.cooked_data.ethernet.eth_type == ntohs(ETH_P_IP) &&
	 buffer_rec.cooked_data.payload.ip.proto == PROTO_UDP && 
	 buffer_rec.cooked_data.payload.udp.udphdr.dst_port == ntohs(SRC_PORT)
	 && buffer_rec.cooked_data.payload.udp.udphdr.udp_len == htons(sizeof(struct udp_hdr) + sizeof(uint16_t))
	 && !memcpy(buffer_u.cooked_data.ethernet.dst_addr, this_mac, sizeof(this_mac)));

	p = (char *)(&buffer_rec.cooked_data.payload.udp.udphdr);	
	p +=  8;
	ack = (uint16_t)*p;

	printf("Recebdo Ack %x\n", ack);
	if(ack != (id + 1))
	{
	 	goto resendStart;
	}

	id++;
	expoente = 1;
	ack_expected = id + 1;

	while(run)
	{

		resend:
		printf("\nEnviando %0.1f pacotes\n", pow(2, expoente));
		for(int i=0; i < pow(2, expoente); i++)
		{
			memset(&app.data, '\0', sizeof(app.data));
			fread(&app.data, sizeof(uint8_t), 512, file);
			
			app.id = id;
			app.controle = 0;
			app.padd = 0;

			if(feof(file))
			{
				num_acks = i + 1;
				i = pow(2, expoente);
				size = strlen(app.data);
				app.controle |= LAST;

				if(size < 512){
					app.controle |= PADDING;
					size = 512 - size;
					if(size > 255)
					{
						app.controle |= PADDING_256;
						size -= 256;
					}
					app.padd = size;
				}
			}
			else
			{
				num_acks = i + 1;
			}

			app.app_chksum = htons(in_cksum((short *)&app, sizeof(app.id) + sizeof(app.controle) + sizeof(app.padd) + sizeof(app.data)));
				/* Fill UDP payload */
			memcpy(buffer_u.raw_data + sizeof(struct eth_hdr) + sizeof(struct ip_hdr) + sizeof(struct udp_hdr), &app, sizeof(struct application));

			printf("Enviando -> id : %d , controle %d, padd %d, chk %d\n", app.id, app.controle, app.padd, app.app_chksum);

			/* Send it.. */
			memcpy(socket_address.sll_addr, dst_mac, 6);
			if (sendto(sockfd, buffer_u.raw_data, sizeof(struct eth_hdr) + sizeof(struct ip_hdr) + sizeof(struct udp_hdr) + sizeof(struct application), 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
				printf("Send failed\n");

			if(id < 64*1024 -1)
				id++;
			else
				id = 0;

		}
		
		printf("Esperando %d acks, prox ack %d\n", num_acks, ack_expected);
		for(int i=0; i < num_acks; i++)
		{

			inicio = time(NULL);
			fim = time(NULL);
			
			do{
				fim = time(NULL);
			
				if(( fim - inicio ) > DEF_TIMEOUT)
				{
					printf("Recomeçando slow start, timeout: %ld!\n", (fim - inicio));
					expoente = 0;
					id = ack;
					fseek(file, (ack - 1)*512, SEEK_SET);
					goto resend;
				}

				numbytes = recvfrom(sockfd, buffer_rec.raw_data, ETH_LEN, 0, NULL, NULL);
			}while(buffer_rec.cooked_data.ethernet.eth_type == ntohs(ETH_P_IP) &&
			buffer_rec.cooked_data.payload.ip.proto == PROTO_UDP && 
			buffer_rec.cooked_data.payload.udp.udphdr.dst_port == ntohs(SRC_PORT)
			&& buffer_rec.cooked_data.payload.udp.udphdr.udp_len == htons(sizeof(struct udp_hdr) + sizeof(uint16_t))
			&& !memcpy(buffer_u.cooked_data.ethernet.dst_addr, this_mac, sizeof(this_mac)));

			p = (char *)(&buffer_rec.cooked_data.payload.udp.udphdr);	
			p +=  8;
			ack = (uint16_t)*p;

			printf("Recebdo Ack %d\n", ack);
			if(ack != ack_expected)
			{
				printf("Ack recebido diferente do esperado, rec: %d, ex: %d\n", ack, ack_expected);
				printf("Duplicados: %d\n", dup_ack);
				if(dup_ack == 3)
				{
					printf("Recomeçando slow start, fast retransmit, 3 ack duplicados!\n");
					expoente = 0;
					id = ack;
					fseek(file, (ack - 1)*512, SEEK_SET);
					goto resend;
				}
				else
				{
					dup_ack++;
				}
			}
			else
			{
				dup_ack = 0;
				ack_expected++;
			}

		}
		expoente++;

		if(feof(file))
		{
			run = false;
		}

	}

	printf("Envio finalizado, fechando arquivo!\n");
	fclose(file);
	return 0;
}