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
#include "checksum.h"

#define PROTO_UDP	17
#define DST_PORT	54321

//char bcast_mac[6] =	{0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
char dst_mac[6] =	{0x80, 0x00, 0x27, 0x12, 0x38, 0x8e};
char src_mac[6] =	{0x00, 0x00, 0x00, 0x33, 0x33, 0x33};

union eth_buffer buffer_u;

void returnAck(uint16_t ack);

uint32_t ipchksum(uint8_t *packet) //checksum ip
{
	uint32_t sum=0;
	uint16_t i;

	for(i = 0; i < 20; i += 2)
		sum += ((uint32_t)packet[i] << 8) | (uint32_t)packet[i + 1];
	while (sum & 0xffff0000)
		sum = (sum & 0xffff) + (sum >> 16);
	return sum;
}

int sockfd;
char ifName[IFNAMSIZ];
int main(int argc, char *argv[])
{
	struct ifreq ifopts;
	short ack = 0;
	int numbytes;
	char *p;
	FILE *file;
	short padd_rec = 0;
	
	/* Get interface name */
	if (argc > 1)
		strcpy(ifName, argv[1]);
	else
		strcpy(ifName, DEFAULT_IF);

	/* Open RAW socket */
	if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1)
		perror("socket");

	/* End of configuration. Now we can receive data using raw sockets. */

	unsigned short cksum;
	struct application* app;

	while (1){

		numbytes = recvfrom(sockfd, buffer_u.raw_data, ETH_LEN, 0, NULL, NULL);
		if (buffer_u.cooked_data.ethernet.eth_type == ntohs(ETH_P_IP) && buffer_u.cooked_data.payload.ip.proto == PROTO_UDP && buffer_u.cooked_data.payload.udp.udphdr.dst_port == ntohs(DST_PORT)){
			printf("\n\nIP packet, %d bytes - src ip: %d.%d.%d.%d dst ip: %d.%d.%d.%d proto: %d\n",
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
				p = (char *)(&buffer_u.cooked_data.payload.udp.udphdr);	
				p += sizeof(struct udp_hdr);

				app = (struct application *) p;
				printf("id : %d , controle %d, padd %d, chk %d\n", app->id, app->controle, app->padd, app->app_chksum);

				cksum = htons(in_cksum((short *)app, sizeof(app->id) + sizeof(app->controle) + sizeof(app->padd) + sizeof(app->data)));

				if(app->app_chksum != cksum) //checksum error, descartando dados;
				{
					printf("Checksum ERROR ex: %d , rec: %d\n", cksum, app->app_chksum);
					continue;
				}
				printf("Checksum OK\n");

				if(app->id == ack) //conferindo o id com o ack
				{
					if(ack < 64*1024 - 1)
						ack +=1;
					else
						ack = 0;
				
					if((app->controle & START) != 0) //se for START deve-se criar o arquivo
					{
						printf("Abrindo arquivo \n");

						file = fopen("ex.txt", "w");
						//file = fopen(app->data, "w"); //TODO DESCOMENTAR E COMENTAR A DE CIMA, ONLY DEBUG
						
						if (file == NULL)
						{
							printf("ERRO! O arquivo não foi criado!\n");
							return -1;
						}	
					}
					else
					{
						if (file == NULL) 
						{
							printf("Erro no arquivo!, fechando servidor!\n");
							return -1;
						}	

						if((app->controle & LAST) != 0) //se for ultimo pacote cuidar padding e fechar arquivo
						{
							printf("Ultimo Pacote\n");

							if((app->controle & PADDING) != 0)
							{
								printf("Padding \n");
								padd_rec = 0;
								if((app->controle & PADDING_256) != 0)
								{
									printf("Padding > 255\n");
									padd_rec = 256;
								}
								padd_rec += app->padd;

								fwrite (app->data , sizeof(uint8_t), (512 - padd_rec)*sizeof(uint8_t), file);
							}
							else
							{
								fwrite (app->data , sizeof(uint8_t), sizeof(app->data), file);
							}

							printf("Fechando arquivo \n");
							fclose(file);

							returnAck(ack);
							ack = 0;

							continue;
						}
						else
						{
							printf("Recebendo Pacote \n");
							fwrite (app->data , sizeof(uint8_t), sizeof(app->data), file);
						}
					}

					printf("Enviando ack - %d", ack);
					returnAck(ack);
				}
				else
				{
					printf("ACK error, ex: %d, rec: %d", ack, app->id);
					returnAck(ack);
				}

			continue;
		}
	}

	return 0;
}

void returnAck(uint16_t ack)
{
	uint8_t srcip[4];

	buffer_u.cooked_data.payload.ip.len = htons(sizeof(struct ip_hdr) + sizeof(struct udp_hdr) + sizeof(uint16_t));

	srcip[0] = buffer_u.cooked_data.payload.ip.src[0];
	srcip[1] = buffer_u.cooked_data.payload.ip.src[1];
	srcip[2] = buffer_u.cooked_data.payload.ip.src[2];
	srcip[3] = buffer_u.cooked_data.payload.ip.src[3];

	buffer_u.cooked_data.payload.ip.src[0] = buffer_u.cooked_data.payload.ip.dst[0];
	buffer_u.cooked_data.payload.ip.src[1] = buffer_u.cooked_data.payload.ip.dst[1];
	buffer_u.cooked_data.payload.ip.src[2] = buffer_u.cooked_data.payload.ip.dst[2];
	buffer_u.cooked_data.payload.ip.src[3] = buffer_u.cooked_data.payload.ip.dst[3];
	buffer_u.cooked_data.payload.ip.dst[0] = srcip[0];
	buffer_u.cooked_data.payload.ip.dst[1] = srcip[1];
	buffer_u.cooked_data.payload.ip.dst[2] = srcip[2];
	buffer_u.cooked_data.payload.ip.dst[3] = srcip[3];
	buffer_u.cooked_data.payload.ip.sum = htons((~ipchksum((uint8_t *)&buffer_u.cooked_data.payload.ip) & 0xffff));

	/* Fill UDP header */
	uint16_t srcport = buffer_u.cooked_data.payload.udp.udphdr.src_port;
	buffer_u.cooked_data.payload.udp.udphdr.src_port = buffer_u.cooked_data.payload.udp.udphdr.dst_port;
	buffer_u.cooked_data.payload.udp.udphdr.dst_port = srcport;
	buffer_u.cooked_data.payload.udp.udphdr.udp_len = htons(sizeof(struct udp_hdr) + sizeof(uint16_t));
	buffer_u.cooked_data.payload.udp.udphdr.udp_chksum = 0;

	/* Fill UDP payload */
	memcpy(buffer_u.raw_data + sizeof(struct eth_hdr) + sizeof(struct ip_hdr) + sizeof(struct udp_hdr), &ack, sizeof(uint16_t));

	struct sockaddr_ll socket_address;
	struct ifreq if_idx;

	/* Get the index of the interface */
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, ifName, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
		perror("SIOCGIFINDEX");
	socket_address.sll_ifindex = if_idx.ifr_ifindex;
	socket_address.sll_halen = ETH_ALEN;

	/* Send it.. */
	memcpy(socket_address.sll_addr, dst_mac, 6);
	if (sendto(sockfd, buffer_u.raw_data, sizeof(struct eth_hdr) + sizeof(struct ip_hdr) + sizeof(struct udp_hdr) + sizeof(uint16_t), 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
		printf("Send failed\n");
}
