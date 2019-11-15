#define ETH_LEN	1518
#define ETHER_TYPE	0x0800
#define DEFAULT_IF	"eth0"
#define START 0X80
#define LAST 0X40
#define PADDING 0X20
#define PADDING_256 0X01

struct eth_hdr {
	uint8_t dst_addr[6];
	uint8_t src_addr[6];
	uint16_t eth_type;
};

struct ip_hdr {
	uint8_t ver;			/* version, header length */
	uint8_t tos;			/* type of service */
	int16_t len;			/* total length */
	uint16_t id;			/* identification */
	int16_t off;			/* fragment offset field */
	uint8_t ttl;			/* time to live */
	uint8_t proto;			/* protocol */
	uint16_t sum;			/* checksum */
	uint8_t src[4];			/* source address */
	uint8_t dst[4];			/* destination address */
};

struct udp_hdr {
	uint16_t src_port;
	uint16_t dst_port;
	uint16_t udp_len;
	uint16_t udp_chksum;
};

struct udp_packet {
	struct ip_hdr iphdr;
	struct udp_hdr udphdr;
};

union packet_u {
	struct ip_hdr ip;
	struct udp_packet udp;
};

struct eth_frame_s {
	struct eth_hdr ethernet;
	union packet_u payload;
};

union eth_buffer {
	struct eth_frame_s cooked_data;
	uint8_t raw_data[ETH_LEN];
};

struct application {
	uint16_t id;
	uint8_t controle;
	uint8_t padd;
	uint8_t data[512];
	uint16_t app_chksum;
};