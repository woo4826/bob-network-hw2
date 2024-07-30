#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <pcap.h>
#include<libnet.h>
/*
**DO NOT USE**
pcap_findalldevs, pcap_compile, 
pcap_setfilter, pcap_lookupdev, pcap_loop API
*/

void printTitle(const char* title) {
	printf("====================================\n");
	printf("%s\n", title);
	printf("====================================\n");
}
void printEthMac(struct libnet_ethernet_hdr* ethernet) {
	printTitle("Ethernet");
	int src_mac_len = sizeof(ethernet->ether_shost) / sizeof(ethernet->ether_shost[0]); 
	int dst_mac_len = sizeof(ethernet->ether_dhost) / sizeof(ethernet->ether_dhost[0]);
	printf("Src MAC : ");
	for(int i = 0; i < src_mac_len; i++) {
		printf("%02x ", ethernet->ether_shost[i]);
	}
	printf("\nDst MAC : ");
	for(int i = 0; i < dst_mac_len; i++) {
		printf("%02x ", ethernet->ether_dhost[i]);
	}
	printf("\n");
}
void printIPv4(struct libnet_ipv4_hdr* ipv4) {
	printTitle("IPv4");
	printf("Src IP : %s\n", inet_ntoa(ipv4->ip_src));
	printf("Dst IP : %s\n", inet_ntoa(ipv4->ip_dst));
}
void printTCP(struct libnet_tcp_hdr* tcp) {
	printTitle("TCP");
	printf("Src Port : %u\n", ntohs(tcp->th_sport));
	printf("Dst Port : %u\n", ntohs(tcp->th_dport));
}
void printData(const char* data, int len) {
	printTitle("Data");
	bool is_inshort = false;
	is_inshort = len > 20 ? true : false;
	int limit_len = len > 20 ? 20 : len;
	for (int i = 0; i < limit_len; i++) {
		printf("%02x ", data[i]);
		if ((i + 1) % 16 == 0)
			printf("\n");
	}
	if (is_inshort)
		printf("...more data\n");
	printf("\n");
}
void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char * packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		// if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
		// 	printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
		// 	break;
		// }

        struct libnet_ethernet_hdr* ethernet;
		struct libnet_ipv4_hdr* ipv4;
		struct libnet_tcp_hdr* tcp;
		const char* data;
		int d_len;
		
		ethernet = (struct libnet_ethernet_hdr*)packet;
		
		ipv4 = (struct libnet_ipv4_hdr*)(packet + sizeof(*ethernet));
		
		tcp = (struct libnet_tcp_hdr*)(packet + sizeof(*ipv4) + sizeof(*ipv4));
		
		data = (const char*)(packet + sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr) + sizeof(struct libnet_tcp_hdr));
		d_len = header->caplen - sizeof(struct libnet_ethernet_hdr) - sizeof(struct libnet_ipv4_hdr) - sizeof(struct libnet_tcp_hdr);
		
		printEthMac(ethernet);
		
		printIPv4(ipv4);
		
		printTCP(tcp);
		
		printData(data, d_len);
		}

	pcap_close(pcap);
}