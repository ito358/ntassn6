#include <stdio.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
//#include <netinet/gtp.h>

#define LINE_LEN 16

//gtp header structure
struct gtphdr {
	__u8	flags;
	__u8	type;
	__u16	length;
	__u32	tid;
} __attribute__ ((packed));

// IP header structure
struct ip *iph;

// TCP header structure
struct tcphdr *tcph;

// UDP header structure
struct udphdr *udph;

// GTP header structure
struct gtphdr *gtph;

//HTTP header
__u64 *httph;

int main(int argc, char **argv)
{
	pcap_t *fp;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	u_int i=0;
	int res;
	
	struct ether_header *ep;
	unsigned short ether_type;
	
	int total_packet = 0;
	int total_byte = 0;
	int total_time = 0;
	
	int total_tcp_packet = 0;
	int total_tcp_byte = 0;
	int total_udp_packet = 0;
	int total_udp_byte = 0;
	int total_icmp_packet = 0;
	int total_icmp_byte = 0;
	
	int total_http_packet = 0;
	int total_http_byte = 0;
	
	if(argc != 2)
	{	
		printf("usage: %s filename", argv[0]);
		return -1;

	}
	
	
	if ((fp = pcap_open_offline(argv[1],			// name of the device
						 errbuf						// error buffer
						 )) == NULL)
	{
		fprintf(stderr,"\nUnable to open the file %s.\n", argv[1]);
		return -1;
	}
	
	
	while((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0)
	{
		const u_char* tmp_data = pkt_data;
		// read Ethernet header
    	ep = (struct ether_header *)tmp_data;
    	tmp_data += sizeof(struct ether_header);
    	
   		// protocol type 
    	ether_type = ntohs(ep->ether_type);

    	// IP type
    	if (ether_type == ETHERTYPE_IP)
		{
			iph = (struct ip *)tmp_data;
        	// TCP packet
        	if (iph->ip_p == IPPROTO_TCP)
        	{
            	total_tcp_packet++;
        		total_tcp_byte += header->len;
        	    printf("TCP packet\n");
        	}
        	// UDP packet
			else if (iph->ip_p == IPPROTO_UDP)
			{	
				/*
				udph = (struct udphdr*)(tmp_data + iph->ip_hl * 4);
				printf("IP protocol: %x, header length: %x\n", iph->ip_p, iph->ip_hl);
				gtph = (struct gtphdr*)(udph + 8);
				iph = (struct ip*)(gtph + 12);
				printf("UDP src: %x, dest: %x, length: %x, checksum: %x\n", udph->uh_sport, udph->uh_dport, udph->uh_ulen, udph->uh_sum);
				printf("GTP flag: %x, type: %x, length: %x, tid: %x\n", gtph->flags, gtph->type, gtph->length, gtph->tid);
				printf("IP protocol in GTP: %x, header length: %x\n", iph->ip_p, iph->ip_hl);
				*/
				iph = (struct ip*)(tmp_data + iph->ip_hl * 4 + 20);
				if (iph -> ip_p == IPPROTO_TCP)
				{
					tcph = (struct tcphdr*)((u_char*)iph + iph->ip_hl * 4);
					total_tcp_packet++;
        			total_tcp_byte += header->len;
        	    	printf("TCP packet_GTP\n");
        	    	/*
        	    	httph = (__u64*)((u_char*)tcph + tcph->th_off * 4 + 6);
        	    	
        	    	printf("ip header len = %x, tcp header len = %x, HTTP header = %llx\n", iph->ip_hl, tcph->th_off, *httph);
        	    	*/
        	    	printf("ip header addr = %x, tcp header addr = %x\n", *(u_char*)iph, *(u_char*)tcph);
        	    	printf("tcp sport = %d, tcp dport = %d\n", tcph->th_sport, tcph->th_dport);
        	    	if (tcph->th_sport == 20480 || tcph->th_dport == 20480){
        	    		total_http_packet++;
        	    		total_http_byte += header->len;
        	    		printf("HTTP packet_GTP\n");
					}
        	    	
				}
				else if (iph -> ip_p == IPPROTO_UDP)
				{
					total_udp_packet++;
        			total_udp_byte += header->len;
        	    	printf("UDP packet_GTP\n");
				}
				else if (iph -> ip_p == IPPROTO_ICMP)
				{
					total_icmp_packet++;
        			total_icmp_byte += header->len;
        	    	printf("ICMP packet_GTP\n");
				}
			}
			//ICMP packet
			else if (iph->ip_p == IPPROTO_ICMP)
			{
				total_icmp_packet++;
				total_icmp_byte += header->len;
				printf("ICMP packet\n");
			}
		}
		else
		{
			printf("Not IP packet\n");
		}
	
		total_packet++;
		total_byte += header->len;
		total_time += header->ts.tv_usec;
	}
	
	
	if (res == -1)
	{
		printf("Error reading the packets: %s\n", pcap_geterr(fp));
	}
	
	pcap_close(fp);
	
	printf("Total packets: %d, Total bytes: %d\n", total_packet, total_byte);
	printf("Time difference between first and last packet = %d ms\n", total_time);
	printf("Total TCP packets: %d, Total TCP bytes: %d\n", total_tcp_packet, total_tcp_byte);
	printf("Total UDP packets: %d, Total UDP bytes: %d\n", total_udp_packet, total_udp_byte);
	printf("Total ICMP packets: %d, Total ICMP bytes: %d\n", total_icmp_packet, total_icmp_byte);
	printf("Total HTTP packets: %d, Total HTTP bytes: %d\n", total_http_packet, total_http_byte);
	return 0;

}

