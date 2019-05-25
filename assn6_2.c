#include <stdio.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#define LINE_LEN 16

// IP header structure
struct ip *iph;

// TCP header structure
struct tcphdr *tcph;

// UDP header structure
struct udphdr *udph;

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
	
	
	int total_ftp_packet = 0;
	int total_ftp_byte = 0;
	int total_ssh_packet = 0;
	int total_ssh_byte = 0;
	int total_dns_packet = 0;
	int total_dns_byte = 0;
	int total_http_packet = 0;
	int total_http_byte = 0;
	
	if(argc != 2)
	{	
		printf("usage: %s filename", argv[0]);
		return -1;

	}
	
	/* Open the capture file */
	if ((fp = pcap_open_offline(argv[1],			// name of the device
						 errbuf						// error buffer
						 )) == NULL)
	{
		fprintf(stderr,"\nUnable to open the file %s.\n", argv[1]);
		return -1;
	}
	
	/* Retrieve the packets from the file */
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
			printf("IP packet\n");
        	// TCP packet
        	if (iph->ip_p == IPPROTO_TCP)
        	{
        		tcph = (struct tcphdr*)((u_char*)iph + iph->ip_hl * 4);
        	    total_tcp_packet++;
        	    total_tcp_byte += header->len;
        	    printf("TCP packet\n");
        	    
        	    if (tcph->th_sport == 20480 || tcph->th_dport == 20480)
				{
        	    	total_http_packet++;
        	    	total_http_byte += header->len;
        	    	printf("HTTP packet_\n");
				}
				else if (tcph->th_sport == 5120 || tcph->th_dport == 5120 || tcph->th_sport == 5376 || tcph->th_dport == 5376)
				{
					total_ftp_packet++;
					total_ftp_byte += header->len;
					printf("FTP packet\n");
				}
				else if (tcph->th_sport == 5632 || tcph->th_dport == 5632)
				{
					total_ssh_packet++;
					total_ssh_byte += header->len;
					printf("SSH packet\n");
				}
				else if (tcph->th_sport == 13568 || tcph->th_dport == 13568)
				{
					total_dns_packet++;
					total_dns_byte += header->len;
					printf("DNS packet\n");
				}
        	}
			else if (iph->ip_p == IPPROTO_UDP)
			{
				udph = (struct udphdr*)((u_char*)iph + iph->ip_hl * 4);
				total_udp_packet++;
				total_udp_byte += header->len;
				printf("UDP packet\n");
				
				if (udph->uh_sport == 13568 || udph->uh_dport == 13568)
				{
					total_dns_packet++;
					total_dns_byte += header->len;
					printf("DNS packet\n");
				}
			}
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
	printf("Total FTP packets: %d, Total FTP bytes: %d\n", total_ftp_packet, total_ftp_byte);
	printf("Total SSH packets: %d, Total SSH bytes: %d\n", total_ssh_packet, total_ssh_byte);
	printf("Total DNS packets: %d, Total DNS bytes: %d\n", total_dns_packet, total_dns_byte);
	printf("Total HTTP packets: %d, Total HTTP bytes: %d\n", total_http_packet, total_http_byte);
	
	printf("Average packet size = %f bytes, Average packet inter-arrive time = %f ms\n", (float)total_byte / (float)total_packet, (float)total_time / (float)total_packet);
	
	return 0;
}

