/*
Spoofing a simple ICMP request
Done By : Dhruv Verma (C) 2017 gothinski
*/

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include "checksum.c"

void send_raw_ip_packet(struct ipheader* ip) {
	struct sockaddr_in dest_info;
	int enable = 1;
	
	//creat a raw network socket and set its options
	int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));
	
	//provide information about destination
	dest_info.sin_family = AF_INET;
	dest_info.sin_addr = ip->iph_destip;

	//sed the packet out
	printf("Sending spoofer ICMP packer ...\n");
	sendto(sock, ip, ntohs(ip->iph_len), 0, (struct sockaddr*)&dest_info, sizeof(dest_info));
	close(sock);
	}


int main() {
	//***************************//
	
	char buffer[PACKET_LEN];
	memset(buffer, 0, PACKET_LEN);
	
	//filling in ICMP
 
	struct icmpheader *icmp = (struct icmpheader *) (buffer + sizeof(struct ipheader));
	icmp->icmp_type = 8;

	icmp->icmp_chksum = 0;
	icmp->icmp_chksum = in_cksum((unsigned short *)icmp, sizeof(struct icmpheader));
	
	struct ipheader *ip = (struct ipheader *) buffer;
	ip->iph_ver = 4;
	ip->iph_ihl = 5;
	ip->iph_ttl = 20;
	ip->iph_sourceip.s_addr = inet_addr("10.0.2.6");
	ip->iph_destip.s_addr = inet_addr("31.13.71.36");
	ip->iph_protocol = IPPROTO_ICMP;
	//ip->iph_len = htons(sizeof;
	ip->iph_len = htons(sizeof(struct ipheader) + sizeof(struct icmpheader));
	send_raw_ip_packet(ip);
	return 0;
	}






