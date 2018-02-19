/*
A simple spoofing program
Done By : Dhruv Verma (C) 2017 gothinski
*/
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>

void main() {
	struct sockaddr_in dest_info;
	char *data= "Gothinski.\n";
	
	//create network socket
	int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	//provide needed information about destination
	memset((char *) &dest_info, 0, sizeof(dest_info));
	dest_info.sin_family = AF_INET;
	dest_info.sin_addr.s_addr = inet_addr("10.0.2.6");
	dest_info.sin_port = htons(9090);

	//send the packet out
	sendto(sock, data, strlen(data), 0, 
		(struct sockaddr *)&dest_info, sizeof(dest_info));
	close(sock);
	}

