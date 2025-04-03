#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ether.h>

/* Ethernet header */
struct ethheader {
	  u_char  ether_dhost[6]; /* destination host address */
	  u_char  ether_shost[6]; /* source host address */
	  u_short ether_type;     /* protocol type (IP, ARP, RARP, etc) */
};

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

/* TCP Header */
struct tcpheader {
    u_short tcp_sport;               /* source port */
    u_short tcp_dport;               /* destination port */
    u_int   tcp_seq;                 /* sequence number */
    u_int   tcp_ack;                 /* acknowledgement number */
    u_char  tcp_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->tcp_offx2 & 0xf0) >> 4)
    u_char  tcp_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short tcp_win;                 /* window */
    u_short tcp_sum;                 /* checksum */
    u_short tcp_urp;                 /* urgent pointer */
};

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                              const u_char *packet)
{
  struct ethheader *eth = (struct ethheader *)packet;
  if(packet == NULL){
	  fprintf(stderr, "Error : NULL packet received\n");
	  return;
  }
  struct ipheader * ip = (struct ipheader *)(packet + sizeof(struct ethheader));
  struct tcpheader * tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip->iph_ihl * 4);

  if (ntohs(eth->ether_type) == 0x0800 && ip->iph_protocol == 6) { // 0x0800 is IP type
  if (ntohs(tcp->tcp_sport) != 80 && ntohs(tcp->tcp_dport) != 80) return; 
	
    printf("      ethernet header src mac: %s\n", ether_ntoa((struct ether_addr *)eth->ether_shost));   
    printf("      ethernet header dst mac: %s\n", ether_ntoa((struct ether_addr *)eth->ether_dhost)); 

    printf("             IP Header src ip: %s\n", inet_ntoa(ip->iph_sourceip));   
    printf("             IP Header dst ip: %s\n", inet_ntoa(ip->iph_destip)); 

    printf("          TCP Header src port: %d\n", ntohs(tcp->tcp_sport));
    printf("          TCP Header dst port: %d\n", ntohs(tcp->tcp_dport));

    /* determine protocol */
    switch(ip->iph_protocol) {                                 
        case IPPROTO_TCP:
            printf("   Protocol: TCP\n");
            break;
        case IPPROTO_UDP:
            printf("   Protocol: UDP\n");
            return;
        case IPPROTO_ICMP:
            printf("   Protocol: ICMP\n");
            return;
        default:
            printf("   Protocol: others\n");
            return;
    }

    int data_offset = sizeof(struct ethheader) + ip->iph_ihl * 4 + (tcp->tcp_offx2 >> 4) * 4;
    const unsigned char *payload = packet + data_offset;
    int payload_size = header->caplen - data_offset;

    if (payload_size != 0) {
	    printf("              HTTP Data : ");
	    for (int i = 0; i < payload_size; i++) {
		    if(i == 50) break;
		    char c = payload[i];
		    if(c >= 0x20 && c <= 0x7E) {
			    putchar(c);
		    } else {
			    putchar('.');
		    }
      }	
	    printf("\n");
    } else {
	    printf("nop");
    }
  }
} 

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "tcp";
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC with name enp0s3
  handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
  if(handle == NULL){
	  fprintf(stderr, "couldn't open : %s\n", errbuf);
	  return 1;
  }

  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);
  if (pcap_setfilter(handle, &fp) !=0) {
      pcap_perror(handle, "Error:");
      exit(EXIT_FAILURE);
  }

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle);   //Close the handle
  return 0;
}
