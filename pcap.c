#include <stdio.h>  
#include<arpa/inet.h>
#include "pcap.h"  

void print_pcap_file_header(pcap_file_header *pfh){  
	if (pfh==NULL) {  
		return;  
	}  
	printf("=====================\n"  
			"magic:0x%0x\n"  
			"version_major:%u\n"  
			"version_minor:%u\n"  
			"thiszone:%d\n"  
			"sigfigs:%u\n"  
			"snaplen:%u\n"  
			"linktype:%u\n"  
			"=====================\n",  
			pfh->magic,  
			pfh->version_major,  
			pfh->version_minor,  
			pfh->thiszone,  
			pfh->sigfigs,  
			pfh->snaplen,  
			pfh->linktype);  
}  

void print_pcap_header(pcap_header *ph){  
	if (ph==NULL) {  
		return;  
	}  
	printf("=====================\n"  
			"ts.timestamp_s:%u\n"  
			"ts.timestamp_ms:%u\n"  
			"capture_len:%u\n"  
			"len:%d\n"  
			"=====================\n",  
			ph->ts.timestamp_s,  
			ph->ts.timestamp_ms,  
			ph->capture_len,  
			ph->len);  
}  

void print_ether(pcap_data* pd){
	printf("src_mac:""%02x"":""%02x"":""%02x"":""%02x"":""%02x"":""%02x""\n",
			pd->src_mac[0],pd->src_mac[1],pd->src_mac[2],pd->src_mac[3],pd->src_mac[4],pd->src_mac[5]);
	printf("des_mac:""%02x"":""%02x"":""%02x"":""%02x"":""%02x"":""%02x""\n",
			pd->des_mac[0],pd->des_mac[1],pd->des_mac[2],pd->des_mac[3],pd->des_mac[4],pd->des_mac[5]);
	if(pd->data_type==IPv4)
		printf("Type:IPv4(0x0800)\n");
	else if(pd->data_type==IPv6)
		printf("Type:IPv6(0x86dd)\n");
	else if(pd->data_type==ARP)
		printf("Type:ARP(0x0806)\n");
	else
		printf("Type:Other\n");
}

void print_ip(pcap_data* pd){
	printf("ip_head_len:%d\n",pd->ip_head_len);
	printf("src_ip:%s\n",ip_to_str(pd->src_ip));
	printf("des_ip:%s\n",ip_to_str(pd->des_ip));
	printf("TTL:%u\n",pd->time_to_live);
	if(pd->pro_type==TCP)
		printf("protocol:TCP(6)\n");
	else if(pd->pro_type==UDP)
		printf("protocol:UDP(17)\n");
	else
		printf("protocol:other\n");
}

void print_tcp(pcap_data* pd){
	printf("src_port:%d\n",pd->src_port);
	printf("des_port:%d\n",pd->des_port);
	printf("sequence number:%u\n",pd->seq);
	printf("acknowledgement number:%u\n",pd->ack);
	printf("tcp_flags:0x%02x",pd->tcp_flags);
	printf("(");
	if(pd->tcp_flags&FIN)
		printf("FIN,");
	if(pd->tcp_flags&SYN)
		printf("SYN,");
	if(pd->tcp_flags&RST)
		printf("RST,");
	if(pd->tcp_flags&PSH)
		printf("PSH,");
	if(pd->tcp_flags&ACK)
		printf("ACK,");
	if(pd->tcp_flags&URG)
		printf("URG,");
	if(pd->tcp_flags&ECE)
		printf("ECE,");
	if(pd->tcp_flags&CWR)
		printf("CWR,");
	printf("\b)\n");
	printf("winsize:%u\n",pd->winsize);
}

void print_udp(pcap_data* pd){
	printf("src_port:%d\n",pd->src_port);
	printf("des_port:%d\n",pd->des_port);
}


void print_pcap(pcap_data* pd){  
	print_ether(pd);
	if(pd->data_type!=IPv4)
		return;
	print_ip(pd);
	if(pd->pro_type==TCP)
		print_tcp(pd);
	else if(pd->pro_type==UDP)
		print_udp(pd);
	else{
		printf("\n============\n");  
		return;
	}
	printf("\n============\n");  
}


char* ip_to_str(unsigned int netp){
	struct in_addr addr;
	char* net;
	addr.s_addr=netp;
	net=inet_ntoa(addr);
	return net;
}


void pcap_ether(void* data,pcap_data* pd,int pos){
	int i;
	for(i=0;i<MAC_LEN;i++){
		pd->des_mac[i]=*((unsigned char*)data+i+pos);
	//	printf("%016llx\n",des_mac);
	}
	pos+=MAC_LEN;
	for(i=0;i<MAC_LEN;i++){
		pd->src_mac[i]=*((unsigned char*)data+pos+i);
	//	printf("%016llx\n",src_mac);
	}
	pd->data_type=ntohs(*((unsigned short*)data+MAC_LEN));
}

void pcap_ip(void* data,pcap_data* pd,int pos){
	unsigned char ip_head_len=*((unsigned char*)data+pos)&0x0f;
//	printf("ip_head:%02x\n",ip_head_len);
	pd->ip_head_len=FOUR_BYTES*ip_head_len;
	pos+=2*FOUR_BYTES;
	pd->time_to_live=*((unsigned char*)data+pos);
//	printf("ttl:%d\n",pd->time_to_live);
	pos+=ONE_BYTE;
	pd->pro_type=*((unsigned char*)data+pos);
//	printf("type:%d\n",pd->pro_type);
	pos+=ONE_BYTE+TWO_BYTES;
	int iPos=pos;
	unsigned int src_ip=0;
	unsigned int des_ip=0;
	for(pos=iPos+FOUR_BYTES-1;pos>=iPos;pos--){
		src_ip=src_ip<<8;
		src_ip+=*((unsigned char*)data+pos);
	}
	for(pos=iPos+2*FOUR_BYTES-1;pos>=iPos+FOUR_BYTES;pos--){
		des_ip=des_ip<<8;
		des_ip+=*((unsigned char*)data+pos);
	}
	pd->src_ip=src_ip;
	pd->des_ip=des_ip;
}


void pcap_tcp(void* data,pcap_data* pd,int pos){
	unsigned short src_port=0;
	unsigned short des_port=0;
	unsigned int seq=0;
	unsigned int ack=0;
	unsigned short winsize=0;
	int iPos=pos;
	for(pos;pos<iPos+TWO_BYTES;pos++){
		src_port=src_port<<8;
		src_port+=*((unsigned char*)data+pos);
	}
	for(pos;pos<iPos+FOUR_BYTES;pos++){
		des_port=des_port<<8;
		des_port+=*((unsigned char*)data+pos);
	}
	pd->src_port=src_port;
	pd->des_port=des_port;
	iPos=pos;
	for(pos;pos<iPos+FOUR_BYTES;pos++){
		seq=seq<<8;
		seq+=*((unsigned char*)data+pos);
	}
	pd->seq=seq;
//	printf("%u\n",seq);
	for(pos;pos<iPos+2*FOUR_BYTES;pos++){
		ack=ack<<8;
		ack+=*((unsigned char*)data+pos);
	}
	pd->ack=ack;
//	printf("%u\n",ack);
	pos=pos+ONE_BYTE;
	pd->tcp_flags=*((unsigned char*)data+pos);
	pos=pos+ONE_BYTE;
	iPos=pos;
	for(pos;pos<iPos+TWO_BYTES;pos++){
		winsize=winsize<<8;
		winsize+=*((unsigned char*)data+pos);
	}
	pd->winsize=winsize;
//	printf("%u\n",winsize);
}


void pcap_udp(void* data,pcap_data* pd,int pos){
	unsigned short src_port=0;
	unsigned short des_port=0;
	int iPos=pos;
	for(pos;pos<iPos+TWO_BYTES;pos++){
		src_port=src_port<<8;
		src_port+=*((unsigned char*)data+pos);
	}
	for(pos;pos<iPos+FOUR_BYTES;pos++){
		des_port=des_port<<8;
		des_port+=*((unsigned char*)data+pos);
	}
	pd->src_port=src_port;
	pd->des_port=des_port;
//	printf("src_port:%d\n",src_port);
//	printf("des_port:%d\n",des_port);
}

void pcap_packet_ana(void*data,pcap_data* pd){
	/* ethernet*/
	int iPos=0;
	pcap_ether(data,pd,iPos);
	/*ip */
	if(pd->data_type!=IPv4)
		return;
	iPos=2*MAC_LEN+TYPE_LEN;
	pcap_ip(data,pd,iPos);
	iPos=2*MAC_LEN+TYPE_LEN+pd->ip_head_len;
	if(pd->pro_type==TCP)
		pcap_tcp(data,pd,iPos);
	else if(pd->pro_type==UDP)
		pcap_udp(data,pd,iPos);
	else
		return;
}








