#include <stdio.h>  
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>  
#include "pcap.h"  
#define MAX_ETH_FRAME 8192  
#define ERROR_FILE_OPEN_FAILED -1  
#define ERROR_MEM_ALLOC_FAILED -2  
#define ERROR_PCAP_PARSE_FAILED -3  

int main (int argc, const char * argv[])  
{  
	pcap_file_header  pfh;  
	pcap_header  ph;  
	int count=0;  
	void * buff = NULL;  
	int readSize=0;  
	int ret = 0;  
	
	FILE *fp;

	if(argc < 2){
		printf("Usage: pcaptest <filename>\n");
		return 0;
	}else{
		fp = fopen(argv[1], "rw");  
	}
	if (fp==NULL) {  
		fprintf(stderr, "Open file %s error.",argv[1]);  
		ret = ERROR_FILE_OPEN_FAILED;  
		goto ERROR;  
	}  
	fread(&pfh, sizeof(pcap_file_header), 1, fp);     
	print_pcap_file_header(&pfh);  
	//fseek(fp, 0, sizeof(pcap_file_header));  
	buff = (void *)malloc(MAX_ETH_FRAME); 
	if (buff==NULL) {  
		fprintf(stderr, "malloc memory failed.\n");  
		ret = ERROR_MEM_ALLOC_FAILED;  
		goto ERROR;  
	}
	for (count=1; ; count++) {  
		memset(buff,0,MAX_ETH_FRAME);  //init buf
		//read pcap header to get a packet  
		//get only a pcap head count .  
		readSize=fread(&ph, sizeof(pcap_header), 1, fp);  
		if (readSize<=0) {  
			break;  
		}  
		print_pcap_header(&ph);  
		  
		//get a packet contents.  
		//read ph.capture_len bytes.  
		readSize=fread(buff,1,ph.capture_len, fp);  
		if (readSize != ph.capture_len) {  
			fprintf(stderr, "pcap file parse error.\n");  
			ret = ERROR_PCAP_PARSE_FAILED;  
			goto ERROR;  
		}  
		pcap_data pd;
		pcap_packet_ana(buff,&pd);
		print_pcap(&pd);  
		printf("===count:%d,readSize:%d===\n",count,readSize);  

		if (feof(fp) || readSize <=0 ) {   
			break;  
		}  
	}  

ERROR:  
	//free  
	if (buff) {  
		free(buff);  
		buff=NULL;  
	}   
	if (fp) {  
		fclose(fp);  
		fp=NULL;  
	}     
	return ret;  
}  
