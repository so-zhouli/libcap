objects = main.o pcap.o  
pcaptest : $(objects)  
	gcc -g -Wall -o pcaptest  $(objects)  

main.o:pcap.h  
pcap.o:pcap.h  

.PHONY : clean  
clean :  
	rm pcaptest  $(objects)  

