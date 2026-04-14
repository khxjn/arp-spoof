all: arp-spoof

arp-spoof: main.o send-arp.o arp-spoof.o
	gcc -o arp-spoof main.o send-arp.o arp-spoof.o -lpcap

main.o: main.c arp-spoof.h send-arp.h struct_hdr.h
	gcc -c -o main.o main.c

send-arp.o: send-arp.c send-arp.h struct_hdr.h
	gcc -c -o send-arp.o send-arp.c

arp-spoof.o: arp-spoof.c arp-spoof.h send-arp.h struct_hdr.h
	gcc -c -o arp-spoof.o arp-spoof.c

clean:
	rm -f arp-spoof
	rm -f *.o