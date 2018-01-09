all: rsniffer

rsniffer: rsniffer.c
	gcc -I/usr/include/pcap rsniffer.c -o rsniffer -lpcap

clean:
	rm rsniffer
