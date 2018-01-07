all: rsniffer

rsniffer: rsniffer.c
	gcc -I/usr/include/pcap -lpcap rsniffer.c -o rsniffer

clean:
	rm rsniffer
