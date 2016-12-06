all: rsniffer

rsniffer: rsniffer.c
	gcc -lpcap rsniffer.c -o rsniffer

clean:
	rm rsniffer
