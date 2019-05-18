obj-m += driver.o
CC=$(CROSS_COMPILE)gcc

all:
#	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	make config_4.14.0-hyplet
	$(CC) -I /usr/src/linux-headers-4.15.0-47/include -I /usr/src/linux-headers-4.15.0-47/arch/arm64/include -c driver.c -o module/
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
