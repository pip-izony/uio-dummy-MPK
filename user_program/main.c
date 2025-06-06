#define _GNU_SOURCE
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAXIMUM_NUM_PKEY 16

int dummy_pkey_mprotect(void *addr, size_t len, int permission, int pkey) {
    int ret;
    char buf[16];
    int fd = open("/proc/uio-dummy", O_RDWR);
    snprintf(buf, sizeof(buf), "%d", permission);
    ssize_t wlen = write(fd, buf, strlen(buf));

    ret = pkey_mprotect(addr, len, permission, pkey);
    if (ret == -1) {
        printf("[uio user] pkey_mprotect failed!\n");
        exit(1);
    }
    return ret;
}

int main(int argc, char *argv[]) {
    int count = 0;
    int fd;
    int pkey, status;
    int permission;
    void *buf;
    size_t length = 16 * 1024;
    char spinner[] = {'|', '/', '-', '\\'};

    if (argc < 2) {
        printf("Usage: sudo ./user_program <permission>\n");
        return EXIT_FAILURE;
    }
    
    permission = atoi(argv[1]);

    /* mapping with kernel memory */
    fd = open("/dev/uio0", O_RDWR);
    if (fd < 0) {
        printf("[uio user] open error\n");
        return EXIT_FAILURE;
    }

    /* Allocate four page of memory */
    buf = mmap(NULL, length, permission, MAP_SHARED, fd, 0);
    if (buf == MAP_FAILED) {
        printf("[uio user] mmap failed!\n");
        return EXIT_FAILURE;
    }

    printf("[uio user] /dev/uio0 memory mapped at %p\n", buf);

    /* Allocate a protection key */
    pkey = pkey_alloc(0, 0);
    if (pkey == -1) {
	printf("[uio user] pkey_alloc failed!\n");
	return EXIT_FAILURE;
    }

    status = dummy_pkey_mprotect(buf, length, permission, pkey);

    status = pkey_set(pkey, 0);
    if (status == -1) {
	printf("[uio user] pkey_set failed!\n");
	return EXIT_FAILURE;
    }

    if (munmap(buf, length) < 0) {
	printf("munmap failed!\n");
        return EXIT_FAILURE;
    }

    /* write example */
    int irq_on = 1;
    ssize_t wlen = write(fd, &irq_on, sizeof(irq_on));
    printf("Write Success!\n");

    printf("Waiting...");
    while (1) {
	count++;
        printf("\b%c", spinner[count]);
        fflush(stdout);
        usleep(200000);
	count = (count + 1) % 4;
    }

    close(fd);

    return EXIT_SUCCESS;
}
