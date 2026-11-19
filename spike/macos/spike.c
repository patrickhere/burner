// burner on libkrun, spike: boot burner's kernel and image with its own guest
// init and the same four disks as firecracker. no network: TSI is disabled.
//   spike KERNEL ROOTFS SCRATCH JOB RESULT CONSOLE CMDLINE
// CONSOLE is serial or virtio
#include <libkrun.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <termios.h>
#include <unistd.h>
#include <util.h>

static int master;
// copies what the guest writes to its console onto our stdout, byte for byte
static void *pump(void *arg) {
    char buf[65536];
    ssize_t n;
    while ((n = read(master, buf, sizeof buf)) > 0) write(1, buf, n);
    return NULL;
}

#define CHECK(x) do { int r = (x); if (r < 0) { fprintf(stderr, "spike: %s = %d\n", #x, r); return 1; } } while (0)

int main(int argc, char **argv) {
    if (argc != 8) { fprintf(stderr, "usage: spike KERNEL ROOTFS SCRATCH JOB RESULT serial|virtio CMDLINE\n"); return 2; }
    CHECK(krun_set_log_level(1));
    int ctx = krun_create_ctx();
    CHECK(ctx);
    CHECK(krun_set_vm_config(ctx, 1, 512));
    CHECK(krun_disable_implicit_vsock(ctx));
    CHECK(krun_disable_implicit_console(ctx));
    if (strcmp(argv[6], "serial") == 0)
        CHECK(krun_add_serial_console_default(ctx, 0, 1));
    else if (strcmp(argv[6], "pty") == 0) {
        int slave;
        struct termios t;
        if (openpty(&master, &slave, NULL, NULL, NULL) < 0) { perror("openpty"); return 1; }
        tcgetattr(slave, &t);
        cfmakeraw(&t);
        tcsetattr(slave, TCSANOW, &t);
        pthread_t th;
        pthread_create(&th, NULL, pump, NULL);
        CHECK(krun_add_virtio_console_default(ctx, slave, slave, slave));
    } else if (strcmp(argv[6], "port") == 0) {
        int cid = krun_add_virtio_console_multiport(ctx);
        CHECK(cid);
        CHECK(krun_add_console_port_inout(ctx, cid, "burner", 0, 1));
    } else
        CHECK(krun_add_virtio_console_default(ctx, 0, 1, 2));
    CHECK(krun_set_kernel(ctx, argv[1], KRUN_KERNEL_FORMAT_RAW, NULL, argv[7]));
    CHECK(krun_add_disk2(ctx, "rootfs", argv[2], KRUN_DISK_FORMAT_RAW, true));
    CHECK(krun_add_disk2(ctx, "scratch", argv[3], KRUN_DISK_FORMAT_RAW, false));
    CHECK(krun_add_disk2(ctx, "job", argv[4], KRUN_DISK_FORMAT_RAW, true));
    CHECK(krun_add_disk2(ctx, "result", argv[5], KRUN_DISK_FORMAT_RAW, false));
    CHECK(krun_start_enter(ctx));
    return 1;
}
