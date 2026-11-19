// burner on libkrun with a network: spike.c plus a virtio-net device whose
// frames go over a unixgram socketpair to burner-macnet. TSI stays off.
//   spike-net KERNEL ROOTFS SCRATCH JOB RESULT CONSOLE CMDLINE MACNET [MACNET ARGS]
// MACNET gets "--fd N" in front of its args, N being its end of the pair
//   cc -O2 -I/opt/homebrew/opt/libkrun/include -L/opt/homebrew/opt/libkrun/lib -lkrun spike-net.c -o spike-net
//   codesign --force -s - --entitlements ent.plist spike-net
#include <libkrun.h>
#include <fcntl.h>
#include <pthread.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <termios.h>
#include <unistd.h>
#include <util.h>

extern char **environ;

static int master;
static void *pump(void *arg) {
    char buf[65536];
    ssize_t n;
    while ((n = read(master, buf, sizeof buf)) > 0) write(1, buf, n);
    return NULL;
}

#define CHECK(x) do { int r = (x); if (r < 0) { fprintf(stderr, "spike: %s = %d\n", #x, r); return 1; } } while (0)

// starts burner-macnet on one end of a fresh socketpair, returns the other.
// the child inherits only stdio and its own end, so the VM's end closing is
// something it can see
static int start_net(char **argv, int argc) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) < 0) { perror("socketpair"); return -1; }
    fcntl(sv[0], F_SETFD, FD_CLOEXEC);
    // macos defaults to a few frames of buffer and a 2k datagram cap
    int rcv = 4 << 20, snd = 64 << 10;
    setsockopt(sv[0], SOL_SOCKET, SO_RCVBUF, &rcv, sizeof rcv);
    setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &snd, sizeof snd);
    char fd[16];
    snprintf(fd, sizeof fd, "%d", sv[1]);
    char **args = calloc(argc + 3, sizeof *args);
    args[0] = argv[0];
    args[1] = "--fd";
    args[2] = fd;
    for (int i = 1; i < argc; i++) args[i + 2] = argv[i];
    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    posix_spawnattr_setflags(&attr, POSIX_SPAWN_CLOEXEC_DEFAULT);
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    for (int i = 0; i < 3; i++) posix_spawn_file_actions_addinherit_np(&fa, i);
    posix_spawn_file_actions_addinherit_np(&fa, sv[1]);
    pid_t pid;
    int e = posix_spawn(&pid, argv[0], &fa, &attr, args, environ);
    if (e != 0) { fprintf(stderr, "spike: spawn %s: %s\n", argv[0], strerror(e)); return -1; }
    fprintf(stderr, "spike: burner-macnet pid %d\n", pid);
    close(sv[1]);
    return sv[0];
}

int main(int argc, char **argv) {
    if (argc < 9) { fprintf(stderr, "usage: spike-net KERNEL ROOTFS SCRATCH JOB RESULT serial|virtio|pty CMDLINE MACNET [ARGS]\n"); return 2; }
    // before anything else is open, so the child has nothing else to inherit
    int net = start_net(argv + 8, argc - 8);
    if (net < 0) return 1;
    CHECK(krun_set_log_level(1));
    int ctx = krun_create_ctx();
    CHECK(ctx);
    CHECK(krun_set_vm_config(ctx, 1, 512));
    CHECK(krun_disable_implicit_vsock(ctx));
    CHECK(krun_disable_implicit_console(ctx));
    // burner's slot 0 mac. no offload features, so every frame is a plain
    // checksummed ethernet frame of at most 1514 bytes
    uint8_t mac[6] = {0x06, 0x00, 0xac, 0x1d, 0x00, 0x00};
    CHECK(krun_add_net_unixgram(ctx, NULL, net, mac, 0, 0));
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
