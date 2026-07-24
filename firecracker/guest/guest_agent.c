#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <linux/reboot.h>
#include <linux/vm_sockets.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/reboot.h>
#include <sys/socket.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#define EH_VSOCK_PORT 5000
#define EH_MAX_FRAME 4096
#define EH_MAX_REQUESTS 32

static int make_directory(const char *path, mode_t mode) {
    if (mkdir(path, mode) == 0 || errno == EEXIST) return 0;
    return -1;
}

static int mount_or_present(
    const char *source,
    const char *target,
    const char *filesystem,
    unsigned long flags,
    const void *data
) {
    if (mount(source, target, filesystem, flags, data) == 0 || errno == EBUSY) return 0;
    return -1;
}

static int prepare_pid_one(void) {
    const char *credential_names[] = {
        "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
        "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "GOOGLE_APPLICATION_CREDENTIALS",
        "GITHUB_TOKEN", "CI_JOB_TOKEN", "KUBECONFIG",
    };
    size_t index;
    if (getpid() != 1 || geteuid() != 0) return -1;
    if (make_directory("/proc", 0555) != 0 || make_directory("/sys", 0555) != 0
        || make_directory("/dev", 0755) != 0 || make_directory("/scratch", 0700) != 0) return -1;
    if (mount_or_present("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) != 0) return -1;
    if (mount_or_present("sysfs", "/sys", "sysfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) != 0) return -1;
    if (mount_or_present("devtmpfs", "/dev", "devtmpfs", MS_NOSUID, "mode=0755") != 0) return -1;
    if (mount("/dev/vdb", "/scratch", "ext4", MS_NOSUID | MS_NODEV | MS_NOATIME, NULL) != 0) return -1;
    for (index = 0; index < sizeof(credential_names) / sizeof(credential_names[0]); index += 1) {
        unsetenv(credential_names[index]);
    }
    setenv("PATH", "/", 1);
    return 0;
}

static int read_exact(int fd, void *buffer, size_t length) {
    size_t offset = 0;
    while (offset < length) {
        ssize_t count = read(fd, (char *)buffer + offset, length - offset);
        if (count == 0) return 0;
        if (count < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        offset += (size_t)count;
    }
    return 1;
}

static int write_exact(int fd, const void *buffer, size_t length) {
    size_t offset = 0;
    while (offset < length) {
        ssize_t count = write(fd, (const char *)buffer + offset, length - offset);
        if (count < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        offset += (size_t)count;
    }
    return 0;
}

static int write_frame(int fd, const char *payload) {
    size_t length = strlen(payload);
    if (length == 0 || length > EH_MAX_FRAME) return -1;
    uint32_t header = htonl((uint32_t)length);
    if (write_exact(fd, &header, sizeof(header)) != 0) return -1;
    return write_exact(fd, payload, length);
}

static int authority_file_count(void) {
    const char *paths[] = {
        "/root/.ssh/id_rsa",
        "/root/.aws/credentials",
        "/var/run/secrets/kubernetes.io/serviceaccount/token",
        "/run/secrets",
        "/sys/hypervisor/metadata",
    };
    int count = 0;
    size_t index;
    for (index = 0; index < sizeof(paths) / sizeof(paths[0]); index += 1) {
        if (access(paths[index], F_OK) == 0) count += 1;
    }
    return count;
}

static int authority_environment_count(void) {
    const char *names[] = {
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AZURE_CLIENT_SECRET",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "GITHUB_TOKEN",
        "KUBECONFIG",
    };
    int count = 0;
    size_t index;
    for (index = 0; index < sizeof(names) / sizeof(names[0]); index += 1) {
        const char *value = getenv(names[index]);
        if (value != NULL && value[0] != '\0') count += 1;
    }
    return count;
}

static void handle_client(int client) {
    unsigned int requests = 0;
    struct timeval timeout = {.tv_sec = 5, .tv_usec = 0};
    setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    while (requests < EH_MAX_REQUESTS) {
        uint32_t header;
        int status = read_exact(client, &header, sizeof(header));
        if (status <= 0) return;
        uint32_t length = ntohl(header);
        if (length == 0 || length > EH_MAX_FRAME) return;
        char payload[EH_MAX_FRAME + 1];
        status = read_exact(client, payload, length);
        if (status <= 0) return;
        payload[length] = '\0';
        requests += 1;
        if (strcmp(payload, "{\042type\042:\042root_probe\042}") == 0) {
            char response[256];
            snprintf(
                response,
                sizeof(response),
                "{\042authority_environment\042:%d,\042authority_files\042:%d,\042package_manager\042:false,\042uid\042:%u}",
                authority_environment_count(),
                authority_file_count(),
                (unsigned int)geteuid()
            );
            if (write_frame(client, response) != 0) return;
        } else if (strcmp(payload, "{\042type\042:\042shutdown\042}") == 0) {
            if (write_frame(client, "{\042accepted\042:true}") != 0) return;
            shutdown(client, SHUT_WR);
            usleep(100000);
            reboot(LINUX_REBOOT_CMD_RESTART);
            return;
        } else {
            if (write_frame(client, "{\042error\042:\042unknown_message\042,\042ok\042:false}") != 0) return;
        }
    }
}

int main(void) {
    if (prepare_pid_one() != 0) return 69;
    int server = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (server < 0) return 70;
    struct sockaddr_vm address;
    memset(&address, 0, sizeof(address));
    address.svm_family = AF_VSOCK;
    address.svm_cid = VMADDR_CID_ANY;
    address.svm_port = EH_VSOCK_PORT;
    if (bind(server, (struct sockaddr *)&address, sizeof(address)) != 0) return 71;
    if (listen(server, 1) != 0) return 72;
    while (1) {
        int client = accept(server, NULL, NULL);
        if (client < 0) {
            if (errno == EINTR) continue;
            return 73;
        }
        handle_client(client);
        close(client);
    }
}
