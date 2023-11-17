#include <libssh2.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <ctype.h>
#include "vssh.h"

#ifndef NDEBUG
    #define debug printf
#else
    #define debug (void)sizeof
#endif

void ssh_error(ssh_t *ssh) {
    fprintf(stderr, "[-] ssh: %s: %s\n", ssh->comment, ssh->info);
}

char *ssh_error_str(ssh_t *ssh) {
    char buffer[1024];
    sprintf(buffer, "%s: %s", ssh->comment, ssh->info);

    return strdup(buffer);
}

// system error
int ssh_error_set(ssh_t *ssh, char *comment, int value) {
    ssh->comment = comment;
    ssh->info = strerror(errno);
    return value;
}

// network name error
int ssh_error_network_set(ssh_t *ssh, char *comment, int error, int value) {
    ssh->comment = comment;
    ssh->info = gai_strerror(error);
    return value;
}

// custom error
int ssh_error_custom_set(ssh_t *ssh, char *comment, char *error, int value) {
    ssh->comment = comment;
    ssh->info = error;
    return value;
}

void ssh_diep(ssh_t *ssh) {
    ssh_error(ssh);
    exit(EXIT_FAILURE);
}

ssh_t *ssh_initialize() {
    ssh_t *ssh;
    int value;

    if(!(ssh = calloc(sizeof(ssh_t), 1)))
        return NULL;

    if((value = libssh2_init(0)) != 0) {
        fprintf(stderr, "[-] ssh: libssh2 initialization failed [%d]\n", value);
        free(ssh);
        return NULL;
    }

    // set our ssh pointer as session abstract to access it inside callback
    if(!(ssh->session = libssh2_session_init_ex(NULL, NULL, NULL, (void *) ssh))) {
        free(ssh);
        return NULL;
    }

    return ssh;
}

void ssh_free(ssh_t *ssh) {
    if(ssh->agent) {
        libssh2_agent_disconnect(ssh->agent);
        libssh2_agent_free(ssh->agent);
    }

    close(ssh->sockfd);

    libssh2_session_free(ssh->session);
    free(ssh->username);
    free(ssh->host);
    free(ssh);
}

int ssh_connect(ssh_t *ssh, char *hostname, char *port) {
    struct addrinfo hints;
    struct addrinfo *sinfo;
    int status;

    memset(&hints, 0, sizeof(hints));

    debug("[+] connecting to ssh session\n");
    debug("[+] remote host: [%s:%s]\n", hostname, port);

    if((status = getaddrinfo(hostname, port, &hints, &sinfo)) != 0)
        return ssh_error_network_set(ssh, "getaddrinfo", status, 1);

    // note: using sinfo->ai_protocol doesn't works reliably on macos
    // if((ssh->sockfd = socket(sinfo->ai_family, sinfo->ai_socktype, 0)) < 0) {

    if((ssh->sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        return ssh_error_set(ssh, "socket", 1);
    }

    if(connect(ssh->sockfd, sinfo->ai_addr, sinfo->ai_addrlen) != 0) {
        return ssh_error_set(ssh, "connect", 1);
    }

    freeaddrinfo(sinfo);

    // keep track of host and port in context
    ssh->host = strdup(hostname);
    ssh->port = atoi(port);

	return 0;
}

void ssh_session_disconnect(ssh_t *ssh) {
    libssh2_session_disconnect(ssh->session, "Normal shutdown, see ya soon");
}

int ssh_handshake(ssh_t *ssh) {
    int fingertype;

    if(libssh2_session_handshake(ssh->session, ssh->sockfd) < 0)
        return 1;

    if(!(ssh->fingerprint = libssh2_hostkey_hash(ssh->session, LIBSSH2_HOSTKEY_HASH_SHA1)))
        return 1;

    if(ssh->fingerprint)
        ssh->fingerlength = 20; // sha-1

    return 0;
}

void ssh_fingerprint_dump(ssh_t *ssh) {
    if(ssh->fingerlength < 20) {
        printf("[unknown fingerprint length]");
        return;
    }

    printf("0x");
    for(size_t i = 0; i < 20; i++)
        printf("%02x", (unsigned char) ssh->fingerprint[i]);
}

char *ssh_fingerprint_hex(ssh_t *ssh) {
    char buffer[1024];

    if(ssh->fingerlength < 20)
        return NULL;

    sprintf(buffer, "0x");
    for(size_t i = 0; i < 20; i++)
        sprintf(buffer + (i * 2) + 2, "%02x", (unsigned char) ssh->fingerprint[i]);

    return strdup(buffer);
}

int ssh_authenticate_agent(ssh_t *ssh, char *username) {
    struct libssh2_agent_publickey *identity, *prev_identity = NULL;
    int rc;

    debug("[+] initializing ssh-agent connection\n");
    ssh->agent = libssh2_agent_init(ssh->session);
    ssh->username = strdup(username);

    if(!ssh->agent)
        return ssh_error_custom_set(ssh, "agent", "could not initialize agent support", 1);

    if(libssh2_agent_connect(ssh->agent))
        return ssh_error_custom_set(ssh, "agent", "could not connect to ssh-agent", 1);

    if(libssh2_agent_list_identities(ssh->agent))
        return ssh_error_custom_set(ssh, "agent", "could not request identities to ssh-agent", 1);

    while(1) {
        if((rc = libssh2_agent_get_identity(ssh->agent, &identity, prev_identity)) == 1)
            break;

        if(rc < 0)
            return ssh_error_custom_set(ssh, "agent", "could not obtain identity to ssh-agent", 1);

        if((rc = libssh2_agent_userauth(ssh->agent, ssh->username, identity)) == 0) {
            debug("[+] authenticating %s with %s succeed\n", ssh->username, identity->comment);
            return 0;
        }

        debug("[+] authenticating %s with %s failed\n", ssh->username, identity->comment);

        prev_identity = identity;
    }

    debug("[+] no identities could authenticate user %s\n", ssh->username);
    return 2;
}

int ssh_authenticate_password(ssh_t *ssh, char *username, char *password) {
    ssh->username = strdup(username);

    if(libssh2_userauth_password(ssh->session, ssh->username, password) != 0)
        return ssh_error_custom_set(ssh, "password", "authentication failed", 1);

    return 0;
}

static LIBSSH2_USERAUTH_KBDINT_RESPONSE_FUNC(ssh_kbi_callback) {
    ssh_t *ssh = (ssh_t *) *abstract;

    if(num_prompts == 1) {
        responses[0].text = strdup(ssh->password);
        responses[0].length = (unsigned int) strlen(ssh->password);
    }
}

int ssh_authenticate_kb_interactive(ssh_t *ssh, char *username, char *password) {
    ssh->username = strdup(username);
    ssh->password = strdup(password);

    if(libssh2_userauth_keyboard_interactive(ssh->session, ssh->username, ssh_kbi_callback) != 0)
        return ssh_error_custom_set(ssh, "keyboard-interactive", "authentication failed", 1);

    // remove password from memory
    memset(ssh->password, 0x00, strlen(password));
    free(ssh->password);
    ssh->password = NULL;

    return 0;
}

static int ssh_stdout_resize(ssh_command_t *cmd) {
    if(!(cmd->stdout = realloc(cmd->stdout, sizeof(char *) * cmd->stdouts)))
        return 1;

    if(!(cmd->stdlens = realloc(cmd->stdlens, sizeof(size_t) * cmd->stdouts)))
        return 1;

    return 0;
}

static int ssh_stdout_need_resize(ssh_command_t *cmd) {
    return (cmd->stdalloc >= cmd->stdouts - 1);
}

static int ssh_command_read(ssh_t *ssh, ssh_command_t *command, ssh_execute_cb_t cb) {
    int length;
    char buffer[8192];

    while(1) {
        if((length = libssh2_channel_read(ssh->channel, buffer, sizeof(buffer))) <= 0)
            return 0;

        command->bytesread += length;
        ssh->bytesread += length;

        // enlarge stdout buffer if not large enough
        if(ssh_stdout_need_resize(command)) {
            command->stdouts += 16;
            ssh_stdout_resize(command);
        }

        command->stdout[command->stdalloc] = malloc(length);
        command->stdlens[command->stdalloc] = length;

        memcpy(command->stdout[command->stdalloc], buffer, length);

        command->stdalloc += 1;

        if(cb)
            cb(ssh, command, buffer, length);

    }
}

static ssh_command_t *ssh_execute_callback(ssh_t *ssh, char *command, ssh_execute_cb_t cb) {
    int rc;

    if((ssh->channel = libssh2_channel_open_session(ssh->session)) == NULL) {
        ssh_error_custom_set(ssh, "session", "could not create session channel", 1);
        return NULL;
    }

    debug("[+] executing: %s\n", command);

    if((rc = libssh2_channel_exec(ssh->channel, command)) != 0)
        return NULL;

    ssh_command_t *cmd = calloc(sizeof(ssh_command_t), 1);
    if(!cmd)
        return NULL;

    cmd->stdouts = 16;
    ssh_stdout_resize(cmd);

    cmd->command = strdup(command);
    ssh_command_read(ssh, cmd, cb);

    rc = libssh2_channel_close(ssh->channel);

    if(rc == 0) {
        cmd->exitcode = libssh2_channel_get_exit_status(ssh->channel);
        libssh2_channel_get_exit_signal(ssh->channel, &cmd->exitsignal, NULL, NULL, NULL, NULL, NULL);
    }

    libssh2_channel_free(ssh->channel);

    return cmd;
}

ssh_command_t *ssh_execute(ssh_t *ssh, char *command) {
    return ssh_execute_callback(ssh, command, NULL);
}

// print buffer on the console
static void ssh_execute_stream_cb(ssh_t *ssh, ssh_command_t *command, char *buffer, size_t length) {
    fwrite(buffer, length, 1, stdout);
    fflush(stdout);
}

ssh_command_t *ssh_execute_stream(ssh_t *ssh, char *command) {
    return ssh_execute_callback(ssh, command, ssh_execute_stream_cb);
}

char *ssh_command_stdout_get(ssh_command_t *command) {
    char *output = malloc(command->bytesread);
    size_t reminder = 0;

    for(int i = 0; i < command->stdalloc; i++) {
        memcpy(output + reminder, command->stdout[i], command->stdlens[i]);
        reminder += command->stdlens[i];
    }

    return output;
}

static void ssh_scp_progress_cb(ssh_t *ssh, char *source, char *destination, size_t xfer, size_t length) {
    if(xfer == 0) {
        printf("[+] initializing transfert...\n");
        fflush(stdout);
        return;
    }

    printf("\r[+] transfert: %lu / %lu bytes [%02.0f %%]", xfer, length, ((double) xfer / length) * 100.0);

    if(xfer == length)
        printf(" done.\n");

    fflush(stdout);
}

int ssh_file_download_progress(ssh_t *ssh, char *remotepath, char *localpath, ssh_scp_cb_t progress) {
    libssh2_struct_stat fileinfo;
    ssize_t got = 0;
    int length;
    int fd;

    debug("[+] preparing to download remote file: %s -> %s\n", remotepath, localpath);

    if((ssh->channel = libssh2_scp_recv2(ssh->session, remotepath, &fileinfo)) == NULL)
        return ssh_error_custom_set(ssh, "session", "could not create scp session channel", 1);

    if((fd = creat(localpath, 0664)) < 0)
        return ssh_error_set(ssh, "open", 1);

    printf("[+] reading %lu bytes from remote host\n", fileinfo.st_size);

    while(got < fileinfo.st_size) {
        char buffer[1024];
        int amount = sizeof(buffer);

        if((fileinfo.st_size - got) < amount) {
            amount = (int)(fileinfo.st_size - got);
        }

        if((length = libssh2_channel_read(ssh->channel, buffer, amount)) < 0) {
            printf("[-] error while reading data: %d\n", length);
            break;
        }

        if(write(fd, buffer, length) != length) {
            printf("[-] write error occured locally\n");
            break;
        }

        got += length;
    }

    close(fd);
    libssh2_channel_free(ssh->channel);

    return 0;
}

int ssh_file_upload(ssh_t *ssh, char *localfile, char *remotefile) {
    struct stat sb;
    int length;
    int fd;
    int rc;

    if(stat(localfile, &sb) < 0)
        return ssh_error_set(ssh, "stat", 1);

    int mode = sb.st_mode & 0777;
    if((ssh->channel = libssh2_scp_send(ssh->session, remotefile, mode, sb.st_size)) == NULL)
        return ssh_error_custom_set(ssh, "send", "could not open scp send channel", 1);

    printf("[+] preparing to send %lu bytes (%s -> %s)\n", sb.st_size, localfile, remotefile);
    /*
    if(!channel) {
        char *errmsg;
        int errlen;
        int err = libssh2_session_last_error(session, &errmsg, &errlen, 0);
        fprintf(stderr, "Unable to open a session: (%d) %s\n", err, errmsg);
        goto shutdown;
    }
    */

    // if stat worked, should not fails
    if((fd = open(localfile, O_RDONLY)) < 0)
        return ssh_error_set(ssh, "open", 1);

    printf("[+] sending file ");
    do {
        char buffer[1024];

        printf(".");
        fflush(stdout);

        if((length = read(fd, buffer, sizeof(buffer))) <= 0)
            break;

        char *ptr = buffer;

        do {
            if((rc = libssh2_channel_write(ssh->channel, ptr, length)) < 0) {
                ssh_error_custom_set(ssh, "write", "could not write buffer to remote host", 1);
                break;
            }

            ptr += rc;
            length -= rc;

        } while(length);

        if(progress)
            progress(ssh, localfile, remotefile, sent, sb.st_size);

        sent += length;

    } while(1);

    debug(" sent.\n");
    debug("[+] waiting for scp termination\n");

    libssh2_channel_send_eof(ssh->channel);
    libssh2_channel_wait_eof(ssh->channel);
    libssh2_channel_wait_closed(ssh->channel);

    return 0;
}

void ssh_command_free(ssh_command_t *cmd) {
    for(int i = 0; i < cmd->stdalloc; i++)
        free(cmd->stdout[i]);

    free(cmd->stdlens);
    free(cmd->stdout);
    free(cmd->command);
    free(cmd->exitsignal);
    free(cmd);
}

int demo(int argc, char *argv[]) {
    char *host = "10.241.0.230";
    char *port = "22";
    // char *user = "admin";
    char *user = "root";

    if(argc > 1)
        host = argv[1];

    printf("[+] initializing ssh wrapper\n");
    ssh_t *ssh = ssh_initialize();

    printf("[+] initializing connection: %s:%s\n", host, port);
    if(ssh_connect(ssh, host, port))
        ssh_diep(ssh);

    printf("[+] connection established\n");

    printf("[+] initializing ssh handshake\n");
    if(ssh_handshake(ssh))
        ssh_diep(ssh);

    printf("[+] ssh session established\n");

    char *finger = ssh_fingerprint_hex(ssh);
    printf("[+] host fingerprint: %s\n", finger);
    free(finger);


#if 1
    printf("[+] authenticating using ssh-agent\n");
    if(ssh_authenticate_agent(ssh, user))
       return 1;
#endif

#if 0
    printf("[+] authenticating using simple password\n");
    // char *password = "admin";
    char *password = "aaaa";
    if(ssh_authenticate_password(ssh, user, password)) {
        printf("[-] authentication failed\n");
        return 1;
    }

#endif

#if 0
    printf("[+] authenticating using keyboard-interactive\n");
    char *password = "aaaa";
    if(ssh_authenticate_kb_interactive(ssh, user, password)) {
        printf("[-] authentication failed\n");
        return 1;
    }

#endif

#if 0
    ssh_execute(ssh, "/system resource print");
    ssh_execute(ssh, "/export file=zos");
    if(ssh_file_download(ssh, "zos.rsc", "/tmp/zos.rsc"))
        ssh_diep(ssh);

    printf("[+] updating configuration\n");
    system("sed s/defconf/maxux/g /tmp/zos.rsc > /tmp/zos.rsc.updated");

    if(ssh_file_upload(ssh, "/tmp/zos.rsc.updated", "zos-updated.rsc"))
        ssh_diep(ssh);

    // ssh_execute(ssh, "/import file=zos-updated.rsc");
#endif

    // ssh_file_download(ssh, "/etc/passwd");
    // ssh_file_upload(ssh, "/etc/passwd", "/tmp/passwd-scp");

    ssh_command_t *cmd = ssh_execute_stream(ssh, "dmidecode");
    if(cmd) {
        printf("<< command: %s\n", cmd->command);
        printf("<< exit code: %d\n", cmd->exitcode);
        printf("<< exit signal: %s\n", cmd->exitsignal);
        printf("<< bytes read: %ld\n", cmd->bytesread);

        char *x = ssh_command_stdout_get(cmd);
        // fwrite(x, cmd->bytesread, 1, stdout);
        free(x);
    }
    ssh_command_free(cmd);

    cmd = ssh_execute(ssh, "uname -a");
    ssh_command_free(cmd);

    cmd = ssh_execute(ssh, "false");
    ssh_command_free(cmd);

    ssh_session_disconnect(ssh);
    ssh_free(ssh);

    libssh2_exit();

    return 0;
}

#ifndef VSSH_NO_MAIN
int main(int argc, char *argv[]) {
    return demo(argc, argv);
}
#endif
