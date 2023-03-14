#include <libssh2.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <ctype.h>

typedef struct ssh_t {
    // internals context
    int sockfd;
    LIBSSH2_SESSION *session;
    LIBSSH2_CHANNEL *channel;
    LIBSSH2_AGENT *agent;

    // host information
    const char *host;
    const int port;

    const char *fingerprint;
    size_t fingerlength;

    // user settings
    char *username;
    char *password;

    // statistics
    size_t bytesread;

    // error handling
    const char *comment;
    const char *info;

} ssh_t;

typedef struct ssh_command_t {
    const char *command;

    // output buffer FIXME
    char *stdout;

    // exit status
    int exitcode;
    char *exitsignal;

    // statistics
    size_t bytesread;

} ssh_command_t;

void ssh_error(ssh_t *ssh) {
    fprintf(stderr, "[-] ssh: %s: %s\n", ssh->comment, ssh->info);
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

    if(!(ssh->session = libssh2_session_init())) {
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

    libssh2_session_free(ssh->session);
    free(ssh->username);
    free(ssh);
}

int ssh_connect(ssh_t *ssh, char *hostname, char *port, char *username) {
    struct addrinfo hints;
    struct addrinfo *sinfo;
    int status;

    memset(&hints, 0, sizeof(hints));

    if((status = getaddrinfo(hostname, port, &hints, &sinfo)) != 0)
        return ssh_error_network_set(ssh, "getaddrinfo", status, 1);

    // note: using sinfo->ai_protocol doesn't works reliably on macos

    if((ssh->sockfd = socket(sinfo->ai_family, sinfo->ai_socktype, 0)) < 0) {
        return ssh_error_set(ssh, "socket", 1);
    }

    if(connect(ssh->sockfd, sinfo->ai_addr, sinfo->ai_addrlen) != 0) {
        return ssh_error_set(ssh, "connect", 1);
    }

    freeaddrinfo(sinfo);

    // link username to context
    ssh->username = strdup(username);

	return 0;
}

int ssh_handshake(ssh_t *ssh) {
    int fingertype;

    if(libssh2_session_handshake(ssh->session, ssh->sockfd) < 0)
        return 1;

    if(!(ssh->fingerprint = libssh2_session_hostkey(ssh->session, &ssh->fingerlength, &fingertype)))
        return 1;

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

int ssh_authenticate_agent(ssh_t *ssh) {
    struct libssh2_agent_publickey *identity, *prev_identity = NULL;
    int rc;

    printf("[+] initializing ssh-agent connection\n");
    ssh->agent = libssh2_agent_init(ssh->session);

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
            printf("[+] authenticating %s with %s succeed\n", ssh->username, identity->comment);
            return 0;
        }

        printf("[+] authenticating %s with %s failed\n", ssh->username, identity->comment);

        prev_identity = identity;
    }

    printf("[+] no identities could authenticate user %s\n", ssh->username);
    return 2;
}

int ssh_authenticate_password(ssh_t *ssh, char *password) {
    if(libssh2_userauth_password(ssh->session, ssh->username, password) != 0)
        return 1;

    return 0;
}

int ssh_command_read(ssh_t *ssh, ssh_command_t *command) {
    int length;
    char buffer[8192];

    while(1) {
        if((length = libssh2_channel_read(ssh->channel, buffer, sizeof(buffer))) <= 0)
            return 0;

        command->bytesread += length;
        ssh->bytesread += length;

        fprintf(stderr, "----------------------------\n");
        fwrite(buffer, length, 1, stdout);
        fflush(stdout);
        fprintf(stderr, "----------------------------\n");
    }
}

int ssh_execute(ssh_t *ssh, char *command) {
    int rc;

    if((ssh->channel = libssh2_channel_open_session(ssh->session)) == NULL)
        return ssh_error_custom_set(ssh, "session", "could not create session channel", 1);

    if((rc = libssh2_channel_exec(ssh->channel, command)) != 0)
        return 1;

    ssh_command_t cmd = {.bytesread = 0};
    ssh_command_read(ssh, &cmd);

    int exitcode = 127;
    rc = libssh2_channel_close(ssh->channel);

    char *exitsignal;

    if(rc == 0) {
        exitcode = libssh2_channel_get_exit_status(ssh->channel);

        libssh2_channel_get_exit_signal(ssh->channel, &exitsignal, NULL, NULL, NULL, NULL, NULL);
    }

    printf("Exit: %d, signal: %s\n", exitcode, exitsignal);

    libssh2_channel_free(ssh->channel);

    return 0;
}
int main(int argc, char *argv[]) {
    char *host = "2a02:::";
    // char *host = "10.241.0.67";
    char *port = "22";
    char *user = "root";

    printf("[+] initializing ssh wrapper\n");
    ssh_t *ssh = ssh_initialize();

    printf("[+] initializing connection: %s:%s\n", host, port);
    if(ssh_connect(ssh, host, port, user))
        ssh_diep(ssh);

    printf("[+] connection established\n");

    printf("[+] initializing ssh handshake\n");
    if(ssh_handshake(ssh))
        ssh_diep(ssh);

    printf("[+] ssh session established\n");

    printf("[+] host fingerprint: ");
    ssh_fingerprint_dump(ssh);
    printf("\n");

    printf("[+] authenticating using ssh-agent\n");
    if(ssh_authenticate_agent(ssh))
       return 1;

    // printf("[+] authenticating using password\n");
    // char *password = "xxxx";
    // if(ssh_authenticate_password(ssh, password))
    //    return 1;

    ssh_execute(ssh, "uptime");
    ssh_execute(ssh, "uname -a");
    ssh_execute(ssh, "false");

    libssh2_session_disconnect(ssh->session, "Normal shutdown, see ya soon");

    close(ssh->sockfd);
    ssh_free(ssh);

    // libssh2_exit();

    return 0;
}
