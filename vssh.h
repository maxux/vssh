#ifndef VSSH_H
    #define VSSH_H

    #include <libssh2.h>

    typedef struct ssh_t {
        // internals context
        int sockfd;
        LIBSSH2_SESSION *session;
        LIBSSH2_CHANNEL *channel;
        LIBSSH2_AGENT *agent;

        // host information
        char *host;
        int port;

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
        char *command;

        // keep a list of buffers for stdout
        // this avoid to keep a single buffer to enlarge each time
        char **stdout;
        size_t *stdlens;
        size_t stdouts;
        size_t stdalloc;

        // exit status
        int exitcode;
        char *exitsignal;

        // statistics
        size_t bytesread;

    } ssh_command_t;

    typedef void (*ssh_execute_cb_t)(ssh_t *, ssh_command_t *cmd, char *buffer, size_t length);
    typedef void (*ssh_scp_cb_t)(ssh_t *, char *source, char *destination, size_t xfer, size_t length);

    void ssh_error(ssh_t *ssh);
    char *ssh_error_str(ssh_t *ssh);
    int ssh_error_set(ssh_t *ssh, char *comment, int value);
    int ssh_error_network_set(ssh_t *ssh, char *comment, int error, int value);
    int ssh_error_custom_set(ssh_t *ssh, char *comment, char *error, int value);
    void ssh_diep(ssh_t *ssh);

    ssh_t *ssh_initialize();
    void ssh_free(ssh_t *ssh);
    int ssh_connect(ssh_t *ssh, char *hostname, char *port);

    void ssh_session_disconnect(ssh_t *ssh);
    int ssh_handshake(ssh_t *ssh);

    void ssh_fingerprint_dump(ssh_t *ssh);
    char *ssh_fingerprint_hex(ssh_t *ssh);

    int ssh_authenticate_agent(ssh_t *ssh, char *username);
    int ssh_authenticate_password(ssh_t *ssh, char *username, char *password);
    int ssh_authenticate_kb_interactive(ssh_t *ssh, char *username, char *password);

    ssh_command_t *ssh_execute(ssh_t *ssh, char *command);
    ssh_command_t *ssh_execute_callback(ssh_t *ssh, char *command, ssh_execute_cb_t cb);
    char *ssh_command_stdout_get(ssh_command_t *command);

    int ssh_file_download(ssh_t *ssh, char *remotepath, char *localpath);
    int ssh_file_upload(ssh_t *ssh, char *localfile, char *remotefile);

    int ssh_file_download_progress(ssh_t *ssh, char *remotepath, char *localpath, ssh_scp_cb_t progress);
    int ssh_file_upload_progress(ssh_t *ssh, char *localfile, char *remotefile, ssh_scp_cb_t progress);

#endif
