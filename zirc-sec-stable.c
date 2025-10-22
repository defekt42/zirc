/*
* Secure IRC Client (Libevent + TLS) - ZIRC-SEC with OpenBSD HARDENING
*
* This version incorporates all previous fixes (linker, auto-join, security, color fix)
* and adds OpenBSD's critical pledge() and unveil() system calls to sandbox the process.
* It includes strong log file permission control (fchmod 0600) and cleaner sandboxing logic.
*
* FIXED: unveil() is now called AFTER initial connection to avoid blocking DNS/SSL access
*
* The hardening calls are made portable using stubs and ENOSYS checks,
* allowing the code to compile and run on other Unix-like systems.
*
* Compile on OpenBSD (requires linking libutil for pledge/unveil):
* cc -o zirc-sec zirc-sec.c \
* -lssl -lcrypto -levent_openssl -levent_core -levent_extra -levent \
* -lm -lpthread -lutil \
* -O2 -Wall -Wextra -Wpedantic \
* -fstack-protector-strong \
* -fPIE -pie \
* -Wformat -Wformat-security
*
* Compile on Linux/other Unix (no -lutil needed):
* gcc -o zirc-sec zirc-sec.c \
* -lssl -lcrypto -levent_openssl -levent_core -levent_extra -levent \
* -lm -lpthread \
* -O2 -Wall -Wextra -Wpedantic \
* -fstack-protector-strong \
* -fPIE -pie \
* -Wformat -Wformat-security
*
* Usage:
* ./zirc-sec <server> <port> <nick> [nickserv_pass or 'prompt']
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <signal.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/types.h>

/* --- OpenBSD Portability Stubs --- */
#ifdef __OpenBSD__
 #include <unistd.h>
#else
 #include <errno.h>
 #ifndef ENOSYS
 #define ENOSYS 38 /* Define ENOSYS if not defined by errno.h on all systems */
 #endif

 /* Provide weak stubs for sandboxing calls on non-OpenBSD systems */
 static inline int pledge(const char *promises, const char *paths) {
      (void)promises; (void)paths; errno = ENOSYS; return -1;
 }
 static inline int unveil(const char *path, const char *perm) {
      (void)path; (void)perm; errno = ENOSYS; return -1;
 }
#endif


#include <termios.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509_vfy.h>
#include <openssl/crypto.h>

#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>
#include <event2/buffer.h>
#include <event2/util.h>

/* --- Constants and Global State --- */
#define PING_INTERVAL_SEC 8
#define BUFFER_SIZE 4096
#define LOGFILE "irc.log"
#define LOG_MAX_SIZE (5 * 1024 * 1024) // 5 MB Log Rotation Limit
#define CHANNEL "##"
#define IRC_MAX_MSG_LEN 512
#define MAX_RECONNECT_DELAY 60
#define MAX_RECONNECT_ATTEMPTS 10
#define CONNECTION_TIMEOUT_SEC 10

/* Libevent/OpenSSL global handles */
static SSL_CTX *ctx = NULL;
static struct event_base *base = NULL;
static struct bufferevent *bev = NULL;
static struct bufferevent *stdin_bev = NULL;
static struct event *ping_timer = NULL;

/* Connection State */
static char server_host[256];
static char server_port[16];
static int reconnect_delay = 2;
static int reconnect_attempts_count = 0;

/* IRC State */
static int reg = 0;
static int joined = 0;
static char nick[64];
static char *password = NULL;
static size_t password_len = 0;
static FILE *logfp = NULL;

/* ANSI color codes for terminal output */
#define ANSI_RESET "\x1b[0m"
#define ANSI_BOLD "\x1b[1m"
#define ANSI_ITALIC "\x1b[3m"
#define ANSI_UNDER "\x1b[4m"
#define ANSI_BLINK "\x1b[5m"
#define ANSI_LIGHT_BLUE "\x1b[94m"
#define ANSI_BRIGHT_YELLOW "\x1b[93m"
#define ANSI_MAGENTA "\x1b[35m"
#define ANSI_BRIGHT_RED "\x1b[91m"
#define ANSI_BRIGHT_GREEN "\x1b[92m"

/* --- Custom IRC Color Mapping (FIXED) --- */
static const int irc_to_256[] = {
    15,     /* 0 - white */
    0,      /* 1 - black */
    19,     /* 2 - blue (navy) */
    34,     /* 3 - green */
    196,    /* 4 - red */
    52,     /* 5 - brown/maroon */
    127,    /* 6 - purple */
    208,    /* 7 - orange */
    226,    /* 8 - yellow */
    46,     /* 9 - light green */
    51,     /* 10 - cyan (teal) */
    87,     /* 11 - light cyan */
    75,     /* 12 - light blue */
    207,    /* 13 - pink */
    244,    /* 14 - grey */
    252     /* 15 - light grey */
};


/* --- Function Prototypes --- */
static void handle_server_msg(char *line);
static void handle_user_input(char *line);
static void write_raw_line(const char *s);
static void sendln(const char *s);
static void check_and_rotate_log(void);
static void print_ts(const char *prefix, const char *msg);
static char *get_secure_password(size_t *len_out);
static void cleanup_and_exit_internal(int code);
static void cleanup_handler(void);
static int dial(const char *host, const char *port);
static void read_cb(struct bufferevent *bev_arg, void *ctx);
static void stdin_read_cb(struct bufferevent *bev_arg, void *ctx);
static void event_cb(struct bufferevent *bev_arg, short events, void *ctx);
static void ping_cb(evutil_socket_t fd, short events, void *arg);
static void reconnect_cb(evutil_socket_t fd, short events, void *arg);


/* --- Cleanup with zeroization --- */
static void cleanup_and_exit_internal(int code) {
    if (ping_timer) { event_free(ping_timer); ping_timer = NULL; }
    if (stdin_bev) { bufferevent_free(stdin_bev); stdin_bev = NULL; }
    if (bev) { bufferevent_free(bev); bev = NULL; }
    if (base) { event_base_free(base); base = NULL; }
    if (ctx) { SSL_CTX_free(ctx); ctx = NULL; }
    if (logfp) { fclose(logfp); logfp = NULL; }

    if (password && password_len) {
        OPENSSL_cleanse(password, password_len);
        free(password);
        password=NULL; password_len=0;
        fprintf(stderr, "\n" ANSI_BRIGHT_RED "*** Sensitive data cleared from memory (Zeroized)." ANSI_RESET "\n");
    }

    exit(code);
}

static void cleanup_handler(void) {
    cleanup_and_exit_internal(0);
}


/* --- Secure password prompt --- */
static char *get_secure_password(size_t *len_out) {
    struct termios old_term, new_term;
    char *p = calloc(1, BUFFER_SIZE);
    if (!p) return NULL;

    if (tcgetattr(STDIN_FILENO, &old_term) == -1) { free(p); return NULL; }
    new_term = old_term;
    new_term.c_lflag &= ~ECHO;
    new_term.c_lflag |= ECHONL;

    fprintf(stderr, "Enter NickServ password (input hidden): "); fflush(stderr);
    if (tcsetattr(STDIN_FILENO, TCSANOW, &new_term) == -1) { free(p); return NULL; }

    if (!fgets(p, BUFFER_SIZE, stdin)) {
        *len_out = 0;
        tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
        OPENSSL_cleanse(p, BUFFER_SIZE);
        free(p);
        return NULL;
    }

    tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
    size_t len = strlen(p);
    if (len > 0 && p[len-1] == '\n') { p[len-1] = '\0'; len--; }

    if (len == 0) {
        OPENSSL_cleanse(p, BUFFER_SIZE);
        free(p);
        return NULL;
    }

    *len_out = len;
    return p;
}


/* --- Reconnect with Exponential Backoff --- */
static void reconnect_cb(evutil_socket_t fd, short events, void *arg) {
    (void)fd; (void)events; (void)arg;
    reconnect_attempts_count++;
    dial(server_host, server_port);
}

static void schedule_reconnect(void) {
    if (reconnect_attempts_count >= MAX_RECONNECT_ATTEMPTS) {
        fprintf(stderr, "\n" ANSI_BRIGHT_RED "*** ERROR: Maximum reconnection attempts (%d) reached. Exiting." ANSI_RESET "\n", MAX_RECONNECT_ATTEMPTS);
        cleanup_and_exit_internal(1);
        return;
    }

    struct timeval tv = {reconnect_delay, 0};

    fprintf(stderr, "*** Reconnecting in %d seconds (Attempt %d/%d)...\n",
            reconnect_delay, reconnect_attempts_count + 1, MAX_RECONNECT_ATTEMPTS);

    if (event_base_once(base, -1, EV_TIMEOUT, reconnect_cb, NULL, &tv) < 0) {
        fprintf(stderr, "ERROR: Failed to schedule reconnect timer.\n");
        cleanup_and_exit_internal(1);
        return;
    }

    reconnect_delay = (reconnect_delay * 2 > MAX_RECONNECT_DELAY) ?
        MAX_RECONNECT_DELAY : reconnect_delay * 2;
}


/* --- Dial server securely --- */
static int dial(const char *host, const char *port) {
    struct addrinfo hints, *res;
    int s;

    fprintf(stderr, "*** Attempting to connect to %s:%s...\n", host, port);

    reg = 0;
    joined = 0;

    if (!ctx) {
        ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx) {
            fprintf(stderr, "SSL_CTX_new failed: %s\n",
                    ERR_error_string(ERR_get_error(), NULL));
            return -1;
        }

        if (SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) == 0) {
            fprintf(stderr, "SSL_CTX_set_min_proto_version failed\n");
        }

        if (SSL_CTX_set_cipher_list(ctx,
                                    "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
                                    "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
                                    "DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:"
                                    "!aNULL:!eNULL:!EXPORT:!DES:!MD5:!PSK:!RC4:!SEED") == 0)
        {
            fprintf(stderr, "SSL_CTX_set_cipher_list failed\n");
        }

        SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);
        SSL_CTX_set_options(ctx, SSL_OP_NO_RENEGOTIATION);

        SSL_CTX_set_default_verify_paths(ctx);
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &res) != 0) {
        fprintf(stderr, "getaddrinfo failed.\n");
        schedule_reconnect();
        return -1;
    }
    s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s < 0 || connect(s, res->ai_addr, res->ai_addrlen) < 0) {
        if (s >= 0) close(s);
        freeaddrinfo(res);
        fprintf(stderr, "Socket connection failed: %s\n", strerror(errno));
        schedule_reconnect();
        return -1;
    }
    freeaddrinfo(res);

    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        fprintf(stderr, "SSL_new failed: %s\n",
                ERR_error_string(ERR_get_error(), NULL));
        close(s);
        schedule_reconnect();
        return -1;
    }
    SSL_set_tlsext_host_name(ssl, host);

    X509_VERIFY_PARAM *param = SSL_get0_param(ssl);
    if (!X509_VERIFY_PARAM_set1_host(param, host, 0)) {
        fprintf(stderr, "Hostname param setup failed.\n");
        SSL_free(ssl);
        close(s);
        schedule_reconnect();
        return -1;
    }

    bev = bufferevent_openssl_socket_new(base, s, ssl,
                                         BUFFEREVENT_SSL_CONNECTING,
                                         BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
    if (!bev) {
        fprintf(stderr, "bufferevent_openssl_socket_new failed\n");
        SSL_free(ssl);
        close(s);
        schedule_reconnect();
        return -1;
    }

    struct timeval timeout_tv = {CONNECTION_TIMEOUT_SEC, 0};
    bufferevent_set_timeouts(bev, &timeout_tv, &timeout_tv);

    bufferevent_setcb(bev, read_cb, NULL, event_cb, NULL);
    bufferevent_enable(bev, EV_READ | EV_WRITE);

    fprintf(stderr, "*** Bufferevent created. Waiting for handshake...\n");

    return 0;
}

/* --- Keep-Alive Timer Callback (PING - Not logged) --- */
static void ping_cb(evutil_socket_t fd, short events, void *arg) {
    (void)fd; (void)events; (void)arg;

    // Use write_raw_line() instead of sendln() to prevent logging of periodic PINGs.
    write_raw_line("PING :keepalive");
}


/* --- Send raw line to server --- */
static void write_raw_line(const char *s) {
    char buf[BUFFER_SIZE];
    if (strlen(s) >= IRC_MAX_MSG_LEN) {
        fprintf(stderr, "*** WARNING: Message too long (%zu bytes), truncating.\n", strlen(s));
    }

    int len = snprintf(buf, sizeof(buf), "%.*s\r\n", IRC_MAX_MSG_LEN - 2, s);

    if (len > 0 && bev) {
        bufferevent_write(bev, buf, len);
    }
}

/* --- Send line to server and log (for user commands/important notices) --- */
static void sendln(const char *s) {
    write_raw_line(s);

    if (logfp) {
        // Must check/rotate log before logging anything, including commands!
        check_and_rotate_log();
        fprintf(logfp, ">>> %s\n", s);
        fflush(logfp);
    }
}


/* --- Log Rotation Function --- */
static void check_and_rotate_log(void) {
    if (!logfp) return;

    struct stat st;
    if (fstat(fileno(logfp), &st) != 0) return;

    if ((long)st.st_size >= LOG_MAX_SIZE) {
        printf(ANSI_BOLD ANSI_BRIGHT_YELLOW "*** Log file rotation triggered. Archiving %s to %s.old." ANSI_RESET "\n", LOGFILE, LOGFILE);

        fclose(logfp);

        remove(LOGFILE ".old");

        if (rename(LOGFILE, LOGFILE ".old") != 0) {
            perror("Error renaming log file for rotation");
            logfp = NULL;
            return;
        }

        logfp = fopen(LOGFILE, "a");
        if (!logfp) {
            perror("fopen logfile after rotation");
            fprintf(stderr, "*** Warning: Continuing without logging after failed rotation.\n");
        } else {
            /* ensure file is not world-readable (0600) */
            fchmod(fileno(logfp), S_IRUSR|S_IWUSR);
        }
    }
}


/* --- Utilities (Color Parsing / Sanitization) --- */
static int is_valid_char(unsigned char c) {
    /* Accept printable ASCII (0x20..0x7E) OR bytes with high-bit set (UTF-8 sequences).
        Also allow a small set of IRC control codes. */
    if (c >= 0x20 || (c & 0x80)) return 1;

    switch (c) {
        case 0x01: /* CTCP */
        case 0x02: /* bold */
        case 0x03: /* color */
        case 0x04: /* hex color extension in some clients */
        case 0x0F: /* reset */
        case 0x16: /* reverse */
        case 0x1D: /* italic */
        case 0x1F: /* underline */
            return 1;
        default:
            return 0;
    }
}


static void sanitize(char *in, size_t n) {
    for (size_t i = 0; i < n && in[i]; i++) {
        unsigned char c = in[i];
        if (!is_valid_char(c)) {
            in[i] = '?';
        }
    }
}

static void print_ts(const char *prefix, const char *msg) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timebuf[16];

    strftime(timebuf, sizeof(timebuf), "%H%M%S", tm_info);

    if (logfp) {
        check_and_rotate_log();
    }

    printf(ANSI_LIGHT_BLUE "[%s]" ANSI_RESET " %s", timebuf, prefix);

    if (logfp) {
        fprintf(logfp, "[%s] %s%s\n", timebuf, prefix, msg);
        fflush(logfp);
    }

    /* Process the message character by character for IRC codes and ANSI sequences */
    for (const char *p = msg; *p; p++) {
        unsigned char c = *p;

        switch (c) {
            case 0x02: printf(ANSI_BOLD); break;
            case 0x1D: printf(ANSI_ITALIC); break;
            case 0x1F: printf(ANSI_UNDER); break;
            case 0x16:
            case 0x0F: printf(ANSI_RESET); break;

            case 0x03:
                printf(ANSI_RESET);
                p++;

                if (*p && isdigit(*p)) {
                    int fg_color_id = *p - '0';
                    p++;
                    if (*p && isdigit(*p)) {
                        fg_color_id = fg_color_id * 10 + (*p - '0');
                        p++;
                    }

                    if (fg_color_id >= 0 && fg_color_id < 16) {
                        printf("\x1b[38;5;%dm", irc_to_256[fg_color_id]);
                    } else if (fg_color_id >= 16 && fg_color_id < 256) {
                        printf("\x1b[38;5;%dm", fg_color_id);
                    } else {
                        printf(ANSI_RESET);
                    }
                }

                if (*p == ',' && *(p+1) && isdigit(*(p+1))) {
                    p++;
                    int bg_color_id = *p - '0';
                    p++;
                    if (*p && isdigit(*p)) {
                        bg_color_id = bg_color_id * 10 + (*p - '0');
                        p++;
                    }

                    if (bg_color_id >= 0 && bg_color_id < 16) {
                        printf("\x1b[48;5;%dm", irc_to_256[bg_color_id]);
                    } else if (bg_color_id >= 16 && bg_color_id < 256) {
                        printf("\x1b[48;5;%dm", bg_color_id);
                    }
                }
                p--;
                break;

            case 0x04:
                printf(ANSI_RESET);
                for (int i=0; i<6; i++) {
                    if(*(p+1) && isxdigit(*(p+1))) p++;
                    else break;
                }
                break;

            case 0x01:
                break;

            case '\x1b':
                putchar(c);
                p++;
                if (*p == '[') {
                    putchar(*p);
                    p++;
                    const char *start = p;

                    while (*p && *p != 'm' && (isdigit(*p) || *p == ';' || *p == ':')) {
                        putchar(*p);
                        p++;
                    }

                    if (*p == 'm') {
                        putchar(*p);
                    } else {
                        p = start - 2;
                    }
                } else {
                    p--;
                }
                break;

            default:
                if (c >= 0x20 || (c & 0x80)) {
                    putchar(c);
                }
        }
    }

    printf(ANSI_RESET "\n");
}


/* --- IRC Protocol Handlers --- */
static void handle_server_msg(char *line) {
    /* Handle PING requests from server (no print/log) */
    if (strncmp(line, "PING ", 5) == 0) {
        char pong[512];
        snprintf(pong, sizeof(pong), "PONG %s", line + 5);
        write_raw_line(pong);
        return;
    }

    /* Handle PONG responses from server (no print/log) */
    if (strstr(line, " PONG ") != NULL) {
        return;
    }

    /* === ROBUST PRIVMSG HANDLER (Hostmask Fix) === */
    char *privmsg_start = strstr(line, "PRIVMSG ");
    if (privmsg_start) {
        char *prefix_line_start = strchr(line, ':');
        if (!prefix_line_start) {
            goto fall_through;
        }

        char *message_content = strrchr(line, ':');
        if (message_content) message_content++; else message_content = "(No message)";

        char *prefix_start = prefix_line_start + 1;
        char nickname[64];
        char *bang_pos = strchr(prefix_start, '!');
        size_t nick_len = bang_pos ? (size_t)(bang_pos - prefix_start) : strlen(prefix_start);

        if (!bang_pos) {
            char *space_pos = strchr(prefix_start, ' ');
            if (space_pos) nick_len = (size_t)(space_pos - prefix_start);
        }

        nick_len = nick_len < sizeof(nickname) - 1 ? nick_len : sizeof(nickname) - 1;
        strncpy(nickname, prefix_start, nick_len);
        nickname[nick_len] = '\0';

        char *target_start = privmsg_start + 8;
        char *target_end = strchr(target_start, ' ');
        char target[64];

        if (target_end) {
            size_t target_len = (size_t)(target_end - target_start);
            target_len = target_len < sizeof(target) - 1 ? target_len : sizeof(target) - 1;
            strncpy(target, target_start, target_len);
            target[target_len] = '\0';
        } else {
            strncpy(target, "UNKNOWN", sizeof(target) - 1);
            target[sizeof(target) - 1] = '\0';
        }

        int is_private_msg = (strcmp(target, nick) == 0);
        int is_action = (strlen(message_content) >= 8 && message_content[0] == '\001' &&
                         strncmp(message_content + 1, "ACTION ", 7) == 0);

        char prefix_buf[256];
        const char *display_msg = message_content;

        if (is_action) {
            display_msg = message_content + 8;
            size_t msg_len = strlen(display_msg);
            if (msg_len > 0 && display_msg[msg_len - 1] == '\001') {
                ((char*)display_msg)[msg_len - 1] = '\0';
            }
            int written = snprintf(prefix_buf, sizeof(prefix_buf), "[%s] * %s ", target, nickname);
            if (written >= (int)sizeof(prefix_buf)) {
                fprintf(stderr, "*** Warning: Prefix buffer truncated\n");
            }

        } else if (is_private_msg) {
            int written = snprintf(prefix_buf, sizeof(prefix_buf),
                                   ANSI_BOLD ANSI_BRIGHT_YELLOW
                                   "[PRIVATE MESSAGE] " ANSI_RESET "<%s>: ", nickname);
            if (written >= (int)sizeof(prefix_buf)) {
                fprintf(stderr, "*** Warning: Prefix buffer truncated\n");
            }
        } else {
            int written = snprintf(prefix_buf, sizeof(prefix_buf), "[%s] <%s>: ", target, nickname);
            if (written >= (int)sizeof(prefix_buf)) {
                fprintf(stderr, "*** Warning: Prefix buffer truncated\n");
            }
        }

        print_ts(prefix_buf, display_msg);

        return;
    }
    /* === END ROBUST PRIVMSG HANDLER === */


    /* Fallback to strtok for numerics and other standard messages */
    char line_copy[BUFFER_SIZE];
    line_copy[sizeof(line_copy) - 1] = '\0';
    snprintf(line_copy, sizeof(line_copy), "%s", line);

    char *words[10];
    int nwords = 0;
    char *tok = strtok(line_copy, " ");
    while (tok && nwords < 10) {
        words[nwords++] = tok;
        tok = strtok(NULL, " ");
    }

    if (nwords < 2) {
        goto fall_through;
    }

    /* Handle Successful Registration (001 numeric) */
    if (nwords >= 2 && strcmp(words[1], "001") == 0 && !reg) {
        reg = 1;
        printf("*** Registered with server.\n");

        if (password) {
            char identmsg[512];
            snprintf(identmsg, sizeof(identmsg), "PRIVMSG NickServ :IDENTIFY %s", password);
            write_raw_line(identmsg);

            if (logfp) {
                check_and_rotate_log();
                fprintf(logfp, ">>> PRIVMSG NickServ :IDENTIFY ******\n");
                fflush(logfp);
            }

            OPENSSL_cleanse(password, password_len);
            free(password);
            password = NULL;
            password_len = 0;

            printf("*** Sent NickServ identification (Password zeroized and hidden in log)\n");
        }

        // Auto-join is intentionally NOT here. It waits for 396.
    }

    /* Handle Cloak Confirmation (396) and Auto-Join */
    // This is the correct place to JOIN to ensure hostmask is cloaked first.
    if (nwords >= 2 && strcmp(words[1], "396") == 0 && !joined) {
        joined = 1;

        char joinbuf[256];
        snprintf(joinbuf, sizeof(joinbuf), "JOIN %s", CHANNEL);
        sendln(joinbuf);

        printf(ANSI_BOLD ANSI_BRIGHT_GREEN "*** Cloak confirmed. Joining default channel %s" ANSI_RESET "\n", CHANNEL);

        goto fall_through;
    }

    /* Filter out noise */
    if (nwords >= 2 && (strcmp(words[1], "MODE") == 0 || strcmp(words[1], "JOIN") == 0 ||
                        strcmp(words[1], "PART") == 0 || strcmp(words[1], "QUIT") == 0)) {
        return;
    }

fall_through:
    print_ts("<<< ", line);
}

static void handle_user_input(char *line) {
    if (strlen(line) > IRC_MAX_MSG_LEN - 50) {
        printf("*** Error: Input too long (%zu characters). IRC messages are limited.\n", strlen(line));
        return;
    }

    sanitize(line, strlen(line));

    if (line[0] == '/') {
        if (strcmp(line, "/quit") == 0 || strcmp(line, "/QUIT") == 0) {
            sendln("QUIT :Leaving");
            printf("*** Disconnecting...\n");
            sleep(1);
            cleanup_and_exit_internal(0);
        }
        else if (strcmp(line, "/help") == 0 || strcmp(line, "/HELP") == 0) {
            printf("\n" ANSI_BOLD "*** Available Commands:" ANSI_RESET "\n");
            printf(" " ANSI_BOLD "/JOIN #channel" ANSI_RESET " - Join a channel\n");
            printf(" " ANSI_BOLD "/MSG <nick> <message>" ANSI_RESET " - Send private message\n");
            printf(" " ANSI_BOLD "/ME <action>" ANSI_RESET " - Send action to %s\n", CHANNEL);
            printf(" " ANSI_BOLD "/QUIT" ANSI_RESET " - Disconnect and exit\n");
            printf(" " ANSI_BOLD "/HELP" ANSI_RESET " - Show this help\n");
            printf(" " ANSI_BOLD "/<raw IRC command>" ANSI_RESET " - Send raw IRC command\n");
            printf(" " ANSI_BOLD "Anything else" ANSI_RESET " - Send message to %s\n\n", CHANNEL);
        }
        else if (strncmp(line, "/MSG ", 5) == 0 || strncmp(line, "/msg ", 5) == 0) {
            char *target = line + 5;
            char *msg = strchr(target, ' ');
            if (msg) {
                *msg++ = '\0';
                char privmsg[BUFFER_SIZE];
                snprintf(privmsg, sizeof(privmsg), "PRIVMSG %s :%s", target, msg);
                sendln(privmsg);

                char echo_prefix[256];
                int written = snprintf(echo_prefix, sizeof(echo_prefix),
                                       ANSI_BOLD ANSI_BRIGHT_YELLOW
                                       "[PRIVATE MESSAGE to %s] " ANSI_RESET "<%s%s%s>: ",
                                       target, ANSI_MAGENTA, nick, ANSI_RESET);
                if (written >= (int)sizeof(echo_prefix)) {
                    fprintf(stderr, "*** Warning: Prefix buffer truncated\n");
                }
                print_ts(echo_prefix, msg);
            } else {
                printf("*** Usage: /MSG <nick> <message>\n");
            }
        }
        else if (strncmp(line, "/ME ", 4) == 0 || strncmp(line, "/me ", 4) == 0) {
            char *msg = line + 4;
            char privmsg[BUFFER_SIZE];
            snprintf(privmsg, sizeof(privmsg), "PRIVMSG %s :\001ACTION %s\001", CHANNEL, msg);
            sendln(privmsg);

            char echo_prefix[256];
            int written = snprintf(echo_prefix, sizeof(echo_prefix), "[%s] * %s%s%s ",
                                   CHANNEL, ANSI_MAGENTA, nick, ANSI_RESET);
            if (written >= (int)sizeof(echo_prefix)) {
                fprintf(stderr, "*** Warning: Prefix buffer truncated\n");
            }
            print_ts(echo_prefix, msg);
        }
        else {
            sendln(line + 1);
            print_ts("-> ", line);
        }
    } else {
        char msg[BUFFER_SIZE];
        snprintf(msg, sizeof(msg), "PRIVMSG %s :%s", CHANNEL, line);
        sendln(msg);

        char echo_prefix[256];
        int written = snprintf(echo_prefix, sizeof(echo_prefix), "[%s] <%s%s%s>: ",
                               CHANNEL, ANSI_MAGENTA, nick, ANSI_RESET);
        if (written >= (int)sizeof(echo_prefix)) {
            fprintf(stderr, "*** Warning: Prefix buffer truncated\n");
        }
        print_ts(echo_prefix, line);
    }
}


/* --- Libevent Callbacks --- */
static void read_cb(struct bufferevent *bev_arg, void *ctx) {
    (void)ctx;
    struct evbuffer *input = bufferevent_get_input(bev_arg);
    char *line;
    while ((line = evbuffer_readln(input, NULL, EVBUFFER_EOL_CRLF))) {
        handle_server_msg(line);
        free(line);
    }
}

static void stdin_read_cb(struct bufferevent *bev_arg, void *ctx) {
    (void)ctx;
    struct evbuffer *input = bufferevent_get_input(bev_arg);
    char *line;
    while ((line = evbuffer_readln(input, NULL, EVBUFFER_EOL_LF))) {
        handle_user_input(line);
        free(line);
    }
}

static void event_cb(struct bufferevent *bev_arg, short events, void *ctx) {
    (void)ctx;

    if (events & BEV_EVENT_CONNECTED) {
        SSL *ssl = bufferevent_openssl_get_ssl(bev_arg);
        if (ssl) {
            long verify = SSL_get_verify_result(ssl);
            if (verify != X509_V_OK) {
                fprintf(stderr, "\n" ANSI_BRIGHT_RED "SECURITY ERROR: TLS Certificate Verification FAILED: %s" ANSI_RESET "\n",
                        X509_verify_cert_error_string(verify));
                bufferevent_free(bev);
                bev = NULL;
                schedule_reconnect();
                return;
            }
        }

        fprintf(stderr, "*** Connection successful and certificate verified!\n");

        reconnect_delay = 2;
        reconnect_attempts_count = 0;

        if (ping_timer) {
            event_free(ping_timer);
            ping_timer = NULL;
        }
        struct timeval tv = {PING_INTERVAL_SEC, 0};
        ping_timer = event_new(base, -1, EV_PERSIST | EV_TIMEOUT, ping_cb, NULL);
        if (!ping_timer) {
            fprintf(stderr, "*** Warning: Could not create ping timer\n");
        } else {
            event_add(ping_timer, &tv);
        }

        char regbuf[256];
        snprintf(regbuf, sizeof(regbuf), "NICK %s", nick);
        sendln(regbuf);
        snprintf(regbuf, sizeof(regbuf), "USER %s 0 * :%s", nick, nick);
        sendln(regbuf);

    } else if (events & (BEV_EVENT_ERROR | BEV_EVENT_EOF | BEV_EVENT_TIMEOUT)) {

        if (events & BEV_EVENT_TIMEOUT) {
            fprintf(stderr, "\n*** Connection timed out.\n");
        } else if (events & BEV_EVENT_ERROR) {
            int err = EVUTIL_SOCKET_ERROR();
            fprintf(stderr, "\n*** Fatal Network Error: %s\n", evutil_socket_error_to_string(err));

            unsigned long ssl_err;
            while ((ssl_err = bufferevent_get_openssl_error(bev_arg))) {
                fprintf(stderr, "*** SSL Error: %s\n", ERR_error_string(ssl_err, NULL));
            }
        } else if (events & BEV_EVENT_EOF) {
            fprintf(stderr, "\n*** Server closed connection (EOF).\n");
        }

        if (ping_timer) {
            event_free(ping_timer);
            ping_timer = NULL;
        }

        bufferevent_free(bev);
        bev = NULL;

        schedule_reconnect();
    }
}


/* --- Main --- */
int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <server> <port> <nick> [nickserv_pass or 'prompt']\n", argv[0]);
        fprintf(stderr, "\nExamples:\n");
        fprintf(stderr, " %s irc.libera.chat 6697 mynick\n", argv[0]);
        fprintf(stderr, " %s irc.libera.chat 6697 mynick prompt\n", argv[0]);
        fprintf(stderr, " %s irc.libera.chat 6697 mynick mypassword\n", argv[0]);
        return 1;
    }

    if (!OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL)) {
        fprintf(stderr, "OpenSSL init failed\n");
        return 1;
    }
    signal(SIGPIPE, SIG_IGN);
    atexit(cleanup_handler);

    const char *server = argv[1];
    const char *port = argv[2];

    if (strlen(argv[3]) > (sizeof(nick) - 1)) {
        fprintf(stderr, "Error: Nickname too long. Max length is %zu bytes.\n", sizeof(nick) - 1);
        return 1;
    }

    strncpy(server_host, server, sizeof(server_host) - 1);
    server_host[sizeof(server_host) - 1] = '\0';
    strncpy(server_port, port, sizeof(server_port) - 1);
    server_port[sizeof(server_port) - 1] = '\0';
    strncpy(nick, argv[3], sizeof(nick) - 1);
    nick[sizeof(nick) - 1] = '\0';

    if (argc >= 5) {
        if (strcmp(argv[4], "prompt") == 0) {
            password = get_secure_password(&password_len);
            if (!password) {
                fprintf(stderr, "Failed to read password.\n");
                return 1;
            }
        } else {
            fprintf(stderr, "\n" ANSI_BRIGHT_RED "╔═══════════════════════════════════════════════════════════╗\n");
            fprintf(stderr, "║ ⚠️  SECURITY WARNING ⚠️  ║\n");
            fprintf(stderr, "╚═══════════════════════════════════════════════════════════╝" ANSI_RESET "\n");
            fprintf(stderr, ANSI_BRIGHT_YELLOW "Password entered on command line is visible in process lists!\n" ANSI_RESET);
            fprintf(stderr, ANSI_BOLD "Recommended:" ANSI_RESET " Use " ANSI_BOLD "'prompt'" ANSI_RESET " for secure input:\n");
            fprintf(stderr, " $ %s %s %s %s " ANSI_BOLD "prompt" ANSI_RESET "\n\n", argv[0], argv[1], argv[2], argv[3]);
            fprintf(stderr, ANSI_BRIGHT_RED "Continuing in 3 seconds..." ANSI_RESET "\n");
            sleep(3);

            if (strlen(argv[4]) >= BUFFER_SIZE) {
                fprintf(stderr, "Error: NickServ password too long.\n");
                return 1;
            }
            password = strdup(argv[4]);
            if (!password) {
                fprintf(stderr, "Error: Memory allocation failed for password.\n");
                return 1;
            }
            password_len = strlen(password);
        }
    }

    /* --- Open log file early and set permissions (but don't unveil yet) --- */
    logfp = fopen(LOGFILE, "a");
    if (logfp) {
        // Set log file permissions immediately upon creation/open to 0600
        if (fchmod(fileno(logfp), S_IRUSR|S_IWUSR) == -1) {
            perror("fchmod logfile");
        }
    } else {
        perror("fopen logfile");
        fprintf(stderr, "*** Warning: Continuing without logging.\n");
    }

    base = event_base_new();
    if (!base) {
        fprintf(stderr, "Could not initialize libevent!\n");
        return 1;
    }

    if (evutil_make_socket_nonblocking(STDIN_FILENO) < 0) {
        fprintf(stderr, "*** Warning: Failed to make STDIN non-blocking. Continuing anyway.\n");
    }

    stdin_bev = bufferevent_socket_new(base, STDIN_FILENO, BEV_OPT_DEFER_CALLBACKS);
    if (!stdin_bev) {
        fprintf(stderr, "Failed to set up stdin buffer event.\n");
        return 1;
    }
    bufferevent_setcb(stdin_bev, stdin_read_cb, NULL, NULL, NULL);
    bufferevent_enable(stdin_bev, EV_READ);

    printf("\n");
    printf(ANSI_BOLD ANSI_BRIGHT_YELLOW "═══════════════════════════════════════════════════════════\n" ANSI_RESET);
    printf(ANSI_BOLD " ZIRC-SEC v1.2 (OpenBSD Hardened TLS Client) \n" ANSI_RESET);
    printf(ANSI_BOLD ANSI_BRIGHT_YELLOW"═══════════════════════════════════════════════════════════\n" ANSI_RESET);
    printf("\n");
    printf(ANSI_BOLD "Security Features Enabled:\n" ANSI_RESET);
    printf(" ✓ TLS Encryption (OpenSSL)\n");
    printf(" ✓ Password Zeroization\n");
    printf(" ✓ Input Validation (UTF-8 Compatible!)\n");
    printf(" ✓ Log File Permissions (0600) & Rotation (Max %ld MB)\n", (long)LOG_MAX_SIZE / 1024 / 1024);
    printf(" ✓ CORRECTED 256-Color Support\n");

    /* --- Establish initial connection BEFORE applying unveil() --- */
    if (dial(server_host, server_port) < 0) {
        fprintf(stderr, "Initial connection setup failed.\n");
        return 1;
    }

    /* --- NOW apply OpenBSD hardening AFTER connection is established --- */
    int sandboxing_enabled = 0;

    /* Apply unveil() to restrict filesystem access */
    if (logfp) {
        // Unveil the log file with read, create, and write permissions
        if (unveil(LOGFILE, "rcw") == 0) {
            sandboxing_enabled = 1;
        } else if (errno != ENOSYS) {
            perror("unveil logfile");
        }

        // Unveil the backup log file
        if (unveil(LOGFILE ".old", "rcw") == 0) {
            sandboxing_enabled = 1;
        } else if (errno != ENOSYS) {
            perror("unveil logfile.old");
        }

        // Lock down the entire filesystem to only the unveiled paths
        if (sandboxing_enabled && unveil(NULL, NULL) == -1) {
            if (errno != ENOSYS) {
                perror("unveil lock");
                cleanup_and_exit_internal(1);
            }
            sandboxing_enabled = 0; // Failed to lock
        }
    }

    /* Apply pledge() to restrict system calls */
    if (pledge("stdio inet fattr rpath wpath tty proc", NULL) == -1) {
        if (errno == ENOSYS) {
            // Non-OpenBSD system, sandboxing not available
        } else {
            perror("pledge");
            cleanup_and_exit_internal(1);
        }
    } else {
        sandboxing_enabled = 1; // Pledge succeeded
    }

    // Print final sandboxing status
    if (sandboxing_enabled) {
        printf(ANSI_BOLD ANSI_BRIGHT_GREEN " ✓ OpenBSD Sandboxing Enabled (pledge/unveil)\n" ANSI_RESET);
    } else {
        fprintf(stderr, ANSI_BOLD ANSI_BRIGHT_RED " ✗ OpenBSD Sandboxing Not Available/Failed. Code running UNSANDBOXED.\n" ANSI_RESET);
    }

    printf("\n");
    printf(ANSI_BOLD "Connected as: " ANSI_MAGENTA "%s" ANSI_RESET "\n", nick);
    printf(ANSI_BOLD "Default channel: " ANSI_RESET "%s\n", CHANNEL);
    printf("\n");
    printf(ANSI_BOLD "Quick Start:\n" ANSI_RESET);
    printf(" " ANSI_BOLD "/HELP" ANSI_RESET " - Show all commands\n");
    printf(" " ANSI_BOLD "/QUIT" ANSI_RESET " - Disconnect\n");
    printf(" Type anything - Send to %s\n", CHANNEL);
    printf("\n");
    printf(ANSI_BOLD ANSI_LIGHT_BLUE "═══════════════════════════════════════════════════════════\n" ANSI_RESET);
    printf("\n");

    fprintf(stderr, "*** Entering event loop (Sandboxing status displayed above)...\n");
    event_base_dispatch(base);

    fprintf(stderr, "*** Event loop exited.\n");
    cleanup_and_exit_internal(0);

    return 0;
}
