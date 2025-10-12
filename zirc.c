// zirc_plus.c — BSD-friendly hybrid server-only echo IRC client
// Build: cc -Wall -O2 -std=c99 zirc_plus.c -lssl -lcrypto -lreadline -o zirc_plus

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <netdb.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <signal.h>
#include <errno.h>

#define MAXLINE 512
#define HISTORY_SIZE 10
#define MAXNICKS 64
#define PING_INTERVAL_SECONDS 60
#define RECONNECT_INTERVAL 10 // Seconds to wait between reconnect attempts
#define CTCP_ACTION_START "\x01" "ACTION "
#define CTCP_ACTION_END "\x01"
#define LINEPRINT_SUFFIX_CHAR '\\'

// --- Connection and TLS State ---
static SSL *ssl = NULL;
static SSL_CTX *ctx = NULL;
static int s = -1; // Socket descriptor: -1 when disconnected
static time_t last_connect_attempt = 0; // Timestamp of the last connection try

// --- Client Configuration and State ---
static char nick[64] = "defekt";
static char user[64] = "zirc-0.2";
static char channel[64] = "";
static const char *nspass = NULL;

static char nicks[MAXNICKS][64];
static size_t nnicks = 0;

static char bufln[4096] = {0};
static int local_channel_echo = 1;

// --- Global Connection Parameters for Reconnect ---
static char global_host[MAXLINE] = {0};
static char global_port[8] = {0};
static int global_use_tls = 0;

// --- Struct for Parsed IRC Message (Robust Parsing) ---
typedef struct {
    char prefix[128]; // Nick!User@Host or ServerName
    char command[16];
    char arg1[128];   // Target (channel or nick) - always the first middle parameter
    char *message;    // The trailing parameter (starts with ':')
    char *full_line;  // Pointer to the start of the original line buffer
} IrcMessage;

/* ===== Utility ===== */
static void die(const char *msg){ perror(msg); exit(1); }

// Print messages without corrupting the readline prompt
static void print_status(const char *fmt, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    // Save, clear line, print, restore
    rl_save_prompt();
    rl_message("\33[2K\r"); // Move to start of line and erase
    printf("*** %s\n", buf);
    rl_restore_prompt();
    rl_on_new_line();
    rl_redisplay();
}


// sendln is memory-safe using vsnprintf and bounds checking
static void sendln(int s, const char *fmt, ...) {
    char buf[MAXLINE+3];
    va_list ap;
    va_start(ap, fmt);
    int len = vsnprintf(buf, sizeof buf-2, fmt, ap);
    va_end(ap);

    if (len > 0 && len < sizeof(buf) - 2) {
        buf[len] = '\r';
        buf[len+1] = '\n';
        buf[len+2] = 0;
        len += 2;
    } else {
        return; // Handle overflow safely
    }

    if(ssl) SSL_write(ssl, buf, len);
    else send(s, buf, len, 0);
}

// Optimization: Use snprintf for guaranteed null termination and bounds checking.
static void add_nick(const char *n) {
    for(size_t i = 0; i < nnicks; i++)
        if(!strcmp(nicks[i], n)) return;
    if(nnicks < MAXNICKS) {
        snprintf(nicks[nnicks], sizeof(nicks[0]), "%s", n);
        nnicks++;
    }
}

// Timestamp generation utility
static void get_timestamp(char *ts_buf, size_t buf_size) {
    time_t t = time(NULL);
    struct tm *tm = localtime(&t);
    strftime(ts_buf, buf_size, "%H:%M", tm);
}

/* ===== Nick Completion ===== */
static char *nick_generator(const char *text, int state) {
    static size_t i;
    if(!state) i = 0;
    // NOTE: strdup allocates memory that needs to be freed. Readline typically
    // handles freeing the returned string, but this is a point of concern in
    // larger projects. We rely on readline's internal cleanup here.
    while(i < nnicks){
        const char *n = nicks[i++];
        if(strncmp(n,text,strlen(text))==0) return strdup(n);
    }
    return NULL;
}

static char **nick_completion(const char *text,int start,int end){
    (void)start; (void)end;
    return rl_completion_matches(text, nick_generator);
}

/* ===== ANSI 256-color ===== */
// print_colored relies on a large stack buffer (8KB) but is otherwise safe due to bounds checking (j<sizeof ansi-10)
static void print_colored(const char *msg){
    char ansi[8192]; size_t j=0;
    for(size_t i=0; msg[i] && j<sizeof ansi-10; i++){
        unsigned char c=msg[i];
        if(c==0x02) j+=snprintf(ansi+j,sizeof ansi-j,"\x1B[1m");
        else if(c==0x1F) j+=snprintf(ansi+j,sizeof ansi-j,"\x1B[4m");
        else if(c==0x16) j+=snprintf(ansi+j,sizeof ansi-j,"\x1B[7m");
        else if(c==0x06) j+=snprintf(ansi+j,sizeof ansi-j,"\x1B[5m");
        else if(c==0x0F) j+=snprintf(ansi+j,sizeof ansi-j,"\x1B[0m");
        else if(c==0x03){
            int fg=-1,bg=-1;
            if(msg[i+1]>='0'&&msg[i+1]<='9'){ fg=msg[++i]-'0';
                if(msg[i+1]>='0'&&msg[i+1]<='9') fg=fg*10+(msg[++i]-'0'); }
            if(msg[i+1]==','){ i++; if(msg[i+1]>='0'&&msg[i+1]<='9'){ bg=msg[++i]-'0';
                if(msg[i+1]>='0'&&msg[i+1]<='9') bg=bg*10+(msg[++i]-'0'); }}
            if(fg>=0&&fg<256&&bg>=0&&bg<256) j+=snprintf(ansi+j,sizeof ansi-j,"\x1B[38;5;%dm\x1B[48;5;%dm",fg,bg);
            else if(fg>=0&&fg<256) j+=snprintf(ansi+j,sizeof ansi-j,"\x1B[38;5;%dm",fg);
        } else ansi[j++]=c;
    }
    ansi[j]=0;
    printf("%s\x1B[0m\n",ansi);
}

/* ===== IRC Connect ===== */
static int irc_connect(const char *host, const char *port, int use_tls){
    struct addrinfo hints={0}, *res, *rp;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    last_connect_attempt = time(NULL); // Record attempt time

    if(getaddrinfo(host,port,&hints,&res)!=0) {
        print_status("Error: Could not resolve hostname %s", host);
        return -1; // Return -1 on failure
    }

    int temp_s = -1;
    for(rp=res; rp; rp=rp->ai_next){
        temp_s=socket(rp->ai_family,rp->ai_socktype,rp->ai_protocol);
        if(temp_s<0) continue;
        if(connect(temp_s,rp->ai_addr,rp->ai_addrlen)==0) break;
        close(temp_s); temp_s=-1;
    }
    freeaddrinfo(res);

    if(temp_s<0) {
        print_status("Error: Failed to connect to %s:%s (%s)", host, port, strerror(errno));
        return -1;
    }

    if(use_tls){
        SSL_library_init();
        SSL_load_error_strings();
        ctx=SSL_CTX_new(TLS_client_method());
        if(!ctx) { print_status("Error: SSL_CTX_new failed."); close(temp_s); return -1; }
        ssl=SSL_new(ctx);
        SSL_set_fd(ssl,temp_s);
        if(SSL_connect(ssl)!=1){
            print_status("Error: SSL_connect failed: %s",ERR_reason_error_string(ERR_get_error()));
            SSL_free(ssl); ssl = NULL;
            // SSL_CTX cleanup is delayed until program exit.
            close(temp_s); return -1;
        }
    }
    return temp_s;
}

// Function to connect and send initial registration commands
static void irc_connect_and_register() {
    // Cleanup previous SSL connection if it existed
    if (ssl) { SSL_free(ssl); ssl = NULL; }
    if (s > 0) { close(s); s = -1; }

    print_status("Attempting connection to %s:%s via %s...", global_host, global_port, global_use_tls ? "TLS" : "TCP");
    s = irc_connect(global_host, global_port, global_use_tls);

    if (s > 0) {
        if(nspass) sendln(s,"PASS %s",nspass);
        sendln(s,"NICK %s",nick);
        sendln(s,"USER %s 0 * :%s",user,user);
        sendln(s,"JOIN %s",channel);
        print_status("Connected and initial registration sent as %s.", nick);
    } else {
        // Connection failed, s is already -1
        print_status("Connection failed. Retrying in %d seconds.", RECONNECT_INTERVAL);
    }
}

/* ===== Signal Handler for Terminal Resize ===== */
// When the terminal size changes, libreadline needs to be notified to re-calculate dimensions.
static void handle_resize(int sig) {
    (void)sig; // Silence unused warning
    rl_resize_terminal();
}

/* ===== IRC Message Parser (Robust) ===== */
static int parse_irc_line(char *line, IrcMessage *msg) {
    if (!line || !*line) return 0;

    memset(msg, 0, sizeof(IrcMessage));
    msg->full_line = line;
    char *p = line;
    char *token;

    // 1. Parse optional prefix
    if (p[0] == ':') {
        p++; // Skip ':'
        token = strsep(&p, " ");
        if (token) strncpy(msg->prefix, token, sizeof(msg->prefix) - 1);
    }

    // 2. Parse command (MANDATORY)
    token = strsep(&p, " ");
    if (!token) return 0;
    strncpy(msg->command, token, sizeof(msg->command) - 1);

    // 3. Parse arguments and trailing parameter (message)
    while (p && *p) {
        // Skip leading spaces
        while (*p == ' ') p++;
        if (!*p) break;

        if (p[0] == ':') {
            // Trailing parameter found: this is the message
            msg->message = p + 1; // Content starts after ':'
            break;
        }

        // Middle parameter
        token = strsep(&p, " ");

        if (token) {
            // Only store arg1 (the target/channel), ignore subsequent middle parameters for simplicity
            if (!msg->arg1[0]) {
                strncpy(msg->arg1, token, sizeof(msg->arg1) - 1);
            }
        }
    }

    if (!msg->command[0]) return 0;
    return 1;
}

/* ===== Handle IRC Line (Refactored) ===== */
static void handle_irc_line(char *line){
    // Clear the current input line before printing the message
    rl_save_prompt();
    rl_message("\33[2K\r");

    IrcMessage msg;
    if (!parse_irc_line(line, &msg)) goto restore_prompt;

    // PING response is handled correctly:
    if(!strcmp(msg.command, "PING")){
        sendln(s,"PONG :%s", msg.message ? msg.message : ""); // PONG uses the message as token
        goto restore_prompt;
    }

    if(!strcmp(msg.command,"PRIVMSG") && msg.message){
        char sender[64] = "";
        sscanf(msg.prefix,"%63[^!]",sender);
        add_nick(sender);
        char ts[32];
        get_timestamp(ts, sizeof(ts));

        char *target = msg.arg1;
        int is_private_message = (strcmp(target, nick) == 0);

        // --- CTCP Action check ---
        if (strstr(msg.message, CTCP_ACTION_START) == msg.message && strlen(msg.message) > strlen(CTCP_ACTION_START) && msg.message[strlen(msg.message)-1] == CTCP_ACTION_END[0]) {
            char *action_content = msg.message + strlen(CTCP_ACTION_START);
            size_t content_len = strlen(action_content);
            action_content[content_len-1] = '\0'; // Temporarily null terminate before printing

            // Display action message: [TS] * Nick Action Message
            printf("\x1B[90m[\x1B[0m%s\x1B[90m]\x1B[0m * %s ",ts,sender);
            print_colored(action_content);

            action_content[content_len-1] = CTCP_ACTION_END[0]; // Restore
        } else {
            // Regular PRIVMSG
            if (is_private_message) {
                // Display PM: [TS] {Sender} Message (ANSI color 31 is red)
                printf("[%s] \x1B[31m{%s}\x1B[0m ",ts,sender);
            } else {
                // Display Channel Message: [TS] <Sender> Message
                printf("\x1B[90m[\x1B[0m%s\x1B[90m]\x1B[0m <%s> ",ts,sender);
            }
            print_colored(msg.message);
        }
    }

    // JOIN uses the trailing message as the channel name
    if(!strcmp(msg.command, "JOIN") && msg.message){
        snprintf(channel, sizeof(channel), "%s", msg.message);
        print_status("Joined %s", channel);
    }

    // RPL_TOPIC (332)
    if(!strcmp(msg.command, "332") && msg.message)
        print_status("Topic for %s: %s", msg.arg1, msg.message);

    // Catch generic numeric replies and print them for debugging/status (e.g. 001, 353, etc.)
    else if (msg.command[0] >= '0' && msg.command[0] <= '9') {
        printf("--- %s %s :%s\n", msg.command, msg.arg1, msg.message ? msg.message : "");
    }

    // RPL_WELCOME (001) is often used to send NickServ identify
    if(!strcmp(msg.command, "001") && nspass)
        sendln(s,"PRIVMSG NickServ :IDENTIFY %s",nspass);

restore_prompt:
    // After the message has printed, restore the saved input and redraw the prompt cleanly.
    rl_restore_prompt();
    rl_on_new_line();
    rl_redisplay();
}

/* ===== Readline Callback ===== */
static void handle_input(char *input_from_rl){
    if(!input_from_rl){ sendln(s,"QUIT :defektive connection"); exit(0); }
    if(!*input_from_rl){ free(input_from_rl); return; }

    if (s < 0) {
        print_status("Error: Not connected to server. Use /connect <host> <port> or wait for reconnect.");
        free(input_from_rl);
        rl_redisplay();
        return;
    }

    char *current_input = input_from_rl;

    char *action_to_display = NULL;
    char *msg_to_display = NULL;

    // --- Start Multi-line Input Logic ---
    size_t input_len = strlen(current_input);
    if (input_len > 0 && current_input[input_len - 1] == LINEPRINT_SUFFIX_CHAR) {
        current_input[input_len - 1] = '\0';

        size_t bufln_len = strlen(bufln);
        if (bufln_len + input_len - 1 < sizeof(bufln) - 1) {
            strncat(bufln, current_input, sizeof(bufln) - bufln_len - 1);
        } else {
            print_status("Error: Multi-line command buffer overflow. Clearing buffer.");
            bufln[0] = '\0';
        }

        free(current_input);
        rl_replace_line("", 0);
        rl_on_new_line();
        rl_redisplay();
        return;
    }

    if (*bufln) {
        size_t final_len = strlen(bufln) + input_len;

        if (final_len < sizeof(bufln)) {
            strncat(bufln, current_input, sizeof(bufln) - strlen(bufln) - 1);

            free(current_input);
            current_input = strdup(bufln);
            bufln[0] = '\0';

            if (!current_input) die("strdup");
        } else {
            print_status("Error: Final merged command too long (%zu > 4096). Command aborted.", final_len);
            bufln[0] = '\0';
            free(current_input);
            rl_replace_line("", 0);
            rl_on_new_line();
            rl_redisplay();
            return;
        }
    }
    // --- End Multi-line Input Logic ---

    if(*current_input) add_history(current_input);
    if(history_length>HISTORY_SIZE) remove_history(0);

    rl_replace_line("", 0);
    rl_on_new_line();
    printf("\33[2K\r"); fflush(stdout);

    char buf[MAXLINE];

    // =======================================================

    if(*current_input=='/'){
        char *action_msg = NULL;

        // Handle /me command (IRC ACTION)
        if (!strncmp(current_input, "/me ", 4) && strlen(current_input) > 4) {
            action_msg = current_input + 4;
        }
        // Handle /m alias (IRC ACTION)
        else if (!strncmp(current_input, "/m ", 3) && strlen(current_input) > 3) {
            action_msg = current_input + 3;
        }

        if (action_msg) {
            snprintf(buf,sizeof buf,"PRIVMSG %s :%s%s%s",channel, CTCP_ACTION_START, action_msg, CTCP_ACTION_END);
            sendln(s,buf);
            action_to_display = action_msg; // Capture content for optional local echo
        }
        // Handle other IRC commands
        else {
            memmove(current_input,current_input+1,strlen(current_input));

            // --- ADD /MSG COMMAND (Private Message) ---
            if (!strncmp(current_input, "msg ", 4)) {
                char target[64];
                char *message_start = strchr(current_input + 4, ' ');

                if (message_start && message_start[1]) {
                    size_t target_len = message_start - (current_input + 4);

                    if (target_len > 0 && target_len < sizeof(target)) {
                        snprintf(target, sizeof(target), "%.*s", (int)target_len, current_input + 4);
                        char *message = message_start + 1;

                        snprintf(buf, sizeof buf, "PRIVMSG %s :%s", target, message);
                        sendln(s, buf);

                        free(current_input);
                        rl_redisplay();
                        return;
                    } else {
                        print_status("Error: Invalid DM target or format.");
                    }
                } else {
                    print_status("Error: Usage: /msg <target> <message>");
                }
            }
            // --- END /MSG COMMAND ---

            // Any other command (e.g. JOIN, NICK, etc.) is sent directly
            else {
                snprintf(buf,sizeof buf,"%s",current_input);
                sendln(s,buf);
            }
        }
    } else {
        // Plain channel message: send it
        snprintf(buf,sizeof buf,"PRIVMSG %s :%s",channel,current_input);
        sendln(s,buf);
        msg_to_display = current_input; // Capture content for optional local echo
    }

    // Perform local echo for channel messages and actions.
    if (local_channel_echo && (action_to_display || msg_to_display)) {
        char ts[32];
        get_timestamp(ts, sizeof(ts));

        // Use distinct colors for self-echo to differentiate from server echo (green/blue combo)
        if (action_to_display) {
            printf("[%s] * \x1B[34m%s\x1B[0m ",ts,nick);
            print_colored(action_to_display);
        } else if (msg_to_display) {
            printf("\x1B[90m[\x1B[0m%s\x1B[90m]\x1B[0m \x1B[90m<\x1B[34m%s\x1B[90m>\x1B[0m ",ts,nick);
            print_colored(msg_to_display);
        }
    }

    free(current_input);
    rl_redisplay();
}

/* ===== Main ===== */
int main(int argc,char **argv){
    if(argc<5){ print_status("usage: %s <host> <port> <nick> <channel> [password]",argv[0]); exit(1);}

    // Store connection args globally
    snprintf(global_host, sizeof(global_host), "%s", argv[1]);
    snprintf(global_port, sizeof(global_port), "%s", argv[2]);
    global_use_tls = (strcmp(global_port,"6697")==0 || strcmp(global_port,"9999")==0); // Assume 6697/9999 are common TLS ports

    // Store user args
    snprintf(nick, sizeof(nick), "%s", argv[3]);
    snprintf(channel, sizeof(channel), "%s", argv[4]);

    nspass=(argc>5)?argv[5]:NULL;

    using_history();
    stifle_history(HISTORY_SIZE);
    rl_attempted_completion_function = nick_completion;
    rl_callback_handler_install("> ", handle_input);

    if (signal(SIGWINCH, handle_resize) == SIG_ERR) {
        perror("signal");
    }

    char inbuf[MAXLINE+1], linebuf[MAXLINE+1]; size_t off=0;

    // --- Initial connection attempt ---
    irc_connect_and_register();

    // --- Main Loop with Reconnect Logic ---
    while(1){
        if (s < 0) {
            time_t now = time(NULL);

            // Check if enough time has passed since the last attempt
            if (now - last_connect_attempt >= RECONNECT_INTERVAL) {
                irc_connect_and_register();
            } else {
                // Wait until the next attempt time
                sleep(RECONNECT_INTERVAL - (now - last_connect_attempt) > 0 ?
                         RECONNECT_INTERVAL - (now - last_connect_attempt) : 1);
            }
            if (s < 0) continue; // If connection still failed, loop again
        }

        // Inner loop: Active connection handling
        while(s > 0){
            fd_set r;
            FD_ZERO(&r);
            FD_SET(s,&r);
            FD_SET(0,&r);
            int maxfd = (s>0)?s:0;

            struct timeval tv;
            tv.tv_sec = PING_INTERVAL_SECONDS;
            tv.tv_usec = 0;

            int ret = select(maxfd+1,&r,NULL,NULL,&tv);

            if(ret<0) {
                if (errno == EINTR) {
                    continue;
                }
                break; // Break on fatal error
            }

            // Client-side keep-alive PING
            if (ret == 0) {
                sendln(s, "PING :%ld", (long)time(NULL));
                continue;
            }

            if(FD_ISSET(s,&r)){
                // Use a non-blocking read operation with SSL/recv
                ssize_t n = ssl ? SSL_read(ssl,inbuf,MAXLINE) : recv(s,inbuf,MAXLINE,0);

                if(n<=0){
                    print_status("Connection to server lost (%s). Retrying...",
                                 n == 0 ? "Server closed connection" : strerror(errno));
                    if(ssl){ SSL_free(ssl); ssl = NULL; }
                    close(s);
                    s = -1;
                    break; // Break the inner loop for reconnection attempt
                }

                for(ssize_t i=0;i<n;i++){
                    if(inbuf[i]=='\r') continue;
                    if(inbuf[i]=='\n'){
                        linebuf[off]=0;
                        if(off) handle_irc_line(linebuf);
                        off=0;
                        continue;
                    }
                    if(off < sizeof linebuf-1) linebuf[off++] = inbuf[i];
                }
            }

            if(FD_ISSET(0,&r))
                rl_callback_read_char();
        }

        // If s == -1, the inner loop broke due to disconnection, outer loop continues to retry.
        if (s > 0) break; // If s > 0 here, it broke due to a non-recoverable select error.
    }

    rl_callback_handler_remove();
    if(ssl){ SSL_shutdown(ssl); SSL_free(ssl); SSL_CTX_free(ctx); }
    if (s > 0) close(s);
    return 0;
}
