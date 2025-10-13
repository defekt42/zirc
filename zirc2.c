// zirc0.c minimal posix client
// cc -std=c11 -O2 -Wall -pedantic -D_POSIX_C_SOURCE=200809L -o zirc0 zirc0.c
// ./zirc0 nick user_name real_name irc.libera.chat 6667 "#channel" "password"

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netdb.h>
#include <termios.h>
#include <signal.h>

#define MAXLINE 512
#define HISTORY 10

/* --- Terminal raw mode --- */
static struct termios orig_term;
static void restore_term(void) { tcsetattr(STDIN_FILENO, TCSANOW, &orig_term); }
static void set_raw(void) {
    struct termios t;
    tcgetattr(STDIN_FILENO, &orig_term);
    atexit(restore_term);
    t = orig_term;
    t.c_lflag &= ~(ICANON | ECHO);
    t.c_cc[VMIN] = 1;
    t.c_cc[VTIME] = 0;
    tcsetattr(STDIN_FILENO, TCSANOW, &t);
}

/* --- Connect to IRC server --- */
static int dial(const char *h,const char *p){
    struct addrinfo hints={0},*res,*rp; int fd=-1;
    hints.ai_socktype=SOCK_STREAM;
    if(getaddrinfo(h,p,&hints,&res)) return -1;
    for(rp=res;rp;rp=rp->ai_next){
        fd=socket(rp->ai_family,rp->ai_socktype,rp->ai_protocol);
        if(fd>=0 && connect(fd,rp->ai_addr,rp->ai_addrlen)==0) break;
        if(fd>=0) close(fd),fd=-1;
    }
    freeaddrinfo(res); return fd;
}

/* --- Print with timestamp and IRC colors --- */
static void print_ts(FILE *f,const char *msg){
    char ts[32],ansi[4096]; time_t t=time(NULL);
    strftime(ts,sizeof ts,"%H:%M:%S",localtime(&t));
    size_t j=0;
    for(size_t i=0; msg[i] && j<sizeof ansi-10; i++){
        unsigned char c=msg[i];
        if(c==0x02) j+=snprintf(ansi+j,sizeof ansi-j,"\x1B[1m");
        else if(c==0x1F) j+=snprintf(ansi+j,sizeof ansi-j,"\x1B[4m");
        else if(c==0x16) j+=snprintf(ansi+j,sizeof ansi-j,"\x1B[7m");
        else if(c==0x06) j+=snprintf(ansi+j,sizeof ansi-j,"\x1B[5m");
        else if(c==0x0F) j+=snprintf(ansi+j,sizeof ansi-j,"\x1B[0m");
        else if(c==0x03){ int fg=-1,bg=-1;
            if(msg[i+1]>='0'&&msg[i+1]<='9'){ fg=msg[++i]-'0';
                if(msg[i+1]>='0'&&msg[i+1]<='9') fg=fg*10+(msg[++i]-'0'); }
            if(msg[i+1]==','){ i++; if(msg[i+1]>='0'&&msg[i+1]<='9'){ bg=msg[++i]-'0';
                if(msg[i+1]>='0'&&msg[i+1]<='9') bg=bg*10+(msg[++i]-'0'); }}
            if(fg>=0&&bg>=0) j+=snprintf(ansi+j,sizeof ansi-j,"\x1B[38;5;%dm\x1B[48;5;%dm",fg,bg);
            else if(fg>=0)   j+=snprintf(ansi+j,sizeof ansi-j,"\x1B[38;5;%dm",fg);
        } else ansi[j++]=c;
    }
    ansi[j]=0;
    printf("[%s] %s\x1B[0m\n",ts,ansi);
    if(f) fprintf(f,"[%s] %s\n",ts,msg);
}

/* --- Send line to IRC --- */
static void sendln(int fd,const char *s){
    char b[MAXLINE+3]; size_t n=strlen(s); if(n>MAXLINE) n=MAXLINE;
    memcpy(b,s,n); b[n++]='\r'; b[n++]='\n'; send(fd,b,n,0);
}

/* --- Sanitize input --- */
static void sanitize(char *in,size_t n){
    for(size_t i=0;i<n;i++){
        unsigned char c=in[i];
        if((c>=0x20&&c<=0x7E)||c=='\t'||c==0x02||c==0x1F||c==0x16||c==0x0F||c==0x06) continue;
        else if(c==0x03){ if(i+1<n && in[i+1]>='0' && in[i+1]<='9') i++;
            if(i+1<n && in[i+1]>='0' && in[i+1]<='9') i++;
            if(i+1<n && in[i+1]==',') i++;
            if(i+1<n && in[i+1]>='0' && in[i+1]<='9') i++;
            if(i+1<n && in[i+1]>='0' && in[i+1]<='9') i++;
        } else in[i]='?';
    }
}

/* --- Main --- */
int main(int ac,char **av){
    const char *nick=getenv("NICK")?getenv("NICK"):"defekt";
    const char *user=getenv("USER")?getenv("USER"):"zirc";
    const char *real=getenv("REALNAME")?getenv("REALNAME"):"zero client";
    const char *host="127.0.0.1",*port="6667";
    const char *chan=getenv("CHANNEL")?getenv("CHANNEL"):"##";
    const char *logf=getenv("LOGFILE")?getenv("LOGFILE"):"irc.log";
    const char *nspass=getenv("NICKSERV_PASS");
    if(ac>1) nick=av[1]; if(ac>2) user=av[2]; if(ac>3) real=av[3];
    if(ac>4) host=av[4]; if(ac>5) port=av[5]; if(ac>6) chan=av[6];
    if(ac>7) nspass=av[7];

    FILE *lf=fopen(logf,"a"); if(!lf) lf=stderr;
    set_raw();
    int s=dial(host,port); if(s<0) return 1;

    char buf[MAXLINE+1],line[2048],in[MAXLINE+1];
    char history[HISTORY][MAXLINE+1]={0};
    int hist_pos=0,hist_len=0,reg=0; size_t off=0;

    snprintf(buf,sizeof buf,"NICK %s",nick); sendln(s,buf);
    snprintf(buf,sizeof buf,"USER %s 0 * :%s",user,real); sendln(s,buf);

    fd_set r;
    while(1){
        FD_ZERO(&r); FD_SET(s,&r); FD_SET(0,&r);
        if(select(s+1,&r,0,0,0)<0) break;

        /* Incoming IRC messages */
        if(FD_ISSET(s,&r)){
            ssize_t n=recv(s,in,MAXLINE,0); if(n<=0) break;
            for(ssize_t i=0;i<n;i++){
                if(in[i]=='\r') continue;
                if(in[i]=='\n'){ line[off]=0;
                    if(!strncmp(line,"PING :",6)){
                        snprintf(buf,sizeof buf,"PONG :%s",line+6); sendln(s,buf);
                    } else {
                        char sender[64]="",cmd[16]="",target[64]="",*msg=NULL;
                        if(line[0]==':'){
                            char *p=strchr(line,' '); if(p){
                                size_t l=p-line-1; if(l>sizeof sender-1) l=sizeof sender-1;
                                strncpy(sender,line+1,l); sender[l]=0;
                                char *bang=strchr(sender,'!'); if(bang) *bang=0;
                                sscanf(p+1,"%15s %63s",cmd,target);
                                msg=strstr(p," :"); if(msg) msg+=2;
                            }
                        }
                        if(!strcmp(cmd,"PRIVMSG") && msg){
                            if(strcmp(sender,nick)!=0) print_ts(lf,msg);
                        } else print_ts(lf,line);

                        if(strstr(line," 001 ")){  /* successful registration */
                            reg=1;
                            sleep(5);  /* Delay before optional identify */
                            if(nspass){
                                snprintf(buf,sizeof buf,"PRIVMSG NickServ :IDENTIFY %s %s",nick,nspass);
                                sendln(s,buf);
                                sleep(5);  /* Delay before join */
                            }
                            if(chan){
                                snprintf(buf,sizeof buf,"JOIN %s",chan);
                                sendln(s,buf);
                            }
                        }
                    }
                    off=0; continue;
                }
                if(off<sizeof line-1) line[off++]=in[i];
            }
        }

        /* Outgoing user input (buffered until Enter) */
        static char inputbuf[MAXLINE+1];
        static size_t inputlen = 0;

        if (FD_ISSET(0, &r)) {
            unsigned char ch;
            ssize_t n = read(0, &ch, 1);
            if (n <= 0) break;

            if (ch == 27) { // possible escape sequence
                unsigned char seq[2];
                if (read(0, seq, 2) == 2 && seq[0] == '[') {
                    if (seq[1] == 'A' && hist_len > 0) { // up
                        hist_pos = (hist_pos - 1 + hist_len) % hist_len;
                        inputlen = strnlen(history[hist_pos], MAXLINE);
                        strncpy(inputbuf, history[hist_pos], inputlen);
                        inputbuf[inputlen] = 0;
                        printf("\r> %s \033[K", inputbuf);
                        fflush(stdout);
                        continue;
                    } else if (seq[1] == 'B' && hist_len > 0) { // down
                        hist_pos = (hist_pos + 1) % hist_len;
                        inputlen = strnlen(history[hist_pos], MAXLINE);
                        strncpy(inputbuf, history[hist_pos], inputlen);
                        inputbuf[inputlen] = 0;
                        printf("\r> %s \033[K", inputbuf);
                        fflush(stdout);
                        continue;
                    }
                }
                continue;
            }

            if (ch == 127 || ch == '\b') { // backspace
                if (inputlen > 0) inputbuf[--inputlen] = 0;
                printf("\r> %s \033[K", inputbuf);
                fflush(stdout);
                continue;
            }

            if (ch == '\n' || ch == '\r') { // enter pressed
                inputbuf[inputlen] = 0;
                printf("\n");
                sanitize(inputbuf, inputlen);
                if (inputlen && reg) {
                    strncpy(history[hist_len % HISTORY], inputbuf, MAXLINE);
                    history[hist_len % HISTORY][MAXLINE] = 0;
                    hist_len++;
                    hist_pos = hist_len % HISTORY;

                    if (inputbuf[0] == '/') {
                        memmove(inputbuf, inputbuf + 1, inputlen);
                        if (!strncmp(inputbuf, "MSG ", 4)) {
                            char *sp = strchr(inputbuf + 4, ' ');
                            if (sp && sp[1]) {
                                *sp = 0;
                                snprintf(buf, sizeof buf, "PRIVMSG %s :%s", inputbuf + 4, sp + 1);
                            } else continue;
                        } else snprintf(buf, sizeof buf, "%s", inputbuf);
                    } else snprintf(buf, sizeof buf, "PRIVMSG %s :%s", chan, inputbuf);
                    sendln(s, buf);
                }
                inputlen = 0;
                inputbuf[0] = 0;
                printf("> ");
                fflush(stdout);
                continue;
            }

            if (inputlen < MAXLINE - 1 && ch >= 0x20 && ch <= 0x7E) {
                inputbuf[inputlen++] = ch;
                inputbuf[inputlen] = 0;
                printf("\r> %s", inputbuf);
                fflush(stdout);
            }
        }

    }
    if(lf) fclose(lf);
    close(s);
    return 0;
}
