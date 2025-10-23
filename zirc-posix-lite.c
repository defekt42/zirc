/* zirc.c Minimal POSIX IRC client with ANSI-rendered colors/blink
 * socat tcp-listen:6697 openssl-connect:irc.freenode.net:6697
 * sic -h 127.0.0.1 -p 6697 -n your-nickname
 * cc -std=c11 -O2 -Wall -pedantic -D_POSIX_C_SOURCE=200809L -o zirc zirc.c
 * Usage: ./zirc [nick] [user] [realname] [host] [port] [#channel] [nickserv_pass]
 * ./zirc your_nick zirc "not important" 127.0.0.1 6697 "##" "password"
*/
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

#define MAXLINE 512
/* Connect to IRC server */
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
/* Print with timestamp, render colors (all 256-color) and reset ANSI */
static void print_ts(FILE *f,const char *prefix,const char *msg){
    char ts[32],ansi[8192]; time_t t=time(NULL);
    strftime(ts,sizeof ts,"%H:%M:%S",localtime(&t));
    size_t j=0;
    for(size_t i=0; msg[i] && j<sizeof ansi-10; i++){
        unsigned char c=msg[i];
        if(c==0x02) j+=snprintf(ansi+j,sizeof ansi-j,"\x1B[1m");       // bold
        else if(c==0x1F) j+=snprintf(ansi+j,sizeof ansi-j,"\x1B[4m");  // underline
        else if(c==0x16) j+=snprintf(ansi+j,sizeof ansi-j,"\x1B[7m");  // reverse
        else if(c==0x06) j+=snprintf(ansi+j,sizeof ansi-j,"\x1B[5m");  // blink
        else if(c==0x0F) j+=snprintf(ansi+j,sizeof ansi-j,"\x1B[0m");  // reset
        else if(c==0x03){ // color
            int fg=-1,bg=-1;
            if(msg[i+1]>='0'&&msg[i+1]<='9'){ fg=msg[++i]-'0';
                if(msg[i+1]>='0'&&msg[i+1]<='9') fg=fg*10+(msg[++i]-'0'); }
            if(msg[i+1]==','){ i++; if(msg[i+1]>='0'&&msg[i+1]<='9'){ bg=msg[++i]-'0';
                if(msg[i+1]>='0'&&msg[i+1]<='9') bg=bg*10+(msg[++i]-'0'); }}
            if(fg>=0&&fg<256 && bg>=0 && bg<256) j+=snprintf(ansi+j,sizeof ansi-j,"\x1B[38;5;%dm\x1B[48;5;%dm",fg,bg);
            else if(fg>=0 && fg<256) j+=snprintf(ansi+j,sizeof ansi-j,"\x1B[38;5;%dm",fg);
        } else ansi[j++]=c;
    }
    ansi[j++]=0;
    printf("[%s] %s %s\x1B[0m\n",ts,prefix,ansi);
    if(f) fprintf(f,"[%s] %s %s\n",ts,prefix,msg);
}
/* IRC helpers */
static void sendln(int fd,const char *s){
    char b[MAXLINE+3]; size_t n=strlen(s); if(n>MAXLINE) n=MAXLINE;
    memcpy(b,s,n); b[n++]='\r'; b[n++]='\n'; send(fd,b,n,0);
}
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
    int s=dial(host,port); if(s<0) return 1;

    char buf[MAXLINE+1],line[2048],in[MAXLINE+1]; size_t off=0; int reg=0;
    snprintf(buf,sizeof buf,"NICK %s",nick); sendln(s,buf);
    snprintf(buf,sizeof buf,"USER %s 0 * :%s",user,real); sendln(s,buf);
    fd_set r;
    while(1){
        FD_ZERO(&r); FD_SET(s,&r); FD_SET(0,&r);
        if(select(s+1,&r,0,0,0)<0) break;
        /* incoming */
        if(FD_ISSET(s,&r)){
            ssize_t n=recv(s,in,MAXLINE,0); if(n<=0) break;
            for(ssize_t i=0;i<n;i++){
                if(in[i]=='\r') continue;
                if(in[i]=='\n'){ line[off]=0;

                    if(!strncmp(line,"PING :",6)){
                        snprintf(buf,sizeof buf,"PONG :%s",line+6);
                        sendln(s,buf);
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
                        char prefix[128];
                        if(!strcmp(cmd,"PRIVMSG") && msg){
                            if(strcmp(sender,nick)!=0){ // show only others
                                snprintf(prefix,sizeof prefix,"%s:",sender);
                                print_ts(lf,prefix,msg);
                            }
                        } else {
                            snprintf(prefix,sizeof prefix,"%s",sender[0]?sender:"*");
                            print_ts(lf,prefix,line);
                        }
                        if(strstr(line," 001 ")){ reg=1;
                            if(nspass){ snprintf(buf,sizeof buf,"PRIVMSG NickServ :IDENTIFY %s %s",nick,nspass);
                                sendln(s,buf); }
                            if(chan){ sleep(8); /* delay before join */
                                snprintf(buf,sizeof buf,"JOIN %s",chan);
                                sendln(s,buf); }
                        }
                    }
                    off=0; continue;
                }
                if(off<sizeof line-1) line[off++]=in[i];
            }
        }
        /* outgoing */
        if(FD_ISSET(0,&r)){
            ssize_t n=read(0,in,MAXLINE); if(n<=0) break;
            while(n>0&&(in[n-1]=='\n'||in[n-1]=='\r')) n--; in[n]=0;
            sanitize(in,n); if(n==0||!reg) continue;

            if(in[0]=='/'){ memmove(in,in+1,n);
                if(!strncmp(in,"MSG ",4)){ char *sp=strchr(in+4,' ');
                    if(sp&&sp[1]){ *sp=0; snprintf(buf,sizeof buf,"PRIVMSG %s :%s",in+4,sp+1); }
                    else continue;
                } else snprintf(buf,sizeof buf,"%s",in);
            } else snprintf(buf,sizeof buf,"PRIVMSG %s :%s",chan,in);
            sendln(s,buf);
        }
    }
    sendln(s, "QUIT :defektive connection: stand by...");
    if(lf) fclose(lf); close(s); return 0;
}
