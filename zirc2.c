// zirc2.c minimal posix client
// cc -std=c11 -O2 -Wall -pedantic -D_POSIX_C_SOURCE=200809L -o zirc2 zirc2.c
// ./zirc2 nick user_name real_name irc.libera.chat 6667 "#channel" "password"

#define _POSIX_C_SOURCE 200112L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <time.h>
#include <ctype.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define BUFSZ 1024

static const char *irc_colors[16] = {
    "\033[37m","\033[30m","\033[34m","\033[32m",
    "\033[31m","\033[31;1m","\033[35m","\033[33m",
    "\033[33;1m","\033[32;1m","\033[36m","\033[36;1m",
    "\033[34;1m","\033[35;1m","\033[37;1m","\033[0m"
};

static void irc_to_ansi(const char *in,char *out,size_t n){
    const char *p=in; char *q=out; size_t left=n-1;
    while(*p && left>0){
        if(*p=='\003'){ p++; int c=(*p>='0'&&*p<='9')?(*p++-'0'):0;
            if(*p>='0'&&*p<='9'){ c=c*10+(*p++-'0'); }
            if(c>=0 && c<16){ size_t l=strlen(irc_colors[c]);
                if(l<left){ memcpy(q,irc_colors[c],l); q+=l; left-=l; } }
        } else if(*p=='\002'){ const char *seq="\033[1m"; size_t l=strlen(seq);
            if(l<left){ memcpy(q,seq,l); q+=l; left-=l; } p++;
        } else if(*p=='\037'){ const char *seq="\033[4m"; size_t l=strlen(seq);
            if(l<left){ memcpy(q,seq,l); q+=l; left-=l; } p++;
        } else if(*p=='\026'){ const char *seq="\033[7m"; size_t l=strlen(seq);
            if(l<left){ memcpy(q,seq,l); q+=l; left-=l; } p++;
        } else if(*p=='\017'){ const char *seq="\033[0m"; size_t l=strlen(seq);
            if(l<left){ memcpy(q,seq,l); q+=l; left-=l; } p++;
        } else if(*p=='\006'){ const char *seq="\033[5m"; size_t l=strlen(seq);
            if(l<left){ memcpy(q,seq,l); q+=l; left-=l; } p++;
        } else { *q++=*p++; left--; }
    }
    const char *reset="\033[0m"; size_t l=strlen(reset);
    if(l<left){ memcpy(q,reset,l); q+=l; } *q=0;
}

static void print_ts(FILE *lf,const char *prefix,const char *msg){
    char buf[BUFSZ*2]; irc_to_ansi(msg,buf,sizeof buf);
    time_t t=time(NULL); struct tm *tm=localtime(&t);
    char ts[32]; strftime(ts,sizeof ts,"%H:%M:%S",tm);
    if(prefix&&*prefix) printf("[%s] %s %s\n",ts,prefix,buf);
    else printf("[%s] %s\n",ts,buf);
    fflush(stdout);
    if(lf){
        if(prefix&&*prefix) fprintf(lf,"[%s] %s %s\n",ts,prefix,msg);
        else fprintf(lf,"[%s] %s\n",ts,msg);
        fflush(lf);
    }
}

static void sendln(SSL *ssl,const char *s){
    if(!s || !*s) return;
    SSL_write(ssl,s,strlen(s));
    SSL_write(ssl,"\r\n",2);
}

int main(void){
    const char *nick=getenv("NICK")?getenv("NICK"):"your_nick";
    const char *user=getenv("USER")?getenv("USER"):"name";
    const char *real=getenv("REALNAME")?getenv("REALNAME"):"R_name";
    const char *chan=getenv("CHANNEL")?getenv("CHANNEL"):"#channel";
    const char *pass=getenv("PASS");
    const char *srv=getenv("SERVER")?getenv("SERVER"):"irc.libera.chat";
    const char *port= getenv("PORT")?getenv("PORT"):"6697";
    const char *logf=getenv("LOGFILE")?getenv("LOGFILE"):"irc.log";
    FILE *lf=fopen(logf,"a");

    SSL_library_init(); SSL_load_error_strings();
    const SSL_METHOD *meth=TLS_client_method();
    SSL_CTX *ctx=SSL_CTX_new(meth);
    if(!ctx){ ERR_print_errors_fp(stderr); exit(1); }
    SSL *ssl=SSL_new(ctx);

    struct addrinfo hints, *res;
    memset(&hints,0,sizeof hints);
    hints.ai_family=AF_UNSPEC; hints.ai_socktype=SOCK_STREAM;
    if(getaddrinfo(srv,port,&hints,&res)!=0){ perror("getaddrinfo"); exit(1); }
    int sock=socket(res->ai_family,res->ai_socktype,res->ai_protocol);
    if(sock<0){ perror("socket"); exit(1); }
    if(connect(sock,res->ai_addr,res->ai_addrlen)<0){ perror("connect"); exit(1); }
    SSL_set_fd(ssl,sock);
    if(SSL_connect(ssl)<=0){ ERR_print_errors_fp(stderr); exit(1); }

    char buf[BUFSZ],msgbuf[BUFSZ*2]; fd_set r;

    // IRC registration
    snprintf(msgbuf,sizeof msgbuf,"NICK %s",nick); sendln(ssl,msgbuf);
    snprintf(msgbuf,sizeof msgbuf,"USER %s 0 * :%s",user,real); sendln(ssl,msgbuf);
    if(pass){ snprintf(msgbuf,sizeof msgbuf,"PRIVMSG NickServ :IDENTIFY %s",pass); sendln(ssl,msgbuf); }
    snprintf(msgbuf,sizeof msgbuf,"JOIN %s",chan); sendln(ssl,msgbuf);

    while(1){
        FD_ZERO(&r); FD_SET(0,&r); FD_SET(sock,&r);
        if(select(sock+1,&r,NULL,NULL,NULL)<0) break;

        if(FD_ISSET(0,&r)){
            if(!fgets(buf,sizeof buf,stdin)) break;
            buf[strcspn(buf,"\n")] = 0;
            if(!*buf) continue;
            if(buf[0]=='/'){
                if(!strncmp(buf,"/me ",4)){
                    snprintf(msgbuf,sizeof msgbuf,"PRIVMSG %s :\001ACTION %s\001",chan,buf+4);
                    sendln(ssl,msgbuf);
                } else {
                    snprintf(msgbuf,sizeof msgbuf,"%s",buf+1); // send raw command
                    sendln(ssl,msgbuf);
                }
            } else {
                snprintf(msgbuf,sizeof msgbuf,"PRIVMSG %s :%s",chan,buf);
                sendln(ssl,msgbuf);
            }
        }

        if(FD_ISSET(sock,&r)){
            int n=SSL_read(ssl,buf,sizeof buf-1);
            if(n<=0) break;
            buf[n]=0;
            char *line=strtok(buf,"\r\n");
            while(line){
                if(!strncmp(line,"PING :",6)){
                    snprintf(msgbuf,sizeof msgbuf,"PONG %s",line+5);
                    sendln(ssl,msgbuf);
                } else {
                    char sender[64]="",target[64]="",cmd[32]="",*msg=NULL;
                    if(line[0]==':'){
                        char *sp=strchr(line,' '), *sp2;
                        if(sp){
                            size_t l=sp-line-1; if(l>sizeof sender-1) l=sizeof sender-1;
                            strncpy(sender,line+1,l); sender[l]=0;
                            char *bang=strchr(sender,'!'); if(bang) *bang=0;
                            sp2=strchr(sp+1,' ');
                            if(sp2){
                                size_t lc=sp2-sp-1; if(lc>sizeof cmd-1) lc=sizeof cmd-1;
                                strncpy(cmd,sp+1,lc); cmd[lc]=0;
                                char *sp3=strchr(sp2+1,' ');
                                if(sp3){
                                    size_t lt=sp3-sp2-1; if(lt>sizeof target-1) lt=sizeof target-1;
                                    strncpy(target,sp2+1,lt); target[lt]=0;
                                    msg=strchr(sp3+1,':'); if(msg) msg++;
                                }
                            }
                        }
                    }
                    char prefix[128];
                    if(!strcmp(cmd,"PRIVMSG") && msg){
                        if(msg[0]==1 && strncmp(msg+1,"ACTION ",7)==0){
                            snprintf(prefix,sizeof prefix,"* %s",sender);
                            print_ts(lf,prefix,msg+8);
                        } else { snprintf(prefix,sizeof prefix,"%s %s:",sender,target);
                            print_ts(lf,prefix,msg); }
                    } else if(!strcmp(cmd,"JOIN")){ snprintf(prefix,sizeof prefix,"* %s",sender);
                        print_ts(lf,prefix,"joined the channel");
                    } else if(!strcmp(cmd,"PART")){ snprintf(prefix,sizeof prefix,"* %s",sender);
                        if(msg) print_ts(lf,prefix,msg); else print_ts(lf,prefix,"left the channel");
                    } else if(!strcmp(cmd,"QUIT")){ snprintf(prefix,sizeof prefix,"* %s",sender);
                        if(msg) print_ts(lf,prefix,msg); else print_ts(lf,prefix,"quit");
                    } else print_ts(lf,"",line);
                }
                line=strtok(NULL,"\r\n");
            }
        }
    }

    if(lf) fclose(lf);
    SSL_shutdown(ssl); SSL_free(ssl); SSL_CTX_free(ctx); close(sock);
    return 0;
}
