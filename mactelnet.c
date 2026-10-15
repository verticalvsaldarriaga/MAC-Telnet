/*
    Mac-Telnet - Connect to RouterOS or mactelnetd devices via MAC address
    Copyright (C) 2010, Håkon Nessjøen <haakon.nessjoen@gmail.com>

    Shameless hack by Ali Onur Uyar to add support for SSH Tunneling through
    MAC-Telnet protocol.
    Copyright (C) 2011, Ali Onur Uyar <aouyar@gmail.com>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/
#define _DEFAULT_SOURCE
#include <libintl.h>
#include <locale.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <endian.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <sys/time.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#ifdef __LINUX__
#include <linux/if_ether.h>
#endif
#include <libgen.h>
#include "md5.h"
#include "protocol.h"
#include "console.h"
#include "interfaces.h"
#include "users.h"
#include "config.h"
#include "mactelnet.h"
#include "mndp.h"


#define PROGRAM_NAME "MAC-Telnet"

#define _(String) gettext (String)

static int sockfd = 0;
static int insockfd;
static int fwdfd = 0;

static unsigned int outcounter = 0;
static unsigned int incounter = 0;
static int sessionkey = 0;
static int running = 1;

static unsigned char use_raw_socket = 0;
static unsigned char terminal_mode = 0;
static int tunnel_conn = 0;
static int launch_ssh = 0;

static unsigned char srcmac[ETH_ALEN];
static unsigned char dstmac[ETH_ALEN];

static struct in_addr sourceip; 
static struct in_addr destip;
static int sourceport;
static int fwdport = MT_TUNNEL_CLIENT_PORT;

static int connect_timeout = CONNECT_TIMEOUT;
static char run_mndp = 0;
static int mndp_timeout = 0;

static int is_a_tty = 1;
static int quiet_mode = 0;
static int batch_mode = 0;

static int keepalive_counter = 0;

static unsigned char encryptionkey[128];
static char username[255];
static char password[255];
static char nonpriv_username[255];
static int sent_auth = 0;

struct net_interface interfaces[MAX_INTERFACES];
struct net_interface *active_interface;

/* Protocol data direction */
unsigned char mt_direction_fromserver = 0;

static unsigned int send_socket;

/* SSH Executable Path */
static char ssh_path[512];

/* SSH additional args. */
static char **ssh_argv;


static int handle_packet(unsigned char *data, int data_len);

static void print_version() {
	fprintf(stderr, PROGRAM_NAME " " PROGRAM_VERSION "\n");
}

static int send_udp(struct mt_packet *packet, int retransmit) {
	int sent_bytes;

	/* Clear keepalive counter */
	keepalive_counter = 0;

	if (!use_raw_socket) {
		/* Init SendTo struct */
		struct sockaddr_in socket_address;
		memset(&socket_address, 0, sizeof(socket_address));
		socket_address.sin_family = AF_INET;
		socket_address.sin_port = htons(MT_MACTELNET_PORT);
		socket_address.sin_addr.s_addr = htonl(INADDR_BROADCAST);

		sent_bytes = sendto(send_socket, packet->data, packet->size, 0, (struct sockaddr*)&socket_address, sizeof(socket_address));
	} else {
		sent_bytes = net_send_udp(sockfd, active_interface, srcmac, dstmac, &sourceip,  sourceport, &destip, MT_MACTELNET_PORT, packet->data, packet->size);
	}

	/* 
	 * Retransmit packet if no data is received within
	 * retransmit_intervals milliseconds.
	 */
	if (retransmit) {
		int i;

		for (i = 0; i < MAX_RETRANSMIT_INTERVALS; ++i) {
			fd_set read_fds;
			int reads;
			struct timeval timeout;
			int interval = retransmit_intervals[i] * 1000;

			/* Init select */
			FD_ZERO(&read_fds);
			FD_SET(insockfd, &read_fds);
			timeout.tv_sec = 0;
			timeout.tv_usec = interval;

			/* Wait for data or timeout */
			reads = select(insockfd + 1, &read_fds, NULL, NULL, &timeout);
			if (reads && FD_ISSET(insockfd, &read_fds)) {
				unsigned char buff[1500];
				int result;

				bzero(buff, 1500);
				result = recvfrom(insockfd, buff, 1500, 0, 0, 0);

				/* Handle incoming packets, waiting for an ack */
				if (result > 0 && handle_packet(buff, result) == MT_PTYPE_ACK) {
					return sent_bytes;
				}
			}

			/* Retransmit */
			send_udp(packet, 0);
		}

		if (is_a_tty && terminal_mode) {
			reset_term();
		}

		fprintf(stderr, _("\nConnection timed out\n"));
		exit(1);
	}
	return sent_bytes;
}

static void send_auth(char *username, char *password) {
	struct mt_packet data;
	unsigned short width = 0;
	unsigned short height = 0;
	char *terminal = getenv("TERM");
	char md5data[100];
	size_t pwlen;
	unsigned char md5sum[17];
	int plen;
	md5_state_t state;

	/* Concat string of 0 + password + encryptionkey */
	md5data[0] = 0;
	pwlen = strnlen(password, 82);
	memcpy(md5data + 1, password, pwlen);
	memcpy(md5data + 1 + pwlen, encryptionkey, 16);

	/* Generate md5 sum of md5data with a leading 0 */
	md5_init(&state);
	md5_append(&state, (const md5_byte_t *)md5data, pwlen + 17);
	md5_finish(&state, (md5_byte_t *)md5sum + 1);
	md5sum[0] = 0;

	/* Send combined packet to server */
	init_packet(&data, MT_PTYPE_DATA, srcmac, dstmac, sessionkey, outcounter);
	plen = add_control_packet(&data, MT_CPTYPE_PASSWORD, md5sum, 17);
	plen += add_control_packet(&data, MT_CPTYPE_USERNAME, username, strlen(username));
	plen += add_control_packet(&data, MT_CPTYPE_TERM_TYPE, terminal, strlen(terminal));
	
	if (is_a_tty && get_terminal_size(&width, &height) != -1) {
		width = htole16(width);
		height = htole16(height);
		plen += add_control_packet(&data, MT_CPTYPE_TERM_WIDTH, &width, 2);
		plen += add_control_packet(&data, MT_CPTYPE_TERM_HEIGHT, &height, 2);
	}

	outcounter += plen;

	/* TODO: handle result */
	send_udp(&data, 1);
	sent_auth = 1;
}

static void sig_winch(int sig) {
	unsigned short width,height;
	struct mt_packet data;
	int plen;

	/* terminal height/width has changed, inform server */
	if (get_terminal_size(&width, &height) != -1) {
		init_packet(&data, MT_PTYPE_DATA, srcmac, dstmac, sessionkey, outcounter);
		width = htole16(width);
		height = htole16(height);
		plen = add_control_packet(&data, MT_CPTYPE_TERM_WIDTH, &width, 2);
		plen += add_control_packet(&data, MT_CPTYPE_TERM_HEIGHT, &height, 2);
		outcounter += plen;

		send_udp(&data, 1);
	}

	/* reinstate signal handler */
	signal(SIGWINCH, sig_winch);
}

static int handle_packet(unsigned char *data, int data_len) {
	struct mt_mactelnet_hdr pkthdr;
	parse_packet(data, &pkthdr);

	/* We only care about packets with correct sessionkey */
	if (pkthdr.seskey != sessionkey) {
		return -1;
	}

	/* Handle data packets */
	if (pkthdr.ptype == MT_PTYPE_DATA) {
		struct mt_packet odata;
		struct mt_mactelnet_control_hdr cpkt;
		int success = 0;

		/* Always transmit ACKNOWLEDGE packets in response to DATA packets */
		init_packet(&odata, MT_PTYPE_ACK, srcmac, dstmac, sessionkey, pkthdr.counter + (data_len - MT_HEADER_LEN));
		send_udp(&odata, 0);

		/* Accept first packet, and all packets greater than incounter, and if counter has
		wrapped around. */
		if (incounter == 0 || pkthdr.counter > incounter || (incounter - pkthdr.counter) > 65535) {
			incounter = pkthdr.counter;
		} else {
			/* Ignore double or old packets */
			return -1;
		}

		/* Parse controlpacket data */
		success = parse_control_packet(data + MT_HEADER_LEN, data_len - MT_HEADER_LEN, &cpkt);

		while (success) {

			/* If we receive encryptionkey, transmit auth data back */
			if (!tunnel_conn && cpkt.cptype == MT_CPTYPE_ENCRYPTIONKEY) {
				memcpy(encryptionkey, cpkt.data, cpkt.length);
				send_auth(username, password);
			}
			/* Using MAC-SSH server must not send authentication request.
			 * Authentication is handled by tunneled SSH Client and Server.
			 */
			else if (tunnel_conn && cpkt.cptype == MT_CPTYPE_ENCRYPTIONKEY) {
				fprintf(stderr, _("Server %s does not seem to use MAC-SSH Protocol. Please Try using MAC-Telnet instead.\n"), ether_ntoa((struct ether_addr *)dstmac));
				exit(1);
			}

			/* If the (remaining) data did not have a control-packet magic byte sequence,
			   the data is raw terminal data to be outputted to the terminal. */
			else if (!tunnel_conn && cpkt.cptype == MT_CPTYPE_PLAINDATA) {
				cpkt.data[cpkt.length] = 0;
				fputs((const char *)cpkt.data, stdout);
			}
			/* If the (remaining) data did not have a control-packet magic byte sequence,
			   the data is raw terminal data to be tunneled to local SSH Client. */
			else if (tunnel_conn && cpkt.cptype == MT_CPTYPE_PLAINDATA) {
				if (send(fwdfd, cpkt.data, cpkt.length, 0) < 0) {
					fprintf(stderr, _("Terminal client disconnected.\n"));
					/* exit */
					running = 0;
				}
			}

			/* END_AUTH means that the user/password negotiation is done, and after this point
			   terminal data may arrive, so we set up the terminal to raw mode. */
			else if (!tunnel_conn && cpkt.cptype == MT_CPTYPE_END_AUTH) {

				if (!sent_auth) {
					fprintf(stderr, _("Server %s does not seem to use MAC-Telnet Protocol. Please Try using MAC-SSH instead.\n"), ether_ntoa((struct ether_addr *)dstmac));
					exit(1);
				}

				/* we have entered "terminal mode" */
				terminal_mode = 1;

				if (is_a_tty) {
					/* stop input buffering at all levels. Give full control of terminal to RouterOS */
					raw_term();

					setvbuf(stdin,  (char*)NULL, _IONBF, 0);

					/* Add resize signal handler */
					signal(SIGWINCH, sig_winch);
				}
			}
			else if (tunnel_conn && cpkt.cptype == MT_CPTYPE_END_AUTH) {

			}

			/* Parse next controlpacket */
			success = parse_control_packet(NULL, 0, &cpkt);
		}
	}
	else if (pkthdr.ptype == MT_PTYPE_ACK) {
		/* Handled elsewhere */
	}

	/* The server wants to terminate the connection, we have to oblige */
	else if (pkthdr.ptype == MT_PTYPE_END) {
		struct mt_packet odata;

		/* Acknowledge the disconnection by sending a END packet in return */
		init_packet(&odata, MT_PTYPE_END, srcmac, dstmac, pkthdr.seskey, 0);
		send_udp(&odata, 0);

		if (!quiet_mode) {
			fprintf(stderr, _("Connection closed.\n"));
		}

		/* exit */
		running = 0;
	} else {
		fprintf(stderr, _("Unhandeled packet type: %d received from server %s\n"), pkthdr.ptype, ether_ntoa((struct ether_addr *)dstmac));
		return -1;
	}

	return pkthdr.ptype;
}

static int find_interface() {
	fd_set read_fds;
	struct mt_packet data;
	struct sockaddr_in myip;
	unsigned char emptymac[ETH_ALEN];
	int i, testsocket;
	struct timeval timeout;
	int optval = 1;

	/* TODO: reread interfaces on HUP */
	bzero(&interfaces, sizeof(struct net_interface) * MAX_INTERFACES);

	bzero(emptymac, ETH_ALEN);

	if (net_get_interfaces(interfaces, MAX_INTERFACES) <= 0) {
		fprintf(stderr, _("Error: No suitable devices found\n"));
		exit(1);
	}

	for (i = 0; i < MAX_INTERFACES; ++i) {
		if (!interfaces[i].in_use) {
			break;
		}

		/* Skip loopback interfaces */
		if (memcmp("lo", interfaces[i].name, 2) == 0) {
			continue;
		}

		/* Initialize receiving socket on the device chosen */
		myip.sin_family = AF_INET;
		memcpy((void *)&myip.sin_addr, interfaces[i].ipv4_addr, IPV4_ALEN);
		myip.sin_port = htons(sourceport);

		/* Initialize socket and bind to udp port */
		if ((testsocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
			continue;
		}

		setsockopt(testsocket, SOL_SOCKET, SO_BROADCAST, &optval, sizeof(optval));
		setsockopt(testsocket, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

		if (bind(testsocket, (struct sockaddr *)&myip, sizeof(struct sockaddr_in)) == -1) {
			close(testsocket);
			continue;
		}

		/* Ensure that we have mac-address for this interface  */
		if (!interfaces[i].has_mac) {
			close(testsocket);
			continue;
		}

		/* Set the global socket handle and source mac address for send_udp() */
		send_socket = testsocket;
		memcpy(srcmac, interfaces[i].mac_addr, ETH_ALEN);
		active_interface = &interfaces[i];

		/* Send a SESSIONSTART message with the current device */
		init_packet(&data, MT_PTYPE_SESSIONSTART, srcmac, dstmac, sessionkey, 0);
		send_udp(&data, 0);

		timeout.tv_sec = connect_timeout;
		timeout.tv_usec = 0;

		FD_ZERO(&read_fds);
		FD_SET(insockfd, &read_fds);
		select(insockfd + 1, &read_fds, NULL, NULL, &timeout);
		if (FD_ISSET(insockfd, &read_fds)) {
			/* We got a response, this is the correct device to use */
			return 1;
		}

		close(testsocket);
	}
	return 0;
}

/*
 * TODO: Rewrite main() when all sub-functionality is tested
 */
int main (int argc, char **argv) {
	int result;
	struct mt_packet data;
	struct sockaddr_in si_me;
	unsigned char buff[1500];
	unsigned char print_help = 0, have_username = 0, have_password = 0;
	unsigned char drop_priv = 0;
	int c;
	int optval = 1;

	setlocale(LC_ALL, "");
	bindtextdomain("mactelnet","/usr/share/locale");
	textdomain("mactelnet");

	/* Set default for ssh_path. */
	strncpy(ssh_path, SSH_PATH, sizeof(ssh_path) - 1);
	ssh_path[sizeof(ssh_path) - 1] = '\0';

    /* Ignore args after -- for MAC-Telnet client. */
	int mactelnet_argc = argc;
	int i;
	for (i=0; i < argc; i++) {
		if (strlen(argv[i]) == 2 && strncmp(argv[i], "--", 2) == 0) {
			mactelnet_argc = i;
			break;
		}
	}

	while (1) {
		c = getopt(mactelnet_argc, argv, "nqlt:u:p:vh?SFP:c:U:B");

		if (c == -1) {
			break;
		}

		switch (c) {

			case 'n':
				use_raw_socket = 1;
				break;

			case 'S':
				tunnel_conn = 1;
				launch_ssh = 1;
				break;

			case 'F':
				tunnel_conn = 1;
				break;

			case 'P':
				fwdport = atoi(optarg);
				break;

			case 'u':
				/* Save username */
				strncpy(username, optarg, sizeof(username) - 1);
				username[sizeof(username) - 1] = '\0';
				have_username = 1;
				break;

			case 'p':
				/* Save password */
				strncpy(password, optarg, sizeof(password) - 1);
				password[sizeof(password) - 1] = '\0';
				have_password = 1;
				break;

			case 'U':
				/* Save nonpriv_username */
				strncpy(nonpriv_username, optarg, sizeof(nonpriv_username) - 1);
				nonpriv_username[sizeof(nonpriv_username) - 1] = '\0';
				drop_priv = 1;
				break;

			case 'c':
				/* Save ssh executable path */
				strncpy(ssh_path, optarg, sizeof(ssh_path) - 1);
				ssh_path[sizeof(ssh_path) - 1] = '\0';
				break;

			case 't':
				connect_timeout = atoi(optarg);
				mndp_timeout = connect_timeout;
				break;

			case 'l':
				run_mndp = 1;
				break;

			case 'v':
				print_version();
				exit(0);
				break;

			case 'q':
				quiet_mode = 1;
				break;

			case 'B':
				batch_mode = 1;
				break;

			case 'h':
			case '?':
				print_help = 1;
				break;

		}
	}
	if (run_mndp) {
		return mndp(mndp_timeout, batch_mode);
	}
	if (argc - optind < 1 || print_help) {
		print_version();
		fprintf(stderr, _("Usage: %s <MAC|identity> [-v] [-h] [-q] [-n] [-l] [-B] [-S] [-P <port>] "
		                  "[-t <timeout>] [-u <user>] [-p <pass>] [-c <path>] [-U <user>]\n"), argv[0]);

		if (print_help) {
			fprintf(stderr, _("\nParameters:\n"
			"  MAC            MAC-Address of the RouterOS/mactelnetd device. Use MNDP to \n"
			"                 discover it.\n"
			"  identity       The identity/name of your destination device. Uses MNDP \n"
			"                 protocol to find it.\n"
			"  -l             List/Search for routers nearby (MNDP). You may use -t to set timeout.\n"
			"  -B             Batch mode. Use computer readable output (CSV), for use with -l.\n"
			"  -n             Do not use broadcast packets. Less insecure but requires\n"
			"                 root privileges.\n"
			"  -t <timeout>   Amount of seconds to wait for a response on each interface.\n"
			"  -u <user>      Specify username on command line.\n"
			"  -p <password>  Specify password on command line.\n"
			"  -U <user>      Drop privileges to this user. Used in conjunction with -n\n"
			"                 for security.\n"
			"  -S             Use MAC-SSH instead of MAC-Telnet. (Implies -F)\n"
			"                 Forward SSH connection through MAC-Telnet and launch SSH client.\n"
			"  -F             Forward connection through of MAC-Telnet without launching the \n"
			"                 SSH Client.\n"
			"  -P <port>      Local TCP port for forwarding SSH connection.\n"
			"                 (If not specified, port 2222 by default.)\n"
			"  -c <path>      Path for ssh client executable. (Default: /usr/bin/ssh)\n"
			"  -q             Quiet mode.\n"
			"  -v             Print version and exit.\n"
			"  -h             This help.\n"
			"\n"
			"All arguments after '--' will be passed to the ssh client command.\n"
			"\n"));
		}
		return 1;
	}

	/* Setup command line for ssh client */
	if (launch_ssh) {
		int ssh_argc;
		int add_argc;
		ssh_argc = argc - mactelnet_argc;
		add_argc = ssh_argc;
		ssh_argc += 3; /* Port option and hostname: -p <port> <host>*/
		if (have_username) {
			ssh_argc += 2;  /* Login name option: -l <user> */
		}
		ssh_argv = (char **) calloc(ssh_argc + 1, sizeof(char *));
		char *ssh_path_c = strndup(ssh_path, sizeof(ssh_path) - 1);
		char *ssh_filename = basename(ssh_path_c);
		int idx = 0;
		ssh_argv[idx++] = ssh_filename;
		int i;
		for (i = 1; i < add_argc; i++) {
			ssh_argv[idx++] = argv[mactelnet_argc + i];
		}
		char portstr[8];
		snprintf(portstr, 8, "%d", fwdport);
		ssh_argv[idx++] = strdup("-p");
		ssh_argv[idx++] = strndup(portstr, sizeof(portstr) - 1);
		if (have_username) {
			ssh_argv[idx++] = strdup("-l");
			ssh_argv[idx++] = username;
		}
		ssh_argv[idx++] = strdup("127.0.0.1");
		ssh_argv[idx++] = (char*) 0;
	}

	is_a_tty = isatty(fileno(stdout)) && isatty(fileno(stdin));
	if (!is_a_tty) {
		quiet_mode = 1;
	}

	/* Seed randomizer */
	srand(time(NULL));

	if (use_raw_socket) {
		if (geteuid() != 0) {
			fprintf(stderr, _("You need to have root privileges to use the -n parameter.\n"));
			return 1;
		}

		sockfd = net_init_raw_socket();
	}

	if (drop_priv) {
		drop_privileges(nonpriv_username);
	}

	/* Receive regular udp packets with this socket */
	insockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (insockfd < 0) {
		perror("insockfd");
		return 1;
	}

	if (!use_raw_socket) {
		if (setsockopt(insockfd, SOL_SOCKET, SO_BROADCAST, &optval, sizeof (optval))==-1) {
			perror("SO_BROADCAST");
			return 1;
		}
	}

	/* Need to use, to be able to autodetect which interface to use */
	setsockopt(insockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof (optval));

	/* Get mac-address from string, or check for hostname via mndp */
	if (!query_mndp_or_mac(argv[optind], dstmac, !quiet_mode)) {
		/* No valid mac address found, abort */
		return 1;
	}

	if (!tunnel_conn && !have_username) {
		if (!quiet_mode) {
			printf(_("Login: "));
		}
		scanf("%254s", username);
	}

	if (!tunnel_conn && !have_password) {
		char *tmp;
		tmp = getpass(quiet_mode ? "" : _("Password: "));
		strncpy(password, tmp, sizeof(password) - 1);
		password[sizeof(password) - 1] = '\0';
		/* security */
		memset(tmp, 0, strlen(tmp));
#ifdef __GNUC__
		free(tmp);
#endif
	}

	if (tunnel_conn) {
		/* Setup signal handler for broken tunnels. */
		signal(SIGPIPE,SIG_IGN);

		/* Setup Server socket for receiving connection from local SSH Client. */
		int fwdsrvfd;
		fwdsrvfd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (fwdsrvfd < 0) {
			perror("fwdsrvfd");
			return 1;
		}
		if(setsockopt(fwdsrvfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof (optval)) < 0) {
			perror("SO_REUSEADDR");
			return 1;
		}

		/* Bind to server socket for receiving terminal client connection. */
		struct sockaddr_in srv_socket;
		memset(&srv_socket, 0, sizeof(srv_socket));
		srv_socket.sin_family = AF_INET;
		srv_socket.sin_port = htons(fwdport);
		srv_socket.sin_addr.s_addr = inet_addr("127.0.0.1");
		if (bind(fwdsrvfd, (struct sockaddr *) &srv_socket, sizeof(srv_socket)) < 0) {
			fprintf(stderr, _("Error binding to %s:%d, %s\n"), "127.0.0.1", fwdport, strerror(errno));
			return 1;
		}
		if (listen(fwdsrvfd, 1) < 0) {
			fprintf(stderr, _("Failed listen on server socket %s:%d, %s\n"), "127.0.0.1", fwdport, strerror(errno));
			return 1;
		}

		/* Fork child to execute SSH Client locally and connect to parent
		 * waiting for connection from child if launch_ssh is requested.
		 */
		int pid;
		if (launch_ssh) {
			pid = fork();
		}

		if (!launch_ssh || pid > 0) {
			/* Parent code. Waits for connection to local end of tunnel */

			/* Close stdin and stdout, leave stderr active for error messages.
			 * The terminal will be handled by client connecting to local end of tunnel. */
			close(0);
			close(1);

			/* Wait for remote terminal client connection on server port. */
			fprintf(stderr, _("Waiting for tunnel connection on port: %d\n"), fwdport);
			struct sockaddr_in cli_socket;
			unsigned int cli_socket_len = sizeof(cli_socket);
			memset(&cli_socket, 0, sizeof(cli_socket));
			if ((fwdfd = accept(fwdsrvfd, (struct sockaddr *) &cli_socket, &cli_socket_len)) < 0) {
				perror("fwdfd");
			}
			if(setsockopt(fwdfd, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(optval)) < 0) {
				perror("SO_KEEPALIVE");
				return 1;
			}
			fprintf(stderr, _("Client connected to tunnel from port: %d\n"), ntohs(cli_socket.sin_port));
		}
		else if (launch_ssh && pid == 0) {
			/* Child Code. Executes SSH Client and connects to parent to tunnel
			 * connection through MAC-Telnet protocol. */
			if (use_raw_socket) {
				close(sockfd);
			}
			close(insockfd);
			close(fwdsrvfd);

			/* Give time to parent to initialize listening port. */
			sleep(2);

			/* Execute SSH Client. */
			execvp(ssh_path, ssh_argv);
			perror("Execution of terminal client failed.");
			exit(1);
		}
		/* Fork failure. */
		else {
			fprintf(stderr, _("Execution of terminal client failed.\n"));
			if (use_raw_socket) {
				close(sockfd);
			}
			close(insockfd);
			return 1;
		}
	}

	/* Set random source port */
	sourceport = 1024 + (rand() % 1024);

	/* Set up global info about the connection */
	inet_pton(AF_INET, (char *)"255.255.255.255", &destip);
	memcpy(&sourceip, &(si_me.sin_addr), IPV4_ALEN);

	/* Session key */
	sessionkey = rand() % 65535;

	/* stop output buffering */
	setvbuf(stdout, (char*)NULL, _IONBF, 0);

	if (!quiet_mode) {
		printf(_("Connecting to %s..."), ether_ntoa((struct ether_addr *)dstmac));
	}

	/* Initialize receiving socket on the device chosen */
	memset((char *) &si_me, 0, sizeof(si_me));
	si_me.sin_family = AF_INET;
	si_me.sin_port = htons(sourceport);

	/* Bind to udp port */
	if (bind(insockfd, (struct sockaddr *)&si_me, sizeof(si_me)) == -1) {
		fprintf(stderr, _("Error binding to %s:%d, %s\n"), inet_ntoa(si_me.sin_addr), sourceport, strerror(errno));
		return 1;
	}

	if (!find_interface() || (result = recvfrom(insockfd, buff, 1400, 0, 0, 0)) < 1) {
		fprintf(stderr, _("Connection failed.\n"));
		return 1;
	}
	if (!quiet_mode) {
		printf(_("done\n"));
	}

	/* Handle first received packet */
	handle_packet(buff, result);

	init_packet(&data, MT_PTYPE_DATA, srcmac, dstmac, sessionkey, 0);
	outcounter +=  add_control_packet(&data, MT_CPTYPE_BEGINAUTH, NULL, 0);

	/* TODO: handle result of send_udp */
	result = send_udp(&data, 1);

	while (running) {
		fd_set read_fds;
		int reads;
		static int terminal_gone = 0;
		struct timeval timeout;

		int maxfd = 0;
		maxfd = insockfd > fwdfd ? insockfd : fwdfd;

		/* Init select */
		FD_ZERO(&read_fds);
		if (!tunnel_conn && !terminal_gone) {
			/* Setup fd to read input from terminal. */
			FD_SET(0, &read_fds);
		}
		else if (tunnel_conn) {
			/* Setup fd to read input from local SSH Client. */
			FD_SET(fwdfd, &read_fds);
		}
		FD_SET(insockfd, &read_fds);

		timeout.tv_sec = 1;
		timeout.tv_usec = 0;

		/* Wait for data or timeout */
		reads = select(maxfd+1, &read_fds, NULL, NULL, &timeout);
		if (reads > 0) {
			/* Handle data from server */
			if (FD_ISSET(insockfd, &read_fds)) {
				bzero(buff, 1500);
				result = recvfrom(insockfd, buff, 1500, 0, 0, 0);
				handle_packet(buff, result);
			}
			unsigned char keydata[512];
			int datalen = 0;
			/* Handle data from keyboard/local terminal */
			if (!tunnel_conn && FD_ISSET(0, &read_fds) && terminal_mode) {
				datalen = read(STDIN_FILENO, &keydata, 512);
			}
			/* Handle data from local SSH client */
			if (tunnel_conn && FD_ISSET(fwdfd, &read_fds)) {
				datalen = read(fwdfd, &keydata, 512);
			}
			if (datalen > 0) {
				/* Data received, transmit to server */
				init_packet(&data, MT_PTYPE_DATA, srcmac, dstmac, sessionkey, outcounter);
				add_control_packet(&data, MT_CPTYPE_PLAINDATA, &keydata, datalen);
				outcounter += datalen;
				send_udp(&data, 1);
			}
			else if (datalen < 0) {
				terminal_gone = 1;
			}
		/* Handle select() timeout */
		} else {
			/* handle keepalive counter, transmit keepalive packet every 10 seconds
			   of inactivity  */
			if (keepalive_counter++ == 10) {
				struct mt_packet odata;
				init_packet(&odata, MT_PTYPE_ACK, srcmac, dstmac, sessionkey, outcounter);
				send_udp(&odata, 0);
			}
		}
	}

	if (!tunnel_conn && is_a_tty && terminal_mode) {
		/* Reset terminal back to old settings */
		reset_term();
	}

	close(sockfd);
	close(insockfd);
	if (tunnel_conn && fwdfd > 0) {
		close(fwdfd);
	}

	return 0;
}
