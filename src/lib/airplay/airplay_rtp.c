/**
 *  Copyright (C) 2011-2012  Juho Vähä-Herttua
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#include "airplay_rtp.h"
//#include "airplay.h"
#include <shairplay/airplay.h>
#include "airplay_buffer.h"
#include "netutils.h"
#include "utils.h"
#include "compat.h"
#include "logger.h"

#define NO_FLUSH (-42)

struct airplay_rtp_s {
	logger_t *logger;
	airplay_callbacks_t callbacks;

	/* Buffer to handle all resends */
	airplay_buffer_t *buffer;

	/* Remote address as sockaddr */
	struct sockaddr_storage remote_saddr;
	socklen_t remote_saddr_len;

	/* MUTEX LOCKED VARIABLES START */
	/* These variables only edited mutex locked */
	int running;
	int joined;

	float volume;
	int volume_changed;
	unsigned char *metadata;
	int metadata_len;
	unsigned char *coverart;
	int coverart_len;
	char *dacp_id;
	char *active_remote_header;
	unsigned int progress_start;
	unsigned int progress_curr;
	unsigned int progress_end;
	int progress_changed;

	int flush;
	thread_handle_t thread;
	mutex_handle_t run_mutex;
	/* MUTEX LOCKED VARIABLES END */

	/* Remote control and timing ports */
	unsigned short control_rport;
	unsigned short timing_rport;

	/* Sockets for control, timing and data */
	int csock, tsock, dsock;

	/* Local control, timing and data ports */
	unsigned short control_lport;
	unsigned short timing_lport;
	unsigned short data_lport;

	/* Initialized after the first control packet */
	struct sockaddr_storage control_saddr;
	socklen_t control_saddr_len;
	unsigned short control_seqnum;
};

static int
airplay_rtp_parse_remote(airplay_rtp_t *airplay_rtp, const char *remote)
{
	char *original;
	char *current;
	char *tmpstr;
	int family;
	int ret;

	assert(airplay_rtp);

	current = original = strdup(remote);
	if (!original) {
		return -1;
	}
	tmpstr = utils_strsep(&current, " ");
	if (strcmp(tmpstr, "IN")) {
		free(original);
		return -1;
	}
	tmpstr = utils_strsep(&current, " ");
	if (!strcmp(tmpstr, "IP4") && current) {
		family = AF_INET;
	} else if (!strcmp(tmpstr, "IP6") && current) {
		family = AF_INET6;
	} else {
		free(original);
		return -1;
	}
	if (strstr(current, ":")) {
		/* FIXME: iTunes sends IP4 even with an IPv6 address, does it mean something */
		family = AF_INET6;
	}
	ret = netutils_parse_address(family, current,
	                             &airplay_rtp->remote_saddr,
	                             sizeof(airplay_rtp->remote_saddr));
	if (ret < 0) {
		free(original);
		return -1;
	}
	airplay_rtp->remote_saddr_len = ret;
	free(original);
	return 0;
}

airplay_rtp_t *
airplay_rtp_init(logger_t *logger, airplay_callbacks_t *callbacks, const char *remote,
              const char *rtpmap, const char *fmtp,
              const unsigned char *aeskey, const unsigned char *aesiv)
{
	airplay_rtp_t *airplay_rtp;

    assert(logger);
    assert(callbacks);
    assert(remote);
    assert(rtpmap);
	assert(fmtp);

	airplay_rtp = calloc(1, sizeof(airplay_rtp_t));
	if (!airplay_rtp) {
		return NULL;
	}
	airplay_rtp->logger = logger;
	memcpy(&airplay_rtp->callbacks, callbacks, sizeof(airplay_callbacks_t));
	airplay_rtp->buffer = airplay_buffer_init(rtpmap, fmtp, aeskey, aesiv);
	if (!airplay_rtp->buffer) {
		free(airplay_rtp);
		return NULL;
	}
	if (airplay_rtp_parse_remote(airplay_rtp, remote) < 0) {
		free(airplay_rtp);
		return NULL;
	}

	airplay_rtp->running = 0;
	airplay_rtp->joined = 1;
	airplay_rtp->flush = NO_FLUSH;
	MUTEX_CREATE(airplay_rtp->run_mutex);

	return airplay_rtp;
}

void
airplay_rtp_destroy(airplay_rtp_t *airplay_rtp)
{
}

static int
airplay_rtp_init_sockets(airplay_rtp_t *airplay_rtp, int use_ipv6, int use_udp)
{
}

static int
airplay_rtp_resend_callback(void *opaque, unsigned short seqnum, unsigned short count)
{
	return 0;
}

static int
airplay_rtp_process_events(airplay_rtp_t *airplay_rtp, void *cb_data)
{
	return 0;
}

static THREAD_RETVAL
airplay_rtp_thread_udp(void *arg)
{
	return 0;
}

static THREAD_RETVAL
airplay_rtp_thread_tcp(void *arg)
{
	return 0;
}

void
airplay_rtp_start(airplay_rtp_t *airplay_rtp, int use_udp, unsigned short control_rport, unsigned short timing_rport,
               unsigned short *control_lport, unsigned short *timing_lport, unsigned short *data_lport)
{
}

void
airplay_rtp_set_volume(airplay_rtp_t *airplay_rtp, float volume)
{
}

void
airplay_rtp_set_metadata(airplay_rtp_t *airplay_rtp, const char *data, int datalen)
{
}

void
airplay_rtp_set_coverart(airplay_rtp_t *airplay_rtp, const char *data, int datalen)
{
}

void 
airplay_rtp_remote_control_id(airplay_rtp_t *airplay_rtp, const char *dacp_id, const char *active_remote_header)
{
}

void
airplay_rtp_set_progress(airplay_rtp_t *airplay_rtp, unsigned int start, unsigned int curr, unsigned int end)
{
}

void
airplay_rtp_flush(airplay_rtp_t *airplay_rtp, int next_seq)
{
}

void
airplay_rtp_stop(airplay_rtp_t *airplay_rtp)
{
}
