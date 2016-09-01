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

#ifndef AIRPLAY_RTP_H
#define AIRPLAY_RTP_H

/* For airplay_callbacks_t */
//#include "airplay.h"
#include <shairplay/airplay.h>
#include "logger.h"

#define AIRPLAY_AESKEY_LEN 16
#define AIRPLAY_AESIV_LEN  16
#define AIRPLAY_PACKET_LEN 32768

typedef struct airplay_rtp_s airplay_rtp_t;

airplay_rtp_t *airplay_rtp_init(logger_t *logger, airplay_callbacks_t *callbacks, const char *remote,
                          const char *rtpmap, const char *fmtp,
                          const unsigned char *aeskey, const unsigned char *aesiv);
void airplay_rtp_start(airplay_rtp_t *airplay_rtp, int use_udp, unsigned short control_rport, unsigned short timing_rport,
                    unsigned short *control_lport, unsigned short *timing_lport, unsigned short *data_lport);
void airplay_rtp_set_volume(airplay_rtp_t *airplay_rtp, float volume);
void airplay_rtp_set_metadata(airplay_rtp_t *airplay_rtp, const char *data, int datalen);
void airplay_rtp_set_coverart(airplay_rtp_t *airplay_rtp, const char *data, int datalen);
void airplay_rtp_remote_control_id(airplay_rtp_t *airplay_rtp, const char *dacp_id, const char *active_remote_header);
void airplay_rtp_set_progress(airplay_rtp_t *airplay_rtp, unsigned int start, unsigned int curr, unsigned int end);
void airplay_rtp_flush(airplay_rtp_t *airplay_rtp, int next_seq);
void airplay_rtp_stop(airplay_rtp_t *airplay_rtp);
void airplay_rtp_destroy(airplay_rtp_t *airplay_rtp);

#endif
