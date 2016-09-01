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

#ifndef AIRPLAY_BUFFER_H
#define AIRPLAY_BUFFER_H

typedef struct airplay_buffer_s airplay_buffer_t;

/* From ALACMagicCookieDescription.txt at http://http://alac.macosforge.org/ */
typedef struct {
	unsigned int frameLength;
	unsigned char compatibleVersion;
	unsigned char bitDepth;
	unsigned char pb;
	unsigned char mb;
	unsigned char kb;
	unsigned char numChannels;
	unsigned short maxRun;
	unsigned int maxFrameBytes;
	unsigned int avgBitRate;
	unsigned int sampleRate;
} ALACSpecificConfig;

typedef int (*airplay_resend_cb_t)(void *opaque, unsigned short seqno, unsigned short count);

airplay_buffer_t *airplay_buffer_init(const char *rtpmap,
                                const char *fmtp,
                                const unsigned char *aeskey,
                                const unsigned char *aesiv);

const ALACSpecificConfig *airplay_buffer_get_config(airplay_buffer_t *airplay_buffer);
int airplay_buffer_queue(airplay_buffer_t *airplay_buffer, unsigned char *data, unsigned short datalen, int use_seqnum);
const void *airplay_buffer_dequeue(airplay_buffer_t *airplay_buffer, int *length, int no_resend);
void airplay_buffer_handle_resends(airplay_buffer_t *airplay_buffer, airplay_resend_cb_t resend_cb, void *opaque);
void airplay_buffer_flush(airplay_buffer_t *airplay_buffer, int next_seq);

void airplay_buffer_destroy(airplay_buffer_t *airplay_buffer);

#endif
