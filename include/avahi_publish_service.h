#ifndef __PUBLISH_SERVICE_H__
#define __PUBLISH_SERVICE_H__

//#define AVAHI_DEBUG
#ifdef AVAHI_DEBUG
#define AVAHI_DBGPRINT printf
#else
#define AVAHI_DBGPRINT
#endif

#define TOOLS_NAME "YongTV"
#define AIRPLAY_INSTANCE_NAME "iTools[DESKTOP-9CE9T7M]"
#define AIRTUNES_INSTANCE_NAME "40167E813D5C@iTools[DESKTOP-9CE9T7M]"
#define AIRPLAY_TYPE "_airplay._tcp"
#define AIRTUNES_TYPE "_raop._tcp"
#define AIRPLAY_PORT 62769
#define AIRTUNES_PORT 62770

typedef unsigned char             uint8_t; 
typedef unsigned short int        uint16_t;
typedef unsigned int              uint32_t;

void avahi_client_init();

int avahi_service_add(int id, const char *name, const char *type, uint16_t port, const void *txtRecord, int txtLen);

int avahi_service_del(int id);

#endif

