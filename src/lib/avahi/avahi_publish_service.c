/***
  This file is part of avahi.

  avahi is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as
  published by the Free Software Foundation; either version 2.1 of the
  License, or (at your option) any later version.

  avahi is distributed in the hope that it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
  or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General
  Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with avahi; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
  USA.
***/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <pthread.h>
#include <string.h>

#include <avahi-client/client.h>
#include <avahi-client/publish.h>

#include <avahi-common/alternative.h>
#include <avahi-common/simple-watch.h>
#include <avahi-common/malloc.h>
#include <avahi-common/error.h>
#include <avahi-common/timeval.h>

#include <utils.h>

#include <avahi_publish_service.h>

typedef struct asp_publicsh_serivce_struct {
    int id;         //ASP2.0 advertisement id of this service
    char *name;     //ASP2.0 instance name of this service
    char *type;     //ASP2.0 type of this service
    AvahiEntryGroup *group;
    struct asp_publicsh_serivce_struct *next;
} ASP_PUB_SVC_T;

AvahiClient *g_client = NULL;
static AvahiSimplePoll *simple_poll = NULL;
static ASP_PUB_SVC_T *g_services = NULL;
static int g_server_busy = 0;


static void entry_group_callback(AvahiEntryGroup *g, AvahiEntryGroupState state, AVAHI_GCC_UNUSED void *userdata) {
    //assert(g == group || group == NULL);
    //group = g;

    /* Called whenever the entry group state changes */

    switch (state) {
        case AVAHI_ENTRY_GROUP_ESTABLISHED :
            /* The entry group has been established successfully */
            fprintf(stderr, "Service successfully established.\n");
            g_server_busy = 0;
            break;

        case AVAHI_ENTRY_GROUP_COLLISION : {
            //char *n;

            /* A service name collision with a remote service
             * happened. Let's pick a new name */
            /*n = avahi_alternative_service_name(name);
            avahi_free(name);
            name = n;
            */

            fprintf(stderr, "Service name collision, renaming service\n");
            

            /* And recreate the services */
            //create_services(avahi_entry_group_get_client(g));
            break;
        }

        case AVAHI_ENTRY_GROUP_FAILURE :

            fprintf(stderr, "Entry group failure: %s\n", avahi_strerror(avahi_client_errno(avahi_entry_group_get_client(g))));

            /* Some kind of failure happened while we were registering our services */
            avahi_simple_poll_quit(simple_poll);
            break;

        case AVAHI_ENTRY_GROUP_UNCOMMITED:
            g_server_busy = 1;
            fprintf(stderr, "Service group uncommited\n");
            break;
        case AVAHI_ENTRY_GROUP_REGISTERING:
            g_server_busy = 1;
            fprintf(stderr, "Service group registering\n");
            ;
    }
}

static void client_callback(AvahiClient *c, AvahiClientState state, AVAHI_GCC_UNUSED void * userdata) {
    assert(c);

    /* Called whenever the client or server state changes */

    switch (state) {
        case AVAHI_CLIENT_S_RUNNING:

            /* The server has startup successfully and registered its host
             * name on the network, so it's time to create our services */
            //create_services(c);
            break;

        case AVAHI_CLIENT_FAILURE:

            fprintf(stderr, "Client failure: %s\n", avahi_strerror(avahi_client_errno(c)));
            avahi_simple_poll_quit(simple_poll);

            break;

        case AVAHI_CLIENT_S_COLLISION:

            /* Let's drop our registered services. When the server is back
             * in AVAHI_SERVER_RUNNING state we will register them
             * again with the new host name. */

        case AVAHI_CLIENT_S_REGISTERING:

            /* The server records are now being established. This
             * might be caused by a host name change. We need to wait
             * for our own records to register until the host name is
             * properly esatblished. */

            //if (group)
            //    avahi_entry_group_reset(group);

            break;

        case AVAHI_CLIENT_CONNECTING:
            ;
    }
}

//static void modify_callback(AVAHI_GCC_UNUSED AvahiTimeout *e, void *userdata) {
//    AvahiClient *client = userdata;
//
//    fprintf(stderr, "Doing some weird modification\n");
//
//    avahi_free(name);
//    name = avahi_strdup("Modified MegaPrinter");
//
//    /* If the server is currently running, we need to remove our
//     * service and create it anew */
//    if (avahi_client_get_state(client) == AVAHI_CLIENT_S_RUNNING) {
//
//        /* Remove the old services */
//        if (group)
//            avahi_entry_group_reset(group);
//
//        /* And create them again with the new name */
//        create_services(client);
//    }
//}

static void *avahi_client_thread(void *args)
{
    int error;
    //int ret = 1;
    //struct timeval tv;

    /* Allocate main loop object */
    if (!(simple_poll = avahi_simple_poll_new())) {
        fprintf(stderr, "Failed to create simple poll object.\n");
        goto fail;
    }

    //name = avahi_strdup("MegaPrinter");

    /* Allocate a new client */
    g_client = avahi_client_new(avahi_simple_poll_get(simple_poll), 0, client_callback, NULL, &error);

    /* Check wether creating the client object succeeded */
    if (!g_client) {
        fprintf(stderr, "Failed to create client: %s\n", avahi_strerror(error));
        goto fail;
    }

    /* After 10s do some weird modification to the service */
    /*avahi_simple_poll_get(simple_poll)->timeout_new(
        avahi_simple_poll_get(simple_poll),
        avahi_elapse_time(&tv, 1000*10, 0),
        modify_callback,
        g_client);
        */

    /* Run the main loop */
    avahi_simple_poll_loop(simple_poll);

    //ret = 0;

fail:

    /* Cleanup things */

    if (g_client)
        avahi_client_free(g_client);

    if (simple_poll)
        avahi_simple_poll_free(simple_poll);

    //avahi_free(name);

    return NULL;
}

void avahi_client_init(){
    //start thread
    pthread_t thread_id;
    pthread_attr_t  attr;
    
    if (g_client) {
        printf("The avahi client had inited!\n");
        return;
    }
    
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 0x40000);
    if (pthread_create(&thread_id, &attr, &avahi_client_thread, NULL)) {
        fprintf(stderr, "create avahi_client_thread error!!\n");
    }
}

int avahi_service_add(int id, const char *name, const char *type, uint16_t port, const void *txtRecord, int txtLen) {
    int ret;
    ASP_PUB_SVC_T *service;
    //va_list va;
    AvahiStringList *txt;
    assert(g_client);

    /* If this is the first time we're called, let's create a new
     * entry group if necessary */

    //check duplicate

    //check server busy
    while (g_server_busy)
        usleep(10000);

    service = (ASP_PUB_SVC_T *)avahi_malloc0(sizeof(ASP_PUB_SVC_T));
    if (!service)
        return -1;

    service->id = id;

    if (!(service->group = avahi_entry_group_new(g_client, entry_group_callback, NULL))) {
        fprintf(stderr, "avahi_entry_group_new() failed: %s\n", avahi_strerror(avahi_client_errno(g_client)));
        goto fail;
    }

    /* If the group is empty (either because it was just created, or
     * because it was reset previously, add our entries.  */

    if (avahi_entry_group_is_empty(service->group)) {

        /* Create some random TXT data */
        //snprintf(r, sizeof(r), "random=%i", rand());

        /* We will now add two services and one subtype to the entry
         * group. The two services have the same name, but differ in
         * the service type (IPP vs. BSD LPR). Only services with the
         * same name should be put in the same entry group. */

        /* Add the service for IPP */
	if (txtLen > 0)
	    avahi_string_list_parse(txtRecord, txtLen, &txt);
        
	if ((ret = avahi_entry_group_add_service_strlst(service->group, AVAHI_IF_UNSPEC, AVAHI_PROTO_UNSPEC, 0, name, type, NULL, NULL, port, txt)) < 0) {
            avahi_string_list_free(txt);
            /*if (ret == AVAHI_ERR_COLLISION)
                goto collision;*/

            fprintf(stderr, "Failed to add service: %s\n", avahi_strerror(ret));
            goto fail;
        }
        avahi_string_list_free(txt);
        
        /* Add the same service for BSD LPR */
        /*if ((ret = avahi_entry_group_add_service(group, AVAHI_IF_UNSPEC, AVAHI_PROTO_UNSPEC, 0, name, "_printer._tcp", NULL, NULL, 515, NULL)) < 0) {

            if (ret == AVAHI_ERR_COLLISION)
                goto collision;

            fprintf(stderr, "Failed to add _printer._tcp service: %s\n", avahi_strerror(ret));
            goto fail;
        }*/

        /* Add an additional (hypothetic) subtype */
        /*if ((ret = avahi_entry_group_add_service_subtype(group, AVAHI_IF_UNSPEC, AVAHI_PROTO_UNSPEC, 0, name, "_printer._tcp", NULL, "_magic._sub._printer._tcp") < 0)) {
            fprintf(stderr, "Failed to add subtype _magic._sub._printer._tcp: %s\n", avahi_strerror(ret));
            goto fail;
        }*/

        /* Tell the server to register the service */
        if ((ret = avahi_entry_group_commit(service->group)) < 0) {
            fprintf(stderr, "Failed to commit entry group: %s\n", avahi_strerror(ret));
            goto fail;
        }
    }

    service->next = g_services;
    g_services = service;

    return 0;

/*collision:

    fprintf(stderr, "Service name collision, renaming service to '%s'\n", name);

    avahi_entry_group_free(service->group);
    avahi_free(service);
    return -1;
*/
fail:
    avahi_entry_group_free(service->group);
    avahi_free(service);
    //avahi_simple_poll_quit(simple_poll);
    return -1;
}

int avahi_service_del(int id)
{
    ASP_PUB_SVC_T *service, *service_prev = NULL;

    service = g_services;
    while (service) {
        if (service->id == id) {
            //match, remove this service
            if (service_prev)
                service_prev->next = service->next;
            else
                g_services = service->next;

            avahi_entry_group_free(service->group);
            avahi_free(service);
            return 0;
        }

        service_prev = service;
        service = service->next;
    }

    return -1;
}

#define MAX_HWADDR_LEN 6
#define MAX_DEVICEID 18
#define MAX_SERVNAME 256

int avahi_register_airplay_service(char *name, int adv_id, uint16_t port, const char *hwaddr, int hwaddrlen, const char *svc_info, int svc_info_len)
{
    char deviceid[3*MAX_HWADDR_LEN];
    char *temp;
    int ret;
    int i;

    if(name == NULL){
        printf("airtunes service name is null...\n");
        return -1;
    }

    if(hwaddr == NULL){
        printf("airtunes hwaddr is null...\n");
        return -1;
    }

    if(svc_info == NULL){
        printf("airtunes service info is null...\n");
        return -1;
    }

    /* Convert hardware address to string */
    ret = utils_hwaddr_airplay(deviceid, sizeof(deviceid), hwaddr, hwaddrlen);
    if (ret < 0) {
	/* FIXME: handle better */
	return -1;
    }
    printf("avahi_register_airplay_service: devceid = %s port = %d\n", deviceid, port);

    temp = strstr(svc_info, "deviceid=");
    if(!temp){
	printf("temp is NULL...\n");
	return -1;
    }else{
	for(i = 0; i < strlen(deviceid); i++){
	    *(temp + 9 + i)  = deviceid[i];
	}
    }

    if (avahi_service_add(adv_id, name, "_airplay._tcp", port, svc_info, svc_info_len) != 0) {
        printf("%s %d avahi_service_add failed! adv_id=%d s_name=%s\n", __func__, __LINE__, adv_id, name);
        return -1;
    }

    return 0;
}

int avahi_register_airtunes_service(char *name, int adv_id, uint16_t port, const char *hwaddr, int hwaddrlen, const char *svc_info, int svc_info_len)
{
    char servname[MAX_SERVNAME];
    int ret;

    if(name == NULL){
		printf("airtunes service name is null...\n");
		return -1;
    }	

    if(hwaddr == NULL){
		printf("airtunes hwaddr is null...\n");
		return -1;
    }	

    if(svc_info == NULL){
		printf("airtunes service info is null...\n");
		return -1;
    }	
	
    /* Convert hardware address to string */
    ret = utils_hwaddr_raop(servname, sizeof(servname), hwaddr, hwaddrlen);
    if (ret < 0) {
		/* FIXME: handle better */
		return -1;
    }

    /* Check that we have bytes for 'hw@name' format */
    if (sizeof(servname) < strlen(servname)+1+strlen(name)+1) {
		/* FIXME: handle better */
		return -2;
    }

    strncat(servname, "@", sizeof(servname)-strlen(servname)-1);
    strncat(servname, name, sizeof(servname)-strlen(servname)-1);

    printf("avahi_register_airtunes_service:servname = %s port = %d\n", servname, port);

    if (avahi_service_add(adv_id, servname, "_raop._tcp", port, svc_info, svc_info_len) != 0) {
        printf("%s %d avahi_service_add failed! adv_id=%d s_name=%s\n", __func__, __LINE__, adv_id, servname);
        return -1;
    }

    return 0;
}
