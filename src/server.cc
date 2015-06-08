/*
 * This file is part of lpicollector
 *
 * Copyright (c) 2013 The University of Waikato, Hamilton, New Zealand.
 * Author: Meenakshee Mungro
 *         Shane Alcock
 *
 * All rights reserved.
 *
 * This code has been developed by the University of Waikato WAND
 * research group. For further information please see http://www.wand.net.nz/
 *
 * lpicollector is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * lpicollector is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with lpicollector. If not, see <http://www.gnu.org/licenses/>.
 */


#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/types.h>
#include <netdb.h>
#include <pthread.h>
#include <signal.h>
#include <assert.h>
#include <map>

#include <libwandevent.h>
#include <libfifo.h>

#include "server.h"

using namespace std;

/* Maximum number of clients that can be connected to the server at a time. */
int max_clients;

/* Variable to store the number of currently connected clients */
static int clientCounter = 0;

wand_event_handler_t *evnt_hdl = NULL;

typedef map<int, Client_t *> Client_map;
Client_map cl_map;

struct fifo_t *fifo = NULL;

Lpi_collect_buffer_t *protolist_buffer = NULL;

/* Mutex used to protect the client map while it is being read from/written to */
pthread_mutex_t mutex_client;
/* signals to block */
static sigset_t   signal_mask; 

pthread_mutex_t mutex_cond;
pthread_cond_t client_cond;

void *messaging_thread(void *ptr) {
	int rc;
	
	/* Blocking the SIGINT and SIGTERM signals */
	sigemptyset (&signal_mask);
	sigaddset (&signal_mask, SIGINT);
	sigaddset (&signal_mask, SIGTERM);
	rc = pthread_sigmask (SIG_BLOCK, &signal_mask, NULL);
	if (rc != 0) {
		fprintf(stderr, "Error blocking signlas!\n");		
	}
		
	while (true) {
		pthread_mutex_lock(&mutex_cond);
		
		assert(fifo);
		/* if there's no data in fifo, then wait */
		if(fifo_ptr_available(fifo, fifo->head, fifo->tail) == 0) {
			pthread_cond_wait(&client_cond, &mutex_cond);
		}
		/* There's data in the FIFO at this point, so unlock the mutex 
		 * and resume */
		pthread_mutex_unlock(&mutex_cond);
		
		/* call method that sends to fifo */
		write_fifo_network();
	}
	
	pthread_mutex_destroy(&mutex_cond);
	pthread_cond_destroy(&client_cond);
	pthread_exit(NULL);	
}

void set_proto_buffer(Lpi_collect_buffer_t *buf)
{
	protolist_buffer = buf;
}

/* buffer, buf_used */
static int message_client(int fd, char* buf, int buf_len) 
{
	int sent = 0;

        /* Continue sending until ALL of the buffer has been sent correctly */
        while (sent < buf_len) {
                int ret = send(fd, buf + sent, buf_len - sent, 0);
                if (ret == -1) {
                        perror("send");
                        printf("Error sending message to client!");
                        return -1;
                }
                sent += ret;
        }
}

static void disconnect_client(wand_event_handler_t *ev_hdl, int fd, void *data, 
			enum wand_eventtype_t event_type)
{
	
	pthread_mutex_lock(&mutex_client);
	/* If found, delete the fd and its client from the map and decrement the 
	 * client counter */	
	if (!(cl_map.find(fd) == cl_map.end())) {
		wand_del_fd(ev_hdl, fd);
				
		cl_map.erase(fd);
		clientCounter--;
		
		fifo_dealloc_ptr(fifo, ((Client_t*)data)->client_fifo_ptr);
		
		close(fd);
		
		free(data);
		
		printf("Client disconnected!\n");
		printf("Server: Number of connected clients: %lu\n",
                                                                clientCounter);
	}	
	pthread_mutex_unlock(&mutex_client);
}

void accept_connections(wand_event_handler_t *ev_hdl, int fd, void *data,
                        enum wand_eventtype_t event_type)
{
        printf("Server: trying to accept connection...\n");
        int lis_sock = fd;

        struct sockaddr_storage remote;
        socklen_t addr_size = sizeof (remote);

        int new_fd = 0;

        new_fd = accept(lis_sock, (struct sockaddr *)&remote, &addr_size);

        if (new_fd == -1) {
                perror("accept");
                
                return;
        } else {
                /* Array of clients not full yet, add client to array of 
                 * connected clients */
                if (clientCounter < max_clients) {
                        /* Create Client struct */
                        Client_t *newClient = (Client_t*)malloc(sizeof(Client_t));
                        newClient->fd = new_fd;
                        
                        /* Initialise a fifo_ptr_t for each client by calling the 
                         * fifo_alloc_ptr fucntion with the FIFO and offset */
                        newClient->client_fifo_ptr = fifo_alloc_ptr(fifo, 
							fifo->head->offset);
                        
                        /* Send list of protocols to client */
                        if (protolist_buffer == NULL) {
				fprintf(stderr, "lpicp_export_init has not been run and protocol list has not been initialised!\n");
				close(newClient->fd);
				return;
			}
			/* Call method which sends the protocol data in the buffer 
			 * to the client before it is added to the client list */
                        message_client(newClient->fd, protolist_buffer->buf,
							protolist_buffer->buf_used);
                        
                        /* Add new client to the map of Clients */
                        pthread_mutex_lock(&mutex_client);
                        cl_map[new_fd] = newClient;
                        pthread_mutex_unlock(&mutex_client);
                        
                        clientCounter++;
                        
                        printf("Server: Accepted connection!\n");
                        printf("Server: Number of connected clients: %lu\n",
                                                                clientCounter);
                        
                        /* Setting up the client callback for when the client 
                         * sends an EOF before disconnecting */
                       	wand_add_fd(evnt_hdl, new_fd, EV_READ, newClient,
					disconnect_client);
                        
                } else {
                        printf("Server: Maximum number of connections reached! Cannot accept new clients!\n");
                        
                        char msg[] = "Server has exceeded the number of possible connections. Try again later!\n";

                        if (message_client(new_fd, msg, strlen(msg)))
                                close(new_fd);
                }
        }
}

void init_server(int max_cl, wand_event_handler_t *e_hdl, 
				uint64_t fifo_size)
{
        max_clients = max_cl;
        
        evnt_hdl = e_hdl;
        
        /* Creating a memory backed FIFO with the specified size(in bytes) */
        fifo = create_fifo(fifo_size, NULL);
        
        /* Initialise mutex */
        pthread_mutex_init(&mutex_client, NULL);
        
        /* Initialise condition and its mutex */
        pthread_cond_init(&client_cond, NULL);     
        pthread_mutex_init(&mutex_cond, NULL);
}

int push_buffer_fifo(Lpi_collect_buffer_t *buffer)
{
	if (clientCounter == 0) {
		return 0;
	}
	if (fifo_write(fifo, buffer->buf, buffer->buf_used) == 0) {
		fprintf(stderr, "FIFO does not have enough free space!\n");
		return -1;
	}
	
	/* Send a condition signal to wake up the other thread */	
	pthread_cond_signal(&client_cond);	
	
	return 0;
}

int write_fifo_network()
{
	pthread_mutex_lock(&mutex_client);
	
	fifo_offset_t biggest = 0;
	fifo_ptr_t *small_ptr = fifo->head;
	
	/* Try to send the data in the FIFO to each of the connected clients */
        for (Client_map::iterator ii=cl_map.begin(); ii!=cl_map.end(); ii++)
        {
		/* Calculate the amount of data to send since the last time sending 
		 * was successful */
		fifo_offset_t to_send = fifo_ptr_available(fifo, fifo->head, 
						(*ii).second->client_fifo_ptr);
		/* Send data in the FIFO to the fd */
		fifo_offset_t sent = fifo_ptr_read_fd(fifo, (*ii).second->client_fifo_ptr, 
						(*ii).first, to_send);
						
		/* Update the client's FIFO pointer */
		fifo_ptr_update(fifo, (*ii).second->client_fifo_ptr, sent);
		
		
		if (biggest < fifo_ptr_available(fifo, fifo->head, 
						(*ii).second->client_fifo_ptr)) {
			biggest = fifo_ptr_available(fifo, fifo->head, 
						(*ii).second->client_fifo_ptr);
			small_ptr = (*ii).second->client_fifo_ptr;			
		}		
	}
	fifo_ptr_assign(fifo, fifo->tail, small_ptr);
	
	pthread_mutex_unlock(&mutex_client);
	
	return 0;
}


