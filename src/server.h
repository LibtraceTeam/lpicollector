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
 * This code is proprietary to the University of Waikato and may not be shared,
 * distributed or copied without the express permission of the University of
 * Waikato. If you believe you have acquired this code outside of those terms, 
 * please email contact@wand.net.nz immediately.
 *
 * $Id: server.h 68 2014-08-15 04:13:45Z salcock $
 */


#ifndef LPI_SERVER_H_
#define LPI_SERVER_H_

#include <libwandevent.h>

/* Struct that contains a file descriptor which is used to store details about 
 * connected clients */
typedef struct client {
        int fd;
        struct wand_fdcb_t *client_cb;	
        fifo_ptr_t *client_fifo_ptr;
} Client_t;

/* Struct which holds a buffer of bytes to be sent to the clients, a count of 
 * the bytes used and the number of bytes exported from the buffer.
 */
typedef struct lpi_collect_buffer {
        char buf[65535];
        void *subheader;
        uint16_t buf_used;
        uint16_t buf_exported;
} Lpi_collect_buffer_t;

/* */
void accept_connections(wand_event_handler_t *ev_hdl, int fd, void *data, 
		enum wand_eventtype_t event_type);

/* Method which writes the FIFO out to the connected clients */
int write_fifo_network();

/* Method which pushes the data in the buffer onto the FIFO */
int push_buffer_fifo(Lpi_collect_buffer_t *buffer);

void *messaging_thread(void *ptr);

/* Method which initialises the server and carries out any setup required to 
 * get the server up and running */
void init_server(int max_cl, wand_event_handler_t *e_hdl, 
							uint64_t fifo_size);
							
void set_proto_buffer(Lpi_collect_buffer_t *buf);

#endif
