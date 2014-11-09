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
 * $Id: lpicp.cc 14 2013-02-08 04:31:25Z mrm31 $
 */

#include <sys/param.h>
#include "lpicp.h"

#if 0

/* Handy 32 bit byteswapping function - borrowed from libtrace */
static inline uint32_t byteswap32(uint32_t num)
{
	return ((num&0x000000FFU)<<24)
		| ((num&0x0000FF00U)<<8)
		| ((num&0x00FF0000U)>>8)
		| ((num&0xFF000000U)>>24);
}


/* Event handler 64 bit byte swapping function */
static inline uint64_t byteswap64(uint64_t num)
{
	return (byteswap32((num&0xFFFFFFFF00000000ULL)>>32))
		|((uint64_t)byteswap32(num&0x00000000FFFFFFFFULL)<<32);
}


#ifndef __BYTE_ORDER
#warning "Byte order is not defined"
#endif



uint64_t ntoh64(uint64_t num) {
#if __BYTE_ORDER == __BIG_ENDIAN
	return num;
#else
	return byteswap64(num);
#endif
}

uint64_t hton64(uint64_t num) {
#if __BYTE_ORDER == __BIG_ENDIAN
	return num;
#else
	return byteswap64(num);
#endif
}

#endif
