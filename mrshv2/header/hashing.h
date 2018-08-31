/* 
 * File:   hashing.h
 * Author: Frank Breitinger
 *
 * Created on 5. Juni 2012, 13:22
 */

#ifndef HASHING_H
#define	HASHING_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"
#include "fingerprint.h"
#include "bloomfilter.h"



int         hashFileToFingerprint(FINGERPRINT *fingerprint, FILE *handle);
uint32      roll_hashx(unsigned char c, uchar window[], uint32 rhData[]);
uint32      djb2x(unsigned char c, uchar window[], unsigned int n);
int         hashPacketBuffer(FINGERPRINT *bloom,const unsigned char *packet, const size_t length);

#endif	/* HASHING_H */

