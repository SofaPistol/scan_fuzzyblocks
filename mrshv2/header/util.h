/* 
 * File:   util.h
 * Author: mustafakarabat
 *
 * Created on 5. Juni 2012, 14:38
 */
#ifndef UTIL_H
#define	UTIL_H
#include <stdio.h>
#include <stdint.h>
#include "../header/config.h"



unsigned int	find_file_size(FILE *fh);
//void        	fnv64Bit_old(char *hashstring, uint64 *hashv);
//void 		fnv64Bit(char hashstring[], uint64 *hashv, int start, int end);
uint64	 		fnv64Bit( unsigned char pBuffer[], int start, int end);


#endif	/* UTIL_H */

