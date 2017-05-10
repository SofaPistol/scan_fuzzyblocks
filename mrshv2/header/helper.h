/* 
 * File:   util.h
 * Author: mustafakarabat
 *
 * Created on 5. Juni 2012, 14:38
 */
#ifndef HELPER_H
#define	HELPER_H
#include <stdio.h>
#include <stdint.h>
#include "../header/config.h"

#ifdef __cplusplus
extern "C" {
#endif

FILE    *getFileHandle(char *filename);

#ifdef __cplusplus
}
#endif

#endif	/* HELPER_H */

