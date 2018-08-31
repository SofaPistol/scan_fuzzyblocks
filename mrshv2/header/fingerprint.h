/* 
 * File:   bloom.h
 * Author: Frank Breitinger
 *
 * Created on 17. April 2013, 23:34
 */

#ifndef FINTERPRINT_H
#define	FINTERPRINT_H

#include "bloomfilter.h"




typedef struct FINGERPRINT {
	//List of Bloom filters
    BLOOMFILTER *bf_list;
    BLOOMFILTER *bf_list_last_element;
    
    //Pointer to next fingerprint
    struct FINGERPRINT *next;
    
   // After storing of MAXBLOCKS blocks are inserted, a new filter is created.
   // 'amount_of_BF' counts the number of filters we have for a file
   unsigned int  amount_of_BF;

   // File name and size of the original file
   char          file_name[200];
   unsigned int  filesize;
        
}FINGERPRINT;




FINGERPRINT         *init_empty_fingerprint();
FINGERPRINT         *init_fingerprint_for_file(FILE *handle, char *filename);
int                 fingerprint_destroy(FINGERPRINT *fp);

int                 fingerprint_compare(FINGERPRINT *fingerprint1, FINGERPRINT *fingerprint2);
int                 bloom_max_score(BLOOMFILTER *bf, FINGERPRINT *fingerprint);
void                add_hash_to_fingerprint(FINGERPRINT *fp, uint64 hash_value);
double              compute_e_min(int blocks_in_bf1, int blocks_in_bf2);

//unsigned int        read_input_hash_file(FINGERPRINT_LIST *fpl,FILE *handle);

void add_new_bloomfilter(FINGERPRINT *fp, BLOOMFILTER *bf);
void                print_fingerprint(FINGERPRINT *fp);


#endif	/* BLOOM_H */




