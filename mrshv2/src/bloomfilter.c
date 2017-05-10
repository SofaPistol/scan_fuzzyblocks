/**
 * AUTHOR: Frank Breitinger
 * DATE: April 2013
 * Email: Frank.Breitinger@cased.de
 */
#include <stdio.h>
#include <math.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "../header/config.h"
#include "base64/modp_b64.h"
#include "../header/hashing.h"
#include "../header/bloomfilter.h"
#include "../header/util.h"



//Returns an empty Bloom filter
BLOOMFILTER *init_empty_BF(){
	BLOOMFILTER *bf;
	if (!(bf=(BLOOMFILTER *)calloc(1,sizeof(BLOOMFILTER))))
	 {
	     fprintf(stderr,"[*] Error in initializing bloom_read \n");
	     exit(-1);
	 }
	bf->next = NULL;
	bf->amount_of_blocks = 0;
	return bf;
}


//Destroy a Bloom filter
void destroy_bf(BLOOMFILTER *bf) {
    free(bf->array);
    free(bf);
    bf=NULL;
}





/*
 * adds a hash value (eg. FNV) to the Bloom filter
 */
void add_hash_to_bloomfilter(BLOOMFILTER *bf, uint64 hash_value){
	unsigned short masked_bits;
	short byte_pos,bit_pos, one_counter=0;


	//add the hash value to the bloom filter
	for(int j=0;j<SUBHASHES;j++) {

         //masked_bits = ( *(md5_value) >> (SHIFTOPS*j)) & MASK;
          masked_bits = ( hash_value >> (SHIFTOPS * j)) & MASK;
          byte_pos = masked_bits >> 3;
          bit_pos = masked_bits & 0x7;

          if((bf->array[byte_pos]>>bit_pos)&1 == 1)
        	  one_counter++;
          bf->array[byte_pos] |= (1<<(bit_pos));
	}
	//if all bits were set to one, there is nothing new and we ignore this block
	//in worst case it is an attack
	if(one_counter != SUBHASHES)
		bf->amount_of_blocks++;
}


/*
 * computes the hamming weight (bits set to one) within an integer.
 * one should pass a unsigned char *array
 */
unsigned short count_bits_set_to_one_of_BF(unsigned char filter[]) {
    unsigned short  counted_bits=0;
    int a,v;
    int *tmp = filter;

    for(a=0;a<FILTERSIZE/4;a++){
    	v = tmp[a];
    	v = v - ((v >> 1) & 0x55555555);                //put count of each 2 bits into those 2 bits
    	v = (v & 0x33333333) + ((v >> 2) & 0x33333333); //put count of each 4 bits into those 4 bits
    	counted_bits += ((v + (v >> 4) & 0xF0F0F0F) * 0x1010101) >> 24;
    }
    return counted_bits;
}







unsigned short bloom_common_bits(unsigned char bit_array_one[], unsigned char bit_array_two[]) {
    unsigned char buffer[FILTERSIZE]={0};
    int a;
    for(a=0;a<FILTERSIZE;a++)
        buffer[a] = bit_array_one[a] & bit_array_two[a];

    return count_bits_set_to_one_of_BF(buffer);
}







/*
 * Convert a hex string to a binary sequence (used for reading in hash lists)
 */
void convert_hex_binary(const unsigned char *hex_string, BLOOMFILTER *bf)
{
    unsigned int i=0;

	//WARNING: no sanitization or error-checking whatsoever
	for(i = 0; i < FILTERSIZE; i++) {
	  	  sscanf(hex_string, "%2hhx", &bf->array[i]);
	  	  hex_string += 2 * sizeof(char);
	}
}







