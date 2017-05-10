/* 
 * File:   bloom.h
 * Author: mustafakarabat
 *
 * Created on 17. April 2012, 23:34
 */

#ifndef BLOOMFILTER_H
#define	BLOOMFILTER_H

/* 
 * We define a struct BLOOM, with all the properties a BLoom-Filter needs.
 */
//typedef struct {
typedef struct BLOOMFILTER {
    // For a filter_size of 256 Bytes.
    unsigned char array[FILTERSIZE];
    
    // We store the number of blocks we add to each filter in count_added_blocks
    short int amount_of_blocks;
    
    // Pointer to next Bloomfilter
    struct BLOOMFILTER *next;
    
} BLOOMFILTER;

#ifdef __cplusplus
extern "C" {
#endif

BLOOMFILTER     *init_empty_BF();
void            destroy_bf(BLOOMFILTER *bf);

void            bloom_set_bit(unsigned char *bit_array, unsigned short value);
unsigned short  count_bits_set_to_one_of_BF(unsigned char *filter);
unsigned short  bloom_common_bits(unsigned char *bit_array_one, unsigned char *bit_array_two);

void            add_hash_to_bloomfilter(BLOOMFILTER *bf, uint64 hash_value);
void            convert_hex_binary(const unsigned char *hex_string, BLOOMFILTER *bf);

#ifdef __cplusplus
}
#endif

#endif	/* BLOOM_H */




