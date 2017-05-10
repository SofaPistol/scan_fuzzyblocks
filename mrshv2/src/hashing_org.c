#include "../header/hashing.h"
#include "../header/util.h"
#include <stdio.h>
#include <openssl/md5.h>



uint32 roll_hashx(unsigned char c, uchar window[], uint32 rhData[])
{
    rhData[2] -= rhData[1];
    rhData[2] += (ROLLING_WINDOW * c);

    rhData[1] += c;
    rhData[1] -= window[rhData[0] % ROLLING_WINDOW];

    window[rhData[0] % ROLLING_WINDOW] = c;
    rhData[0]++;

    /* The original spamsum AND'ed this value with 0xFFFFFFFF which
       in theory should have no effect. This AND has been removed 
       for performance (jk) */
    rhData[3] = (rhData[3] << 5); //& 0xFFFFFFFF;
    rhData[3] ^= c;

    return rhData[1] + rhData[2] + rhData[3];
}

uint32 djb2x(unsigned char c, uchar window[], unsigned int n)
{
    unsigned long hash = 5381;
    int i;
    unsigned char tmp;
    window[n % ROLLING_WINDOW] = c;

    for(i=0;i<7;i++)
    {
        tmp = window[(n+i) % ROLLING_WINDOW],
            hash = ((hash << 5) + hash) + tmp;
    }

    return hash;
}


int hashFileToFingerprint(FINGERPRINT *fingerprint, FILE *handle)
{
    unsigned long  bytes_read;   //stores the number of characters read from input file
    unsigned int   i,j;
    unsigned int   chunk_index      = 0;
    unsigned int   bits             = 0;
    unsigned char  *byte_buffer     = NULL;
    unsigned short masked_bits      = 0;

    /*we need this arrays for our extended rollhash function*/
    uchar window[ROLLING_WINDOW] = {0};
    uint32 rhData[4]             = {0};

    // Comment these lines 
    /*
       MD5_CTX mdContext;
       MD5_Init (&mdContext);
       unsigned char md5_value[MD5_DIGEST_LENGTH] = {0}; //16Bytes
       */


    if((byte_buffer = (unsigned char*)malloc(sizeof(unsigned char)*fingerprint->filesize))==NULL)
        return -1;


    unsigned char chunk[BLOCK_SIZE_MAX+1] = {0};   // <<----------- Array size for chunk could be to small !!!!!
  //  memset(chunk,0,sizeof(chunk));

    // bytes_read stores the number of characters we read from our file
    fseek(handle,0L, SEEK_SET);	
    if((bytes_read = fread(byte_buffer,sizeof(unsigned char),fingerprint->filesize,handle))==0)
        return -1;

    unsigned int current_index = 0;
    uint64 hashvalue=0;
    uint64 rValue;
    for(i=0; i<bytes_read;i++)
    {
        /*  
         * rValue = djb2x(byte_buffer[i],window,i);  
         */ 
    	//printf("%i \n", chunk_index);
        rValue  = roll_hashx(byte_buffer[i], window, rhData);  
        chunk[chunk_index++] = byte_buffer[i];

        if (rValue % BLOCK_SIZE == BLOCK_SIZE-1 || chunk_index >= BLOCK_SIZE_MAX)
        {
            //MD5_Update (&mdContext, chunk, chunk_index-1);
            //MD5_Final (md5_value,&mdContext);
            fnv64Bit(chunk, &hashvalue, chunk_index); //,current_index, FNV1_64_INIT);
            add_hash_to_fingerprint(fingerprint, hashvalue);

            memset(chunk,1,BLOCK_SIZE_MAX+1);

            hashvalue = 0;
            chunk_index = 0;
            if(i+SKIPPED_BYTES < bytes_read)
            {
            	i += SKIPPED_BYTES;
            	//for(j=0; j<SKIPPED_BYTES;j++){
            		//chunk[chunk_index++] = byte_buffer[i++];
            	//}
            }
        }
    }
    //For our last block when using MD5
    /*
       MD5_Update (&mdContext, chunk, chunk_index-1);
       MD5_Final (md5_value,&mdContext);
       for(j=0;j<SUBHASHES;j++) { 
       masked_bits = ( *(md5_value) >> (SHIFTOPS * j)) & MASK;
    //printf("Masked_bits: %d\n", masked_bits);
    bloom_add(bloom,masked_bits);
    }
    */
    fnv64Bit(chunk,&hashvalue, chunk_index);
    add_hash_to_fingerprint(fingerprint, hashvalue);

    free(byte_buffer);
    return 1;	
}

int hashPacketBuffer(FINGERPRINT *fingerprint, const unsigned char *packet, const size_t length)
{
    unsigned int i,j, k;
    unsigned int chunk_index    = 0;
    unsigned int bits           = 0;
    unsigned short masked_bits  = 0;

    uchar window[ROLLING_WINDOW] = {0};
    uint32 rhData[4]             = {0};
    unsigned char chunk[BLOCK_SIZE*5000]={0};   // <<----------- Array size for chunk could be to small !!!!!
    memset(chunk,0,sizeof(chunk));

    unsigned int current_index = 0;
    uint64 hashvalue=0;
    uint64 rValue;
    for(i=0; i<length;i++)
    {
        /*  
         * rValue = djb2x(byte_buffer[i],window,i);  
         */ 
        rValue  = roll_hashx(packet[i], window, rhData);  
        chunk[chunk_index++] = packet[i];
        if (rValue % BLOCK_SIZE == BLOCK_SIZE-1) 
        {
            //MD5_Update (&mdContext, chunk, chunk_index-1);
            //MD5_Final (md5_value,&mdContext);
            fnv64Bit(chunk,&hashvalue,chunk_index); //,current_index, FNV1_64_INIT);
            add_hash_to_fingerprint(fingerprint, hashvalue);

            memset(chunk,0,BLOCK_SIZE*5000);

            hashvalue = 0;
            chunk_index = 0;
            if(i+SKIPPED_BYTES < length)
            {
            	for(j=0; j<SKIPPED_BYTES;j++){
            	   chunk[chunk_index++] = packet[i++];
            	}
            }
        }
    }

    fnv64Bit(chunk,&hashvalue, chunk_index);
    add_hash_to_fingerprint(fingerprint, hashvalue);

    return 1;

}


void print_md5value(unsigned char *md5_value)
{
    int i;
    for(i=0;i<MD5_DIGEST_LENGTH;i++)
        printf("%02x",md5_value[i]);
    puts("");
}
