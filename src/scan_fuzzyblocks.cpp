/**
 *
 * scan_fuzzyblocks:
 *
 * Scanner for generating and comparing blockwise similarity hashes
 */
 
// general includes
#include <iostream>
#include <iomanip>
#include <fstream>
#include <sys/types.h>

// bulk extractor
#include "config.h"
#include "be13_api/bulk_extractor_i.h"

// sdhash
#include "sdhash/sdbf/sdbf_class.h"
#include "sdhash/sdbf/sdbf_defines.h"

// mrshv2
#include "mrshv2/header/config.h"
#include "mrshv2/header/hashing.h"
#include "mrshv2/header/bloomfilter.h"
#include "mrshv2/header/fingerprint.h"
#include "mrshv2/header/fingerprintList.h"

// user settings
static std::string fuz_mode = "none";                      // import or scan
static std::string fuz_hash_type = "sdhash";               // import or scan
static uint32_t fuz_block_size = 4096;                     // import or scan
static uint32_t fuz_step_size = 4096;                      // import or scan
static int32_t fuz_threshold = 10;                         // scan
static std::string fuz_hashfile = "fuz_hashes.txt";        // scan
// static uint32_t fuz_count = 0;

// scanner runtime modes
enum mode_type_t {MODE_NONE, MODE_SCAN, MODE_IMPORT};
static mode_type_t scanner_mode = MODE_NONE;

// mrshv2s config.h declares a MODES struct that holds variables needed in different parts of the program (e.g. for fingerprint comparison)
// config.h also defines the *mode pointer for this struct
// not to be confused with the above mode_type_t scanner_mode
MODES *mode = NULL;

static void do_sdhash_import(const class scanner_params &sp, const recursion_control_block &rcb);
static void do_sdhash_scan(const class scanner_params &sp, const recursion_control_block &rcb);
static void do_mrshv2_import(const class scanner_params &sp, const recursion_control_block &rcb);
static void do_mrshv2_scan(const class scanner_params &sp, const recursion_control_block &rcb);

// detect if block is empty
inline bool empty_sbuf(const sbuf_t &sbuf)
{
    for (size_t i=1; i<sbuf.bufsize; i++) {
        if (sbuf[i] != sbuf[0]) {
            return false;
        }
    }
    return true;    // all the same
}

// loads all sdbfs from a file into a new set
// similar to the sdbf api function sdbf_set::sdbf_set(const char *fname) but skips lines beginning with #
inline void fuz_sdbf_set(const char *fname, sdbf_set *newset)
{   
    std::string line;
    ifstream ifs(fname,ifstream::in|ios::binary);
        if (ifs.is_open()) {
            while(std::getline(ifs, line)) {

                if (line.length()==0) 
                    break;
                    
                if (line[0] == '#')
                    // skip comments
                    continue;
               
                newset->set_name((string)fname);
                sdbf *sdbfm = new sdbf(line);
                newset->add(sdbfm);
            }
        } else {
            std::cerr << "Cannot open: " << fname << "\n";
        }
        
        ifs.close();
        newset->vector_init();
}

// compares two sdbf sets and returns results
// similar to sdbf_set::compare_to_quiet(sdbf_set *other,int32_t threshold, uint32_t sample_size, int32_t thread_count, bool fast)
// but without utilizing openmp multi-threading code (bulk_extractor should handle multi-threading)
inline std::string fuz_compare_two_sets(sdbf_set *set1, sdbf_set *set2, int32_t threshold, uint32_t sample_size, bool fast, char sep = '|')
{
    std::stringstream out;
    out.fill('0');
    int tend = set2->size();
    int qend = set1->size();
    
    if (fast) {
        for (int i = 0; i < tend ; i++) {
            set1->at(i)->fast();
        }
        for (int i = 0; i < qend ; i++) {
            set1->at(i)->fast();
        }
    }
    
    for (int i = 0; i < qend ; i++) {
        for (int j = 0; j < tend ; j++) {
            int32_t score = set1->at(i)->compare(set2->at(j),sample_size);
            if (score >= threshold) {
                {
                out << set1->at(i)->name() << sep << set2->at(j)->name() ;
                if (score != -1)
                    out << sep << setw (3) << score << std::endl;
                else 
                    out << sep << score << std::endl;
                }
            }
        }
    }
    
    return out.str();
}

// loads all mrshv2 fingerprints from a file into a new fingerprint list
// similar to mrshv2s read_fingerprint_file(FINGERPRINT_LIST *fpl, FILE *handle) but skips lines beginning with #
// and only processes 1 filter per hash
inline void fuz_fp_list(const char *fname, FINGERPRINT_LIST *fpl)
{
    char delim = ':';
    // 	int amount_of_BF = 0;
    int blocks_in_last_bf = 0;
    std::string line, hex_string;
    
    ifstream ifs(fname, ifstream::in|ios::binary);
    if (ifs.is_open()) {
        // iterate through each line and parse the mrshv2 hash
        while(std::getline(ifs, line)) {
            if (line.length()==0) 
                break;
                
            if (line[0] == '#')
            // skip comments
                continue;               
            
            FINGERPRINT *fp = init_empty_fingerprint();
            add_new_fingerprint(fpl, fp);
            
            stringstream linestream(line);
            std::string item;
            int counter = 0;
            
            while (std::getline(linestream, item, delim)) {
                switch(counter) {
                    case 0:
                        // get the filename
                        strcpy(fp->file_name, item.c_str()); break;

                    case 1:
                        // get the filesize
                        fp->filesize = stoi(item); break;

                    case 2:
                        // get the count of the filters, not needed in this case since each hash has eaxactly 1 filter
                        // amount_of_BF = stoi(item);
                        break;

                    case 3:
                        // get the filter block count
                        blocks_in_last_bf = stoi(item); break;

                    case 4:
                        // get the hex fingerprint
                        hex_string = item;
                        break;

                    default:
                        std::cerr << "error parsing fingerprint file\n";
                        break;
                }
                    
                counter++;

                if (!hex_string.empty()) {
    	            // reset bf_list when we read in a LIST
    	            fp->bf_list = NULL;
    	            fp->bf_list_last_element = NULL;

                    // we only have 1 filter per hash, otherwise for(int i=0; i<=amount_of_BF;i++)...
    		        // create a bloomfilter and add it to the fingerprint
    		        BLOOMFILTER *bf = init_empty_BF();

                    // decode base64 bf to binary and fill bf
                    int len;
                    unsigned char *bfbin = (uint8_t *)b64decode((char*)hex_string.c_str(),hex_string.length(),&len);
                    memcpy(bf->array, bfbin, 256);
    		        add_new_bloomfilter(fp, bf);
                    free(bfbin);
                    
        		    // update block count;
        		    fp->bf_list_last_element->amount_of_blocks = blocks_in_last_bf;
                }
              }
        }
    } else {
        std::cerr << "Cannot open: " << fname << "\n";
    }
}

// returns a fingerprint list as std::string
inline std::string fuz_fplist_to_string(FINGERPRINT_LIST *fpl)
{
    std::stringstream fpl_str;
    FINGERPRINT *fptmp = fpl->list;
    //int j;
    fpl_str.fill('0');

	while(fptmp != NULL){                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   
		// each fingerprint

		BLOOMFILTER *bftmp = fptmp->bf_list;
		
		fpl_str << fptmp->file_name << ":" << fptmp->filesize << ":" << fptmp->amount_of_BF << ":" << fptmp->bf_list_last_element->amount_of_blocks << ":";
				
		while (bftmp != NULL) {
    	    // each bloomfilter (just 1 in our case)
            
            // new base64 encoding instead of hex encoding of original mrshv2, copied from sdhash
            // no clue why sdhash uses length+3, elaborate...
            char *b64 = b64encode((char*)bftmp->array, 256+3);
            fpl_str << b64;
            free(b64);
                    
            fpl_str << std::dec;
            // move to next bloomfilter
            bftmp = bftmp->next;
        }
    
	    fpl_str << endl;    
    
        // move to next fingerprint
	    fptmp = fptmp->next;
	}
	
	return fpl_str.str();
}

// Compares two fingerprint lists and returns results
inline std::string fuz_compare_two_fplists(FINGERPRINT_LIST *fpl1, FINGERPRINT_LIST *fpl2, char sep = '|')
{
    std::stringstream out;    
    int score;
    FINGERPRINT *tmp1 = fpl1->list;
    out.fill('0');

    while (tmp1 != NULL){
	    FINGERPRINT *tmp2 = fpl2->list;
	    
	    while (tmp2 != NULL){
		    score = fingerprint_compare(tmp1, tmp2);
		    
	        if(score >= mode->threshold)
	            out << tmp1->file_name << sep << tmp2->file_name << sep << setw(3) << score << std::endl;
	            //printf("%s | %s | %.3i \n", tmp1->file_name, tmp2->file_name, score);
	        
	        tmp2 = tmp2->next;
	    }
	    tmp1 = tmp1->next;
    }
        
    return out.str();
}   

extern "C"
void scan_fuzzyblocks(const class scanner_params &sp, const recursion_control_block &rcb)
{
	switch(sp.phase) {
        // startup
        case scanner_params::PHASE_STARTUP: {

			sp.info->name        = "fuzzyblocks";
            sp.info->author      = "Daniel Gasperschitz";
            sp.info->description = "Scanner for generating and comparing blockwise similarity hashes";
            sp.info->flags       = scanner_info::SCANNER_DISABLED;
            
            // fuz_mode
            std::stringstream ss_fuz_mode;
            ss_fuz_mode << "Operational mode [none|import|scan]\n"
                << "        none    - The scanner is active but performs no action.\n"
                << "        import  - Import block similarity hashes.\n"
                << "        scan    - Scan for matching block similiarity hashes.";
            sp.info->get_config("fuz_mode", &fuz_mode, ss_fuz_mode.str());
            
            // fuz_hash_type
            std::stringstream ss_fuz_hash_type;
            ss_fuz_hash_type
                << "Selects the similarity hash algorithm.\n"
                << "      Currently valid options are 'sdhash' (default) and 'mrshv2'.";
            sp.info->get_config("fuz_hash_type", &fuz_hash_type, ss_fuz_hash_type.str());
            
            // fuz_block_size
            sp.info->get_config("fuz_block_size", &fuz_block_size,
                         "Selects the block size to hash, in bytes (default=4096).");

            // fuz_step_size
            std::stringstream ss_fuz_step_size;
            ss_fuz_step_size
                << "Selects the step size. Scans and imports along\n"
                << "      this step value (default=4096).";
            sp.info->get_config("fuz_step_size", &fuz_step_size, ss_fuz_step_size.str());
            
            // fuz_threshold
            std::stringstream ss_fuz_threshold;
            ss_fuz_threshold
                << "Selects the threshold for similirity scores.\n"
                << "      Valid only in scan mode (default=10).";
            sp.info->get_config("fuz_threshold", &fuz_threshold, ss_fuz_threshold.str());

            // fuz_hashfile
            std::stringstream ss_fuz_hashfile;
            ss_fuz_hashfile
                << "Selects the input hashfile used for comparision. Can include path to the file.\n"
                << "      Valid only in scan mode (default=fuz_hashfile.txt).";
            sp.info->get_config("fuz_hashfile", &fuz_hashfile, ss_fuz_hashfile.str());
            
            // configure the "feature" output file depending on mode
            if (fuz_mode == "import") {
                sp.info->feature_names.insert("fuz_hashes");
            }
            
            if (fuz_mode == "scan") {
                sp.info->feature_names.insert("fuz_scores");
            }
            
            return;
        }

        // init
        case scanner_params::PHASE_INIT: {
        	// validate the input parameters

            // fuz_mode
            if (fuz_mode == "none") {
                scanner_mode = MODE_NONE;
            } else if (fuz_mode == "import") {
                scanner_mode = MODE_IMPORT;
            } else if (fuz_mode == "scan") {
                scanner_mode = MODE_SCAN;
            } else {
                // bad mode
                std::cerr << "Error.  Parameter 'fuz_mode' value '"
                          << fuz_mode << "' must be [none|import|scan].\n"
                          << "Cannot continue.\n";
                exit(1);
            }

            // fuz_hash_type
            if (fuz_hash_type != "sdhash" && fuz_hash_type != "mrshv2" ) {
                std::cerr << "Error.  Value for parameter 'fuz_hash_type' is invalid.\n"
                          << "Cannot continue.\n";
                exit(1);
            }
            
            // fuz_block_size
            if (fuz_block_size == 0) {
                std::cerr << "Error.  Value for parameter 'fuz_block_size' is invalid.\n"
                          << "Cannot continue.\n";
                exit(1);
            }
            
            // todo: allow larger block sizes too by scaling down mrshv2s BLOCK_SIZE bloomfilter parameter,
            // which dictates the amount of features produced per block
            if (fuz_hash_type == "mrshv2" && fuz_block_size > 8192) {
                fuz_block_size = 8192;
                std::cerr << "Blocksize reset to 8192 bytes, which is currently the maximum possible bytesize so bloomfilters can hold all mrshv2 features\n";
            }

            // hashdb_step_size
            if (fuz_step_size == 0) {
                std::cerr << "Error.  Value for parameter 'fuz_step_size' is invalid.\n"
                          << "Cannot continue.\n";
                exit(1);
            }
            
            if (fuz_step_size == 0) {
                std::cerr << "Error.  Value for parameter 'fuz_step_size' is invalid.\n"
                          << "Cannot continue.\n";
                exit(1);
            }

			// perform setup based on mode                        
            switch(scanner_mode) {
                case MODE_IMPORT: {                    
                    // show relevant settable options
                    std::cout << "Plugin: scan_fuzzyblocks\n"
                              << "Mode: import\n"
                              << "Hashing Scheme: " << fuz_hash_type << std::endl;                  
                                        
                    if (fuz_hash_type == "mrshv2") {                                           
                	    mode = (MODES *)malloc(sizeof(MODES));
    
                        if(mode == NULL) {
                            std::cerr << "malloc error\n";
                            exit(1);
                        }
                        
                        //set mrshv2 mode
	                    mode->compare = false;
	                    mode->gen_compare = false;
	                    mode->compareLists = false;
	                    mode->file_comparison = false;
	                    mode->helpmessage = false;
	                    mode->print = false;
	                    mode->threshold = 1;
	                    mode->recursive = false;
	                    mode->path_list_compare = false;
                	}
                    
                    return;
                }

                case MODE_SCAN: {
                    // show relevant settable options
                    std::cout << "Plugin: scan_fuzzyblocks\n"
                              << "Mode: scan\n"
                              << "Hashing Scheme: " << fuz_hash_type << std::endl;
                                            
                    if (fuz_hash_type == "mrshv2") {
                	    mode = (MODES *)malloc(sizeof(MODES));
    
                        if(mode == NULL) {
                            std::cerr << "malloc error\n";
                            exit(1);
                        }
                        
                        //set mrshv2 mode
	                    mode->compare = false;
	                    mode->gen_compare = false;
	                    mode->compareLists = false;
	                    mode->file_comparison = false;
	                    mode->helpmessage = false;
	                    mode->print = false;
	                    mode->threshold = fuz_threshold;
	                    mode->recursive = false;
	                    mode->path_list_compare = false;
                	}
                    
                    return;
                }

                case MODE_NONE: {
                    // show relevant settable options
                    return;
                }
                    
                default: {
                    // program error
                    assert(0);
                }
            }
		}
		
        // scan
        case scanner_params::PHASE_SCAN: {
            std::cout << "Data is being processed...\n" << std::endl;
        	switch(scanner_mode) {
            	case MODE_IMPORT:
                	if (fuz_hash_type == "sdhash") {
                	    do_sdhash_import(sp, rcb);
                	    return;
                	}
                	if (fuz_hash_type == "mrshv2") {
                	    do_mrshv2_import(sp, rcb);
                	    return;
                	}
                case MODE_SCAN:
                	if (fuz_hash_type == "sdhash") {
                	    do_sdhash_scan(sp, rcb);
                	    return;
                	}
                	if (fuz_hash_type == "mrshv2") {
                	    do_mrshv2_scan(sp, rcb);
                	    return;
                	}
                default:
                	// the user should have just left the scanner disabled.
                	// no action.
                	return;
            }
        }

        // shutdown
        case scanner_params::PHASE_SHUTDOWN: {
            
            if (mode != NULL) {
                free(mode);
            }
            
            return;
        }

        // there are no other bulk_extractor scanner state actions
        default: {
            // no action for other bulk_extractor scanner states
            return;
        }
    }
}

// perform sdhash import
static void do_sdhash_import(const class scanner_params &sp, const recursion_control_block &rcb) 
{
	// get the feature recorder
    feature_recorder* fuz_hashes_recorder = sp.fs.get_name("fuz_hashes");
    
    // create sdbf set that stores all the sdbf hashes
    sdbf_set *set1 = new sdbf_set();
    
    // create vector that stores pointers to the sdbf hash names
    //set1->set_name("test");
    std::vector <string *> sdnames;
	
	// create reference to the sbuf
	const sbuf_t& sbuf = sp.sbuf;
	
	// iterate through the blocks of the sbuf and hash each block
    for (size_t offset=0; offset<sbuf.pagesize; offset+=fuz_step_size) {
		// create a child sbuf of what we would hash
        const sbuf_t sbuf_to_hash(sbuf, offset, fuz_block_size);
        
		// ignore empty blocks
        if (empty_sbuf(sbuf_to_hash)){
        	continue;
        }
        
        // sdbf name = filename + forensic path of the processed block
        sdnames.push_back(new string(sp.fs.get_input_fname() + "-" + sbuf_to_hash.pos0.str()));
        //maybe use offset/fuz_block_size       

        // sdbf api: sdbf::sdbf(const char *name, char *str, uint32_t dd_block_size, uint64_t length,index_info *info)
        // generates a new sdbf from a char *string
        // the sdbf name is const char *string hence the above dynamic string allocation and the sdnames vector
        sdbf *sdbf_block = new sdbf(sdnames.back()->c_str(), (char*)sbuf_to_hash.buf, fuz_block_size, sbuf_to_hash.bufsize, NULL);
        set1->add(sdbf_block);
	}
	
	set1->vector_init();
	
	//sdhashs to_string function appends endl at the end of the string. this pops the endl to prevent writing blank lines to the output file
	std::string set1_str = set1->to_string();
	set1_str.erase(set1_str.end()-1);
	fuz_hashes_recorder->write(set1_str);
	
    // delete allocations
	for(size_t i=0; i<sdnames.size(); i++) {
	    delete sdnames[i];
	}
	
	delete set1;
}

// perform sdhash scan
static void do_sdhash_scan(const class scanner_params &sp, const recursion_control_block &rcb) 
{
    // get the feature recorder
    feature_recorder* fuz_scores_recorder = sp.fs.get_name("fuz_scores");
    
    // create sdbf sets that store all the sdbf hashes
    sdbf_set *set1 = new sdbf_set();
    sdbf_set *set2 = new sdbf_set();

    // loads all sdbfs from a file into a new set
    fuz_sdbf_set(fuz_hashfile.c_str(), set2);
    
    if(!set2->empty()) {
        // create vector that stores pointers to the sdbf hash names
        //set1->set_name("test");
        std::vector <string *> sdnames;
	
	    // create reference to the sbuf
	    const sbuf_t& sbuf = sp.sbuf;
	
	    // iterate through the blocks of the sbuf and hash each block
        for (size_t offset=0; offset<sbuf.pagesize; offset+=fuz_step_size) {
		    // create a child sbuf of what we would hash
            const sbuf_t sbuf_to_hash(sbuf, offset, fuz_block_size);
            
		    // ignore empty blocks
            if (empty_sbuf(sbuf_to_hash)){
            	continue;
            }
            
            // sdbf name = filename + forensic path of the processed block
            sdnames.push_back(new string(sp.fs.get_input_fname() + "-" + sbuf_to_hash.pos0.str()));
        	
        	// sdbf api: sdbf::sdbf(const char *name, char *str, uint32_t dd_block_size, uint64_t length,index_info *info)
            // generates a new sdbf from a char *string
            // the sdbf name is const char *string hence the above dynamic string allocation and the sdnames vector
            sdbf *sdbf_block = new sdbf(sdnames.back()->c_str(), (char*)sbuf_to_hash.buf, fuz_block_size, sbuf_to_hash.bufsize, NULL);
            set1->add(sdbf_block);     
	    }
	
	    set1->vector_init();

        std::string fuz_results = fuz_compare_two_sets(set1, set2, fuz_threshold, 0, false);
        
        //sdbfs compare function appends endl at the end of the string. this pops the endl to prevent writing blank lines to the output file
        fuz_results.erase(fuz_results.end()-1);
        fuz_scores_recorder->write(fuz_results);
	
        // delete allocations
	    for(size_t i=0; i<sdnames.size(); i++) {
	        delete sdnames[i];
	    }
    } else {
        cout << "Nothing to compare.\n" << endl;
    }
                                     
    delete set1;
    delete set2;
}

// perform mrshv2 import
static void do_mrshv2_import(const class scanner_params &sp, const recursion_control_block &rcb) 
{ 
    // get the feature recorder
    feature_recorder* fuz_hashes_recorder = sp.fs.get_name("fuz_hashes");
	
	// create reference to the sbuf
	const sbuf_t& sbuf = sp.sbuf;
	
	// create fingerprint list that stores all the block fingerprints
	FINGERPRINT_LIST *fpl = init_empty_fingerprintList();
	
	
	// iterate through the blocks of the sbuf and hash each block
    for (size_t offset=0; offset<sbuf.pagesize; offset+=fuz_step_size) {    
        // create a child sbuf of what we would hash
        const sbuf_t sbuf_to_hash(sbuf, offset, fuz_block_size);
        
        // create empty fingerprint for the block
        FINGERPRINT *fp_block = init_empty_fingerprint();
        
        // mrshv2 only allows fingerprint names with a maximum of 200 characters including terminating null
        std::string fp_block_name = sp.fs.get_input_fname() + "-" + sbuf_to_hash.pos0.str();
        if (fp_block_name.length() > 200) {
            // erase beginning of the string if name becomes too long (for the lack of a better solution for now)
            fp_block_name = fp_block_name.erase(0, fp_block_name.length()-200);
        }
        strcpy(fp_block->file_name , fp_block_name.c_str());
        
		// ignore empty blocks
        if (empty_sbuf(sbuf_to_hash)){
        	continue;
        }
        
        // mrshv2 hashing function for a (packet)buffer
        // int hashPacketBuffer(FINGERPRINT *fingerprint, const unsigned char *packet, const size_t length)
        hashPacketBuffer(fp_block, (unsigned char *)sbuf_to_hash.buf, fuz_block_size);
        
  		// add block fingerprint to fp list
  		add_new_fingerprint(fpl, fp_block);
  		
  		// fingerprint_destroy(fp_block) not needed if fps are added to fplist
    }
    
    //print_fingerprintList(fpl);
    
    // write hashes to file
    std::string fplist_str = fuz_fplist_to_string(fpl);
	fplist_str.erase(fplist_str.end()-1);
	fuz_hashes_recorder->write(fplist_str);
    
    fingerprintList_destroy(fpl);
}

// perform mrshv2 scan
static void do_mrshv2_scan(const class scanner_params &sp, const recursion_control_block &rcb) 
{
    // get the feature recorder
    feature_recorder* fuz_scores_recorder = sp.fs.get_name("fuz_scores");
    
    // create reference to the sbuf
	const sbuf_t& sbuf = sp.sbuf;
    
    // create fingerprint list that stores all the block fingerprints
	FINGERPRINT_LIST *fpl1 = init_empty_fingerprintList();
	FINGERPRINT_LIST *fpl2 = init_empty_fingerprintList();
    
    // load fingerprints from file 
    fuz_fp_list(fuz_hashfile.c_str(), fpl1);
    
    if (fpl1->size != 0) {
        // iterate through the blocks of the sbuf and hash each block
        for (size_t offset=0; offset<sbuf.pagesize; offset+=fuz_step_size) {
            // create a child sbuf of what we would hash
            const sbuf_t sbuf_to_hash(sbuf, offset, fuz_block_size);
            
            // create empty fingerprint for the block
            FINGERPRINT *fp_block = init_empty_fingerprint();
            
            // mrshv2 only allows fingerprint names with a maximum of 200 characters including terminating null
            std::string fp_block_name = sp.fs.get_input_fname() + "-" + sbuf_to_hash.pos0.str();
            if (fp_block_name.length() > 200) {
                // erase beginning of the string if name becomes too long (for the lack of a better solution for now)
                fp_block_name = fp_block_name.erase(0, fp_block_name.length()-200);
            }
            strcpy(fp_block->file_name , fp_block_name.c_str());
            
	        // ignore empty blocks
            if (empty_sbuf(sbuf_to_hash)){
            	continue;
            }
            
            // mrshv2 hashing function for a (packet)buffer
            // int hashPacketBuffer(FINGERPRINT *fingerprint, const unsigned char *packet, const size_t length)
            hashPacketBuffer(fp_block, (unsigned char *)sbuf_to_hash.buf, fuz_block_size);
            
	        // add block fingerprint to fp list
	        add_new_fingerprint(fpl2, fp_block);
        }

        // compare fingerprint lists
        std::string fuz_results = fuz_compare_two_fplists(fpl1, fpl2);

        // pop last endl to prevent writing blank lines and write scores
        fuz_results.erase(fuz_results.end()-1);
        fuz_scores_recorder->write(fuz_results);
    } else {
        cout << "Nothing to compare.\n" << endl;
    }

    //print_fingerprintList(fpl2);
    fingerprintList_destroy(fpl1);
    fingerprintList_destroy(fpl2);  
}
