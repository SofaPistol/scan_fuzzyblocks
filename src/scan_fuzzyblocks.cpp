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
#include <vector>

// bulk extractor
#include "config.h"
#include "be13_api/bulk_extractor_i.h"

// sdhash
#include "sdhash/sdbf/sdbf_class.h"

// mrshv2
extern "C" {
#include "mrshv2/header/config.h"
#include "mrshv2/header/hashing.h"
#include "mrshv2/header/fingerprintList.h"
}

// ssdeep
#include "fuzzy.h"

struct ssdeep_digest {
    std::string name;
    char hash[FUZZY_MAX_RESULT] = {};
};

// user settings
static std::string fuz_mode = "none";                   // import or scan
static std::string fuz_hash_type = "sdhash-dd";         // import or scan
static uint32_t fuz_block_size = 4096;                  // import or scan
static uint32_t fuz_step_size = fuz_block_size;         // import or scan
static int32_t fuz_threshold = 10;                      // scan
static std::string fuz_hashfile = "fuz_hashes.txt";     // scan
static std::string fuz_sep = "|";                       // scan

// differentiate between sdhash stream and block processing
static bool fuz_sdhash_dd = true;

// scanner runtime modes
enum mode_type_t {MODE_NONE, MODE_SCAN, MODE_IMPORT};
static mode_type_t scanner_mode = MODE_NONE;

// mrshv2s config.h declares a MODES struct used in different parts of the program (e.g. for fingerprint comparison)
// not to be confused with the above mode_type_t scanner_mode
MODES *mode = NULL;

static void do_sdhash_import(const class scanner_params &sp, const recursion_control_block &rcb);
static void do_sdhash_scan(const class scanner_params &sp, const recursion_control_block &rcb);

static void do_mrshv2_import(const class scanner_params &sp, const recursion_control_block &rcb);
static void do_mrshv2_scan(const class scanner_params &sp, const recursion_control_block &rcb);

static void do_ssdeep_import(const class scanner_params &sp, const recursion_control_block &rcb);
static void do_ssdeep_scan(const class scanner_params &sp, const recursion_control_block &rcb);

// detect if block is empty
inline bool empty_sbuf(const sbuf_t &sbuf)
{
    for (size_t i = 1; i < sbuf.bufsize; i++) {
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
    ifstream ifs(fname, ifstream::in|ios::binary);
        if (ifs.is_open()) {
            while(std::getline(ifs, line)) {

                if (line.length()==0) break;
                
                // skip comments
                if (line[0] == '#') continue;
               
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
// similar to sdbf_set::compare_to_quiet(sdbf_set *other, int32_t threshold, uint32_t sample_size, int32_t thread_count, bool fast)
// but without utilizing openmp multi-threading code (bulk_extractor should handle multi-threading)
inline std::string fuz_compare_two_sets(sdbf_set *set1, sdbf_set *set2, int32_t threshold, uint32_t sample_size, bool fast)
{
    std::stringstream out;
    out.fill('0');
    int tend = set2->size();
    int qend = set1->size();

    // fast mode unused for now
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
            int32_t score = set1->at(i)->compare(set2->at(j), sample_size);
            if (score >= threshold) {
                {
                out << set1->at(i)->name() << fuz_sep << set2->at(j)->name() ;
                if (score != -1)
                    out << fuz_sep << setw (3) << score << std::endl;
                else 
                    out << fuz_sep << score << std::endl;
                }
            }
        }
    }
    
    return out.str();
}

// loads all mrshv2 fingerprints from a file into a new fingerprint list
// similar to mrshv2s read_fingerprint_file(FINGERPRINT_LIST *fpl, FILE *handle) but with b64 decoding and skipping of comment lines beginning with #
inline void fuz_fp_list(const char *fname, FINGERPRINT_LIST *fpl)
{
    char delim = ':';
    int amount_of_BF = 0, blocks_in_last_bf = 0;
    std::string line;
    char *b64_string;
    
    ifstream ifs(fname, ifstream::in|ios::binary);
    if (ifs.is_open()) {
        // iterate through each line and parse the mrshv2 hash
        while(std::getline(ifs, line)) {
            if (line.length()==0) break;
            
            // skip comments
            if (line[0] == '#') continue;               
            
            FINGERPRINT *fp = init_empty_fingerprint();
            add_new_fingerprint(fpl, fp);
            
            stringstream linestream(line);
            std::string item;
            int counter = 0;
            
            while (std::getline(linestream, item, delim)) {
                switch(counter) {
                    case 0:
                        // get the filename
                        strcpy(fp->file_name, item.c_str());
                        break;
                        
                    case 1:
                        // get the filesize
                        fp->filesize = stoi(item);
                        break;
                        
                    case 2:
                        // get the count of the filters
                        amount_of_BF = stoi(item);
                        break;
                        
                    case 3:
                        // get the filter block count
                        blocks_in_last_bf = stoi(item);
                        break;
                        
                    case 4:
                        // get the b64 fingerprint
                        b64_string = (char*)calloc(item.length()+1, sizeof(char));
                        strcpy(b64_string, item.c_str());
                        break;

                    default:
                        std::cerr << "error parsing fingerprint file\n";
                        break;
                }
                    
                counter++;

                if(b64_string!=NULL) {
                    // reset bf_list when we read in a LIST
                    fp->bf_list = NULL;
                    fp->bf_list_last_element = NULL;
                    // length of an encoded bloomfilter
                    uint32_t bf_b64_length = 4 * (FILTERSIZE/3 + 1 * (FILTERSIZE % 3 > 0 ? 1 : 0));
                    
                    for(int i=0; i<=amount_of_BF; i++) {
                        // create new bloomfilter and add it to the fingerprint
                        BLOOMFILTER *bf = init_empty_BF();
                        add_new_bloomfilter(fp, bf);
                        
                        //decode b64 filter to binary
                        int dec_len = 0;
                        unsigned char *dec_str = (uint8_t *)b64decode((char*)b64_string + i*bf_b64_length, (int)bf_b64_length, &dec_len);
                                      
                        // fill bf
                        memcpy(bf->array, dec_str, FILTERSIZE);
                        
                        bf->amount_of_blocks = MAXBLOCKS;
                        free(dec_str);
                        dec_str = NULL;
                    }
                    
                    // the last bloomfilter may not have MAXBLOCKS -> update it
                    fp->bf_list_last_element->amount_of_blocks = blocks_in_last_bf;
                    
                    free(b64_string);
                    b64_string = NULL;
                }
              }
        }
    } else {
        std::cerr << "Cannot open: " << fname << "\n";
    }
}

// returns an mrshv2 fingerprint list as std::string
inline std::string fuz_fplist_to_string(const FINGERPRINT_LIST *fpl)
{
    std::stringstream fpl_str;
    FINGERPRINT *fptmp = fpl->list;
    fpl_str.fill('0');

    while(fptmp != NULL)  {
        // each fingerprint
        
        BLOOMFILTER *bftmp = fptmp->bf_list;
        
        fpl_str << fptmp->file_name << ":" << fptmp->filesize << ":" << fptmp->amount_of_BF << ":" << fptmp->bf_list_last_element->amount_of_blocks << ":";
        
        while (bftmp != NULL) {
            // each bloomfilter
            
            // uses base64 encoding instead of hex encoding of original mrshv2
            // sadly each filter has to be encoded/decoded seperately -> slightly more padding overhead
            // (sdhash can encode multiple filters at once since all filters of an sdhash are stored in a single array)
            char *b64 = b64encode((char*)bftmp->array, FILTERSIZE);
            fpl_str << b64;
            free(b64);

            // move to next bloomfilter
            bftmp = bftmp->next;
        }

        fpl_str << endl;    
    
        // move to next fingerprint
        fptmp = fptmp->next;
    }
    
    return fpl_str.str();
}

// Compares two mrshv2 fingerprint lists and returns results
inline std::string fuz_compare_two_fplists(const FINGERPRINT_LIST *fpl1, const FINGERPRINT_LIST *fpl2)
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
                out << tmp1->file_name << fuz_sep << tmp2->file_name << fuz_sep << setw(3) << score << std::endl;
            
            tmp2 = tmp2->next;
        }
        tmp1 = tmp1->next;
    }
        
    return out.str();
}   

// loads all ssdeep hashes from a file into a new ssdeep list
inline void fuz_ssdeep_list(const char *fname, std::vector <ssdeep_digest *> &ssdeep_list)
{
    char delim = ',';
    std::string line;
    ifstream ifs(fname, ifstream::in|ios::binary);
    
    if (ifs.is_open()) {
        // iterate through each line and parse the ssdeep hash
        while(std::getline(ifs, line)) {
            if (line.length()==0) break;
            
            // skip comments 
            if (line[0] == '#') continue;               
            
            ssdeep_digest *sdg = new ssdeep_digest;
            
            stringstream linestream(line);
            std::string item;
            int counter = 0;
            
            while (std::getline(linestream, item, delim)) {
                switch(counter) {
                    case 0:
                        // get the hash
                        strcpy(sdg->hash, item.c_str());
                        break;
                    case 1:
                        // get the filename
                        sdg->name = item;
                        break;
                    default:
                        std::cerr << "error parsing fingerprint file\n";
                        break;
                }                   
                counter++;
              }
            ssdeep_list.push_back(sdg);
        }
    } else {
        std::cerr << "Cannot open: " << fname << "\n";
    }
}

// returns an ssdeep list as std::string
inline std::string fuz_ssdeep_list_to_string(const std::vector <ssdeep_digest *> &ssdeep_list)
{
    std::stringstream out;
    for(auto &sdg : ssdeep_list) {
        out << std::string(sdg->hash) << "," << sdg->name << endl;
    }   
    return out.str();
}

// Compares two ssdeep lists and returns results
inline std::string fuz_compare_two_ssdeep_lists(const std::vector <ssdeep_digest *> &ssdeep_list1, const std::vector <ssdeep_digest *> &ssdeep_list2, int32_t threshold)
{
    int score;
    std::stringstream out;
    out.fill('0');
    
    for(auto &sdg1 : ssdeep_list1) {
        for(auto &sdg2 : ssdeep_list2) {
            score = fuzzy_compare (sdg1->hash, sdg2->hash);
            if (score >= threshold) {
                out << sdg1->name << fuz_sep << sdg2->name << fuz_sep << setw(3) << score << endl;
            }
        }
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
                << "      Currently valid options are 'sdhash-dd' (default), 'sdhash', 'mrshv2' and 'ssdeep'.\n";
            sp.info->get_config("fuz_hash_type", &fuz_hash_type, ss_fuz_hash_type.str());
            
            // fuz_block_size
            sp.info->get_config("fuz_block_size", &fuz_block_size,
                         "Selects the block size to hash, in bytes (default=4096).");
            fuz_step_size = fuz_block_size;

            // fuz_step_size
            std::stringstream ss_fuz_step_size;
            ss_fuz_step_size
                << "Selects the step size. Scans and imports along\n"
                << "      this step value (default=fuz_block_size).";
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
            
            // fuz_sep
            std::stringstream ss_fuz_sep;
            ss_fuz_sep
                << "Selects the seperator for the score file.\n"
                << "      Valid only in scan mode (default=\"|\").";
            sp.info->get_config("fuz_sep", &fuz_sep, ss_fuz_sep.str());
            
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
            if (fuz_hash_type != "sdhash-dd" && fuz_hash_type != "sdhash" && fuz_hash_type != "mrshv2" && fuz_hash_type != "ssdeep") {
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

            // fuz_step_size
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
            
            if (fuz_hash_type == "sdhash") fuz_sdhash_dd = false;
            
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
                    if (fuz_hash_type == "sdhash-dd" || fuz_hash_type == "sdhash") {
                        do_sdhash_import(sp, rcb);
                        return;
                    }
                    if (fuz_hash_type == "mrshv2") {
                        do_mrshv2_import(sp, rcb);
                        return;
                    }
                    if (fuz_hash_type == "ssdeep") {
                        do_ssdeep_import(sp, rcb);
                        return;
                    }
                case MODE_SCAN:
                    if (fuz_hash_type == "sdhash-dd" || fuz_hash_type == "sdhash") {
                        do_sdhash_scan(sp, rcb);
                        return;
                    }
                    if (fuz_hash_type == "mrshv2") {
                        do_mrshv2_scan(sp, rcb);
                        return;
                    }
                    if (fuz_hash_type == "ssdeep") {
                        do_ssdeep_scan(sp, rcb);
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
    std::vector <string *> sdnames;
    
    // create reference to the sbuf
    const sbuf_t& sbuf = sp.sbuf;
    
    if(fuz_sdhash_dd) {
        // iterate through the blocks of the sbuf and hash each block
        for (size_t offset=0; offset<sbuf.pagesize; offset+=fuz_step_size) {
            // create a child sbuf of what we would hash
            const sbuf_t sbuf_to_hash(sbuf, offset, fuz_block_size);
            
            // ignore empty blocks
            if (empty_sbuf(sbuf_to_hash)) continue;
            
            // sdbf name = filename + forensic path of the processed block
            sdnames.push_back(new string(sp.fs.get_input_fname() + "-" + sbuf_to_hash.pos0.str()));       

            // sdbf api: sdbf::sdbf(const char *name, char *str, uint32_t dd_block_size, uint64_t length, index_info *info)
            // generates a new sdbf from a char *string
            sdbf *sdbf_block = new sdbf(sdnames.back()->c_str(), (char*)sbuf_to_hash.buf, fuz_block_size, sbuf_to_hash.bufsize, NULL);
            set1->add(sdbf_block);
        }
    } else {
        // iterate through the blocks of the sbuf and hash each block
        for (size_t offset=0; offset<sbuf.pagesize; offset+=fuz_step_size) {
            // create a child sbuf of what we would hash
            const sbuf_t sbuf_to_hash(sbuf, offset, fuz_block_size);
            
            // ignore empty blocks
            if (empty_sbuf(sbuf_to_hash)) continue;
            
            // sdbf name = filename + forensic path of the processed block
            sdnames.push_back(new string(sp.fs.get_input_fname() + "-" + sbuf_to_hash.pos0.str()));

            // sdbf api: sdbf::sdbf(const char *name, char *str, uint32_t dd_block_size, uint64_t length, index_info *info)
            // generates a new sdbf from a char *string
            sdbf *sdbf_block = new sdbf(sdnames.back()->c_str(), (char*)sbuf_to_hash.buf, 0, sbuf_to_hash.bufsize, NULL);
            set1->add(sdbf_block);
        }   
    }
    set1->vector_init();
    
    //pop last endl to prevent writing blank lines to the output file
    std::string set1_str = set1->to_string();
    set1_str.erase(set1_str.end()-1);
    fuz_hashes_recorder->write(set1_str);
    
    // free allocations
    for(auto &name : sdnames) delete name;
    for (uint32_t n=0; n<set1->size(); n++) delete set1->at(n);
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
        std::vector <string *> sdnames;
    
        // create reference to the sbuf
        const sbuf_t& sbuf = sp.sbuf;
        
        if(fuz_sdhash_dd) {
            // iterate through the blocks of the sbuf and hash each block
            for (size_t offset=0; offset<sbuf.pagesize; offset+=fuz_step_size) {
                // create a child sbuf of what we would hash
                const sbuf_t sbuf_to_hash(sbuf, offset, fuz_block_size);
                
                // ignore empty blocks
                if (empty_sbuf(sbuf_to_hash)) continue;
                
                // sdbf name = filename + forensic path of the processed block
                sdnames.push_back(new string(sp.fs.get_input_fname() + "-" + sbuf_to_hash.pos0.str()));
                
                // sdbf api: sdbf::sdbf(const char *name, char *str, uint32_t dd_block_size, uint64_t length, index_info *info)
                // generates a new sdbf from a char *string
                sdbf *sdbf_block = new sdbf(sdnames.back()->c_str(), (char*)sbuf_to_hash.buf, fuz_block_size, sbuf_to_hash.bufsize, NULL);
                set1->add(sdbf_block);     
            }
        } else {
            for (size_t offset=0; offset<sbuf.pagesize; offset+=fuz_step_size) {
                // create a child sbuf of what we would hash
                const sbuf_t sbuf_to_hash(sbuf, offset, fuz_block_size);
                
                // ignore empty blocks
                if (empty_sbuf(sbuf_to_hash)) continue;
                
                // sdbf name = filename + forensic path of the processed block
                sdnames.push_back(new string(sp.fs.get_input_fname() + "-" + sbuf_to_hash.pos0.str()));
                
                // sdbf api: sdbf::sdbf(const char *name, char *str, uint32_t dd_block_size, uint64_t length, index_info *info)
                // generates a new sdbf from a char *string
                sdbf *sdbf_block = new sdbf(sdnames.back()->c_str(), (char*)sbuf_to_hash.buf, 0, sbuf_to_hash.bufsize, NULL);
                set1->add(sdbf_block);     
            }
        }
        
        set1->vector_init();

        std::string fuz_results = fuz_compare_two_sets(set1, set2, fuz_threshold, 0, false);
        
        // pop last endl to prevent writing blank lines to the output file
        fuz_results.erase(fuz_results.end()-1);
        fuz_scores_recorder->write(fuz_results);
    
        // free allocations
        for(auto &name : sdnames) delete name;
        
    } else {
        cout << "Nothing to compare.\n" << endl;
    }
    
    for (uint32_t n=0; n<set1->size(); n++) delete set1->at(n);                       
    delete set1;
    for (uint32_t n=0; n<set2->size(); n++) delete set2->at(n);
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
        
        // ignore empty blocks
        if (empty_sbuf(sbuf_to_hash)) continue;
        
        // create empty fingerprint for the block
        FINGERPRINT *fp_block = init_empty_fingerprint();
        
        // mrshv2 only allows fingerprint names with a maximum of 200 characters including terminating null
        // erase beginning of the string if name becomes too long (for the lack of a better solution for now)
        std::string fp_block_name = sp.fs.get_input_fname() + "-" + sbuf_to_hash.pos0.str();
        if (fp_block_name.length() > 200) {
            fp_block_name = fp_block_name.erase(0, fp_block_name.length()-200);
        }
        strcpy(fp_block->file_name , fp_block_name.c_str());
        fp_block->filesize = fuz_block_size;
        
        // mrshv2 hashing function for a (packet)buffer
        // int hashPacketBuffer(FINGERPRINT *fingerprint, const unsigned char *packet, const size_t length)
        hashPacketBuffer(fp_block, (unsigned char *)sbuf_to_hash.buf, sbuf_to_hash.bufsize);
        
        // add block fingerprint to fp list
        add_new_fingerprint(fpl, fp_block);
        
        // fingerprint_destroy(fp_block) not needed if fps are added to fplist
    }
    
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
            
            // ignore empty blocks
            if (empty_sbuf(sbuf_to_hash)) continue;
            
            // create empty fingerprint for the block
            FINGERPRINT *fp_block = init_empty_fingerprint();
            
            // mrshv2 only allows fingerprint names with a maximum of 200 characters including terminating null
            // erase beginning of the string if name becomes too long (for the lack of a better solution for now)
            std::string fp_block_name = sp.fs.get_input_fname() + "-" + sbuf_to_hash.pos0.str();
            if (fp_block_name.length() > 200) {
                fp_block_name = fp_block_name.erase(0, fp_block_name.length()-200);
            }
            strcpy(fp_block->file_name , fp_block_name.c_str());
            fp_block->filesize = fuz_block_size;
            
            // mrshv2 hashing function for a (packet)buffer
            // int hashPacketBuffer(FINGERPRINT *fingerprint, const unsigned char *packet, const size_t length)
            hashPacketBuffer(fp_block, (unsigned char *)sbuf_to_hash.buf, sbuf_to_hash.bufsize);
            
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

    fingerprintList_destroy(fpl1);
    fingerprintList_destroy(fpl2);
}

// perform ssdeep import
static void do_ssdeep_import(const class scanner_params &sp, const recursion_control_block &rcb)
{   
    // get the feature recorder
    feature_recorder* fuz_hashes_recorder = sp.fs.get_name("fuz_hashes");
    
    // create reference to the sbuf
    const sbuf_t& sbuf = sp.sbuf;
    
    //vector to store pointers to the ssdeep digests
    std::vector <ssdeep_digest *> ssdeep_list;
    
    // iterate through the blocks of the sbuf and hash each block
    for (size_t offset=0; offset<sbuf.pagesize; offset+=fuz_step_size) {
        // create a child sbuf of what we would hash
        const sbuf_t sbuf_to_hash(sbuf, offset, fuz_block_size);
        
        // ignore empty blocks
        if (empty_sbuf(sbuf_to_hash)) continue;
        
        // create ssdeep digest for the block, push pointer to list
        ssdeep_digest *sdg = new ssdeep_digest;
        sdg->name = sp.fs.get_input_fname() + "-" + sbuf_to_hash.pos0.str();
        fuzzy_hash_buf(sbuf_to_hash.buf, sbuf_to_hash.bufsize, sdg->hash);
        ssdeep_list.push_back(sdg);
    }
    
    // write ssdeep list to file
    std::string sdg_str = fuz_ssdeep_list_to_string(ssdeep_list);
    sdg_str.erase(sdg_str.end()-1);
    fuz_hashes_recorder->write(sdg_str);
    
    // free allocations
    for(auto &sdg : ssdeep_list) delete sdg;
}

// perform ssdeep scan
static void do_ssdeep_scan(const class scanner_params &sp, const recursion_control_block &rcb)
{
    // get the feature recorder
    feature_recorder* fuz_scores_recorder = sp.fs.get_name("fuz_scores");
    
    // create reference to the sbuf
    const sbuf_t& sbuf = sp.sbuf;
    
    // vectors to store pointers to the ssdeep digests
    std::vector <ssdeep_digest *> ssdeep_list1;
    std::vector <ssdeep_digest *> ssdeep_list2;
    
    fuz_ssdeep_list(fuz_hashfile.c_str(), ssdeep_list1);
    
    if (ssdeep_list1.size() != 0) {
        // iterate through the blocks of the sbuf and hash each block
        for (size_t offset=0; offset<sbuf.pagesize; offset+=fuz_step_size) {
            // create a child sbuf of what we would hash
            const sbuf_t sbuf_to_hash(sbuf, offset, fuz_block_size);
            
            // ignore empty blocks
            if (empty_sbuf(sbuf_to_hash)) continue;
            
            // create ssdeep digest for the block, push pointer to list
            ssdeep_digest *sdg = new ssdeep_digest;
            sdg->name = sp.fs.get_input_fname() + "-" + sbuf_to_hash.pos0.str();
            fuzzy_hash_buf(sbuf_to_hash.buf, sbuf_to_hash.bufsize, sdg->hash);
            ssdeep_list2.push_back(sdg);
        }
        // compare the two ssdeep lists
        std::string fuz_results = fuz_compare_two_ssdeep_lists(ssdeep_list1, ssdeep_list2, fuz_threshold);
        
        // write results
        fuz_results.erase(fuz_results.end()-1);
        fuz_scores_recorder->write(fuz_results);
    } else {
        cout << "Nothing to compare.\n" << endl;
    }

    // free allocations
    for(auto &sdg1 : ssdeep_list1) delete sdg1;     
    for(auto &sdg2 : ssdeep_list2) delete sdg2;
}
