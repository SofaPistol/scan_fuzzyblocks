PROGRAM=scan_fuzzyblocks.so

# paths to external dependencies.
MRSHV2_PATH=mrshv2
SDHASH_PATH=sdhash

# bulk extractor full path variable. overwrite if necessary.
BE_ABS_PATH=$(HOME)/bulk_extractor

CXX=g++
LD=$(CXX)

CXXFLAGS=-g -pthread -g -O3 -std=c++11 -Wall -MD -D_FORTIFY_SOURCE=2 -Wpointer-arith -Wshadow -Wwrite-strings -Wcast-align -Wredundant-decls -Wdisabled-optimization -Wfloat-equal -Wmultichar -Wmissing-noreturn -Woverloaded-virtual -Wsign-promo -funit-at-a-time -Weffc++ -fPIC -D_FORTIFY_SOURCE=2
LDFLAGS=-shared

INCLUDES=-I./ \
	-I$(BE_ABS_PATH) \
	-I$(BE_ABS_PATH)/src \
	-I$(SDHASH_PATH)/external

LIBRARY_PATHS=-L$(SDHASH_PATH) \
	-L$(SDHASH_PATH)/external/stage/lib \
	-L$(MRSHV2_PATH)

LIBRARIES=-lprotobuf \
	-lsdbf \
	-lmrshv2 \
	-lboost_system \
	-lboost_filesystem \
	-lboost_thread

C_SOURCE_FILES=
CXX_SOURCE_FILES=src/scan_fuzzyblocks.cpp

C_OBJECT_FILES=
CXX_OBJECT_FILES=$(patsubst %.cpp,%.o,$(CXX_SOURCE_FILES))

EXT_OBJECT_FILES=$(BE_ABS_PATH)/src/be13_api/sbuf.o

# all object files necessary for linking.
OBJECT_FILES=$(EXT_OBJECT_FILES) $(C_OBJECT_FILES) $(CXX_OBJECT_FILES)


all: $(PROGRAM)

# compile cpp files.
%.o: %.cpp
	$(CXX) -c $< -o $@ $(CXXFLAGS) $(INCLUDES)

# compile c files.
%.o: %.c
	@echo nothing to do here.

# create shared library plugin.
$(PROGRAM): $(OBJECT_FILES)
	$(LD) $(LDFLAGS) -o $(PROGRAM) $(LIBRARY_PATHS) $(OBJECT_FILES) $(LIBRARIES)

# copy plugin to one of bulk_extractors search directories.
install:
	mkdir -p /usr/local/lib/bulk_extractor
	cp $(PROGRAM) /usr/local/lib/bulk_extractor

# clean-up routine.
clean:
	rm -f $(PROGRAM) $(CXX_OBJECT_FILES) $(C_OBJECT_FILES)


