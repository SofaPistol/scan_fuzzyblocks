PROJECT_SRC = ./src/util.c src/hashing.c src/bloomfilter.c src/fingerprint.c src/fingerprintList.c src/helper.c

C_OBJECT_FILES=$(patsubst %.c,%.o,$(PROJECT_SRC))

NAME=mrshv2

SLIBNAME=lib$(NAME).a

all: $(SLIBNAME)

%.o : %.c
	gcc -c $< -o $@ -fPIC -w -std=c99 -O3 -D_BSD_SOURCE -lcrypto -lm

# custom build
$(SLIBNAME): $(C_OBJECT_FILES)
	ar rcs $(SLIBNAME) $(C_OBJECT_FILES)

clean:
	rm -f $(C_OBJECT_FILES) $(SLIBNAME)

#for DT_DIR feature to work, need to have the _BSD_SOURCE  feature test macro defined. THese are not standard, and GCC does not define the macro when compiling for C99
# -lm: -l means link a library and -m means a math library. Without this option 




