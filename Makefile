#
# Doodling
#


OBJ=list.o interval.o time.o
HDR=rmc_common.h

CFLAGS = -g -DINCLUDE_TEST
.PHONY: all clean


all: $(OBJ) rmc_test

rmc_test: $(OBJ) rmc_test.o
	$(CC) $(CFLAGS) $^ -o $@

clean:
	rm -f $(OBJ) *~ rmc_test.o rmc_test

$(OBJ): $(HDR)
