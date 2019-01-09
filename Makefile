#
# Doodling
#


# OBJ=list.o interval.o time.o pub.o
OBJ= 	common.o \
	pub.o \
	time.o \
	sub.o \
	circular_buffer.o \
	rmc_connection.o \
	rmc_protocol.o \
	rmc_sub_packet.o \
	rmc_pub_packet.o \
	rmc_sub_context.o \
	rmc_pub_context.o \
	rmc_sub_read.o \
	rmc_pub_read.o \
	rmc_sub_write.o \
	rmc_pub_write.o \
	rmc_pub_timeout.o \
	rmc_sub_timeout.o \
	rmc_log.o

TEST_OBJ = sub_interval_test.o \
	rmc_proto_test_common.o \
	rmc_proto_test_pub.o \
	rmc_proto_test_sub.o \
	rmc_log.o \
	pub_test.o \
	list_test.o \
	rmc_test.o \
	sub_test.o \
	circular_buffer_test.o

HDR= rmc_common.h \
		rmc_proto_test_common.h \
		rmc_list_template.h \
		rmc_pub.h \
		reliable_multicast.h \
		rmc_sub.h \
		rmc_log.h \
		circular_buffer.h \
		rmc_protocol.h

LIB_TARGET=librmc.a
LIB_SO_TARGET=librmc.so
TEST_TARGET=rmc_test
WIRESHARK_TARGET=rmc_wireshark_plugin.so

CFLAGS = -ggdb -fpic
.PHONY: all clean etags print_obj


all: $(LIB_TARGET) $(LIB_SO_TARGET) $(TEST_TARGET)  etags

print_obj:
	@echo $(patsubst %,${CURDIR}/%, $(OBJ))

wireshark: $(WIRESHARK_TARGET)

$(TEST_TARGET): $(LIB_TARGET) $(OBJ) $(TEST_OBJ)
	$(CC) $(CFLAGS) -L. -lrmc $^ -o $@

$(LIB_TARGET): $(OBJ)
	ar q $(LIB_TARGET) $(OBJ)

$(LIB_SO_TARGET): $(OBJ)
	gcc -shared -o $(LIB_SO_TARGET) $(OBJ)

etags: 
	@rm -f TAGS
	find . -name '*.h' -o -name '*.c' -print | etags -

clean:
	rm -f $(OBJ) *~ $(TEST_TARGET) $(TEST_OBJ) $(WIRESHARK_TARGET) $(LIB_TARGET) $(LIB_SO_TARGET)

$(OBJ): $(HDR) Makefile 

$(TEST_OBJ): $(HDR) Makefile

$(WIRESHARK_TARGET): rmc_wireshark_plugin.c
	gcc `pkg-config --cflags wireshark` `pkg-config --libs wireshark` -fpic -shared $^ -o $@

