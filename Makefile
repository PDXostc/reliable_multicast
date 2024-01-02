#
# Makefile to build binaries, tests, tarballs, and debian packages.
# To make life easier, consider using the Reliable Multicast build docker container:
# github.com/magnusfeuer/rmc-docker-build
# 

OBJ= pub.o \
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

INST_HDR=reliable_multicast.h \
		rmc_list.h \
		rmc_list_template.h \
		rmc_log.h

HDR=    ${INST_HDR} \
		rmc_proto_test_common.h \
		rmc_pub.h \
		rmc_sub.h \
		circular_buffer.h \
		rmc_protocol.h

LIB_TARGET=librmc.a
VERSION ?= $(shell grep -v '#' VERSION)
VERSION_MAJOR ?= $(word 1, $(subst ., ,$(VERSION)))
LIB_SO_TARGET=librmc.so.${VERSION}
LIB_SO_SONAME_TARGET=librmc.so.${VERSION_MAJOR}
ARCHITECTURE=amd64
TEST_TARGET=rmc_test

#
# Has fallen behind. Untested.
#
WIRESHARK_TARGET=rmc_wireshark_plugin.so
DESTDIR ?= /usr/local
CFLAGS ?= -O2 -fpic -Wall -D_GNU_SOURCE

PACKAGE_BASE_NAME=reliable-multicast
DEBIAN_PACKAGE_BASE_NAME=${PACKAGE_BASE_NAME}_${VERSION}-1_${ARCHITECTURE}
DEBIAN_PACKAGE_NAME=${DEBIAN_PACKAGE_BASE_NAME}.deb
DEBIAN_PACKAGE_DEV_NAME=${DEBIAN_PACKAGE_BASE_NAME}-dev.deb

TARBALL_BASE_NAME=${PACKAGE_BASE_NAME}-${VERSION}
TARBALL_NAME=${TARBALL_BASE_NAME}.tar.gz

.PHONY: all clean etags print_obj install uninstall tar debian

all: $(LIB_TARGET) $(LIB_SO_TARGET) $(TEST_TARGET)

print_obj:
	@echo $(patsubst %,${CURDIR}/%, $(OBJ))

wireshark: $(WIRESHARK_TARGET)

$(TEST_TARGET): $(LIB_SO_TARGET) $(OBJ) $(TEST_OBJ)
	$(CC) $(CFLAGS) -L. -lrmc $^ -o $@

$(LIB_TARGET): $(OBJ)
	ar q $(LIB_TARGET) $(OBJ)

$(LIB_SO_TARGET): $(OBJ)
	$(CC)  -shared $(CFLAGS) -o $(LIB_SO_TARGET) $(OBJ)

install: all uninstall
	install -d ${DESTDIR}/bin
	install -d ${DESTDIR}/lib
	install -d ${DESTDIR}/include
	install -m 0644 ${LIB_TARGET} ${DESTDIR}/lib
	install -m 0644 ${LIB_SO_TARGET} ${DESTDIR}/lib/
	(cd ${DESTDIR}/lib && ln -s ${LIB_SO_TARGET} ${LIB_SO_SONAME_TARGET})
	install -m 0755 ${TEST_TARGET} ${DESTDIR}/bin/
	install -m 0644 ${INST_HDR} ${DESTDIR}/include

uninstall:
	rm -f ${DESTDIR}/lib/${LIB_TARGET}
	rm -f ${DESTDIR}/lib/${LIB_SO_TARGET}
	rm -f ${DESTDIR}/lib/${LIB_SO_SONAME_TARGET}
	rm -f ${DESTDIR}/bin/${TEST_TARGET}
	-(cd ${DESTDIR}/include && rm -f ${INST_HDR})

tar: ${TARBALL_NAME}

${TARBALL_NAME}: clean
	tar  -cvzf ${@} --transform "s,^,${TARBALL_BASE_NAME}/,"  *


# Requires fpm https://fpm.readthedocs.io/en/v1.15.1/index.html
#
debian: ${DEBIAN_PACKAGE_DEV_NAME} ${DEBIAN_PACKAGE_NAME} 

${DEBIAN_PACKAGE_NAME}: DESTDIR=/tmp/rmc-install
${DEBIAN_PACKAGE_NAME}: install
	fpm -s dir -t deb \
		-p ${@} \
		--name ${PACKAGE_BASE_NAME} \
		--license mplv2 \
		--version ${VERSION} \
		--architecture ${ARCHITECTURE} \
		--deb-shlibs "librmc ${VERSION_MAJOR} ${LIB_SO_SONAME_TARGET} (>= ${VERSION})" \
		--depends "libc6 (>= 2.31)" \
		--description "Reliable Multicast library" \
		--url "https://github.com/magnusfeuer/reliable_multicast" \
		--maintainer "Magnus Feuer" \
		${DESTDIR}/lib/librmc.so.${VERSION_MAJOR}=/usr/local/lib/librmc.so.${VERSION_MAJOR} \
		${DESTDIR}/lib/librmc.so.${VERSION}=/usr/local/lib/librmc.so.${VERSION} \
		${DESTDIR}/bin/rmc_test=/usr/local/bin/rmc_test

${DEBIAN_PACKAGE_DEV_NAME}: DESTDIR=/tmp/rmc-install
${DEBIAN_PACKAGE_DEV_NAME}: install
	fpm -s dir -t deb \
		-p ${@} \
		--name ${PACKAGE_BASE_NAME} \
		--license mplv2 \
		--version ${VERSION} \
		--architecture any \
		--description "Reliable Multicast development package" \
		--url "https://github.com/magnusfeuer/reliable_multicast" \
		--maintainer "Magnus Feuer" \
		${DESTDIR}/include/reliable_multicast.h=/usr/local/include/reliable_multicast.h \
		${DESTDIR}/include/rmc_list.h=/usr/local/include/rmc_list.h \
		${DESTDIR}/include/rmc_list_template.h=/usr/local/include/rmc_list_template.h

etags:
	@rm -f TAGS
	find . -name '*.h' -o -name '*.c' -print | etags -

clean:
	rm -f $(OBJ) *~ $(TEST_TARGET) $(TEST_OBJ) $(WIRESHARK_TARGET) $(LIB_TARGET) $(LIB_SO_TARGET) \
		${DEBIAN_PACKAGE_NAME} ${DEBIAN_PACKAGE_DEV_NAME} \
		${TARBALL_NAME}


$(OBJ): $(HDR) Makefile

$(TEST_OBJ): $(HDR) Makefile

$(WIRESHARK_TARGET): rmc_wireshark_plugin.c
	$(CC) `pkg-config --cflags wireshark` `pkg-config --libs wireshark` -fpic -shared $^ -o $@
