CC=gcc
CFLAGS=-g
TARGET:test.exe CommandParser/libcli.a
LIBS=-lpthread -L ./CommandParser -lcli
OBJS=src/hashTable/hash.o \
	 src/spf.o \
	 src/list.o \
	 src/hashTable/node_hash_routines.o \
	 src/hashTable/mac_hash_routines.o \
	 src/hashTable/arp_hash_routines.o \
	 src/hashTable/rt_hash_routines.o \
     src/graph.o \
     src/topology.o \
     src/net.o \
     src/utils.o \
     test/nwcli.o \
     src/communication.o  \
     src/layer2.o \
	 src/layer3.o \
	 src/layer4.o \
	 src/layer5.o \

test.exe:test/testapp.o ${OBJS} CommandParser/libcli.a
	${CC} ${CFLAGS} test/testapp.o ${OBJS} -o test.exe ${LIBS}
testapp.o:testapp.c
	${CC} ${CFLAGS} -c test/testapp.c -o test/testapp.o

src/hashTable/hash.o:src/hashTable/hash.c
	${CC} ${CFLAGS} -c -I . src/hashTable/hash.c -o src/hashTable/hash.o
src/hashTable/node_hash_routines.o:src/hashTable/node_hash_routines.c
	${CC} ${CFLAGS} -c -I . src/hashTable/node_hash_routines.c -o src/hashTable/node_hash_routines.o
src/hashTable/mac_hash_routines.o:src/hashTable/mac_hash_routines.c
	${CC} ${CFLAGS} -c -I . src/hashTable/mac_hash_routines.c -o src/hashTable/mac_hash_routines.o
src/hashTable/rt_hash_routines.o:src/hashTable/rt_hash_routines.c
	${CC} ${CFLAGS} -c -I . src/hashTable/rt_hash_routines.c -o src/hashTable/rt_hash_routines.o
src/hashTable/arp_hash_routines.o:src/hashTable/arp_hash_routines.c
	${CC} ${CFLAGS} -c -I . src/hashTable/arp_hash_routines.c -o src/hashTable/arp_hash_routines.o
src/graph.o:src/graph.c
	${CC} ${CFLAGS} -c -I . src/graph.c -o src/graph.o
src/topology.o:src/topology.c
	${CC} ${CFLAGS} -c -I . src/topology.c -o src/topology.o
src/net.o:src/net.c
	${CC} ${CFLAGS} -c -I . src/net.c -o src/net.o
src/utils.o:src/utils.c
	${CC} ${CFLAGS} -c -I . src/utils.c -o src/utils.o
test/nwcli.o:test/nwcli.c
	${CC} ${CFLAGS} -c -I . test/nwcli.c -o test/nwcli.o
src/communication.o:src/communication.c
	${CC} ${CFLAGS} -c -I . src/communication.c -o src/communication.o
src/layer2.o:src/layer2.c
	${CC} ${CFLAGS} -c -I . src/layer2.c -o src/layer2.o
src/layer3.o:src/layer3.c
	${CC} ${CFLAGS} -c -I . src/layer3.c -o src/layer3.o
src/layer4.o:src/layer4.c
	${CC} ${CFLAGS} -c -I . src/layer4.c -o src/layer4.o
src/layer5.o:src/layer4.c
	${CC} ${CFLAGS} -c -I . src/layer5.c -o src/layer5.o
src/spf.o:src/spf.c
	${CC} ${CFLAGS} -c -I . src/spf.c -o src/spf.o
src/list.o:src/list.c
	${CC} ${CFLAGS} -c -I . src/list.c -o src/list.o
CommandParser/libcli.a:
	(cd CommandParser; make)
clean:
	rm *exe
	(cd src; rm *.o)
	(cd src/hashTable; rm *.o)
	(cd test; rm *.o)
	(cd CommandParser; make clean)
all:
	make
	(cd CommandParser; make)
