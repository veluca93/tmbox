CXXFLAGS:=-O3 -Wall -std=c++17 -flto -g -march=native -I. -fno-exceptions
LDFLAGS:=-flto -lpthread
CXX:=g++

${TGT}build/seccomp_filter/bpf.o.tar: ${TGT}build/seccomp_filter/bpf_i386.o \
	${TGT}build/seccomp_filter/bpf_x86_64.o ${TGT}build/seccomp_filter/bpf_x32.o

BOXES=${TGT}build/unix.o.tar ${TGT}build/namespaces.o.tar

${TGT}bin/tmbox: ${BOXES}

${TGT}build/tests/process_test: ${BOXES}

${TGT}.test_outputs/build/tests/process_test: ${TGT}bin/fork \
	${TGT}bin/vfork ${TGT}bin/thread

${TGT}build/tests/misc_test: ${BOXES}

${TGT}.test_outputs/build/tests/misc_test: ${TGT}bin/abort

${TGT}build/tests/limits_test: ${BOXES}

${TGT}.test_outputs/build/tests/limits_test: ${TGT}bin/busywait \
	${TGT}bin/wait ${TGT}bin/malloc

