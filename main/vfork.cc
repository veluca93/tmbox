#include <sys/syscall.h>
#include <unistd.h>

int main() {
  vfork();
  syscall(SYS_exit, 0);
}
