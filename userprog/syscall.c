#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "filesys/filesys.h"
#include "userprog/process.h"
#include "filesys/file.h"
#include "threads/synch.h"
#include "lib/string.h"
#include "threads/palloc.h"


void syscall_entry (void);
void syscall_handler (struct intr_frame *);
void check_address(void* addr);
void halt(void);
void exit(int status);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int exec (const char *cmd_line);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
struct file* find_file(int fd);
int fork (const char *thread_name,struct intr_frame* if_);
int wait (int pid);
void close (int fd);
void seek (int fd, unsigned position);
unsigned tell (int fd);
int add_file(struct file *file);
int dup2(int oldfd, int newfd);


/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

static struct lock lock;

void
syscall_init (void) {
	lock_init(&lock);
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	uint64_t number = f->R.rax;
	switch (number)
	{
	case SYS_HALT:
		halt();
		break;
	case SYS_EXIT:
		exit(f->R.rdi);
		break;
	case SYS_CREATE:
		f->R.rax = create(f->R.rdi,f->R.rsi);
		break;
	case SYS_REMOVE:
		f->R.rax = remove(f->R.rdi);
		break;
	case SYS_EXEC:
		f->R.rax = exec(f->R.rdi);
		break;
	case SYS_OPEN:
		f->R.rax = open(f->R.rdi);
		break;
	case SYS_FILESIZE:
		f->R.rax = filesize(f->R.rdi);
		break;
	case SYS_READ:
		f->R.rax = read(f->R.rdi,f->R.rsi,f->R.rdx);
		break;
	case SYS_WRITE:
		f->R.rax = write(f->R.rdi,f->R.rsi,f->R.rdx);
		break;
	case SYS_FORK:
		f->R.rax = fork(f->R.rdi,f);
		break;
	case SYS_WAIT:
		f->R.rax = wait(f->R.rdi);
		break;
	case SYS_CLOSE:
		close(f->R.rdi);
		break;
	case SYS_SEEK:
		seek(f->R.rdi,f->R.rsi);
		break;
	case SYS_TELL:
		f->R.rax = tell(f->R.rdi);
		break;
	case SYS_DUP2:
		f->R.rax = dup2(f->R.rdi,f->R.rsi);
		break;
	default:
		thread_exit();
		break;
	}
}

/* Project2-2 User Memory Access */
void check_address(void* addr){
	struct thread* curr = thread_current();
	if(!is_user_vaddr(addr) || addr == NULL || pml4_get_page(curr->pml4,addr) == NULL){
		exit(-1);
	}
}

/* Project2-3 System Call */
void halt(void){
	power_off();
}

/* Project2-3 System Call */
void exit (int status){
	/* status가 1로 넘어온 경우는 정상 종료 */
	struct thread* curr = thread_current();
	curr->exit_status = status;
	printf("%s: exit(%d)\n",curr->name, status);
	thread_exit();
}

/* Project2-3 System Call */
bool create(const char *file, unsigned initial_size){
	check_address(file);
	return filesys_create(file,initial_size);
}

/* Project2-3 System Call */
bool remove(const char *file){
	check_address(file);
	if(filesys_remove(file)){
		return true;
	}
	return false;
}

/* Project2-3 System Call */
int exec (const char *cmd_line){
	check_address(cmd_line);
	char* copy = palloc_get_page(PAL_ZERO);
	if(copy == NULL){
		exit(-1);
	}
	strlcpy(copy,cmd_line,strlen(cmd_line) + 1);
	struct thread* curr = thread_current();
	if (process_exec(copy) == -1){
		return -1;
	}
	NOT_REACHED();
	return 0;
}

/* Project2-3 System Call */
int open (const char *file){
	check_address(file);
	lock_acquire(&lock);
	struct file *fileobj = filesys_open(file);

	if (fileobj == NULL) {
		return -1;
	}

	int fd = add_file(fileobj); // fdt : file data table

	// fd table이 가득 찼다면
	if (fd == -1) {
		file_close(fileobj);
	}
	lock_release(&lock);
	return fd;
}

int add_file(struct file *file){
	struct thread *cur = thread_current();
	struct file **fdt = cur->fd_table;

	/* fd의 위치가 제한 범위를 넘지 않고, fd_table의 인덱스 위치와 일치한다면 */
	// cur->fd_idx 가 어디있지? -> thread.h의 thread 구조체 안에 fd_table과 함께 선언해준다.
	// 제한범위를 나타낼 FDCOUNT_LIMIT 등도 thread.h 파일 내에 선언(#define)해준다.
	while (cur->fd_idx < FDCOUNT_LIMIT && fdt[cur->fd_idx]) {
		cur->fd_idx++;
	}

	// fdt가 가득 찼다면
	if (cur->fd_idx >= FDCOUNT_LIMIT)
		return -1;

	fdt[cur->fd_idx] = file;
	return cur->fd_idx;
}

/* Project2-3 System Call */
int filesize (int fd){
	if(fd < 0 || fd >= FDCOUNT_LIMIT){
		return -1;
	}
	struct thread* curr = thread_current();
	struct file** fdt = curr->fd_table;
	struct file* ret_file = fdt[fd];
	if(ret_file == NULL){
		return -1;
	}
	return file_length(ret_file);
}

/* Project2-3 System Call */
int read (int fd, void *buffer, unsigned size){
	check_address(buffer);
	off_t char_count;
	/* Extra : Dup2 */
	struct file* ret_file = find_file(fd);
	if (ret_file == NULL){
			return -1;
		}
	/* Keyboard 입력 처리 */
	if(fd == 0){
		if(thread_current()->stdin_count == 0){
			NOT_REACHED();
			remove_file(fd);
			return -1;
		}
		while (char_count < size)
			{
				char key = input_getc();
				*(char*)buffer = key;
				char_count++;
				(char*)buffer++;
				if (key == '\0'){
					break;
				}
			}
		
	}
	else if(fd == 1){
		return -1;
	}
	else{
		lock_acquire(&lock);
		char_count = file_read(ret_file,buffer,size);
		lock_release(&lock);
	}
	return char_count;
}

/* Project2-3 System Call */
int write (int fd, const void *buffer, unsigned size) {
	check_address(buffer);
	off_t write_size = 0;
	/* Extra : Dup2*/
	struct file* ret_file = find_file(fd);
	if (ret_file == NULL){
		return -1;
	}
    if (fd == 1) {
		if(thread_current()->stdout_count == 0){
			return -1;
		}
        putbuf(buffer, size);
        return size;
    }else if(fd == 0){
		return -1;
	}else{
		lock_acquire(&lock);
		write_size = file_write(ret_file,buffer,size);
		lock_release(&lock);
	} 
	return write_size;
}

/* Project2-3 System Call */
struct file* find_file(int fd){
	struct thread* curr = thread_current();
	if(fd < 0 || fd >= FDCOUNT_LIMIT){
		return NULL;
	}
	return curr->fd_table[fd];
}

/* Project2-3 System Call */
int fork (const char *thread_name,struct intr_frame* if_){
	check_address(thread_name);
	return process_fork(thread_name,if_);
}

/* Project2-3 System Call */
int wait (int pid){
	return process_wait(pid);
}

/* Project2-3 System Call */
void close (int fd){
	struct file* close_file = find_file(fd);
	if (close_file == NULL) {
		return;
	}
	/* Dup 2 */
	struct thread* curr = thread_current();
	if(fd == 0 || close_file == STDIN){
		curr->stdin_count--;
	}else if(fd == 1 || close_file == STDOUT){
		curr->stdout_count--;
	}
	remove_file(fd);
	if(fd <= 1 || close_file <= 2){
		return;
	}
	if(close_file->dup_count == 0){
		file_close(close_file); 
	}else{
		close_file->dup_count--;
	}
}

void remove_file(int fd)
{
	struct thread *cur = thread_current();

	// Error - invalid fd
	if (fd < 0 || fd >= FDCOUNT_LIMIT)
		return;

	cur->fd_table[fd] = NULL;
}


/* Project2-3 System Call */
void seek (int fd, unsigned position){
	struct file* file = find_file(fd);
	file_seek(file,position);
}

unsigned tell (int fd){
	struct file* file = find_file(fd);
	return file_tell(file);
}

int dup2(int oldfd, int newfd){
	/* Oldfd File Validation */
	struct file* old_file = find_file(oldfd);
	if(old_file == NULL){
		return -1;
	}
	if (oldfd == newfd){
		return newfd;
	}
	/* Check old_file STDIN or STDOUT*/
	struct thread* curr = thread_current();

	if(old_file == STDIN){
		curr->stdin_count++;
	}else if(old_file == STDOUT){
		curr->stdout_count++;
	}else{
		old_file->dup_count++;
	}
	/* Close Newfd File */
	close(newfd);
	curr->fd_table[newfd] = old_file;
	return newfd;
}