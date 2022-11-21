#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "filesys.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);
void check_address(void* addr);
void halt(void);
void exit(int status);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);

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

void
syscall_init (void) {
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
	case SYS_CREATE:
		create(f->R.rdi,f->R.rsi);
	case SYS_REMOVE:
		remove(f->R.rdi);
	default:
		break;
	}
	printf ("system call!\n");
	thread_exit ();
}

/* Project2-2 User Memory Access */
void check_address(void* addr){
	if(!is_user_vaddr(addr)){
		exit(-1);
	}
}

/* Project2-2 User Memory Access */
void halt(void){
	power_off();
}

/* Project2-2 User Memory Access */
void exit (int status){
	/* status가 1로 넘어온 경우는 정상 종료 */
	struct thread* curr = thread_current();
	printf("Process Name : %s, Status : %d \n",curr->name, status);
	thread_exit();
}

bool create(const char *file, unsigned initial_size){
	check_address(file);
	if(filesys_create(file,initial_size)){
		return true;
	}
	return false;
}

bool remove(const char *file){
	check_address(file);
	if(filesys_remove(file)){
		return true;
	}
	return false;
}