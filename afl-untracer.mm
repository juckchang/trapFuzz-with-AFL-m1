#include "llvm-c/Target.h"
#include "llvm-c/Disassembler.h"
#include "llvm-c/DisassemblerTypes.h"
#include "llvm/MC/MCDisassembler/MCDisassembler.h"
#include "llvm/MC/MCInst.h"
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/MC/MCInstrAnalysis.h"


using namespace llvm;

#define __USE_GNU
#define _GNU_SOURCE

#include "config.h"
#include "types.h"
#include "debug.h"

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <errno.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <pthread.h>
#include <libkern/OSCacheControl.h>

#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <sys/types.h>

#include <mach-o/dyld_images.h>
#include <mach-o/fat.h>
#include <mach-o/swap.h>
#include <mach-o/getsect.h>
#include <mach/machine.h>
#include <mach-o/loader.h>
#import <mach/vm_page_size.h>


#define MEMORY_MAP_DECREMENT 0x200000000000
#define MAX_LIB_COUNT 128



#define pageAlign(addr) (vm_address_t)((uintptr_t)(addr) & (~(vm_page_size - 1)))
#define pageAlignEnd(addr) (vm_address_t) (((addr/vm_page_size)+1) * vm_page_size )

#define shadowMeUp(addr) ((void*)(((uintptr_t)addr) + 0x200000000))

// STEP 1:

/* use stdin (1) or a file on the commandline (0) */
static u32 use_stdin = 1;
uint64_t countCover = 0;

/* This is were the testcase data is written into */
static u8 buf[10000];  // this is the maximum size for a test case! set it!

/* If you want to have debug output set this to 1, can also be set with
   AFL_DEBUG  */
static u32 debug = 0;


void dump_registers(ucontext_t* uc)
{
 printf( "\n"
	"x0:%016lx x1:%016lx x2:%016lx x3:%016lx\n"
	"x4:%016lx x5:%016lx x6:%016lx x7:%016lx\n"
	"x8:%016lx x9:%016lx x10:%016lx x11:%016lx\n"
	"x12:%016lx x13:%016lx x14:%016lx x15:%016lx\n"
	"x16:%016lx x17:%016lx x18:%016lx x19:%016lx\n"
	"x20:%016lx x21:%016lx x22:%016lx x23:%016lx\n"
	"x24:%016lx x25:%016lx x26:%016lx x27:%016lx\n"
	"x28:%016lx fp:%016lx lr:%016lx\n"
	"sp:%016lx pc:%016lx cpsr:%08lx\n",
		(unsigned long) uc->uc_mcontext->__ss.__x[0],
		(unsigned long) uc->uc_mcontext->__ss.__x[1],
		(unsigned long) uc->uc_mcontext->__ss.__x[2],
		(unsigned long) uc->uc_mcontext->__ss.__x[3],
		(unsigned long) uc->uc_mcontext->__ss.__x[4],
		(unsigned long) uc->uc_mcontext->__ss.__x[5],
		(unsigned long) uc->uc_mcontext->__ss.__x[6],
		(unsigned long) uc->uc_mcontext->__ss.__x[7],
		(unsigned long) uc->uc_mcontext->__ss.__x[8],
		(unsigned long) uc->uc_mcontext->__ss.__x[9],
		(unsigned long) uc->uc_mcontext->__ss.__x[10],
		(unsigned long) uc->uc_mcontext->__ss.__x[11],
		(unsigned long) uc->uc_mcontext->__ss.__x[12],
		(unsigned long) uc->uc_mcontext->__ss.__x[13],
		(unsigned long) uc->uc_mcontext->__ss.__x[14],
		(unsigned long) uc->uc_mcontext->__ss.__x[15],
		(unsigned long) uc->uc_mcontext->__ss.__x[16],
		(unsigned long) uc->uc_mcontext->__ss.__x[17],
		(unsigned long) uc->uc_mcontext->__ss.__x[18],
		(unsigned long) uc->uc_mcontext->__ss.__x[19],
		(unsigned long) uc->uc_mcontext->__ss.__x[20],
		(unsigned long) uc->uc_mcontext->__ss.__x[21],
		(unsigned long) uc->uc_mcontext->__ss.__x[22],
		(unsigned long) uc->uc_mcontext->__ss.__x[23],
		(unsigned long) uc->uc_mcontext->__ss.__x[24],
		(unsigned long) uc->uc_mcontext->__ss.__x[25],
		(unsigned long) uc->uc_mcontext->__ss.__x[26],
		(unsigned long) uc->uc_mcontext->__ss.__x[27],
		(unsigned long) uc->uc_mcontext->__ss.__x[28],
		(unsigned long) arm_thread_state64_get_fp(uc->uc_mcontext->__ss),
		(unsigned long) arm_thread_state64_get_lr(uc->uc_mcontext->__ss),
		(unsigned long) arm_thread_state64_get_sp(uc->uc_mcontext->__ss),
		(unsigned long) arm_thread_state64_get_pc(uc->uc_mcontext->__ss),
		(unsigned long) uc->uc_mcontext->__ss.__cpsr);
}

// END STEP 1

typedef struct library_list {
  u8 *name;
  u64 addr_start, addr_end;
} library_list_t;

__thread u32 __afl_map_size = MAP_SIZE;
__thread u32 do_exit;

static pid_t     pid = 65537;
static pthread_t __afl_thread;
static u8        __afl_dummy[MAP_SIZE];
static u8       *__afl_area_ptr = __afl_dummy;
static u8       *inputfile;  // this will point to argv[1]
static u32       len;

static library_list_t liblist[MAX_LIB_COUNT];
static u32            liblist_cnt;

static void sigtrap_handler(int signum, siginfo_t *si, void *context);
static void fuzz(void);

void *find_library(char *name) {
  kern_return_t         err;

  task_dyld_info_data_t  task_dyld_info;
  mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
  err = task_info(mach_task_self(), TASK_DYLD_INFO, (task_info_t)&task_dyld_info, &count);

  const struct dyld_all_image_infos *all_image_infos = (const struct dyld_all_image_infos *)task_dyld_info.all_image_info_addr;
  const struct dyld_image_info *image_infos = all_image_infos->infoArray;

  for (size_t i = 0; i < all_image_infos->infoArrayCount; i++) {
    const char *image_name = image_infos[i].imageFilePath;
    mach_vm_address_t image_load_address = (mach_vm_address_t)image_infos[i].imageLoadAddress;
    if (strstr(image_name, name)) {
      return (void*) image_load_address;
    }
  }

  return NULL;

}

#pragma GCC pop_options

/* Error reporting to forkserver controller */

void send_forkserver_error(int error) {

  u32 status;
  if (!error || error > 0xffff) return;
  status = (FS_OPT_ERROR | FS_OPT_SET_ERROR(error));
  if (write(FORKSRV_FD + 1, (char *)&status, 4) != 4) return;

}

/* SHM setup. */

static void __afl_map_shm(void) {

  char *id_str = getenv(SHM_ENV_VAR);
  char *ptr;

  if ((ptr = getenv("AFL_MAP_SIZE")) != NULL) {

    u32 val = atoi(ptr);
    if (val > 0) __afl_map_size = val;

  }

  if (__afl_map_size > MAP_SIZE) {

    if (__afl_map_size > FS_OPT_MAX_MAPSIZE) {

       fprintf(stderr,
              "Error: AFL++ tools *require* to set AFL_MAP_SIZE to %u to "
              "be able to run this instrumented program!\n",
              __afl_map_size);
      if (id_str) {

        send_forkserver_error(FS_ERROR_MAP_SIZE);
        exit(-1);

      }

    } else {

       fprintf(stderr,
              "Warning: AFL++ tools will need to set AFL_MAP_SIZE to %u to "
              "be able to run this instrumented program!\n",
              __afl_map_size);

    }

  }

  if (id_str) {

#ifdef USEMMAP
    const char    *shm_file_path = id_str;
    int            shm_fd = -1;
    unsigned char *shm_base = NULL;

    shm_fd = shm_open(shm_file_path, O_RDWR, 0600);
    if (shm_fd == -1) {

      send_forkserver_error(FS_ERROR_SHM_OPEN);
      exit(1);

    }

    shm_base =
        mmap(0, __afl_map_size, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);

    if (shm_base == MAP_FAILED) {

      close(shm_fd);
      shm_fd = -1;

      send_forkserver_error(FS_ERROR_MMAP);
      exit(2);

    }

    __afl_area_ptr = shm_base;
#else
    u32 shm_id = atoi(id_str);

    __afl_area_ptr = (uint8_t*)shmat(shm_id, 0, 0);

#endif

    if (__afl_area_ptr == (void *)-1) {

      send_forkserver_error(FS_ERROR_SHMAT);
      exit(1);

    }
    __afl_area_ptr[0] = 1;
  }
}

/* Fork server logic. */
inline static void __afl_start_forkserver(void) {

  u8  tmp[4] = {0, 0, 0, 0};
  u32 status = 0;

  if (__afl_map_size <= FS_OPT_MAX_MAPSIZE)
    status |= (FS_OPT_SET_MAPSIZE(__afl_map_size) | FS_OPT_MAPSIZE);
  if (status) status |= (FS_OPT_ENABLED);
  memcpy(tmp, &status, 4);

  if (write(FORKSRV_FD + 1, tmp, 4) != 4) do_exit = 1;
}

inline static u32 __afl_next_testcase(u8 *buf, u32 max_len) {
  s32 status;

  if (read(FORKSRV_FD, &status, 4) != 4) do_exit = 1;

  if (use_stdin) {
    if ((status = read(0, buf, max_len)) <= 0) exit(-1);
  } else {
    status = 1;
  }
  if (write(FORKSRV_FD + 1, &pid, 4) != 4) do_exit = 1;

  __afl_area_ptr[0] = 1;  // put something in the map

  return status;

}

inline static void __afl_end_testcase(int status) {

  if (write(FORKSRV_FD + 1, &status, 4) != 4) do_exit = 1;
  if (do_exit) exit(0);

}

void* findLibraryLoadAddress(const char* libraryFilePath)
{
	task_dyld_info_data_t task_dyld_info;
	mach_msg_type_number_t dyld_info_count = TASK_DYLD_INFO_COUNT;

	kern_return_t kr = task_info(mach_task_self(), TASK_DYLD_INFO, (task_info_t)&task_dyld_info, &dyld_info_count);
	if (kr!=KERN_SUCCESS) FATAL("failed to get task info");

	const struct dyld_all_image_infos* all_image_infos = (const struct dyld_all_image_infos*) task_dyld_info.all_image_info_addr;

	const struct dyld_image_info* image_infos = all_image_infos->infoArray;

	for(size_t i = 0; i < all_image_infos->infoArrayCount; i++)
	{
		const char* imageFilePath = image_infos[i].imageFilePath;
		mach_vm_address_t imageLoadAddress = (mach_vm_address_t)image_infos[i].imageLoadAddress;
		if (strstr(imageFilePath, libraryFilePath))
		{
			return (void*) imageLoadAddress;
		}
	}

	FATAL("Failed to find load address of %s", libraryFilePath);
	return NULL;
}

#define SHADOW(addr) ((void *)(((uintptr_t)addr) + 0x200000000))

extern void sys_icache_invalidate( void *start, size_t len);


void setup_trap_instrumentation(void) {
  struct sigaction s;
  s.sa_flags = SA_SIGINFO;
  s.sa_sigaction = sigtrap_handler;
  sigemptyset(&s.sa_mask);
  sigaction(SIGTRAP, &s, 0);

  __afl_map_size = countCover;
  if (__afl_map_size % 8) __afl_map_size = (((__afl_map_size + 7) >> 3) << 3);
}

static void sigtrap_handler(int signum, siginfo_t *info, void *context) {
  uint64_t addr;
  ucontext_t *ctx = (ucontext_t *)context;
  addr = ctx->uc_mcontext->__ss.__pc;
  
  uint32_t *fault_addr = (uint32_t *)addr;
	uint32_t *shadow 	 = (uint32_t*)shadowMeUp(fault_addr);
	
  uint32_t index = (*shadow) >> 16;
  __afl_area_ptr[index] = 128;

  if (mprotect((void*)pageAlign(fault_addr), vm_page_size, PROT_READ | PROT_WRITE) != 0) FATAL("Failed to mprotect %p writable", fault_addr);

	uint32_t orig_byte = *shadow;

	*fault_addr = orig_byte;

	sys_icache_invalidate(fault_addr, 4);
	__asm__ volatile("dmb ishst" ::: "memory");

	if (mprotect((void*)pageAlign(fault_addr), vm_page_size, PROT_READ | PROT_EXEC) != 0) FATAL("Failed to mprotect %p executable", fault_addr);
}

task_t task;

void getMachHeader(void *mach_header_address, struct mach_header_64 *mach_header)
{
	struct mach_header_64* header = (struct mach_header_64*) mach_header_address;
	*mach_header = *header;
}

void getLoadCommandsBuffer(void *mach_header_address, const struct mach_header_64 *mach_header, void **load_commands)
{
	*load_commands = (void*)((uint64_t)mach_header_address + sizeof(struct mach_header_64));
}

struct section_64 *getSection(void * section_address, const int index, const int swapBytes)
{
	struct section_64 *section = (struct section_64 *) malloc(sizeof(struct section_64));
	memcpy(section, section_address, sizeof(struct section_64));
	
	if (swapBytes)
	{
		swap_section_64(section, 1, NX_UnknownByteOrder);
	}

	return section;	
}

int instrumentASection(uint32_t* baseAddress, uint64_t shadow, uint8_t *section_data, size_t section_size)
{
	LLVMDisasmContextRef dcr = LLVMCreateDisasm(
			"arm64-darwin-unknown", // TripleName
			NULL,
			0,
			NULL,
			NULL
		);

	if (dcr == NULL) FATAL("Could not create disassembler");
	
	char Inst[1024];
	size_t pos = 0 ;
	
	while (pos < section_size)
	{
		uint32_t * PC = (uint32_t *)(section_data + pos);

		struct LLVMDisasmInstructionRes res = LLVMDisasmInstruction(dcr, (uint8_t*)PC, section_size - pos, (uint64_t) PC, Inst, sizeof(Inst));
		if (res.isBranch) {
      uint32_t *shadowAddr 	= (uint32_t *)shadowMeUp(PC);
      uint32_t origByte 		= *PC;
      *shadowAddr 			= origByte;

      uint32_t brk_instr = 0xd4200000 | (1 << 5);

      *PC = brk_instr;
      countCover++;
  	}

		pos += 4;
	}

	LLVMDisasmDispose(dcr);
	return 1;
}

void parseAndInstrument(const char * module, uint32_t* baseAddress)
{
	kern_return_t kr;
	struct mach_header_64 mach_header;
	getMachHeader(baseAddress, &mach_header);

  boolean_t swapBytes = false;
	if (mach_header.magic == MH_CIGAM || mach_header.magic == MH_CIGAM_64 || mach_header.magic == FAT_CIGAM)
		swapBytes = true;	

	void *load_commands_buffer = NULL;
	getLoadCommandsBuffer(baseAddress, &mach_header, &load_commands_buffer);

  uint64_t offset = 0;
	uint32_t moduleSize = 0;

  for (int i = 0; i < mach_header.ncmds; ++i)
	{
		struct load_command *load_cmd = (struct load_command *)((uint64_t)load_commands_buffer + offset);
		struct segment_command_64 *segment_cmd = (struct segment_command_64*) load_cmd;
		
		if (load_cmd->cmd == LC_SEGMENT_64 && strcmp(segment_cmd->segname, "__TEXT") == 0)
		{
			uint64_t addr = (uint64_t)(baseAddress + offset);
			uint32_t segSize = pageAlignEnd(segment_cmd->vmsize);
			uint32_t slide  = (uint64_t)baseAddress - segment_cmd->vmaddr;
      kern_return_t kr = vm_protect((vm_map_t)task, (vm_address_t)addr, (vm_size_t)segSize, false, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);

			if (kr != KERN_SUCCESS) FATAL("failed to make segment addr: %llx as writable", addr);

			uint64_t sections_offset = 0;
			void* sections_base = (void*) ((uint64_t)segment_cmd + sizeof(struct segment_command_64));
      
      uint8_t* lib_page_start = (uint8_t*)baseAddress;
      if ((uintptr_t)lib_page_start % vm_page_size != 0) lib_page_start = (uint8_t*)pageAlign(baseAddress);
      
      void* shadowAddr =  shadowMeUp(lib_page_start);

			uint32_t *shadow = (uint32_t *)mmap(shadowAddr, segSize + vm_page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON| MAP_FIXED, 0, 0);

			if(shadow == MAP_FAILED) FATAL("Failed to mmap shadow memory: %s", strerror(errno));

      for (int isect = 0; isect < segment_cmd->nsects; isect++)
			{	
				uint64_t sect_address = (uint64_t)sections_base + sections_offset;
				struct section_64 * sect = getSection( (void*)( sect_address), isect, swapBytes);
				
				if (sect->flags & S_ATTR_SOME_INSTRUCTIONS || sect->flags & S_ATTR_PURE_INSTRUCTIONS )
				{
					size_t size;
          uint8_t *data = (uint8_t *) getsectiondata((const struct mach_header_64 *)baseAddress, "__TEXT", sect->sectname, &size);
            
          instrumentASection(baseAddress, (uint64_t)shadowAddr, data, size);
				}
				
				free(sect);
				sections_offset += sizeof(struct section_64);
			}
      kr = vm_protect((vm_map_t)task, (vm_address_t)addr, (vm_size_t)segSize, false, VM_PROT_READ | VM_PROT_EXECUTE);
			
			if (kr != KERN_SUCCESS) FATAL("failed to make segment addr: %llx as executable", addr);
    }
    offset += load_cmd->cmdsize;
  }
}

int instrumentMe(const char * libraryFilePath)
{   
	void *loadAddr = findLibraryLoadAddress(libraryFilePath);
	if (!task)
	{
		kern_return_t kr = task_for_pid(mach_task_self(), getpid(), &task);
		if (kr!=KERN_SUCCESS)
			FATAL("failed to get task_for_pid");
	}

	parseAndInstrument(libraryFilePath, (uint32_t*)loadAddr);
	return 0;
}

int main(int argc, char *argv[]) {

  pid = getpid();
  if (getenv("AFL_DEBUG")) debug = 1;

  if (argc > 1) {

    use_stdin = 0;
    inputfile = (u8 *)argv[1];

  }

  // TODO: instrumentMe
  LLVMInitializeAArch64Disassembler();
	LLVMInitializeAArch64TargetInfo();
	LLVMInitializeAArch64TargetMC();

  instrumentMe("/System/Library/Frameworks/CoreAudio.framework/Versions/A/CoreAudio");
  instrumentMe("/System/Library/PrivateFrameworks/AudioToolboxCore.framework/Versions/A/AudioToolboxCore");
  instrumentMe("/System/Library/Frameworks/AudioToolbox.framework/Versions/A/AudioToolbox");

  setup_trap_instrumentation();
  __afl_map_shm();
  __afl_start_forkserver();

  while (1) {
    if ((pid = fork()) == -1) PFATAL("fork failed");

    if (pid) {

      u32 status;
      if (waitpid(pid, (int *)&status, 0) < 0) exit(1);
      __afl_end_testcase(status);

    } else {

      pid = getpid();
      while ((len = __afl_next_testcase(buf, sizeof(buf))) > 0) {

        fuzz();
        _exit(0);

      }

    }

  }

  return 0;

}


// TODO: FUZZ

#include <AudioToolbox/AudioToolbox.h>

typedef struct {
    const void *data;
    size_t size;
    UInt64 pos;
} FileData;

OSStatus readProc(void* clientData, SInt64 position, UInt32 requestCount, void* buffer, UInt32* actualCount) {

  FileData *fileData = (FileData*)clientData;
  size_t dataSize = fileData->size;
  const void *data = fileData->data;
  size_t bytesToRead = 0;

  if (static_cast<UInt64>(position) < dataSize) {
    size_t bytesAvailable = dataSize - static_cast<size_t>(position);
    bytesToRead = requestCount <= bytesAvailable ? requestCount : bytesAvailable;
    memcpy(buffer, static_cast<const uint8_t*>(data) + position, bytesToRead);
  }

  if (actualCount) *actualCount = bytesToRead;

  return noErr;
}

SInt64 getSizeProc(void *inClientData) {
    FileData *fileData = (FileData*)inClientData;
    return fileData->size;
}

static void fuzz(void) {
  FileData file = { buf, len, 0 };

  AudioFileID audioFile;
  OSStatus result = AudioFileOpenWithCallbacks(&file, readProc, 0, getSizeProc, 0, 0, &audioFile);

  if (result != noErr) {
    return;
  }

  ExtAudioFileRef extAudioFileRef;
  result = ExtAudioFileWrapAudioFileID(audioFile, false, &extAudioFileRef);

  if (result != noErr) {
    return;
  }

  AudioFileClose(audioFile);
}

