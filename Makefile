
LLVMFLAGS = -I./llvm-project/llvm/include -I./llvm-project/build/include -std=c++14  -fno-exceptions -fno-rtti -D_DEBUG -D__STDC_CONSTANT_MACROS -D__STDC_FORMAT_MACROS -D__STDC_LIMIT_MACROS

LLVMLDFLAGS = -L./llvm-project/build/lib -Wl,-search_paths_first -Wl,-headerpad_max_install_names -lLLVMAArch64AsmParser -lLLVMAArch64Desc -lLLVMAArch64Disassembler -lLLVMAArch64Info -lLLVMAArch64Utils -lLLVMBinaryFormat -lLLVMDebugInfoCodeView -lLLVMDebugInfoMSF -lLLVMDemangle -lLLVMMC -lLLVMMCDisassembler -lLLVMMCParser -lLLVMSupport -lLLVMTableGen -lLLVMTableGenGlobalISel -lz -lpthread -ledit -lcurses -lm

CFLAGS = -fsanitize=address -framework Foundation -framework CoreGraphics -framework AudioToolbox -framework AppKit -framework CoreText -framework CoreFoundation -framework Foundation -framework CoreGraphics -framework PDFKit $(LLVMFLAGS) $(LLVMLDFLAGS)
CC=clang
CXX=clang++

all:	afl-untracer

afl-untracer:	afl-untracer.mm
	$(CXX) $(CFLAGS) $(LLVMFLAGS) $(LLVMLDFLAGS) -I../../include -g -o afl-untracer afl-untracer.mm

clean:
	rm -f afl-untracer *~ core
