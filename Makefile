# Compiler and flags
NVCC = nvcc
CXX = g++
NVCC_FLAGS = --disable-warnings --generate-line-info
CXX_FLAGS = -lpcap 
INCLUDES = -Iinclude


# Directories
SRCDIR = .


# Files
CU_SOURCES = $(wildcard $(SRCDIR)/*.cu)
CXX_SOURCES = $(wildcard $(SRCDIR)/*.cpp)

# Target
TARGET = main

# Rules
all: $(TARGET)

$(TARGET):
	$(NVCC) $(INCLUDES) -dc $(CU_SOURCES) $(NVCC_FLAGS)
	$(NVCC) -dlink *.o -o device_link.o
	$(NVCC) $(INCLUDES) *.o $(CXX_SOURCES) $(CXX_FLAGS) -o $(TARGET) 
	rm -f *.o device_link.o

clean:
	rm -rf *.o $(TARGET)

.PHONY: all clean
