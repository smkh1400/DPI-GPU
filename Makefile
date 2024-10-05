# Compiler and flags
NVCC = nvcc
CXX = g++
NVCC_FLAGS = --disable-warnings --generate-line-info 
CXX_FLAGS = -lpcap -lyaml-cpp
INCLUDES = -Iinclude


# Directories
SRCDIR = .


# Files
CU_SOURCES = $(wildcard $(SRCDIR)/*.cu)
CXX_SOURCES = $(shell find $(SRCDIR) -type f -name "*.cpp")


CU_SOURCES := $(filter-out %/test.cu, $(CU_SOURCES))
CXX_SOURCES := $(filter-out %/test.cpp, $(CXX_SOURCES))

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
