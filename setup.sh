#!/bin/bash

LLVM_DIR=~/llvm

if [ "$1" = "build" ]; then

  echo "### Downloading llvm and clang ###"
  echo "### Cloning llvm into $LLVM_DIR/src"
  
  mkdir $LLVM_DIR
  cd $LLVM_DIR
  git clone https://github.com/franchiotta/llvm.git src
  cd $LLVM_DIR/src/tools/

  echo "### Cloning clang into $LLVM_DIR/src/tools/clang"
  
  git clone https://github.com/franchiotta/clang.git
  mkdir $LLVM_DIR/build
  cd $LLVM_DIR/build

  echo "### Done. Downloaded source is under $LLVM_DIR/src"
  echo "### Building llvm and clang ###" 

  cmake $LLVM_DIR/src
  cmake --build . 
else
  echo "Unknown option :("
  echo "Available options are:"
  echo " - build        Donwloads llvm and clang source code, and builds them."
fi
