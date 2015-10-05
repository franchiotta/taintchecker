//===-- llvm/Instruction.h - Instruction class definition -------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
///
/// \file
/// This file contains the declaration of the TaintPropagation class.
///
//===----------------------------------------------------------------------===//

#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"

using namespace clang;
using namespace ento;

namespace taintutil {

typedef SmallVector<unsigned, 2> ArgVector;

const unsigned ReturnValueIndex = 100;
const unsigned InvalidArgIndex = 101;

/// \brief A class used to specify taint propagation rules for a function.
///
/// If any of the possible taint source arguments is tainted, all of the
/// destination arguments should also be tainted. Use InvalidArgIndex in the
/// src list to specify that all of the arguments can introduce taint. Use
/// InvalidArgIndex in the dst arguments to signify that all the non-const
/// pointer and reference arguments might be tainted on return. If
/// ReturnValueIndex is added to the dst list, the return value will be
/// tainted.
class TaintPropagation {
protected:
  /// List of arguments which can be taint sources and should be checked.
  ArgVector SrcArgs;
  /// List of arguments which should be tainted on function return.
  ArgVector DstArgs;
  // TODO: Check if using other data structures would be more optimal.

public:
  TaintPropagation() {}
  virtual ~TaintPropagation() {}

  TaintPropagation(unsigned SArg, unsigned DArg, bool TaintRet = false) {
    SrcArgs.push_back(SArg);
    DstArgs.push_back(DArg);
    if (TaintRet)
      DstArgs.push_back(ReturnValueIndex);
  }

  TaintPropagation(unsigned SArg1, unsigned SArg2, unsigned DArg,
                   bool TaintRet = false) {
    SrcArgs.push_back(SArg1);
    SrcArgs.push_back(SArg2);
    DstArgs.push_back(DArg);
    if (TaintRet)
      DstArgs.push_back(ReturnValueIndex);
  }

  void setSrcArg(ArgVector SrcArgs) { this->SrcArgs = SrcArgs; }
  void setDstArg(ArgVector DstArgs) { this->DstArgs = DstArgs; }

  inline void addSrcArg(unsigned A) { SrcArgs.push_back(A); }
  inline void addDstArg(unsigned A) { DstArgs.push_back(A); }

  inline bool isNull() const { return SrcArgs.empty(); }

  inline bool isDestinationArgument(unsigned ArgNum) const {
    return (std::find(DstArgs.begin(), DstArgs.end(), ArgNum) != DstArgs.end());
  }

  /// \brief Pre-process a function which propagates taint according to the
  /// taint rule.
  virtual ProgramStateRef process(const CallExpr *CE,
                                  CheckerContext &C) const = 0;
};
};
