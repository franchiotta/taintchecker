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
/// This file contains utility declaration for the use of CustomTaintChecker
///
//===----------------------------------------------------------------------===//

#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/TaintManager.h"

using namespace clang;
using namespace ento;

namespace taintutil {

/// Is this funcion declaration applicable based on its kind?
bool isFDApplicable(const FunctionDecl *FD);

/// \brief Given a pointer argument, get the symbol of the value it contains
/// (points to).
SymbolRef getPointedToSymbol(CheckerContext &C, const Expr *Arg);

SymbolRef getSymbol(SVal Val);
  
bool isMemberExpr(Expr *Expr);

bool hasGlobalStorage(Expr *Expr);

std::string exprToString(const Expr *E);

void displayWelcome(std::string ConfigFileName, std::string DebugFileName);

std::string replaceMessage(const char *MsgTemplate, const char *MsgToComplete);

template <typename... Args>
void debug(FILE *DebugFile, const char *Format, Args... Arguments) {
  if (DebugFile)
    fprintf(DebugFile, Format, Arguments...);
}

ProgramStateRef removeTaint(ProgramStateRef &PS, const Stmt *S, const 
                              LocationContext *LCtx, 
                              TaintTagType Kind = TaintTagGeneric);

ProgramStateRef removeTaint(ProgramStateRef &PS, SymbolRef Sym,
                              TaintTagType Kind = TaintTagGeneric);

ProgramStateRef removeTaint(ProgramStateRef &PS, const MemRegion *R,
                               TaintTagType Kind = TaintTagGeneric);

class TaintBugVisitor : public BugReporterVisitorImpl<TaintBugVisitor> {
protected:
  SymbolRef Symbol;
  const Expr *Expression;

  // If true, the visitor will look up the node in which the Symbol got
  // tainted. Otherwise, it will look up for the node in which the expression
  // got tainted instead (this is the way the checker marked as tainted return
  // values).
  bool SymbolLookup;

public:
  TaintBugVisitor(SymbolRef Symbol, const Expr *Expression, bool SymbolLookup)
      : Symbol(Symbol), Expression(Expression), SymbolLookup(SymbolLookup) {}

  void Profile(llvm::FoldingSetNodeID &ID) const override {
    static int X = 0;
    ID.AddPointer(&X);
    ID.AddPointer(Symbol);
  }
  
  std::shared_ptr<PathDiagnosticPiece> VisitNode(const ExplodedNode *N,
                                 const ExplodedNode *PrevN,
                                 BugReporterContext &BRC,
                                 BugReport &BR) override;
};
};
