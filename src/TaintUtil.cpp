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
/// This file contains the definitions of the TaintUtil.h declarations
///
//===----------------------------------------------------------------------===//

#include "includes/TaintUtil.h"

namespace taintutil {

bool isFDApplicable(const FunctionDecl *FD) {
  if (!FD)
    return false;
  if (FD->getKind() == Decl::Function || FD->getKind() == Decl::CXXMethod)
    return true;
  return false;
}

SymbolRef getPointedToSymbol(CheckerContext &C, const Expr *Arg) {
  ProgramStateRef State = C.getState();
  SVal AddrVal = State->getSVal(Arg->IgnoreParens(), C.getLocationContext());
  if (AddrVal.isUnknownOrUndef())
    return nullptr;

  Optional<Loc> AddrLoc = AddrVal.getAs<Loc>();
  if (!AddrLoc) {
    return getSymbol(AddrVal);
  }

  const PointerType *ArgTy =
      dyn_cast<PointerType>(Arg->getType().getCanonicalType().getTypePtr());
  SVal Val =
      State->getSVal(*AddrLoc, ArgTy ? ArgTy->getPointeeType() : QualType());

  return getSymbol(Val);
}

SymbolRef getSymbol(SVal Val){
  SymbolRef Symbol = Val.getAsSymbol();
  if (Symbol)
    return Symbol;
  else {
    // If there is no symbol, and the Svals is a lazyCompoundVal. It tries to
    // get the symbolic base, and then return its symbol.
    Optional<clang::ento::nonloc::LazyCompoundVal> lazyCompoundVal =
    Val.getAs<clang::ento::nonloc::LazyCompoundVal>();
    if (lazyCompoundVal) {
      const SymbolicRegion *symbolicRegion =
      lazyCompoundVal->getRegion()->getSymbolicBase();
      if (symbolicRegion)
        return symbolicRegion->getSymbol();
    }
  }
  return nullptr;
}

bool isMemberExpr(Expr *Expr) {
  // See if we have to consider something else.
  if (isa<MemberExpr>(Expr))
    return true;
  return false;
}

bool hasGlobalStorage(Expr *Expr) {
  if (DeclRefExpr *DeclRefEx = dyn_cast<DeclRefExpr>(Expr)) {
    NamedDecl *NamedDc = DeclRefEx->getFoundDecl();
    if (VarDecl *VarDc = dyn_cast<VarDecl>(NamedDc)) {
      if (VarDc->hasGlobalStorage())
        return true;
    }
  }
  return false;
}

std::string exprToString(const Expr *E) {
  clang::LangOptions LangOpts;
  LangOpts.CPlusPlus = true;
  clang::PrintingPolicy Policy(LangOpts);
  std::string TypeS;
  llvm::raw_string_ostream s(TypeS);
  E->printPretty(s, 0, Policy);
  return s.str();
}

void displayWelcome(std::string ConfigFileName, std::string DebugFileName) {
  llvm::outs().changeColor(llvm::outs().SAVEDCOLOR, true, false);
  llvm::outs() << "### Custom Taint Checker ###"
               << "\n";
  llvm::outs() << "Configuration file: " << ConfigFileName.data() << "\n";
  llvm::outs() << "Debug file: " << DebugFileName.data() << "\n";
  llvm::outs() << "\n";
  llvm::outs().resetColor();
}

std::string replaceMessage(const char *MsgTemplate, const char *MsgToComplete) {
  char ReplacedMsg[300];
  sprintf(ReplacedMsg, MsgTemplate, MsgToComplete);
  return std::string(ReplacedMsg);
}

ProgramStateRef removeTaint(ProgramStateRef &PS, const Stmt *S, const LocationContext *LCtx, TaintTagType Kind) {
  SymbolRef Sym = PS->getSVal(S, LCtx).getAsSymbol();
  if (Sym)
    return removeTaint(PS, Sym, Kind);
  
  const MemRegion *R = PS->getSVal(S, LCtx).getAsRegion();
  removeTaint(PS, R, Kind);
  return PS;
}
  
ProgramStateRef removeTaint(ProgramStateRef &PS, SymbolRef Sym,
                              TaintTagType Kind) {
  // If this is a symbol cast, remove the cast before removing the taint. Taint
  // is cast agnostic.
  while (const SymbolCast *SC = dyn_cast<SymbolCast>(Sym))
    Sym = SC->getOperand();
  
  ProgramStateRef NewState = PS->remove<TaintMap>(Sym);
  assert(NewState);
  return NewState;
}

ProgramStateRef removeTaint(ProgramStateRef &PS, const MemRegion *R,
                               TaintTagType Kind) {
  if (const SymbolicRegion *SR = dyn_cast_or_null<SymbolicRegion>(R))
    return removeTaint(PS, SR->getSymbol(), Kind);
  return PS;
}

std::shared_ptr<PathDiagnosticPiece> TaintBugVisitor::VisitNode(const ExplodedNode *N,
                                                const ExplodedNode *PrevN,
                                                BugReporterContext &BRC,
                                                BugReport &BR) {

  ProgramStateRef ProgramState = N->getState();
  ProgramStateRef PrevProgramState = PrevN->getState();

  if (!ProgramState || !PrevProgramState)
    return nullptr;

  const LocationContext *LocContext = N->getLocationContext();
  const LocationContext *PredLocContext = PrevN->getLocationContext();

  if ((ProgramState->isTainted(Symbol) &&
       !PrevProgramState->isTainted(Symbol) && SymbolLookup) ||
      (ProgramState->isTainted(Expression, LocContext) &&
       !ProgramState->isTainted(Expression, PredLocContext) &&
       !SymbolLookup)) {

    ProgramPoint PP = N->getLocation();
    PathDiagnosticLocation L =
        PathDiagnosticLocation::create(PP, BRC.getSourceManager());

    char Message[70];
    sprintf(Message, "Expression '%s' gets tainted here",
            exprToString(Expression).data());
    return std::make_shared<PathDiagnosticEventPiece>(L, Message);
  }
  return nullptr;
}
};
