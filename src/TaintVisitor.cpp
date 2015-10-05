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
/// This file contains the declaration of the Instruction class, which is the
/// base class for all of the VM instructions.
///
//===----------------------------------------------------------------------===//

#include "includes/TaintVisitor.h"

namespace taintutil {

// --------------------------------- //
//    TaintVisitor implementation    //
// --------------------------------- //

void TaintVisitor::Execute(Stmt *Stmt) {
  // Visit each sub-statement of the statement passed as a parameter.
  for (Stmt::child_iterator I = Stmt->child_begin(), E = Stmt->child_end();
       I != E; ++I) {
    class Stmt *SubStmt = *I;
    if (SubStmt) {
      SubStmt->dump();
      Visit(SubStmt);
    }
  }
}

void TaintVisitor::VisitDeclStmt(DeclStmt *declStmt) {}

void TaintVisitor::VisitCallExpr(CallExpr *CE) {
  for (unsigned int i = 0; i < CE->getNumArgs(); ++i) {
    Expr *Arg = CE->getArg(i);
    if (CastExpr *castExpr = dyn_cast<CastExpr>(Arg)) {
      Arg = castExpr->getSubExprAsWritten();
    }
    if (IsMemberExpr(Arg))
      // The arg is a member expression, it has to be marked as tainted.
      MarkTaint(Arg);
  }
}

void TaintVisitor::VisitCXXMemberCallExpr(CallExpr *CE) {
  for (unsigned int i = 0; i < CE->getNumArgs(); ++i) {
    Expr *Arg = CE->getArg(i);
    if (CastExpr *CastEx = dyn_cast<CastExpr>(Arg)) {
      Arg = CastEx->getSubExprAsWritten();
    }
    if (IsMemberExpr(Arg))
      // The arg is a member expression, it has to be marked as tainted.
      MarkTaint(Arg);
  }
  Visit(CE->getDirectCallee()->getBody());
}

void TaintVisitor::VisitBinAssign(BinaryOperator *BO) {
  if (BO->isAssignmentOp()) {
    // We get the left hand part of the assignment.
    Expr *Lhs = BO->getLHS();
    if (IsMemberExpr(Lhs) || HasGlobalStorage(Lhs))
      MarkTaint(Lhs);
  }
}

// Private methods.
bool TaintVisitor::HasGlobalStorage(Expr *Expr) {
  if (DeclRefExpr *DeclRefEx = dyn_cast<DeclRefExpr>(Expr)) {
    NamedDecl *NamedDc = DeclRefEx->getFoundDecl();
    if (VarDecl *VarDc = dyn_cast<VarDecl>(NamedDc)) {
      if (VarDc->hasGlobalStorage())
        return true;
    }
  }
  return false;
}

bool TaintVisitor::IsMemberExpr(Expr *Expr) {
  // See if we have to consider something else.
  if (isa<MemberExpr>(Expr))
    return true;
  return false;
}
};
