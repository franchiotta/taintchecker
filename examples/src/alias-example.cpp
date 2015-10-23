//
//  ### TaintChecker ###
//
//  Since the analyzer works using a memory region model (#see A Memory Model
//  for Static Analysis of C programs paper), it represents memory locations as
//  regions. The effect obtained after assigning pointers is that the assignee
//  will refer to the same region than the assigner (as normal execution).
//  So, marking (or filtering) as tainted a pointer to a certain memory region
//  will have impact to other pointers that point to the same region.
//

#include "Util.h"

void aliasExample() {
  char* objA = source();
  char* objB = objA;   // objA, as well as objB, point to the same region.
  sink(objB);
  filter(objA);
  sink(objB);          // There is no alert here, because the location
                       // being pointed by objB was cleaned in the statement
                       // before.
}