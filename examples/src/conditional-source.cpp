//
//  ### TaintChecker ###
//
//  A very simple example that shows a conditional path, and how the analyzer
//  makes the necessary assumptions to recreate the taint issue.
//  The method 'source' is a generator of tainted data, and the method
//  'anotherMethod' is safe. The analyzer finds the path that takes you to the
//  execution of a sink with tainted data.
//
//  Note: the variable 'flag', which is passed as a parameter, is unknown
//  to the checker, so it is considered symbolic. Its range of values are
//  calculated depending on the taken path.
//

#include "Util.h"

int test(int flag){
  char* data;
  if (flag){
    data = source();          // source is supposed to taint data variable.
  }
  else {
    data = anotherMethod();		// anotherMethod is not a source,
  }                           // thus it is safe.
  sink(data);                 // Should we warn?
  return 0;
}
