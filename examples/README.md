Examples
--------

This file explains how to analyze with our checker the examples included in the project.

How to run the examples?
------------------------

There is a script run-examples.sh, which is a bash script, whose task is to analyze the examples provided. It is very simple, you just have to type:

$ ./run-examples.sh

The resulted report will be placed in *examples/results* directory.

Troubleshooting
---------------

The script will try to run scan-build as it were in the path environment variable. If scan-build is not in the path, you can either add your scan-build there or set up SCAN_BUILD environment variable.

Additionally, scan-build will try to use a clang binary placed relatively to its location. If it cannot find clang, you will get something like this.

$ ./run-examples.sh

  scan-build: error: Cannot find an executable 'clang' relative to scan-build . Consider using --use-analyzer to pick a version of 'clang' to use for static analysis.

To solve this issue, set up 'CLANG' environment variable with the clang binary you want to use with scan-build.
