#!/bin/bash

# -----------------------------------------------------------
#  Under construction!! Eventually this will be improved.
#  	
#  This script runs examples that show the checker behavior.
#  It will create a result folder, where all reports will be
#  placed.
# -----------------------------------------------------------

# Function that takes you to the example directory.
function goToExampleDirectory() {
  example_directory="`dirname \"$0\"`"
  cd $example_directory
}

# Checks if scan-build is in the path variable. If not, tries
# with SCAN_BUILD environment variable.
path_to_scan_build=$(which scan-build);
if [ -z "$path_to_scan_build" ] ; then
 	if [ -z "$SCAN_BUILD" ] ; then
 		echo "Neither scan_build is in the path nor SCAN_BUILD environment variable is set up.";
 		exit;
 	else
 		path_to_scan_build=$SCAN_BUILD;
 	fi
fi

# Checking if CLANG environment variables was set up.
if [ -n "$CLANG" ] ; then
	use_analyzer="--use-analyzer $CLANG";
fi

if [ "$(uname)" == "Darwin" ]; then
    library_path=../lib/libCustomTaintChecker.dylib
elif [ "$(uname)" == "Linux" ]; then
    library_path=../lib/libCustomTaintChecker.so
else
	echo "Plataform not supported"
	exit;
fi

# Takes you to the example directory so we can access the source code and
# configuration files.
goToExampleDirectory

# If results directory doesn't exist, create it.
if [ ! -d "results" ]; then
    mkdir results;
fi

# Folder that will hold the object files generated (At the end of the script
# it will be deleted).
mkdir build

# ------------------- #
#  Running examples   #
# ------------------- #

# First example
$path_to_scan_build $use_analyzer -load-plugin $library_path \
-enable-checker alpha.security.taint.CustomTaintPropagation \
-analyzer-config alpha.security.taint.CustomTaintPropagation:ConfigurationFile=conf/taint-conf.xml \
-o results/report-alias-example \
gcc -c src/alias-example.cpp -o build/alias-example.o;

# Second example
$path_to_scan_build $use_analyzer -load-plugin $library_path \
-enable-checker alpha.security.taint.CustomTaintPropagation \
-analyzer-config alpha.security.taint.CustomTaintPropagation:ConfigurationFile=conf/taint-conf.xml \
-o results/report-compound-example \
gcc -c src/compound-example.cpp -o build/compound-example.o;


# Third example
$path_to_scan_build $use_analyzer -load-plugin $library_path \
-enable-checker alpha.security.taint.CustomTaintPropagation \
-analyzer-config alpha.security.taint.CustomTaintPropagation:ConfigurationFile=conf/taint-conf.xml \
-o results/report-conditional-source \
gcc -c src/conditional-source.cpp -o build/conditional-source.o;

# Fourth example
$path_to_scan_build $use_analyzer -load-plugin $library_path \
-enable-checker alpha.security.taint.CustomTaintPropagation \
-analyzer-config alpha.security.taint.CustomTaintPropagation:ConfigurationFile=conf/taint-conf.xml \
-o results/report-filter-taint \
gcc -c src/filter-taint.cpp -o build/filter-taint.o;

# Fifth example
$path_to_scan_build $use_analyzer -load-plugin $library_path \
-enable-checker alpha.security.taint.CustomTaintPropagation \
-analyzer-config alpha.security.taint.CustomTaintPropagation:ConfigurationFile=conf/taint-conf.xml \
-o results/report-macro-example \
gcc -c src/macro-example.cpp -o build/macro-example.o;

# Sixth example
$path_to_scan_build $use_analyzer -load-plugin $library_path \
-enable-checker alpha.security.taint.CustomTaintPropagation \
-analyzer-config alpha.security.taint.CustomTaintPropagation:ConfigurationFile=conf/taint-conf.xml \
-o results/report-propagate-taint \
gcc -c src/propagate-taint.cpp -o build/propagate-taint.o;

# Remove the build directory that contains the object files used for the
# analysis.
rm -r build
