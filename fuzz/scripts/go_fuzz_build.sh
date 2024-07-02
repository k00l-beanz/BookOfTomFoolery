#!/bin/bash
# Build script for go-fuzz. Utilizes the standalone go-fuzz (https://github.com/dvyukov/go-fuzz)
#

function error() {
	echo "[!] error: $1"
	exit 1
}

function help() {
	echo "usage: ./build.sh -f FUNC -d WORKING_DIR [-lf|-rf]"
	echo -e "\t-f\tName of your function harness"
	echo -e "\t-d\tgo-fuzz: campaign directory; libufzzer: input corpus directory"
	echo -e "\t-rf\tRun fuzzer after compilation"
	echo -e "\t-lf\tCompile and run with libfuzzer"
	exit 0
}

function check_error() {
	ERROR_CODE="$1"
	MESSAGE="$2"

	if [ "$ERROR_CODE" -ne 0 ]; then
		error "$MESSAGE"
	fi
}

function compile_libfuzzer() {
	HARNESS_NAME="$1"
	INPUT_DIR="$2"	
	RUN="$3"

	ARCHIVE_NAME="${HARNESS_NAME}.a"

	echo "[*] Compiling $HARNESS_NAME into $ARCHIVE_NAME with go-fuzz-build..."	
	err=$(go-fuzz-build -func "$HARNESS_NAME" -libfuzzer -o "$ARCHIVE_NAME" . 2>&1)
	check_error "$?" "$err"

	echo "[*] Compiling $ARCHIVE_NAME with libfuzzer..."
	err=$(clang -fsanitize=fuzzer "$ARCHIVE_NAME" -o "$HARNESS_NAME" 2>&1)
	check_error "$?" "$err"

	echo "[*] Creating $INPUT_DIR..."
	mkdir "$INPUT_DIR" 2> /dev/nul
	
	if [ "$RUN" -eq 1 ]; then
		err=$("./$HARNESS_NAME" "$INPUT_DIR" 2>&1)
		check_error "$?" "$err"
	fi
}

function compile_go_fuzz() {
	HARNESS_NAME="$1"
	INPUT_DIR="$2"
	RUN="$3"

	ARCHIVE_NAME="${HARNESS_NAME}.zip"
	
	echo "[*] Compiling $HARNESS_NAME with go-fuzz-build..."
	err=$(go-fuzz-build -func "$HARNESS_NAME" -o "$ARCHIVE_NAME" 2>&1)
	check_error "$?" "$err"

	if [ "$RUN" -eq 1 ]; then
		err=$(go-fuzz -bin "$ARCHIVE_NAME" -func "$HARNESS_NAME" -sonar=false -dumpcover -workdir "$INPUT_DIR" 2>&1)
		check_err "$?" "$err"
	fi

}

# default values of optional
# arguments
LIBFUZZER=0
RUN_FUZZER=0

# require arguments
HARNESS_NOT_FOUND=1
DIR_NOT_FOUND=1

# parse arguments
while getopts "f:d:l:r:h" opt; do
	case "$opt" in
		f)
			HARNESS="$OPTARG"
			HARNESS_NOT_FOUND=0
			;;
		d)
			DIRECTORY="$OPTARG"
			DIR_NOT_FOUND=0
			;;	
		l)
			LIBFUZZER=1
			;;
		r)
			RUN_FUZZER=1
			;;
		h)
			help
			;;	
        /?)
			echo "Invalid argument: -$OPTARG" >&2
			exit 1
			;;
	esac
done

if [ "$HARNESS_NOT_FOUND" -eq 1 ] && [ "$DIR_NOT_FOUND" -eq 1 ]; then
	help
fi

if [ "$HARNESS_NOT_FOUND" -eq 1 ]; then
	error "-f required. Use -h for more information"
elif [ "$DIR_NOT_FOUND" -eq 1 ]; then
	error "-d required. Use -h for more information"
fi

echo "[*] Downloading dependencies..."
err=$(go get github.com/dvyukov/go-fuzz/go-fuzz-dep 2>&1)
check_err "$?" "$err"

if [ $LIBFUZZER -eq 1 ]; then
	compile_libfuzzer "$HARNESS" "$DIRECTORY" "$RUN_FUZZER"
else
	compile_go_fuzz "$HARNESS" "$DIRECTORY" "$RUN_FUZZER"
fi
