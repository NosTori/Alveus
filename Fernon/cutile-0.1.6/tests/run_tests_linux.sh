SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

declare -a TESTS=(
    [0]="array"
    [1]="base64"
    [2]="blowfish"
    [3]="cxx"
    [4]="filesystem"
    [5]="hash_table"
    [6]="ini"
    [7]="shared_library"
    [8]="network"
    [9]="str"
    [10]="cstr"
)

declare -a CPP_TESTS=(
    [0]="defer"
    [1]="str_format"
)

# Builds .so for shared library test.
gcc -c -fpic "$SCRIPT_DIR/shared_library_sample.c"
gcc -shared -o "$SCRIPT_DIR/shared_library_sample.so" "$SCRIPT_DIR/shared_library_sample.o"

for tes in ${TESTS[@]}
do
    SRC="$SCRIPT_DIR/$tes.c"
    OUTNAME="$SCRIPT_DIR/$tes"
    gcc -std=c11 -g3 $SRC -o $OUTNAME 
    g++ -std=c++20 -g3 $SRC -o "${OUTNAME}_cpp" 
done

for tes in ${CPP_TESTS[@]}
do
    SRC="$SCRIPT_DIR/$tes.c"
    OUTNAME="$SCRIPT_DIR/$tes"
    g++ -std=c++20 -g3 $SRC -o "${OUTNAME}_cpp" 
done

for tes in ${TESTS[@]}
do
    "$SCRIPT_DIR/$tes"
    "$SCRIPT_DIR/${tes}_cpp"
done

for tes in ${CPP_TESTS[@]}
do
    "$SCRIPT_DIR/${tes}_cpp"
done
