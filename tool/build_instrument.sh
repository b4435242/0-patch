LLVM_DIR=llvm-project
LLVM_BUILD_DIR=$LLVM_DIR/build


ln -fs ~/0-patch/tool/frontend "$LLVM_DIR/clang-tools-extra/0-patch"

grep -q 0-patch "$LLVM_DIR/clang-tools-extra/CMakeLists.txt" || echo 'add_subdirectory(0-patch)' >> "$LLVM_DIR/clang-tools-extra/CMakeLists.txt"
cd "$LLVM_BUILD_DIR" && ninja
#cp $LLVM_BUILD_DIR/bin/instrument-suspicious bin
#cp $LLVM_BUILD_DIR/bin/apply-patch bin


