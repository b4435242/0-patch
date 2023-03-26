
# clone source
#git clone https://github.com/llvm/llvm-project.git

# build with c++
	#mkdir -p build/llvm-project/build && cd build/llvm-project/build && \
	#cmake -G Ninja ../llvm -DLLVM_ENABLE_PROJECTS="clang;clang-tools-extra" -DCMAKE_BUILD_TYPE=Release && \
       	#ninja && \
	#sudo ninja install
	# rebuild with clang++

mkdir -p llvm-project/build && cd llvm-project/build && \
cmake -G Ninja ../llvm -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_C_COMPILER=clang -DLLVM_ENABLE_PROJECTS="clang;clang-tools-extra" -DLLVM_ENABLE_RTTI=ON -DCMAKE_BUILD_TYPE=Release -DLLVM_TARGETS_TO_BUILD="ARM;AArch64" &&\
ninja 
#sudo ninja install
