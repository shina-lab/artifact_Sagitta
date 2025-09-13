# Build base image
FROM ubuntu:jammy as base
# FROM llvm-13:latest as base # Debug build version
ARG BUILD_TYPE="Release"

LABEL org.opencontainers.image.authors="evan.sultanik@trailofbits.com"

# NOTE(msurovic): We install `clang` and related bitcode utilities via `apt`
# in version 12 because the `clang-13` package contains version 13.0.1 which
# has weird behavior wrt `-Werror`. The flag seems to be raised even if the
# user doesn't explicitly specify so. We believe this is intentional on the
# part of LLVM to mimic `gcc` behavior. MuPDF doesn't build with `clang-13`
# installed from `apt`, for example.

# Install base build dependencies via apt
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get -y update
RUN apt-get -y install lsb-release software-properties-common
RUN apt-get -y install \
  ninja-build                               \
  python3-pip                               \
  python3.8-dev                             \
  golang                                    \
  cmake                                     \
  git                                       \
  file
RUN apt install -y clang-13

# Install python dependencies via pip
RUN pip3 install pytest blight

# Install symlinks to clang and llvm bitcode tools
RUN update-alternatives --install /usr/local/bin/opt opt /usr/bin/opt-13 10 && \
    update-alternatives --install /usr/local/bin/llvm-link llvm-link /usr/bin/llvm-link-13 10 && \
    update-alternatives --install /usr/local/bin/llvm-ar llvm-ar /usr/bin/llvm-ar-13 10 && \
    update-alternatives --install /usr/local/bin/llvm-dis llvm-dis /usr/bin/llvm-dis-13 10 && \
    update-alternatives --install /usr/local/bin/clang clang /usr/bin/clang-13 10 && \
    update-alternatives --install /usr/local/bin/clang++ clang++ /usr/bin/clang++-13 10

# Install gllvm for builds with bitcode references embedded in binary build targets
RUN GO111MODULE=off go get github.com/SRI-CSL/gllvm/cmd/...
ENV PATH=$PATH:/root/go/bin

# Clone llvm to build `libc++` from source
FROM base as llvm-sources

RUN git clone --depth 1 --branch llvmorg-13.0.0 https://github.com/llvm/llvm-project.git /llvm-project

# TODO(msurovic): I don't think there is a reason why we should be building
# both `clean-libcxx` and `poly-libcxx`. The former is used when linking an
# uninstrumented target of the user project. The latter is used when linking
# the instrumented target of the user project. Not building either results in
# `libc++` symbols missing from the instrumented target. Why this happens is
# anyone's guess.

# Build "clean" `libc++` with `gclang`. Used to link the uninstrumented
# target of the user project. Installed into `/cxx_lib/clean_build`.
FROM llvm-sources as clean-libcxx

ENV WLLVM_BC_STORE=/cxx_clean_bitcode
RUN mkdir -p $WLLVM_BC_STORE

ENV LIBCXX_BUILD_DIR=/llvm-project/build
ENV LIBCXX_INSTALL_DIR=/cxx_lib/clean_build

RUN cmake -GNinja \
  -B$LIBCXX_BUILD_DIR \
  -S/llvm-project/runtimes \
  -DCMAKE_BUILD_TYPE=${BUILD_TYPE} \
  -DCMAKE_C_COMPILER="gclang" \
  -DCMAKE_CXX_COMPILER="gclang++" \
  -DCMAKE_INSTALL_PREFIX=$LIBCXX_INSTALL_DIR \
  -DLIBCXXABI_ENABLE_SHARED=NO \
  -DLIBCXX_ENABLE_SHARED=NO \
  -DLLVM_ENABLE_LIBCXX=ON \
  -DLLVM_ENABLE_RUNTIMES="libcxx;libcxxabi"

RUN cmake --build $LIBCXX_BUILD_DIR --target install-cxx install-cxxabi -j$((`nproc`+1))

# Build "poly" `libc++` with `gclang`. Used to link the instrumented
# target of the user project. Installed into `/cxx_lib/poly_build`.
FROM clean-libcxx as poly-libcxx

ENV WLLVM_BC_STORE=/cxx_poly_bitcode
RUN mkdir -p $WLLVM_BC_STORE

ENV LIBCXX_BUILD_DIR=/llvm-project/llvm/build
ENV LIBCXX_INSTALL_DIR=/cxx_lib/poly_build

RUN cmake -GNinja \
  -B$LIBCXX_BUILD_DIR \
  -S/llvm-project/runtimes \
  -DCMAKE_BUILD_TYPE=${BUILD_TYPE} \
  -DCMAKE_C_COMPILER="gclang" \
  -DCMAKE_CXX_COMPILER="gclang++" \
  -DCMAKE_INSTALL_PREFIX=$LIBCXX_INSTALL_DIR \
  -DLIBCXXABI_ENABLE_SHARED=NO \
  -DLIBCXX_ENABLE_SHARED=NO \
  -DLIBCXX_ABI_VERSION=2 \
  -DLIBCXX_HERMETIC_STATIC_LIBRARY=ON \
  -DLIBCXX_ENABLE_STATIC_ABI_LIBRARY=ON \
  -DLLVM_ENABLE_LIBCXX=ON \
  -DLLVM_ENABLE_RUNTIMES="libcxx;libcxxabi"

RUN cmake --build $LIBCXX_BUILD_DIR --target install-cxx install-cxxabi -j$((`nproc`+1))

# Build and install the polytracker
FROM poly-libcxx as polytracker

ARG DFSAN_FILENAME_ARCH=x86_64

WORKDIR /workdir
COPY . /polytracker

RUN ln -s /usr/bin/python3 /usr/bin/python
RUN pip3 install /polytracker

# NOTE: Debugビルドだと、計装時にLLVM側のアサーションが通らない
RUN cmake -GNinja \
  -B/polytracker-build \
  -S/polytracker \
  -DCMAKE_BUILD_TYPE="RelWithDebInfo" \
  -DCMAKE_C_COMPILER="clang" \
  -DCMAKE_CXX_COMPILER="clang++" \
  -DCXX_LIB_PATH=/cxx_lib/poly_build \
  -DCMAKE_INSTALL_PREFIX=/polytracker-install

RUN cmake --build /polytracker-build --target install -j$((`nproc`+1))

ENV DFSAN_LIB_PATH=/polytracker-install/lib/linux/libclang_rt.dfsan-${DFSAN_FILENAME_ARCH}.a
ENV CXX_LIB_PATH=/cxx_lib
ENV COMPILER_DIR=/polytracker-install/share/polytracker

ENV DFSAN_OPTIONS="strict_data_dependencies=0"

ENV WLLVM_BC_STORE=/project_bitcode
ENV WLLVM_ARTIFACT_STORE=/project_artifacts

RUN mkdir $WLLVM_ARTIFACT_STORE && mkdir $WLLVM_BC_STORE

ENV PATH=$PATH:/polytracker-install/bin

### Install utilities
RUN apt install -y gdb ltrace strace curl
### Install build dependency
RUN apt install -y libtinfo-dev