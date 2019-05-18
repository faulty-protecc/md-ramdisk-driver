FROM	ubuntu:bionic

# Install make and dependencies
RUN	apt-get update && \
	apt-get -y install libssl-dev wget tar xz-utils make gcc bc linux-headers-4.15.0-47 kernel-devel && \
	apt-get clean

# Install linaro gcc compailer
RUN	cd /opt && \
	wget --directory-prefix=/opt https://releases.linaro.org/archive/15.05/components/toolchain/binaries/aarch64-linux-gnu/gcc-linaro-4.9-2015.05-x86_64_aarch64-linux-gnu.tar.xz && \
	tar -Jxvf gcc-linaro-4.9-2015.05-x86_64_aarch64-linux-gnu.tar.xz && rm gcc-linaro-4.9-2015.05-x86_64_aarch64-linux-gnu.tar.xz
ENTRYPOINT	sleep infinity
