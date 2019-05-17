#!/bin/bash
# This script creates the driver .ko file
# we are using custom gcc-linaro-4.9-2015.05-x86_64 integrated into docker container

# Check if the docker image exists
# if not builds it according to the Dockerfile file in the current directory
if [ -z "$(docker images | awk '$1=="gcc-linaro" && $2=="4.9"')" ]; then
	docker build --network=host -t gcc-linaro:4.9 --force-rm .
fi

# If the destination path does not exsists create if before running
if [ -d '../module' ]; then
	mkdir ../module
fi

# Target directory for the docker command, because it can not get relative path
DIR=$(cd .. && pwd)

# Create the container
CONTAINER_PID=$(docker run -d -v ${DIR}/:/root/linux-source -v ${DIR}/module:/root/module gcc-linaro:4.9 | cut -c 1-12)

# Run the gcc compilation
docker exec --workdir /root/linux-source ${CONTAINER_PID} make -j8 ARCH=arm64 CROSS_COMPILE=/opt/gcc-linaro-4.9-2015.05-x86_64_aarch64-linux-gnu/bin/aarch64-linux-gnu- DESTDIR=/root/linux-source/module 

# Remove the unnescary continer
docker rm -f ${CONTAINER_PID}
