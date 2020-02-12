FROM ubuntu:bionic as base

RUN dpkg --add-architecture i386

RUN apt update

RUN apt install -y --no-install-recommends libssl-dev:i386 libstdc++6:i386

WORKDIR /app

FROM base as build

RUN apt install -y --no-install-recommends gcc g++ make gcc-multilib g++-multilib libboost-container-dev

COPY . /app

RUN make

FROM base as run

COPY --from=build /app/eimgfs /app/eimgfs
COPY ./dlls /app

RUN chmod a+x /app/eimgfs

ENTRYPOINT ["/app/eimgfs"]

