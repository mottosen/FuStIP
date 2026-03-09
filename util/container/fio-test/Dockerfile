FROM ubuntu:24.04
RUN apt-get update && apt-get install -y fio && rm -rf /var/lib/apt/lists/*
WORKDIR /work
ENTRYPOINT ["fio"]
