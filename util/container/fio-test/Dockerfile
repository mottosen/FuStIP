FROM ubuntu:24.04
RUN apt-get update && apt-get install -y fio && rm -rf /var/lib/apt/lists/*
WORKDIR /work
ENTRYPOINT ["sh", "-c", "sleep 2 && exec fio \"$@\"", "--"]
