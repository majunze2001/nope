# set up the base image
FROM ubuntu:20.04
# make dependencies non-interactive
ENV DEBIAN_FRONTEND=noninteractive
# install apt-get dependencies
RUN apt-get update && apt-get install -y sudo \
    curl \
    wget \
    git \
    python3 \
    npm \
    nlohmann-json3-dev \
    libgmp3-dev \
    nasm
# install rust and cargo
RUN curl --proto '=https' --tlsv1.2 https://sh.rustup.rs -sSf | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"
# clone, build, and install circom
RUN git clone https://github.com/iden3/circom.git
RUN cargo build --release --manifest-path=circom/Cargo.toml
RUN cp circom/target/release/circom /usr/local/bin
# install zkutil
RUN cargo install zkutil
RUN cp /root/.cargo/bin/zkutil /usr/local/bin/
# install node
RUN npm install npm@latest -g && \
    npm install n -g && \
    n latest
# install npm packages
RUN sudo npm install -g snarkjs \
    mocha \
    argparse
# install python packages
RUN sudo apt-get install -y python3-pip && \
    pip3 install --upgrade pip && \
    pip3 install dnspython \
    cryptography \
    ecpy \
    josepy \
    acme
# create user with sudo privileges named reviewer without password
RUN useradd -m reviewer && echo "reviewer:reviewer" | chpasswd && adduser reviewer sudo
RUN echo "reviewer ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers
# modify bashrc to clean up terminal
RUN echo "export PS1='\W > '" >> /home/reviewer/.bashrc
# configure environment
USER reviewer
WORKDIR /home/reviewer
CMD ["/bin/bash", "-l"]
