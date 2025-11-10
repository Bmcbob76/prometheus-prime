ARG BASE_IMAGE
FROM $BASE_IMAGE
WORKDIR /empire
COPY . /empire

SHELL ["/bin/bash", "-c"]

RUN apt-get update && apt-get -y install sudo

# Add a non-root user
RUN echo 'empire ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers
RUN useradd -m empire
RUN chown -R empire:empire /empire
USER empire

RUN sed -i 's/use: mysql/use: sqlite/g' empire/server/config.yaml
RUN yes | /empire/setup/install.sh
RUN rm -rf /empire/empire/server/data/empire*
