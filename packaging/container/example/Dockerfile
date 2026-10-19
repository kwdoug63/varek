# SPDX-License-Identifier: MIT
#
# An agent's image built on VAREK's (packaging/container/README.md, "Your
# agent in the image"): the README's Dockerfile, with the base image as a
# build argument so CI can build it on the image it has just built.
#
#   docker build -t my-agent packaging/container/example
#   docker run --rm <the settings in packaging/container/README.md> my-agent
ARG VAREK_IMAGE=ghcr.io/kwdoug63/varek:1.32.0
FROM ${VAREK_IMAGE}
RUN microdnf -y install python3-pip && pip3 install --no-cache-dir requests && microdnf clean all
COPY agent.py /work/agent.py
CMD ["python3", "/work/agent.py"]
