# SPDX-License-Identifier: MIT
#
# An agent's image built on VAREK's (packaging/container/README.md, "Your
# agent in the image"): the README's Dockerfile, with the base image as a
# build argument so CI can build it on the image it has just built.
#
#   docker build -t my-agent packaging/container/example
#   docker run --rm <the settings in packaging/container/README.md> my-agent
# (the default pinned by digest: VAREK 1.32.0, ghcr.io)
ARG VAREK_IMAGE=ghcr.io/kwdoug63/varek:1.32.0@sha256:8a5706d72bbc8d3cdffa191200ca38bddbac08915b8a0667b687d5ec4725f9cb
FROM ${VAREK_IMAGE}
# requests from the distribution (UBI 9's python3-requests, kept patched by
# Red Hat), not PyPI: the versions without known vulnerabilities need Python
# 3.10, and the image's is 3.9
RUN microdnf -y install python3-requests && microdnf clean all
COPY agent.py /work/agent.py
CMD ["python3", "/work/agent.py"]
