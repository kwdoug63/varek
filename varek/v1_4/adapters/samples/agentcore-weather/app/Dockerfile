FROM public.ecr.aws/docker/library/python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
WORKDIR /app
COPY . .
# every version and hash pinned (requirements.in, compiled)
RUN pip install --no-cache-dir --require-hashes -r requirements.txt
CMD ["opentelemetry-instrument", "python", "main.py"]
