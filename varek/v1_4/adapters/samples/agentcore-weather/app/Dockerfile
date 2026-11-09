FROM public.ecr.aws/docker/library/python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928
WORKDIR /app
COPY . .
# every version and hash pinned (requirements.in, compiled)
RUN pip install --no-cache-dir --require-hashes -r requirements.txt
CMD ["opentelemetry-instrument", "python", "main.py"]
