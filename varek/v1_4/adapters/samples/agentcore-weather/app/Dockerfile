FROM public.ecr.aws/docker/library/python:3.12-slim
WORKDIR /app
COPY . .
RUN pip install --no-cache-dir -r requirements.txt
CMD ["opentelemetry-instrument", "python", "main.py"]
