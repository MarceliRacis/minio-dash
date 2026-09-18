FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py .
COPY preview.py .
COPY ui.html .
COPY locales/ ./locales/

EXPOSE 7474

ENV PORT=7474
ENV MINIO_ENDPOINT=localhost:9000

CMD ["python", "server.py"]
