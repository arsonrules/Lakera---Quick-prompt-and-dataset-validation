FROM python:3.13-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && useradd --create-home app
COPY app.py index.html report.js ./
COPY scenarios ./scenarios
USER app
EXPOSE 8765
# Publish on localhost only: docker run --rm -p 127.0.0.1:8765:8765 lakera-guard-tester
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8765"]
