FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py ./
COPY static/ ./static/
RUN useradd --create-home --uid 10001 sherlock && mkdir -p /app/data && chown -R sherlock:sherlock /app/data
USER sherlock
EXPOSE 8000
CMD ["python", "-m", "uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
