FROM python:3.12-slim

WORKDIR /app
COPY app.py edge.py ./

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

EXPOSE 8000
CMD ["python3", "app.py"]
