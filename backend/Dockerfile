FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1     PYTHONUNBUFFERED=1

WORKDIR /app

# System deps for psycopg2 (binary usually ok, but keep minimal)
RUN apt-get update && apt-get install -y --no-install-recommends     curl  && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY app /app/app

# Default for compose; can be overridden
ENV DATABASE_URL=postgresql+psycopg2://pgas:pgas@db:5432/pgas     PGAS_RULESET_PATH=app/rules/mvp-0.1.yaml

EXPOSE 8000

CMD ["python","-m","uvicorn","app.main:app","--host","0.0.0.0","--port","8000"]
