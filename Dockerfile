FROM python:3.13-slim

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src
COPY webapp ./webapp
COPY config ./config
COPY fixtures ./fixtures

RUN pip install --no-cache-dir -e ".[web]"

EXPOSE 8000

# Lock access behind a token: BIODRIFT_API_TOKEN=... BIODRIFT_ALLOW_ANON_GET=0
CMD ["uvicorn", "webapp.main:app", "--host", "0.0.0.0", "--port", "8000"]
