
FROM python:3.11-slim

WORKDIR /app

COPY pyproject.toml README.md ./
COPY loglens/ ./loglens/

RUN pip install --no-cache-dir . "streamlit>=1.40,<2"

COPY app.py home.py ./
COPY pages/ ./pages/
COPY app/ ./app/
COPY rules/ ./rules/

EXPOSE 8501

CMD ["streamlit", "run", "app.py", "--server.address=0.0.0.0", "--server.port=8501", "--server.headless=true", "--browser.gatherUsageStats=false"]
