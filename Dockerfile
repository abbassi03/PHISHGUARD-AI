FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1
WORKDIR /app
COPY requirements.txt pyproject.toml README.md ./
COPY src ./src
COPY app.py ./app.py
COPY pages ./pages
COPY .streamlit ./.streamlit
RUN python -m pip install --upgrade pip && pip install -r requirements.txt && pip install --no-deps -e .
RUN mkdir -p data/raw artifacts reports/figures reports/metrics
EXPOSE 8501
CMD ["streamlit", "run", "app.py", "--server.address=0.0.0.0", "--server.port=8501"]
