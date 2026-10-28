FROM ghcr.io/astral-sh/uv:0.12.23 AS uv
FROM python:3.12-slim
COPY --from=uv /uv /usr/local/bin/uv
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 UV_PYTHON_DOWNLOADS=never
WORKDIR /app
COPY pyproject.toml uv.lock ./
COPY finding_assistant/ ./finding_assistant/
COPY main.py worker.py ops_tools.py log_transfer.py ./
RUN uv sync --locked --no-dev --no-cache --python /usr/local/bin/python
ENV PATH="/app/.venv/bin:$PATH" FINDING_ASSISTANT_LOG_DIR=""
USER 10001:10001
EXPOSE 8001
CMD ["python", "main.py", "--host", "0.0.0.0", "--port", "8001"]
