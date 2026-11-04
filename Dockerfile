# AgentShield demo image. Non-root, no extra privileges needed.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1

RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin agentshield
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
COPY examples ./examples
RUN pip install --no-cache-dir . && chown -R agentshield:agentshield /app
USER 10001:10001

# Default: run the offline scripted-attacker demo (needs no network and no API key).
CMD ["python", "examples/scripted_attacker.py"]
