FROM python:3.12-slim

# Empêche la mise en mémoire tampon des logs (indispensable pour la console Supervision & logs Hyperfluid)
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8000 \
    MCP_TRANSPORT=streamable-http

WORKDIR /app

# Création d'un utilisateur non-privilégié
RUN useradd --create-home --shell /bin/bash appuser

# Installation des dépendances
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copie du code applicatif
COPY McpX.py .
RUN chown -R appuser:appuser /app

USER appuser

EXPOSE 8000

CMD ["python", "McpX.py"]