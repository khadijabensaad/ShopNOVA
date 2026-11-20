# Contexte de build = racine du dépôt (voir docker-compose.yml) : l'application a besoin de agent/, rag/, data/,
# mcp_server/ (la v1 copiait seulement app/, ce qui cassait l'agent et le RAG dans le conteneur).
FROM python:3.12-slim
WORKDIR /lab
COPY app/requirements.txt app/requirements.txt
RUN pip install --no-cache-dir -r app/requirements.txt
COPY . .
RUN python data/seed.py
WORKDIR /lab/app
EXPOSE 8000
CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8000"]
