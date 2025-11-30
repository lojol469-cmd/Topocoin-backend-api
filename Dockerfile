# syntax=docker/dockerfile:1
FROM python:3.11-slim

# Installer git, curl, unzip et les dépendances de build pour solders
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    libssl-dev \
    libffi-dev \
    python3-dev \
    git \
    curl \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Configurer git pour éviter les prompts d'authentification
RUN git config --global user.name "builder" && git config --global user.email "builder@example.com"

WORKDIR /app

# Copier requirements.txt en premier pour profiter du cache Docker
COPY requirements.txt .

# Télécharger et installer spl-token-py depuis GitHub
RUN curl -L https://github.com/michaelhly/spl-token-py/archive/refs/heads/main.zip -o /tmp/spl-token-py.zip && \
    unzip /tmp/spl-token-py.zip -d /tmp && \
    pip install /tmp/spl-token-py-main && \
    rm -rf /tmp/spl-token-py.zip /tmp/spl-token-py-main

# Mettre à jour pip et installer les dépendances
RUN pip install --no-cache-dir --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

# Copier le reste du code
COPY . .

EXPOSE 8000

CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8000"]