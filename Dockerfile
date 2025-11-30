# syntax=docker/dockerfile:1
FROM python:3.11-slim

# Installer git, curl et les dépendances de build pour solders
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    libssl-dev \
    libffi-dev \
    python3-dev \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Configurer git pour éviter les prompts d'authentification
RUN git config --global user.name "builder" && git config --global user.email "builder@example.com"
ENV GIT_ASKPASS=/bin/true
ENV GIT_TERMINAL_PROMPT=0

WORKDIR /app

# Copier requirements.txt en premier pour profiter du cache Docker
COPY requirements.txt .

# Télécharger et installer solana-py avec spl
RUN git clone --depth 1 https://github.com/michaelhly/solana-py.git /tmp/solana-py && \
    pip install /tmp/solana-py && \
    rm -rf /tmp/solana-py

# Mettre à jour pip et installer les autres dépendances
RUN pip install --no-cache-dir --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

# Copier le reste du code
COPY . .

EXPOSE 8000

CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8000"]