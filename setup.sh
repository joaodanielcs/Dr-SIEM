#!/bin/bash

# ==============================================================================
#  SIEM - Dr.monitora // AUTOMATED PRODUCTION BOOTSTRAP (STRICT HTTPS ONLY)
# ==============================================================================

# 1. Validação de privilégios de segurança
if [ "$EUID" -ne 0 ]; then
  echo "❌ Erro de Segurança: Este script precisa ser executado como root ou com sudo."
  exit 1
fi

# 2. Instalação do motor Docker e Compose oficiais do Debian 13
if ! command -v docker &> /dev/null; then
    echo "📦 Preparando ambiente e Pipeline do Docker..."
    apt-get update -y > /dev/null 2>&1
    apt-get install -y docker.io docker-compose openssl ca-certificates curl > /dev/null 2>&1
    systemctl enable docker > /dev/null 2>&1
    systemctl start docker > /dev/null 2>&1
    echo "✓ Engine do Docker ativada!"
else
    echo "✓ Engine do Docker já validada."
fi

# 3. Fabricação das chaves SSL obrigatórias para o bindi do HTTPS interno
if [ ! -d certs ]; then
    echo "🔐 Gerando chaves SSL internas para sustentação do protocolo HTTPS..."
    mkdir -p certs
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
      -keyout certs/server.key \
      -out certs/server.crt \
      -subj "/C=BR/ST=SP/L=Local/O=SIEM/OU=Infra/CN=siem.local" > /dev/null 2>&1
    chmod 600 certs/server.key > /dev/null 2>&1
    echo "✓ Certificados SSL internos ativados!"
fi

# 4. Geração Dinâmica do Arquivo .env com credenciais de alta entropia
if [ ! -f .env ]; then
    echo "🔒 Provisionando senhas aleatórias seguras para o banco de dados..."
    SENHA_BANCO_ALEATORIA=$(openssl rand -hex 16)

    cat << EOF > .env
# ====== CONFIGURAÇÕES DO BANCO DE DADOS ======
POSTGRES_USER=dbadmin
POSTGRES_PASSWORD=$SENHA_BANCO_ALEATORIA
POSTGRES_DB=dr_siem_governance
EOF

    chmod 600 .env > /dev/null 2>&1
    echo "✓ Arquivo .env protegido gerado!"
else
    echo "✓ Arquivo .env existente detectado."
fi

# 5. Configuração do Serviço de Persistência Systemd (Para o boot do hardware)
echo "⚙️ Configurando serviço Systemd para persistência pós-reboot..."
DIR_ATUAL=$(pwd)

cat << EOF > /etc/systemd/system/dr-siem.service
[Unit]
Description=SIEM - Dr.monitora (Docker Compose Stack)
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=$DIR_ATUAL
ExecStart=/usr/bin/docker compose up -d
ExecStop=/usr/bin/docker compose down
StandardOutput=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload > /dev/null 2>&1
systemctl enable dr-siem.service > /dev/null 2>&1
echo "✓ Serviço dr-siem.service registrado!"

# 6. Inicialização da Stack Docker com Armazenamento Local Relativo
echo "🚀 Subindo os containers do SIEM em ambiente criptografado (Aguarde)..."
docker compose up -d > /dev/null 2>&1

echo "=============================================================================="
echo "🎯 [SIEM - Dr.monitora] INFRAESTRUTURA ONLINE!"
echo "🔒 MODO STRICT HTTPS ATIVO NA PORTA 443"
echo "🔀 No NPM, configure o Forward Scheme como: HTTPS na porta 443"
echo "🔑 Login inicial temporário: admin / admin"
echo "=============================================================================="
