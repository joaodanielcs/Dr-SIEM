#!/bin/bash

# ==============================================================================
#  SIEM - Dr.monitora // SCRIPT DE BOOTSTRAP DAY-0
# ==============================================================================

if [ "$EUID" -ne 0 ]; then
  echo "❌ Erro de Segurança: Este script precisa ser executado como root."
  exit 1
fi

if ! command -v docker &> /dev/null; then
    echo "📦 Instalando dependências e Engine do Docker..."
    apt-get update -y
    apt-get install -y apt-transport-https ca-certificates curl software-properties-common openssl
    curl -fsSL https://download.google.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
    apt-get update -y
    apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
    systemctl enable docker
    systemctl start docker
fi

if [ ! -d certs ]; then
    echo "🔐 Fabricando chaves TLS locais para HTTPS interno..."
    mkdir -p certs
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
      -keyout certs/server.key \
      -out certs/server.crt \
      -subj "/C=BR/ST=SP/L=SaoPaulo/O=DrMonitora/OU=IT/CN=drsiem.local"
    chmod 600 certs/server.key
fi

if [ ! -f .env ]; then
    echo "🔒 Provisionando senhas aleatórias do banco de dados..."
    SENHA_BANCO_ALEATORIA=$(openssl rand -base64 18)

    cat << EOF > .env
# ====== CONFIGURAÇÕES DO BANCO DE DADOS ======
POSTGRES_USER=dbadmin
POSTGRES_PASSWORD=$SENHA_BANCO_ALEATORIA
POSTGRES_DB=dr_siem_governance
EOF

    chmod 600 .env
    echo "✓ Arquivo .env protegido gerado!"
fi

echo "⚙️ Configurando serviço Systemd para o SIEM..."
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

systemctl daemon-reload
systemctl enable dr-siem.service
systemctl start dr-siem.service

echo "=============================================================================="
echo "🎯 [SIEM - Dr.monitora] INFRAESTRUTURA ONLINE!"
echo "🌐 Acesse: HTTPS na porta 443 do servidor"
echo "🔑 Login inicial temporário: admin / admin"
echo "=============================================================================="
