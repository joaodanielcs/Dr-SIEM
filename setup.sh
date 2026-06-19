#!/bin/bash

# ==============================================================================
#  SIEM - Dr.monitora // SCRIPT DE BOOTSTRAP E PROVISIONAMENTO CRIPTOGRÁFICO SSL
# ==============================================================================

echo "🔍 Verificando privilégios e iniciando provisionamento seguro..."

# 1. Validação de privilégios de segurança
if [ "$EUID" -ne 0 ]; then
  echo "❌ Erro de Segurança: Este script precisa ser executado como root."
  exit 1
fi

# 2. Instalação automatizada do motor Docker e Compose
if ! command -v docker &> /dev/null; then
    echo "📦 Preparando ambiente e instalando Docker / Docker Compose..."
    apt-get update -y
    apt-get install -y apt-transport-https ca-certificates curl software-properties-common openssl
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
    apt-get update -y
    apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
    systemctl enable docker
    systemctl start docker
    echo "✓ Engine do Docker ativada!"
else
    echo "✓ Engine do Docker validada."
fi

# 3. Geração Automática dos Certificados SSL Internos (Zero Trust)
if [ ! -d certs ]; then
    echo "🔐 Gerando Certificado SSL Autoassinado para comunicação HTTPS interna..."
    mkdir -p certs
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
      -keyout certs/server.key \
      -out certs/server.crt \
      -subj "/C=BR/ST=SP/L=SaoPaulo/O=DrMonitora/OU=IT/CN=drsiem.local"
    chmod 600 certs/server.key
    echo "✓ Certificados SSL internos gerados!"
fi

# 4. Geração Dinâmica do Arquivo .env
if [ ! -f .env ]; then
    echo "🔒 Gerando credenciais exclusivas e criando o arquivo .env..."
    SENHA_BANCO_ALEATORIA=$(openssl rand -base64 18)

    cat << EOF > .env
# ====== CONFIGURAÇÕES DO BANCO DE DADOS ======
POSTGRES_USER=dbadmin
POSTGRES_PASSWORD=$SENHA_BANCO_ALEATORIA
POSTGRES_DB=dr_siem_governance

# ====== CREDENCIAIS PADRÃO DO PAINEL (PRIMEIRO BOOT) ======
INITIAL_ADMIN_USER=admin
INITIAL_ADMIN_PASSWORD=admin
EOF

    chmod 600 .env
    echo "✓ Arquivo .env estruturado e protegido (Chmod 600 aplicado)!"
else
    echo "✓ Arquivo .env existente detectado. Pulando etapa de geração para preservar dados."
fi

# 5. Configuração do Serviço de Persistência Systemd
echo "⚙️ Registrando serviço dr-siem no Systemd..."
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

# 6. Inicialização da Stack
systemctl daemon-reload
systemctl enable dr-siem.service

echo "🚀 Disparando orquestrador Docker Compose..."
systemctl start dr-siem.service

echo "=============================================================================="
echo "🎯 [SIEM - Dr.monitora] INFRAESTRUTURA MONTADA COM SUCESSO!"
echo "🌐 Painel de Governança disponível em HTTPS na porta padrão 443 do servidor"
echo "🔐 Autenticação da Interface: admin / admin"
echo "=============================================================================="
