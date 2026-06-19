#!/bin/bash

# ==============================================================================
#  SIEM - Dr.monitora // SCRIPT DE BOOTSTRAP E PROVISIONAMENTO CRIPTOGRÁFICO
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

# 3. Geração Dinâmica do Arquivo .env com chaves aleatórias em tempo de execução
if [ ! -f .env ]; then
    echo "🔒 Gerando credenciais exclusivas e criando o arquivo .env..."
    
    # Gera uma senha randômica complexa e segura de 24 caracteres para o banco de dados
    SENHA_BANCO_ALEATORIA=$(openssl rand -base64 18)

    # Escreve o arquivo .env exatamente no formato exigido
    cat << EOF > .env
# ====== CONFIGURAÇÕES DO BANCO DE DADOS ======
POSTGRES_USER=dbadmin
POSTGRES_PASSWORD=$SENHA_BANCO_ALEATORIA
POSTGRES_DB=dr_siem_governance

# ====== CREDENCIAIS PADRÃO DO PAINEL (PRIMEIRO BOOT) ======
INITIAL_ADMIN_USER=admin
INITIAL_ADMIN_PASSWORD=admin
EOF

    # Medida Crítica de SI: Altera permissões para que apenas o Root leia o arquivo
    chmod 600 .env
    echo "✓ Arquivo .env estruturado e protegido com sucesso (Chmod 600 aplicado)!"
else
    echo "✓ Arquivo .env existente detectado. Pulando etapa de geração para preservar dados."
fi

# 4. Configuração do Serviço de Persistência Systemd no Kernel do Linux
echo "⚙️ Registrando serviço dr-siem no Systemd para autoinicialização corporativa..."
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

# 5. Inicialização da Stack
systemctl daemon-reload
systemctl enable dr-siem.service

echo "🚀 Disparando orquestrador Docker Compose..."
systemctl start dr-siem.service

echo "=============================================================================="
echo "🎯 [SIEM - Dr.monitora] INFRAESTRUTURA MONTADA COM SUCESSO!"
echo "🌐 Painel de Governança disponível em: http://$(hostname -I | awk '{print $1}'):8080"
echo "🔐 Autenticação da Interface: admin / admin"
echo "🗄️ Segurança do Banco: Usuário 'dbadmin' com senha criptográfica gerada no .env"
echo "=============================================================================="
