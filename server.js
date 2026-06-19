const express = require('express');
const dgram = require('dgram');
const { Pool } = require('pg');
const cors = require('cors');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Inicialização do Pool do PostgreSQL via variáveis do Docker
const pool = new Pool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: 5432,
});

// === INICIALIZAÇÃO E PRÉ-REQUISITOS DO BANCO ===
async function initDatabase() {
    const client = await pool.connect();
    try {
        // Tabela que armazena os Logons do Active Directory (Event ID 4624)
        await client.query(`
            CREATE TABLE IF NOT EXISTS ad_logons (
                id SERIAL PRIMARY KEY,
                timestamp TIMESTAMPTZ NOT NULL,
                username VARCHAR(100) NOT NULL,
                computer_name VARCHAR(100) NOT NULL,
                ip VARCHAR(45) NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_ad_identity ON ad_logons (ip, timestamp DESC);
        `);

        // Tabela que centraliza as consultas DNS dos 3 Pi-holes
        await client.query(`
            CREATE TABLE IF NOT EXISTS dns_logs (
                id SERIAL PRIMARY KEY,
                timestamp TIMESTAMPTZ NOT NULL,
                ip VARCHAR(45) NOT NULL,
                domain VARCHAR(255) NOT NULL,
                status VARCHAR(20) NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_dns_master ON dns_logs (timestamp DESC);
        `);
        console.log("🟢 [SIEM - Dr.monitora] Tabelas validadas com sucesso.");
    } catch (err) {
        console.error("🔴 Erro de infraestrutura no banco:", err);
    } finally {
        client.release();
    }
}
initDatabase();

// === ENDPOINT: RECONHECIMENTO DE USUÁRIOS DO AD ===
app.post('/api/ad/logon', async (req, res) => {
    const { username, computer_name, ip } = req.body;
    try {
        await pool.query(
            'INSERT INTO ad_logons (timestamp, username, computer_name, ip) VALUES (NOW(), $1, $2, $3)',
            [username.toUpperCase(), computer_name.toUpperCase(), ip]
        );
        res.status(201).json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// === COLETOR SYSLOG INTERNO (PORTA 514 UDP) ===
const syslogServer = dgram.createSocket('udp4');

syslogServer.on('message', async (msg) => {
    const logLinha = msg.toString();
    
    if (logLinha.includes('query[') || logLinha.includes('cached') || logLinha.includes('gravity')) {
        let status = "PERMITIDO";
        if (logLinha.includes('gravity blocked') || logLinha.includes('blocked')) {
            status = "BLOQUEADO";
        }

        const match = logLinha.match(/query\[A+\]\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\s+from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
        if (match) {
            const [_, dominio, ip] = match;
            try {
                await pool.query(
                    'INSERT INTO dns_logs (timestamp, ip, domain, status) VALUES (NOW(), $1, $2, $3)',
                    [ip, dominio, status]
                );
            } catch (err) {
                // Previne interrupção do tráfego UDP em picos de alta requisição
            }
        }
    }
});
syslogServer.bind(514);

// === API DO DASHBOARD: MOTOR DE CORRELAÇÃO DE IDENTIDADES ===
app.get('/api/logs', async (req, res) => {
    let { page = 1, limit = 500, search = '', status = '', start_date, end_date } = req.query;
    page = parseInt(page);
    limit = parseInt(limit);
    const offset = (page - 1) * limit;

    let queryFiltros = [];
    let valores = [];
    let idx = 1;

    if (search) {
        queryFiltros.push(`(d.domain LIKE $${idx} OR d.ip LIKE $${idx})`);
        valores.push(`%${search}%`);
        idx++;
    }
    if (status) {
        queryFiltros.push(`d.status = $${idx}`);
        valores.push(status);
        idx++;
    }
    if (start_date && end_date) {
        queryFiltros.push(`d.timestamp BETWEEN $${idx} AND $${idx + 1}`);
        valores.push(start_date, end_date);
        idx += 2;
    }

    const stringOnde = queryFiltros.length ? 'WHERE ' + queryFiltros.join(' AND ') : '';

    // Subquery correlacionando os timestamps para apontar qual usuário estava logado no momento exato do clique
    const queryPrincipal = `
        SELECT 
            d.id,
            to_char(d.timestamp, 'DD/MM/YYYY HH24:MI:SS') as data_hora,
            d.ip,
            d.domain,
            d.status,
            COALESCE(
                (SELECT a.computer_name FROM ad_logons a WHERE a.ip = d.ip AND a.timestamp <= d.timestamp ORDER BY a.timestamp DESC LIMIT 1),
                CASE WHEN d.ip LIKE '172.16.24.%' THEN 'DISPOSITIVO S/ FIO' ELSE 'NÃO IDENTIFICADO (AD)' END
            ) as hostname,
            COALESCE(
                (SELECT a.username FROM ad_logons a WHERE a.ip = d.ip AND a.timestamp <= d.timestamp ORDER BY a.timestamp DESC LIMIT 1),
                CASE WHEN d.ip LIKE '172.16.24.%' THEN 'MÓVEL / BYOD' ELSE '-' END
            ) as usuario
        FROM dns_logs d
        ${stringOnde}
        ORDER BY d.timestamp DESC
        LIMIT $${idx} OFFSET $${idx + 1}
    `;

    try {
        const totalResultados = await pool.query(`SELECT COUNT(*) FROM dns_logs d ${stringOnde}`, valores.slice(0, idx - 1));
        const resultadoLogs = await pool.query(queryPrincipal, [...valores, limit, offset]);
        
        res.json({
            total: parseInt(totalResultados.rows[0].count),
            page,
            limit,
            data: resultadoLogs.rows
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.listen(8080, () => console.log("🚀 [SIEM - Dr.monitora] Aplicação escutando requisições na porta 8080!"));
