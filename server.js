const express = require('express');
const dgram = require('dgram');
const { Pool } = require('pg');
const { createClient } = require('@clickhouse/client');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Conexão Postgres (Autenticação e Setup)
const pgPool = new Pool({
    host: process.env.PG_HOST,
    user: process.env.PG_USER,
    password: process.env.PG_PASSWORD,
    database: process.env.PG_NAME,
    port: 5432,
});

// Conexão ClickHouse (Big Data / Logs)
const chClient = createClient({
    url: process.env.CH_HOST,
    username: 'default',
    password: '',
});

function gerarHash(senha) {
    return crypto.createHash('sha256').update(senha).digest('hex');
}

// Middleware de Proteção de Tela
function verificarToken(req, res, next) {
    const token = req.headers['authorization'];
    if (!token) return res.status(401).json({ error: 'Autenticação pendente.' });
    
    pgPool.query('SELECT username FROM siem_users WHERE token = $1', [token], (err, result) => {
        if (err || result.rows.length === 0) return res.status(403).json({ error: 'Sessão expirada.' });
        req.usuarioLogado = result.rows[0].username;
        next();
    });
}

// === INICIALIZAÇÃO DOS DOIS BANCOS DE DADOS ===
async function initDatabases() {
    // 1. Inicializa tabelas de segurança no Postgres
    const pgClient = await pgPool.connect();
    try {
        await pgClient.query(`
            CREATE TABLE IF NOT EXISTS siem_users (
                id SERIAL PRIMARY KEY, username VARCHAR(50) UNIQUE NOT NULL,
                password_hash VARCHAR(64) NOT NULL, role VARCHAR(20) DEFAULT 'OPERADOR', token VARCHAR(64)
            );
            CREATE TABLE IF NOT EXISTS system_settings (key VARCHAR(50) PRIMARY KEY, value TEXT NOT NULL);
        `);
        const userCheck = await pgClient.query('SELECT * FROM siem_users LIMIT 1');
        if (userCheck.rows.length === 0) {
            await pgClient.query('INSERT INTO siem_users (username, password_hash, role) VALUES ($1, $2, $3)', 
                [(process.env.INITIAL_ADMIN_USER || 'admin').toUpperCase(), gerarHash(process.env.INITIAL_ADMIN_PASSWORD || 'admin'), 'ADMIN']);
        }
    } finally { pgClient.release(); }

    // 2. Inicializa tabelas de alta performance no ClickHouse (Engine MergeTree por data)
    await chClient.command({
        query: `
            CREATE TABLE IF NOT EXISTS default.ad_logons (
                timestamp DateTime, username String, computer_name String, ip String
            ) ENGINE = MergeTree() ORDER BY (ip, timestamp);
        `
    });

    await chClient.command({
        query: `
            CREATE TABLE IF NOT EXISTS default.dns_logs (
                timestamp DateTime, ip String, domain String, status String
            ) ENGINE = MergeTree() ORDER BY (timestamp, domain);
        `
    });
    console.log("🟢 [SIEM - Dr.monitora] Motores Postgres e ClickHouse inicializados com sucesso!");
}
// Aguarda os containers estabilizarem para criar as tabelas
setTimeout(initDatabases, 5000);

// === ENDPOINTS DE AUTENTICAÇÃO ===
app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const result = await pgPool.query('SELECT id, role FROM siem_users WHERE UPPER(username) = $1 AND password_hash = $2', [username.toUpperCase(), gerarHash(password)]);
        if (result.rows.length > 0) {
            const token = crypto.randomBytes(32).toString('hex');
            await pgPool.query('UPDATE siem_users SET token = $1 WHERE id = $2', [token, result.rows[0].id]);
            res.json({ success: true, token, role: result.rows[0].role });
        } else { res.status(401).json({ error: 'Credenciais inválidas.' }); }
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/auth/logout', verificarToken, async (req, res) => {
    await pgPool.query('UPDATE siem_users SET token = NULL WHERE username = $1', [req.usuarioLogado]);
    res.json({ success: true });
});

// === COLETOR SYSLOG DOS PI-HOLES (DIRECT TO CLICKHOUSE) ===
const syslogServer = dgram.createSocket('udp4');
syslogServer.on('message', async (msg) => {
    const logLinha = msg.toString();
    if (logLinha.includes('query[')) {
        let status = logLinha.includes('blocked') || logLinha.includes('gravity') ? "BLOQUEADO" : "PERMITIDO";
        const match = logLinha.match(/query\[A+\]\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\s+from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
        if (match) {
            const [_, domain, ip] = match;
            try {
                await chClient.insert({
                    table: 'default.dns_logs',
                    values: [{ timestamp: new Date().toISOString().slice(0,19).replace('T', ' '), ip, domain, status }],
                    format: 'JSONEachRow'
                });
            } catch (err) {}
        }
    }
});
syslogServer.bind(514);

// === WEBHOOK INGESTÃO AD (DIRECT TO CLICKHOUSE) ===
app.post('/api/ad/logon', async (req, res) => {
    const { username, computer_name, ip } = req.body;
    try {
        await chClient.insert({
            table: 'default.ad_logons',
            values: [{ timestamp: new Date().toISOString().slice(0,19).replace('T', ' '), username: username.toUpperCase(), computer_name: computer_name.toUpperCase(), ip }],
            format: 'JSONEachRow'
        });
        res.status(201).json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// === CONSULTA MASTER SIEM (BUSCA DINÂMICA NO CLICKHOUSE) ===
app.get('/api/logs', verificarToken, async (req, res) => {
    let { page = 1, limit = 500, search = '', status = '' } = req.query;
    page = parseInt(page); limit = parseInt(limit);
    const offset = (page - 1) * limit;

    let filtros = ['1=1'];
    if (search) filtros.push(`(domain LIKE '%${search}%' OR ip LIKE '%${search}%')`);
    if (status) filtros.push(`status = '${status}'`);
    const whereClause = filtros.join(' AND ');

    try {
        // Query de performance colunar nativa do Clickhouse buscando correlação com os logons do AD
        const query = `
            SELECT 
                formatDateTime(timestamp, '%d/%m/%Y %H:%i:%s') as data_hora,
                ip, domain, status,
                coalesce((SELECT computer_name FROM default.ad_logons WHERE ip = dns_logs.ip AND timestamp <= dns_logs.timestamp ORDER BY timestamp DESC LIMIT 1), if(ip LIKE '172.16.24.%', 'DISPOSITIVO S/ FIO', 'DESCONHECIDO (AD)')) as hostname,
                coalesce((SELECT username FROM default.ad_logons WHERE ip = dns_logs.ip AND timestamp <= dns_logs.timestamp ORDER BY timestamp DESC LIMIT 1), if(ip LIKE '172.16.24.%', 'MÓVEL / BYOD', '-')) as usuario
            FROM default.dns_logs
            WHERE ${whereClause}
            ORDER BY timestamp DESC
            LIMIT ${limit} OFFSET ${offset}
        `;

        const totalQuery = `SELECT count() as count FROM default.dns_logs WHERE ${whereClause}`;
        
        const totalResult = await chClient.query({ query: totalQuery, format: 'JSONEachRow' });
        const totalRows = await totalResult.json();
        const total = totalRows[0] ? parseInt(totalRows[0].count) : 0;

        const dataResult = await chClient.query({ query: query, format: 'JSONEachRow' });
        const data = await dataResult.json();

        res.json({ total, page, limit, data });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.listen(8080);
