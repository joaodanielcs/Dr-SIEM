const express = require('express');
const dgram = require('dgram');
const { Pool } = require('pg');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Inicialização do Banco sem dados fixos (puxa tudo das variáveis de ambiente tratadas pelo Docker)
const pool = new Pool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: 5432,
});

// Helper de Segurança: SHA256 para não expor senhas limpas no banco
function gerarHash(senha) {
    return crypto.createHash('sha256').update(senha).digest('hex');
}

// === MIDDLEWARE DE CRIPTOGRAFIA E VALIDAÇÃO DE SESSÃO ===
function verificarToken(req, res, next) {
    const token = req.headers['authorization'];
    if (!token) return res.status(401).json({ error: 'Acesso negado. Autenticação pendente.' });
    
    pool.query('SELECT username FROM siem_users WHERE token = $1', [token], (err, result) => {
        if (err || result.rows.length === 0) {
            return res.status(403).json({ error: 'Sessão inválida ou expirada.' });
        }
        req.usuarioLogado = result.rows[0].username;
        next();
    });
}

// === CRIAÇÃO E CONFIGURAÇÃO DA INFRAESTRUTURA DE DADOS ===
async function initDatabase() {
    const client = await pool.connect();
    try {
        // Tabela de Controle de Operadores
        await client.query(`
            CREATE TABLE IF NOT EXISTS siem_users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password_hash VARCHAR(64) NOT NULL,
                role VARCHAR(20) DEFAULT 'OPERADOR',
                token VARCHAR(64)
            );
        `);

        // GESTÃO DE CREDENCIAIS ZERO-HARDCODED: 
        // Se a tabela estiver vazia, ele injeta os dados do .env. Se não houver .env, usa admin/admin de forma segura.
        const userCheck = await client.query('SELECT * FROM siem_users LIMIT 1');
        if (userCheck.rows.length === 0) {
            const usuarioInicial = (process.env.INITIAL_ADMIN_USER || 'admin').toUpperCase();
            const senhaInicialRaw = process.env.INITIAL_ADMIN_PASSWORD || 'admin';
            const senhaHash = gerarHash(senhaInicialRaw);

            await client.query(
                'INSERT INTO siem_users (username, password_hash, role) VALUES ($1, $2, $3)',
                [usuarioInicial, senhaHash, 'ADMIN']
            );
            console.log(`⚠️ [SECURITY] Banco novo detectado. Usuário de fábrica criado: ${usuarioInicial}`);
        }

        // Demais tabelas de persistência (Configurações, AD e DNS)
        await client.query(`
            CREATE TABLE IF NOT EXISTS system_settings (
                key VARCHAR(50) PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS ad_logons (
                id SERIAL PRIMARY KEY,
                timestamp TIMESTAMPTZ NOT NULL,
                username VARCHAR(100) NOT NULL,
                computer_name VARCHAR(100) NOT NULL,
                ip VARCHAR(45) NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_ad_identity ON ad_logons (ip, timestamp DESC);

            CREATE TABLE IF NOT EXISTS dns_logs (
                id SERIAL PRIMARY KEY,
                timestamp TIMESTAMPTZ NOT NULL,
                ip VARCHAR(45) NOT NULL,
                domain VARCHAR(255) NOT NULL,
                status VARCHAR(20) NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_dns_master ON dns_logs (timestamp DESC);
        `);

        console.log("🟢 [SIEM - Dr.monitora] Definições de segurança e tabelas aplicadas.");
    } catch (err) {
        console.error("🔴 Falha na inicialização da infra de dados:", err);
    } finally {
        client.release();
    }
}
initDatabase();

// === ENDPOINTS DE AUTENTICAÇÃO ===
app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const hash = gerarHash(password);
        const result = await pool.query(
            'SELECT id, role FROM siem_users WHERE UPPER(username) = $1 AND password_hash = $2',
            [username.toUpperCase(), hash]
        );

        if (result.rows.length > 0) {
            const token = crypto.randomBytes(32).toString('hex');
            await pool.query('UPDATE siem_users SET token = $1 WHERE id = $2', [token, result.rows[0].id]);
            res.json({ success: true, token, role: result.rows[0].role });
        } else {
            res.status(401).json({ error: 'Credenciais inválidas para o domínio do SIEM.' });
        }
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/auth/logout', verificarToken, async (req, res) => {
    try {
        await pool.query('UPDATE siem_users SET token = NULL WHERE username = $1', [req.usuarioLogado]);
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// === ENDPOINTS DE PARÂMETROS DE INFRAESTRUTURA (PROTEGIDOS) ===
app.get('/api/settings', verificarToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM system_settings');
        const config = {};
        result.rows.forEach(row => { config[row.key] = row.value; });
        res.json(config);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/settings', verificarToken, async (req, res) => {
    const configs = req.body;
    try {
        for (const [key, value] of Object.entries(configs)) {
            await pool.query(
                'INSERT INTO system_settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2',
                [key, value]
            );
        }
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// === RECEPTOR SYSLOG DOS PI-HOLES (PORTA 514 UDP) ===
const syslogServer = dgram.createSocket('udp4');
syslogServer.on('message', async (msg) => {
    const logLinha = msg.toString();
    if (logLinha.includes('query[') || logLinha.includes('cached') || logLinha.includes('gravity')) {
        let status = "PERMITIDO";
        if (logLinha.includes('gravity blocked') || logLinha.includes('blocked')) { status = "BLOQUEADO"; }
        
        const match = logLinha.match(/query\[A+\]\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\s+from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
        if (match) {
            const [_, dominio, ip] = match;
            try {
                await pool.query('INSERT INTO dns_logs (timestamp, ip, domain, status) VALUES (NOW(), $1, $2, $3)', [ip, dominio, status]);
            } catch (err) {}
        }
    }
});
syslogServer.bind(514);

// === INGESTÃO VIA WEBHOOK DO AD ===
app.post('/api/ad/logon', async (req, res) => {
    const { username, computer_name, ip } = req.body;
    try {
        await pool.query('INSERT INTO ad_logons (timestamp, username, computer_name, ip) VALUES (NOW(), $1, $2, $3)', [username.toUpperCase(), computer_name.toUpperCase(), ip]);
        res.status(201).json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// === CONSULTA MASTER AUDITORIA (PROTEGIDA) ===
app.get('/api/logs', verificarToken, async (req, res) => {
    let { page = 1, limit = 500, search = '', status = '' } = req.query;
    page = parseInt(page); limit = parseInt(limit);
    const offset = (page - 1) * limit;

    let queryFiltros = []; let valores = []; let idx = 1;
    if (search) { queryFiltros.push(`(d.domain LIKE $${idx} OR d.ip LIKE $${idx})`); valores.push(`%${search}%`); idx++; }
    if (status) { queryFiltros.push(`d.status = $${idx}`); valores.push(status); idx++; }
    const stringOnde = queryFiltros.length ? 'WHERE ' + queryFiltros.join(' AND ') : '';

    const queryPrincipal = `
        SELECT d.id, to_char(d.timestamp, 'DD/MM/YYYY HH24:MI:SS') as data_hora, d.ip, d.domain, d.status,
            COALESCE((SELECT a.computer_name FROM ad_logons a WHERE a.ip = d.ip AND a.timestamp <= d.timestamp ORDER BY a.timestamp DESC LIMIT 1), 'NÃO IDENTIFICADO') as hostname,
            COALESCE((SELECT a.username FROM ad_logons a WHERE a.ip = d.ip AND a.timestamp <= d.timestamp ORDER BY a.timestamp DESC LIMIT 1), '-') as usuario
        FROM dns_logs d ${stringOnde} ORDER BY d.timestamp DESC LIMIT $${idx} OFFSET $${idx + 1}
    `;
    try {
        const totalResultados = await pool.query(`SELECT COUNT(*) FROM dns_logs d ${stringOnde}`, valores.slice(0, idx - 1));
        const resultadoLogs = await pool.query(queryPrincipal, [...valores, limit, offset]);
        res.json({ total: parseInt(totalResultados.rows[0].count), page, limit, data: resultadoLogs.rows });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.listen(8080);
