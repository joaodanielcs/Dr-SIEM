const express = require('express');
const dgram = require('dgram');
const { Pool } = require('pg');
const { createClient } = require('@clickhouse/client');
const ActiveDirectory = require('activedirectory2');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
const https = require('https');
const fs = require('fs');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const pool = new Pool({
    host: process.env.PG_HOST,
    user: process.env.PG_USER,
    password: process.env.PG_PASSWORD,
    database: process.env.PG_NAME,
    port: 5432,
});

const chClient = createClient({
    url: process.env.CH_HOST,
    username: 'default',
    password: '',
});

function gerarHash(senha) {
    return crypto.createHash('sha256').update(senha).digest('hex');
}

function verificarToken(req, res, next) {
    const token = req.headers['authorization'];
    if (!token) return res.status(401).json({ error: 'Autenticação pendente.' });
    
    pool.query('SELECT username, role FROM siem_sessions WHERE token = $1 AND expiracao > NOW()', [token], (err, result) => {
        if (err || result.rows.length === 0) return res.status(403).json({ error: 'Sessão inválida ou expirada.' });
        req.usuarioLogado = result.rows[0].username;
        req.usuarioRole = result.rows[0].role;
        next();
    });
}

async function initDatabases() {
    const pgClient = await pool.connect();
    try {
        await pgClient.query(`
            CREATE TABLE IF NOT EXISTS siem_local_users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password_hash VARCHAR(64) NOT NULL,
                force_change BOOLEAN DEFAULT TRUE
            );
        `);

        const userCheck = await pgClient.query('SELECT * FROM siem_local_users WHERE username = \'ADMIN\'');
        if (userCheck.rows.length === 0) {
            await pgClient.query('INSERT INTO siem_local_users (username, password_hash, force_change) VALUES ($1, $2, $3)', 
                ['ADMIN', gerarHash('admin'), true]);
            console.log("⚠️ [DAY-0] Usuário temporário criado: ADMIN / admin");
        }

        await pgClient.query(`
            CREATE TABLE IF NOT EXISTS system_settings (
                key VARCHAR(50) PRIMARY KEY,
                value TEXT NOT NULL
            );
        `);

        await pgClient.query(`
            CREATE TABLE IF NOT EXISTS siem_sessions (
                token VARCHAR(64) PRIMARY KEY,
                username VARCHAR(100) NOT NULL,
                role VARCHAR(20) NOT NULL,
                expiracao TIMESTAMPTZ NOT NULL
            );
        `);
    } catch (err) {
        console.error("🔴 Erro ao subir tabelas locais:", err);
    } finally { pgClient.release(); }

    try {
        await chClient.command({ query: `CREATE TABLE IF NOT EXISTS default.ad_logons (timestamp DateTime, username String, computer_name String, ip String) ENGINE = MergeTree() ORDER BY (ip, timestamp);` });
        await chClient.command({ query: `CREATE TABLE IF NOT EXISTS default.dns_logs (timestamp DateTime, ip String, domain String, status String) ENGINE = MergeTree() ORDER BY (timestamp, domain);` });
    } catch(e) {}
}
setTimeout(initDatabases, 5000);

app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;
    const userUpper = username.toUpperCase();

    if (userUpper === 'ADMIN') {
        try {
            const hash = gerarHash(password);
            const result = await pool.query('SELECT force_change FROM siem_local_users WHERE username = \'ADMIN\' AND password_hash = $1', [hash]);
            
            if (result.rows.length > 0) {
                const token = crypto.randomBytes(32).toString('hex');
                const forceChange = result.rows[0].force_change;
                
                // CHECAGEM INTELIGENTE DE DAY-0: O AD já foi integrado alguma vez?
                const settingsCheck = await pool.query("SELECT 1 FROM system_settings WHERE key = 'ad_ip'");
                const adConfigured = settingsCheck.rows.length > 0;
                
                await pool.query('INSERT INTO siem_sessions (token, username, role, expiracao) VALUES ($1, $2, $3, NOW() + INTERVAL \'2 hours\')', 
                    [token, 'ADMIN', 'ADMIN']);
                
                return res.json({ 
                    success: true, 
                    token, 
                    username: 'ADMIN', 
                    role: 'ADMIN', 
                    force_change: forceChange,
                    ad_configured: adConfigured // Envia a flag para o front decidir a tela
                });
            } else {
                return res.status(401).json({ error: 'Senha do administrador incorreta.' });
            }
        } catch (err) { return res.status(500).json({ error: err.message }); }
    }

    try {
        const settingsRes = await pool.query('SELECT * FROM system_settings');
        const config = {};
        settingsRes.rows.forEach(row => { config[row.key] = row.value; });

        if (!config.ad_ip || !config.ad_domain || !config.ad_allowed_group) {
            return res.status(400).json({ error: 'O sistema ainda não foi integrado ao Active Directory.' });
        }

        const computedBaseDN = config.ad_domain.split('.').map(part => `DC=${part}`).join(',');
        const computedBindUser = `${config.ad_user}@${config.ad_domain}`;

        const adConfig = {
            url: `ldap://${config.ad_ip}:389`,
            baseDN: computedBaseDN,
            username: computedBindUser,
            password: config.ad_pass,
        };

        const userPrincipalName = `${username}@${config.ad_domain}`;
        const ad = new ActiveDirectory(adConfig);

        ad.authenticate(userPrincipalName, password, (err, authSuccess) => {
            if (err || !authSuccess) return res.status(401).json({ error: 'Credenciais inválidas no Active Directory.' });

            ad.isUserMemberOf(userPrincipalName, config.ad_allowed_group, async (err, isMember) => {
                if (err || !isMember) return res.status(403).json({ error: `Acesso negado. Usuário fora do grupo '${config.ad_allowed_group}'.` });

                const token = crypto.randomBytes(32).toString('hex');
                await pool.query('INSERT INTO siem_sessions (token, username, role, expiracao) VALUES ($1, $2, $3, NOW() + INTERVAL \'8 hours\')', 
                    [token, userUpper, 'OPERADOR']);
                
                res.json({ success: true, token, username: userUpper, role: 'OPERADOR', force_change: false });
            });
        });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/auth/change-password', verificarToken, async (req, res) => {
    const { new_password } = req.body;
    if (req.usuarioLogado !== 'ADMIN') return res.status(403).json({ error: 'Ação exclusiva do administrador.' });

    try {
        const newHash = gerarHash(new_password);
        await pool.query('UPDATE siem_local_users SET password_hash = $1, force_change = FALSE WHERE username = \'ADMIN\'', [newHash]);
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/settings', verificarToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT key, value FROM system_settings');
        const config = {};
        result.rows.forEach(row => { 
            config[row.key] = row.key === 'ad_pass' ? '********' : row.value; 
        });
        res.json(config);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/settings', verificarToken, async (req, res) => {
    if (req.usuarioRole !== 'ADMIN') return res.status(403).json({ error: 'Acesso negado.' });
    const configs = req.body;
    try {
        for (const [key, value] of Object.entries(configs)) {
            if (key === 'ad_pass' && value === '********') continue;
            await pool.query('INSERT INTO system_settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2', [key, value]);
        }
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/auth/logout', verificarToken, async (req, res) => {
    const token = req.headers['authorization'];
    await pool.query('DELETE FROM siem_sessions WHERE token = $1', [token]);
    res.json({ success: true });
});

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

app.get('/api/logs', verificarToken, async (req, res) => {
    let { page = 1, limit = 500, search = '', status = '' } = req.query;
    page = parseInt(page); limit = parseInt(limit);
    const offset = (page - 1) * limit;

    let filtros = ['1=1'];
    if (search) filtros.push(`(domain LIKE '%${search}%' OR ip LIKE '%${search}%')`);
    if (status) filtros.push(`status = '${status}'`);
    const whereClause = filtros.join(' AND ');

    try {
        const query = `
            SELECT 
                formatDateTime(timestamp, '%d/%m/%Y %H:%i:%s') as data_hora, ip, domain, status,
                coalesce((SELECT computer_name FROM default.ad_logons WHERE ip = dns_logs.ip AND timestamp <= dns_logs.timestamp ORDER BY timestamp DESC LIMIT 1), if(ip LIKE '172.16.24.%', 'DISPOSITIVO S/ FIO', 'DESCONHECIDO (AD)')) as hostname,
                coalesce((SELECT username FROM default.ad_logons WHERE ip = dns_logs.ip AND timestamp <= dns_logs.timestamp ORDER BY timestamp DESC LIMIT 1), if(ip LIKE '172.16.24.%', 'MÓVEL / BYOD', '-')) as usuario
            FROM default.dns_logs WHERE ${whereClause} ORDER BY timestamp DESC LIMIT ${limit} OFFSET ${offset}
        `;
        
        const totalResult = await chClient.query({ query: `SELECT count() as count FROM default.dns_logs WHERE ${whereClause}`, format: 'JSONEachRow' });
        const totalRows = await totalResult.json();
        const total = totalRows[0] ? parseInt(totalRows[0].count) : 0;

        const dataResult = await chClient.query({ query: query, format: 'JSONEachRow' });
        const data = await dataResult.json();
        res.json({ total, page, limit, data });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

const sslOptions = {
    key: fs.readFileSync(path.join(__dirname, 'certs/server.key')),
    cert: fs.readFileSync(path.join(__dirname, 'certs/server.crt'))
};

https.createServer(sslOptions, app).listen(8443, () => {
    console.log("🚀 [SIEM] Servidor HTTPS Protegido Ativo na porta 8443!");
});
