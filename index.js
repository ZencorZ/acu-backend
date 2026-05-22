import express from 'express';
import cors from 'cors';
import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import bcrypt from 'bcryptjs';  // ← ИЗМЕНЕНО на bcryptjs
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import crypto from 'crypto';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config();

const app = express();

// Доверие к прокси (для Timeweb)
app.set('trust proxy', 1);

const PORT = process.env.PORT || 3001;
const HOST = '0.0.0.0';

// ========== НАСТРОЙКИ БЕЗОПАСНОСТИ ==========

app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
            imgSrc: ["'self'", "data:", "https:", "http:"],
            connectSrc: ["'self'", "https://whitelistsync.com", "https://api.mojang.com", "https://sessionserver.mojang.com", "https://mcapi.us"],
        },
    },
}));

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { error: 'Слишком много запросов' },
});

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: { error: 'Слишком много попыток входа' },
});

app.use('/api/', limiter);
app.use('/api/admin/login', loginLimiter);

app.use(cors({
    origin: ['https://zencorz-acu-fronend-7d6c.twc1.net', 'http://localhost:3000'],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-API-KEY'],
}));

app.use(express.json({ limit: '10kb' }));

// ========== КОНФИГУРАЦИЯ ==========

const WHITELIST_SYNC_API_KEY = process.env.WHITELIST_SYNC_API_KEY;
const WHITELIST_SYNC_API_URL = 'https://whitelistsync.com/api';
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH;

const WHITELIST_FILE = path.join(__dirname, 'whitelist.json');
const SETTINGS_FILE = path.join(__dirname, 'settings.json');
const RULES_FILE = path.join(__dirname, 'rules.json');

const MINECRAFT_SERVER_IP = '78.109.129.242';
const MINECRAFT_SERVER_PORT = '9028';

// ========== НАСТРОЙКИ ПО УМОЛЧАНИЮ ==========

let settings = {
    autoApproveEnabled: false,
    autoFetchUUID: true,
    autoApproveRules: {
        minUsernameLength: 3,
        requireReason: false,
        requireUUID: false
    },
    whitelistSyncEnabled: false,
    lastUpdated: new Date().toISOString()
};

// ========== ПРАВИЛА ПО УМОЛЧАНИЮ ==========

const DEFAULT_RULES = [
    { id: 1, section: 1, number: 1, title: "Уважение к игрокам", description: "Запрещены оскорбления, дискриминация и токсичное поведение.", icon: "🤝", order: 1 },
    { id: 2, section: 1, number: 2, title: "Запрет на читы", description: "Использование читов, X-Ray, автокликеров запрещено.", icon: "⚡", order: 2 },
    { id: 3, section: 1, number: 3, title: "Гриферство", description: "Разрушение построек других игроков запрещено.", icon: "🏗️", order: 3 },
    { id: 4, section: 1, number: 4, title: "Приватность", description: "Уважайте личное пространство других игроков.", icon: "🔒", order: 4 },
    { id: 5, section: 2, number: 1, title: "Сотрудничество", description: "Поощряется командная игра и взаимопомощь.", icon: "🤝", order: 5 },
    { id: 6, section: 2, number: 2, title: "Чат и общение", description: "Запрещены спам, флуд, капс, реклама.", icon: "💬", order: 6 },
    { id: 7, section: 2, number: 3, title: "Лаги и фермы", description: "Запрещены механизмы, вызывающие лаги.", icon: "🐌", order: 7 },
    { id: 8, section: 2, number: 4, title: "Дюпы и баги", description: "Использование багов запрещено.", icon: "🐛", order: 8 },
    { id: 9, section: 3, number: 1, title: "Строительство", description: "Уважайте чужой труд.", icon: "🏠", order: 9 },
    { id: 10, section: 3, number: 2, title: "PVP и конфликты", description: "PVP только на аренах или с согласия.", icon: "⚔️", order: 10 },
    { id: 11, section: 3, number: 3, title: "Ресурсы и экономика", description: "Будьте честны в торговле.", icon: "💰", order: 11 },
    { id: 12, section: 3, number: 4, title: "Администрация", description: "Решения администрации окончательны.", icon: "👑", order: 12 }
];

let activeSessions = new Map();

function generateToken() {
    return crypto.randomBytes(64).toString('hex');
}

// ========== ФУНКЦИИ ==========

function formatUuid(uuid) {
    if (!uuid) return uuid;
    if (uuid.includes('-')) return uuid.toLowerCase();
    if (uuid.length === 32) {
        return `${uuid.slice(0, 8)}-${uuid.slice(8, 12)}-${uuid.slice(12, 16)}-${uuid.slice(16, 20)}-${uuid.slice(20)}`.toLowerCase();
    }
    return uuid;
}

async function getUUIDFromMojang(username) {
    if (!username || username.trim().length === 0) return null;

    try {
        const response = await fetch(`https://api.mojang.com/users/profiles/minecraft/${username}`, {
            headers: { 'User-Agent': 'AssociationCreateUnits/1.0' }
        });

        if (!response.ok) return null;
        const data = await response.json();
        return data.id ? formatUuid(data.id) : null;
    } catch (error) {
        console.error('Ошибка получения UUID:', error.message);
        return null;
    }
}

async function syncWithWhitelistSync(uuid, username, action = 'add') {
    if (!settings.whitelistSyncEnabled || !WHITELIST_SYNC_API_KEY) return { success: false };

    const formattedUuid = formatUuid(uuid);
    const headers = { 'X-API-KEY': WHITELIST_SYNC_API_KEY, 'Content-Type': 'application/json' };

    try {
        const url = `${WHITELIST_SYNC_API_URL}/whitelist${action === 'add' ? '' : '/' + formattedUuid}`;
        const response = await fetch(url, {
            method: action === 'add' ? 'POST' : 'DELETE',
            headers: headers,
            body: action === 'add' ? JSON.stringify({ uuid: formattedUuid }) : undefined
        });

        if (!response.ok) console.error(`Ошибка Whitelist Sync: ${response.status}`);
        return { success: response.ok };
    } catch (error) {
        console.error('Ошибка Whitelist Sync:', error);
        return { success: false };
    }
}

async function getServerPlayers() {
    try {
        const response = await fetch(`https://mcapi.us/server/status?ip=${MINECRAFT_SERVER_IP}&port=${MINECRAFT_SERVER_PORT}`);

        if (!response.ok) {
            return { online: false, players: 0, maxPlayers: 0, error: "API недоступно" };
        }

        const data = await response.json();

        if (data.online) {
            return {
                online: true,
                players: data.players.now,
                maxPlayers: data.players.max,
                version: data.server.name || "1.20.4",
                motd: data.motd || "Добро пожаловать на сервер Association Create Units!"
            };
        } else {
            return { online: false, players: 0, maxPlayers: 0, error: "Сервер оффлайн" };
        }
    } catch (error) {
        console.error('Ошибка получения статуса сервера:', error.message);
        return { online: false, players: 0, maxPlayers: 0, error: "Ошибка подключения" };
    }
}

async function loadSettings() {
    try {
        const data = await fs.readFile(SETTINGS_FILE, 'utf-8');
        settings = { ...settings, ...JSON.parse(data) };
        console.log('⚙️ Настройки загружены');
    } catch { await saveSettings(); }
}

async function saveSettings() {
    try {
        settings.lastUpdated = new Date().toISOString();
        await fs.writeFile(SETTINGS_FILE, JSON.stringify(settings, null, 2));
    } catch (error) { console.error('Ошибка сохранения настроек:', error); }
}

async function ensureWhitelistFile() {
    try { await fs.access(WHITELIST_FILE); }
    catch { await fs.writeFile(WHITELIST_FILE, JSON.stringify([], null, 2)); }
}

async function ensureRulesFile() {
    try { await fs.access(RULES_FILE); }
    catch { await fs.writeFile(RULES_FILE, JSON.stringify(DEFAULT_RULES, null, 2)); }
}

async function getRules() {
    try {
        const data = await fs.readFile(RULES_FILE, 'utf-8');
        return JSON.parse(data);
    } catch { return DEFAULT_RULES; }
}

async function saveRules(rules) {
    try {
        await fs.writeFile(RULES_FILE, JSON.stringify(rules, null, 2));
        return true;
    } catch { return false; }
}

const adminAuth = (req, res, next) => {
    const token = req.headers['authorization'];
    const session = activeSessions.get(token);
    if (!token || !session || Date.now() > session.expiresAt) {
        if (session) activeSessions.delete(token);
        return res.status(401).json({ error: 'Неавторизованный доступ' });
    }
    next();
};

// ========== API ЭНДПОИНТЫ ==========

app.get('/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.post('/api/admin/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Введите логин и пароль' });
    if (username !== ADMIN_USERNAME) return res.status(401).json({ error: 'Неверный логин или пароль' });

    const isValid = bcrypt.compareSync(password, ADMIN_PASSWORD_HASH);
    if (!isValid) return res.status(401).json({ error: 'Неверный логин или пароль' });

    const newToken = generateToken();
    activeSessions.set(newToken, { createdAt: Date.now(), expiresAt: Date.now() + 24 * 60 * 60 * 1000 });

    for (const [token, session] of activeSessions.entries()) {
        if (Date.now() > session.expiresAt) activeSessions.delete(token);
    }

    res.json({ success: true, token: newToken });
});

app.post('/api/admin/logout', adminAuth, (req, res) => {
    const token = req.headers['authorization'];
    activeSessions.delete(token);
    res.json({ success: true });
});

app.get('/api/admin/settings', adminAuth, async (req, res) => res.json(settings));

app.post('/api/admin/settings', adminAuth, async (req, res) => {
    const { autoApproveEnabled, autoApproveRules, whitelistSyncEnabled, autoFetchUUID } = req.body;
    if (typeof autoApproveEnabled === 'boolean') settings.autoApproveEnabled = autoApproveEnabled;
    if (typeof whitelistSyncEnabled === 'boolean') settings.whitelistSyncEnabled = whitelistSyncEnabled;
    if (typeof autoFetchUUID === 'boolean') settings.autoFetchUUID = autoFetchUUID;
    if (autoApproveRules) settings.autoApproveRules = { ...settings.autoApproveRules, ...autoApproveRules };
    await saveSettings();
    res.json({ success: true, settings });
});

app.get('/api/server-status', async (req, res) => {
    const status = await getServerPlayers();
    res.json(status);
});

app.get('/api/admin/whitelist', adminAuth, async (req, res) => {
    try {
        const data = await fs.readFile(WHITELIST_FILE, 'utf-8');
        res.json(JSON.parse(data));
    } catch { res.status(500).json({ error: 'Ошибка чтения' }); }
});

app.post('/api/whitelist', async (req, res) => {
    const { username, reason, createExperience, discordTag } = req.body;

    if (!username || username.trim().length < 3) {
        return res.status(400).json({ error: 'Никнейм слишком короткий' });
    }

    if (!discordTag || discordTag.trim().length === 0) {
        return res.status(400).json({ error: 'Введите ваш Discord ник' });
    }

    try {
        await ensureWhitelistFile();
        const data = await fs.readFile(WHITELIST_FILE, 'utf-8');
        let applications = JSON.parse(data);

        if (applications.find(a => a.username.toLowerCase() === username.toLowerCase())) {
            return res.status(400).json({ error: 'Заявка с таким ником уже существует' });
        }

        let playerUUID = null;
        if (settings.autoFetchUUID) {
            playerUUID = await getUUIDFromMojang(username);
        }

        const newApplication = {
            id: Date.now(),
            username: username.trim(),
            uuid: playerUUID,
            reason: reason || '',
            createExperience: createExperience || '',
            discordTag: discordTag.trim(),
            status: settings.autoApproveEnabled ? 'approved' : 'pending',
            createdAt: new Date().toISOString(),
            autoApproved: settings.autoApproveEnabled
        };

        applications.push(newApplication);
        await fs.writeFile(WHITELIST_FILE, JSON.stringify(applications, null, 2));

        if (settings.autoApproveEnabled && settings.whitelistSyncEnabled && playerUUID) {
            await syncWithWhitelistSync(playerUUID, username, 'add');
        }

        res.json({
            success: true,
            message: settings.autoApproveEnabled ? '✅ Заявка одобрена! Добро пожаловать!' : '📝 Заявка отправлена на рассмотрение',
            application: newApplication
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Ошибка сохранения заявки' });
    }
});

app.put('/api/admin/whitelist/:id', adminAuth, async (req, res) => {
    const { id } = req.params;
    const { status } = req.body;

    try {
        const data = await fs.readFile(WHITELIST_FILE, 'utf-8');
        let applications = JSON.parse(data);
        const index = applications.findIndex(a => a.id === parseInt(id));
        if (index === -1) return res.status(404).json({ error: 'Заявка не найдена' });

        const oldStatus = applications[index].status;
        applications[index].status = status;
        applications[index].updatedAt = new Date().toISOString();
        await fs.writeFile(WHITELIST_FILE, JSON.stringify(applications, null, 2));

        if (settings.whitelistSyncEnabled && oldStatus === 'pending' && status === 'approved' && applications[index].uuid) {
            await syncWithWhitelistSync(applications[index].uuid, applications[index].username, 'add');
        }

        res.json({ success: true, application: applications[index] });
    } catch { res.status(500).json({ error: 'Ошибка обновления' }); }
});

app.delete('/api/admin/whitelist/:id', adminAuth, async (req, res) => {
    const { id } = req.params;
    try {
        const data = await fs.readFile(WHITELIST_FILE, 'utf-8');
        let applications = JSON.parse(data);
        const deleted = applications.find(a => a.id === parseInt(id));
        const filtered = applications.filter(a => a.id !== parseInt(id));
        if (filtered.length === applications.length) return res.status(404).json({ error: 'Заявка не найдена' });

        await fs.writeFile(WHITELIST_FILE, JSON.stringify(filtered, null, 2));
        if (settings.whitelistSyncEnabled && deleted?.status === 'approved' && deleted?.uuid) {
            await syncWithWhitelistSync(deleted.uuid, deleted.username, 'remove');
        }
        res.json({ success: true });
    } catch { res.status(500).json({ error: 'Ошибка удаления' }); }
});

app.get('/api/rules', async (req, res) => {
    try {
        const rules = await getRules();
        res.json(rules.sort((a, b) => a.order - b.order));
    } catch { res.status(500).json({ error: 'Ошибка загрузки правил' }); }
});

app.get('/api/admin/rules', adminAuth, async (req, res) => {
    try {
        const rules = await getRules();
        res.json(rules.sort((a, b) => a.order - b.order));
    } catch { res.status(500).json({ error: 'Ошибка загрузки правил' }); }
});

app.put('/api/admin/rules/:id', adminAuth, async (req, res) => {
    const { id } = req.params;
    const { title, description, icon, section, number } = req.body;

    try {
        let rules = await getRules();
        const index = rules.findIndex(r => r.id === parseInt(id));
        if (index === -1) return res.status(404).json({ error: 'Правило не найдено' });

        rules[index] = { ...rules[index], title, description, icon, section, number };
        await saveRules(rules);
        res.json({ success: true, rule: rules[index] });
    } catch { res.status(500).json({ error: 'Ошибка обновления' }); }
});

app.post('/api/admin/rules', adminAuth, async (req, res) => {
    const { title, description, icon, section, number } = req.body;
    if (!title || !description) return res.status(400).json({ error: 'Название и описание обязательны' });

    try {
        let rules = await getRules();
        const newId = Math.max(...rules.map(r => r.id), 0) + 1;
        const newOrder = rules.length + 1;

        const newRule = {
            id: newId,
            title,
            description,
            icon: icon || '📌',
            section: section || 1,
            number: number || rules.filter(r => r.section === section).length + 1,
            order: newOrder
        };

        rules.push(newRule);
        await saveRules(rules);
        res.json({ success: true, rule: newRule });
    } catch { res.status(500).json({ error: 'Ошибка добавления' }); }
});

app.delete('/api/admin/rules/:id', adminAuth, async (req, res) => {
    const { id } = req.params;
    try {
        let rules = await getRules();
        const filtered = rules.filter(r => r.id !== parseInt(id));
        if (filtered.length === rules.length) return res.status(404).json({ error: 'Правило не найдено' });

        await saveRules(filtered);
        res.json({ success: true });
    } catch { res.status(500).json({ error: 'Ошибка удаления' }); }
});

// ========== ЗАПУСК ==========

async function init() {
    await loadSettings();
    await ensureWhitelistFile();
    await ensureRulesFile();
    console.log(`\n🚀 Сервер Association Create Units запущен на http://${HOST}:${PORT}`);
    console.log(`🔐 Админ: ${ADMIN_USERNAME || 'admin'}`);
    console.log(`🔄 Whitelist Sync: ${settings.whitelistSyncEnabled ? 'ВКЛ' : 'ВЫК'}`);
    console.log(`🤖 Авто-одобрение: ${settings.autoApproveEnabled ? 'ВКЛ' : 'ВЫК'}`);
    console.log(`🎮 Minecraft сервер: ${MINECRAFT_SERVER_IP}:${MINECRAFT_SERVER_PORT}\n`);
}

init();
app.listen(PORT, HOST);