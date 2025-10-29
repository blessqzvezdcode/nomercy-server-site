#!/usr/bin/env node

const express = require('express');
const { exec } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// Загружаем переменные окружения
require('dotenv').config({ path: '.env.webhook' });

const app = express();
const PORT = 3001; // Отдельный порт для webhook

// Секретный ключ для проверки подписи GitHub
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET || 'nmercy.onlin3BLESSED';

// Путь к проекту
const PROJECT_PATH = '/var/www/nomercy-server-site';

// Middleware для парсинга JSON
app.use(express.json());

// Функция для проверки подписи GitHub
function verifySignature(payload, signature) {
    const hmac = crypto.createHmac('sha256', WEBHOOK_SECRET);
    const digest = 'sha256=' + hmac.update(payload).digest('hex');
    return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(digest));
}

// Функция для выполнения команд
function executeCommand(command) {
    return new Promise((resolve, reject) => {
        exec(command, { cwd: PROJECT_PATH }, (error, stdout, stderr) => {
            if (error) {
                console.error(`Error: ${error}`);
                reject(error);
                return;
            }
            console.log(`stdout: ${stdout}`);
            if (stderr) console.log(`stderr: ${stderr}`);
            resolve(stdout);
        });
    });
}

// Webhook endpoint
app.post('/webhook', async (req, res) => {
    try {
        const signature = req.headers['x-hub-signature-256'];
        const payload = JSON.stringify(req.body);

        // Проверяем подпись (в продакшене обязательно!)
        if (!verifySignature(payload, signature)) {
            console.log('Invalid signature');
            return res.status(401).send('Unauthorized');
        }

        const event = req.headers['x-github-event'];
        
        // Обрабатываем только push события в main ветку
        if (event === 'push' && req.body.ref === 'refs/heads/main') {
            console.log('🚀 Received push to main branch, starting deployment...');
            
            // Логируем информацию о коммите
            const commits = req.body.commits || [];
            commits.forEach(commit => {
                console.log(`📝 Commit: ${commit.message} by ${commit.author.name}`);
            });

            try {
                // 1. Переходим в директорию проекта
                console.log('📁 Changing to project directory...');
                process.chdir(PROJECT_PATH);

                // 2. Получаем последние изменения
                console.log('📥 Pulling latest changes...');
                await executeCommand('git pull origin main');

                // 3. Устанавливаем зависимости (если package.json изменился)
                const changedFiles = commits.flatMap(commit => 
                    [...(commit.added || []), ...(commit.modified || []), ...(commit.removed || [])]
                );
                
                if (changedFiles.includes('package.json') || changedFiles.includes('package-lock.json')) {
                    console.log('📦 Installing dependencies...');
                    await executeCommand('npm install');
                }

                // 4. Перезапускаем PM2
                console.log('🔄 Restarting PM2...');
                await executeCommand('pm2 restart nomercy');

                // 5. Проверяем статус
                console.log('✅ Checking PM2 status...');
                await executeCommand('pm2 list');

                console.log('🎉 Deployment completed successfully!');
                res.status(200).send('Deployment successful');

            } catch (error) {
                console.error('❌ Deployment failed:', error);
                res.status(500).send('Deployment failed: ' + error.message);
            }
        } else {
            console.log(`Ignoring ${event} event or non-main branch`);
            res.status(200).send('Event ignored');
        }

    } catch (error) {
        console.error('Webhook error:', error);
        res.status(500).send('Webhook error');
    }
});

// Healthcheck endpoint
app.get('/health', (req, res) => {
    res.status(200).send('Webhook server is running');
});

// Запускаем сервер
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🎣 GitHub Webhook server running on port ${PORT}`);
    console.log(`📍 Webhook URL: http://nmercy.online:${PORT}/webhook`);
    console.log(`🔐 Secret: ${WEBHOOK_SECRET}`);
});
