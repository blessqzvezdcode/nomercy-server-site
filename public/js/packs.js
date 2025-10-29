
console.log('packs.js loaded successfully');

// Global variable to store current collection
let currentCollection = 'all';

// Change collection function
function changeCollection(collectionId) {
    console.log('Changing collection to:', collectionId);
    currentCollection = collectionId;
    
    // Update gacha machines based on collection
    updateGachaMachines(collectionId);
}

// Update gacha machines based on collection
function updateGachaMachines(collectionId) {
    const gachaMachines = document.querySelectorAll('.gacha-machine');
    
    gachaMachines.forEach(machine => {
        const priceElement = machine.querySelector('.machine-price');
        const descriptionElement = machine.querySelector('.machine-description p');
        
        if (collectionId === 'launch_2025') {
            // Special pricing for collection
            if (priceElement) {
                const currentPrice = priceElement.textContent;
                const newPrice = currentPrice.replace('50', '75').replace('450', '675');
                priceElement.textContent = newPrice;
            }
            
            if (descriptionElement) {
                descriptionElement.textContent = 'Карты из коллекции "Запуск 2025"';
            }
        } else {
            // Reset to default
            if (priceElement) {
                const currentPrice = priceElement.textContent;
                const newPrice = currentPrice.replace('75', '50').replace('675', '450');
                priceElement.textContent = newPrice;
            }
            
            if (descriptionElement) {
                descriptionElement.textContent = 'Одна случайная карточка';
            }
        }
    });
}

// Gacha System - Define early to make it globally available
async function performGacha(type, button) {
    console.log('performGacha called with type:', type);
    console.log('Button element:', button);
    
    // Check if user is logged in
    if (!button) {
        console.error('Button element is null');
        alert('Ошибка: элемент кнопки не найден');
        return;
    }
    
    // Check if user is authenticated
    if (!document.querySelector('nav .nav-buttons a[href="/logout"]')) {
        alert('Необходимо войти в систему для использования гачи');
        return;
    }
    
    const originalText = button.innerHTML;
    
    // Показать анимацию загрузки
    button.disabled = true;
    button.innerHTML = '<span class="btn-icon">⏳</span> Крутка...';
    
    try {
        console.log('Sending request to /api/gacha/pull');
        
        // First test if server is reachable
        const testResponse = await fetch('/api/test');
        const testData = await testResponse.json();
        console.log('Test response:', testData);
        
        const response = await fetch('/api/gacha/pull', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                type: type,
                collection: currentCollection
            })
        });
        
        console.log('Response status:', response.status);
        const data = await response.json();
        console.log('Response data:', data);
        
        if (data.success) {
            // Показать результаты
            showGachaResults(data.cards, type);
            
            // Обновить баланс
            const balanceElement = document.getElementById('balance');
            if (balanceElement) {
                balanceElement.textContent = data.balance;
            }
            
            // Обновить счетчик жалости
            const pityElement = document.getElementById('pity-counter');
            if (pityElement && data.pityCounter !== undefined) {
                pityElement.textContent = data.pityCounter;
            }
            
            // Сбросить кнопку сразу после успешного результата
            button.disabled = false;
            button.innerHTML = originalText;
        } else {
            alert('Ошибка: ' + (data.error || 'Неизвестная ошибка'));
            button.disabled = false;
            button.innerHTML = originalText;
        }
        
    } catch (error) {
        console.error('Gacha error:', error);
        alert('Ошибка при выполнении крутки: ' + error.message);
    } finally {
        button.disabled = false;
        button.innerHTML = originalText;
    }
}

// Make performGacha globally available
window.performGacha = performGacha;

async function loadPacks() {
    const res = await fetch('/api/packs');
    const data = await res.json();
    const container = document.getElementById('packs');
    if (!container) return;
    container.innerHTML = '';
    data.packs.forEach(p => {
        const el = document.createElement('div');
        el.className = 'pack card glow-hover';
        el.innerHTML = `<h4 style="margin:6px 0">${p.name}</h4><p class="small">Цена: ${p.price}</p><button class="btn" onclick="openPack(event,'${p.id}', this)">Открыть</button>`;
        container.appendChild(el);
    });
}

async function openPack(evt, packId, btn) {
    btn.disabled = true;
    try {
        const resp = await fetch('/api/packs/open', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({packId})});
        const data = await resp.json();
        if (!data.ok) {
            alert(data.error || 'Ошибка');
            btn.disabled = false;
            return;
        }
        
        // Показать модальное окно с анимацией
        const modal = document.getElementById('pack-modal');
        const list = document.getElementById('pack-results');
        const overlay = document.getElementById('pack-overlay');
        
        // Очистить предыдущие результаты
        list.innerHTML = '';
        
        // Показать модальное окно с эффектом
        modal.style.display = 'flex';
        overlay.classList.add('active');
        
        // Создать карточки с анимацией
        data.cards.forEach((c, idx) => {
            const item = document.createElement('div');
            item.className = 'card-result ' + (c.rarity||'common');
            item.innerHTML = `
                <div class="card-spinner">
                    <div class="spinner-ring"></div>
                    <div class="spinner-ring"></div>
                    <div class="spinner-ring"></div>
                </div>
                <div class="card-content">
                    <div class="card-image">
                        ${c.image ? `<img src="${c.image}" alt="${c.name}">` : '<div class="card-placeholder">🃏</div>'}
                    </div>
                    <div class="card-info">
                        <div class="name">${c.name}</div>
                        <div class="rarity">${c.rarity}</div>
                    </div>
                </div>
            `;
            list.appendChild(item);
            
            // Анимация появления карточки
            setTimeout(() => {
                item.classList.add('reveal');
                
                // Специальные эффекты для редких карточек
                if (c.rarity === 'rare' || c.rarity === 'epic' || c.rarity === 'legendary') {
                    item.classList.add('shake');
                    setTimeout(() => item.classList.remove('shake'), 1200);
                }
                
                // Эффект взрыва для легендарных карточек
                if (c.rarity === 'legendary') {
                    createExplosionEffect(item);
                }
                
                // Эффект свечения для эпических и легендарных
                if (c.rarity === 'epic' || c.rarity === 'legendary') {
                    item.classList.add('glow-effect');
                }
                
            }, 500 + idx * 800);
        });
        
        // Обновить баланс
        const balanceElement = document.getElementById('balance');
        if (balanceElement) {
            balanceElement.textContent = data.balance;
        }
        
    } finally {
        btn.disabled = false;
    }
}

function createExplosionEffect(element) {
    const explosion = document.createElement('div');
    explosion.className = 'explosion-effect';
    explosion.innerHTML = `
        <div class="explosion-particle"></div>
        <div class="explosion-particle"></div>
        <div class="explosion-particle"></div>
        <div class="explosion-particle"></div>
        <div class="explosion-particle"></div>
    `;
    element.appendChild(explosion);
    
    setTimeout(() => {
        explosion.remove();
    }, 1000);
}

function closeModal() {
    const modal = document.getElementById('pack-modal');
    const overlay = document.getElementById('pack-overlay');
    
    // Анимация закрытия
    overlay.classList.remove('active');
    
    setTimeout(() => {
        modal.style.display = 'none';
    }, 300);
}


function showGachaResults(cards, type) {
    console.log('showGachaResults called with:', cards, type);
    
    const resultsDiv = document.getElementById('gacha-results');
    const cardsGrid = document.getElementById('gacha-cards');
    
    if (!resultsDiv || !cardsGrid) {
        console.error('Gacha results elements not found');
        return;
    }
    
    // Очистить предыдущие результаты
    cardsGrid.innerHTML = '';
    
    // Показать результаты
    resultsDiv.style.display = 'block';
    
    // Создать карточки с анимацией
    cards.forEach((card, index) => {
        const cardElement = document.createElement('div');
        cardElement.className = `gacha-card ${card.rarity}`;
        cardElement.innerHTML = `
            <div class="card-content">
                <div class="card-image">
                    ${card.image ? `<img src="${card.image}" alt="${card.name}">` : '<div class="card-placeholder">🃏</div>'}
                </div>
                <div class="card-info">
                    <div class="name">${card.name}</div>
                    <div class="rarity">${card.rarity}</div>
                </div>
            </div>
        `;
        
        cardsGrid.appendChild(cardElement);
        
        // Красочные анимации в зависимости от редкости
        setTimeout(() => {
            cardElement.classList.add('reveal');
            
            // Специальные эффекты для редких карт
            if (card.rarity === 'rare' || card.rarity === 'RARE') {
                cardElement.classList.add('rare-glow');
                createRareEffect(cardElement);
            }
            
            if (card.rarity === 'epic' || card.rarity === 'EPIC') {
                cardElement.classList.add('epic-glow');
                createEpicEffect(cardElement);
            }
            
            if (card.rarity === 'legendary' || card.rarity === 'LEGENDARY') {
                cardElement.classList.add('legendary-glow');
                createLegendaryEffect(cardElement);
            }
        }, index * 200);
    });
    
    // Прокрутить к результатам
    resultsDiv.scrollIntoView({ behavior: 'smooth' });
    
    console.log('Gacha results displayed successfully');
}

function createRareEffect(element) {
    // Синий светящийся эффект для редких карт
    const glow = document.createElement('div');
    glow.className = 'rare-glow-effect';
    glow.style.cssText = `
        position: absolute;
        top: -5px;
        left: -5px;
        right: -5px;
        bottom: -5px;
        background: linear-gradient(45deg, #00bfff, #0080ff, #0040ff);
        border-radius: 12px;
        opacity: 0.8;
        animation: rarePulse 2s infinite;
        z-index: -1;
    `;
    element.style.position = 'relative';
    element.appendChild(glow);
    
    // Добавляем CSS анимацию
    if (!document.getElementById('rare-animation-style')) {
        const style = document.createElement('style');
        style.id = 'rare-animation-style';
        style.textContent = `
            @keyframes rarePulse {
                0%, 100% { opacity: 0.8; transform: scale(1); }
                50% { opacity: 1; transform: scale(1.05); }
            }
        `;
        document.head.appendChild(style);
    }
}

function createEpicEffect(element) {
    // Фиолетовый светящийся эффект для эпических карт
    const glow = document.createElement('div');
    glow.className = 'epic-glow-effect';
    glow.style.cssText = `
        position: absolute;
        top: -8px;
        left: -8px;
        right: -8px;
        bottom: -8px;
        background: linear-gradient(45deg, #ff00ff, #8000ff, #4000ff, #ff0080);
        border-radius: 15px;
        opacity: 0.9;
        animation: epicRotate 3s infinite linear;
        z-index: -1;
    `;
    element.style.position = 'relative';
    element.appendChild(glow);
    
    // Добавляем CSS анимацию
    if (!document.getElementById('epic-animation-style')) {
        const style = document.createElement('style');
        style.id = 'epic-animation-style';
        style.textContent = `
            @keyframes epicRotate {
                0% { transform: rotate(0deg) scale(1); }
                50% { transform: rotate(180deg) scale(1.1); }
                100% { transform: rotate(360deg) scale(1); }
            }
        `;
        document.head.appendChild(style);
    }
}

function createLegendaryEffect(element) {
    // Золотой взрывной эффект для легендарных карт
    const explosion = document.createElement('div');
    explosion.className = 'legendary-explosion';
    explosion.style.cssText = `
        position: absolute;
        top: -15px;
        left: -15px;
        right: -15px;
        bottom: -15px;
        background: radial-gradient(circle, #ffd700, #ff8c00, #ff4500);
        border-radius: 20px;
        opacity: 1;
        animation: legendaryExplosion 2s ease-out;
        z-index: -1;
    `;
    element.style.position = 'relative';
    element.appendChild(explosion);
    
    // Добавляем CSS анимацию
    if (!document.getElementById('legendary-animation-style')) {
        const style = document.createElement('style');
        style.id = 'legendary-animation-style';
        style.textContent = `
            @keyframes legendaryExplosion {
                0% { 
                    transform: scale(0.5) rotate(0deg); 
                    opacity: 1; 
                }
                50% { 
                    transform: scale(1.3) rotate(180deg); 
                    opacity: 0.8; 
                }
                100% { 
                    transform: scale(1) rotate(360deg); 
                    opacity: 0.6; 
                }
            }
        `;
        document.head.appendChild(style);
    }
}

function closeGachaResults() {
    document.getElementById('gacha-results').style.display = 'none';
}

// Load user collection
async function loadUserCollection() {
    try {
        const response = await fetch('/api/user/cards');
        const data = await response.json();
        
        const userCardsDiv = document.getElementById('user-cards');
        const emptyCollectionDiv = document.getElementById('empty-collection');
        
        if (data.cards && data.cards.length > 0) {
            userCardsDiv.innerHTML = '';
            data.cards.forEach(card => {
                const cardElement = document.createElement('div');
                cardElement.className = `card-item ${card.rarity}`;
                cardElement.innerHTML = `
                    <div class="card-image">
                        ${card.image ? `<img src="${card.image}" alt="${card.name}">` : '<div class="card-placeholder">🃏</div>'}
                    </div>
                    <div class="card-info">
                        <h4>${card.name}</h4>
                        <p class="rarity">${card.rarity}</p>
                        <p class="obtained-date">Получена: ${new Date(card.obtainedAt).toLocaleDateString()}</p>
                    </div>
                    <div class="card-actions">
                        <button class="sell-btn" onclick="sellCard('${card.id}', '${card.name}')">
                            💰 Продать
                        </button>
                        <button class="auction-btn" onclick="createAuction('${card.id}', '${card.name}')">
                            🏆 Аукцион
                        </button>
                    </div>
                `;
                userCardsDiv.appendChild(cardElement);
            });
            emptyCollectionDiv.style.display = 'none';
            userCardsDiv.style.display = 'grid';
        } else {
            userCardsDiv.style.display = 'none';
            emptyCollectionDiv.style.display = 'block';
        }
    } catch (error) {
        console.error('Error loading collection:', error);
    }
}

// Sell card function
async function sellCard(cardId, cardName) {
    const price = prompt(`Введите цену для карты "${cardName}" (в NMCoin):`);
    
    if (!price || isNaN(price) || parseInt(price) <= 0) {
        alert('Пожалуйста, введите корректную цену');
        return;
    }
    
    if (!confirm(`Вы уверены, что хотите продать "${cardName}" за ${price} NMCoin?`)) {
        return;
    }
    
    try {
        const response = await fetch('/api/cards/sell', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                cardId: cardId,
                price: parseInt(price)
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            alert(`Карта "${cardName}" выставлена на продажу за ${price} NMCoin!`);
            // Reload collection
            loadUserCollection();
        } else {
            alert('Ошибка при продаже карты: ' + (data.error || 'Неизвестная ошибка'));
        }
    } catch (error) {
        console.error('Error selling card:', error);
        alert('Ошибка при продаже карты: ' + error.message);
    }
}

// Create auction function
async function createAuction(cardId, cardName) {
    const startingPrice = prompt(`Введите стартовую цену для карты "${cardName}" (в NMCoin):`);
    
    if (!startingPrice || isNaN(startingPrice) || parseInt(startingPrice) <= 0) {
        alert('Пожалуйста, введите корректную стартовую цену');
        return;
    }
    
    const duration = prompt(`Введите длительность аукциона в часах (по умолчанию 24):`, '24');
    const auctionDuration = parseInt(duration) || 24;
    
    if (auctionDuration < 1 || auctionDuration > 168) {
        alert('Длительность аукциона должна быть от 1 до 168 часов (7 дней)');
        return;
    }
    
    if (!confirm(`Создать аукцион для "${cardName}" со стартовой ценой ${startingPrice} NMCoin на ${auctionDuration} часов?`)) {
        return;
    }
    
    try {
        const response = await fetch('/api/cards/auction', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                cardId: cardId,
                startingPrice: parseInt(startingPrice),
                duration: auctionDuration
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            const endTime = new Date(data.endTime).toLocaleString('ru-RU');
            alert(`Аукцион для карты "${cardName}" создан! Стартовая цена: ${startingPrice} NMCoin. Аукцион завершится: ${endTime}`);
            // Reload collection
            loadUserCollection();
        } else {
            alert('Ошибка при создании аукциона: ' + (data.error || 'Неизвестная ошибка'));
        }
    } catch (error) {
        console.error('Error creating auction:', error);
        alert('Ошибка при создании аукциона: ' + error.message);
    }
}

// Tab switching
document.addEventListener('DOMContentLoaded', function() {
    // Tab switching
    document.getElementById('tab-gacha')?.addEventListener('click', function() {
        showTab('gacha');
    });
    
    document.getElementById('tab-collection')?.addEventListener('click', function() {
        showTab('collection');
    });
    
    document.getElementById('tab-collections')?.addEventListener('click', function() {
        showTab('collections');
    });
    
    // Load collection on page load
    loadUserCollection();
    
    // Add recycle button event listeners
    document.getElementById('recycle-selected')?.addEventListener('click', recycleSelectedCards);
    document.getElementById('recycle-all')?.addEventListener('click', recycleAllDuplicates);
});

function showTab(tabName) {
    // Hide all sections
    const gachaSection = document.getElementById('gacha-section');
    const collectionSection = document.getElementById('collection-section');
    const collectionsSection = document.getElementById('collections-section');
    
    if (gachaSection) gachaSection.style.display = 'none';
    if (collectionSection) collectionSection.style.display = 'none';
    if (collectionsSection) collectionsSection.style.display = 'none';
    
    // Show selected section
    if (tabName === 'gacha') {
        if (gachaSection) gachaSection.style.display = 'block';
    } else if (tabName === 'collection') {
        if (collectionSection) {
            collectionSection.style.display = 'block';
            loadUserCollection(); // Reload collection when switching to it
        }
    } else if (tabName === 'collections') {
        if (collectionsSection) {
            collectionsSection.style.display = 'block';
            loadCollections();
            loadMissingCards();
            loadDuplicateCards();
        }
    }
    
    // Update tab buttons
    document.querySelectorAll('.card button').forEach(btn => {
        btn.classList.remove('btn');
        btn.classList.add('btn', 'ghost');
    });
    
    if (event && event.target) {
        event.target.classList.remove('ghost');
        event.target.classList.add('btn');
    }
}

// Load collections progress
async function loadCollections() {
    try {
        const response = await fetch('/api/user/collections');
        const data = await response.json();
        
        if (data.success) {
            const collectionsList = document.getElementById('collections-list');
            collectionsList.innerHTML = '';
            
            for (const [collectionId, collection] of Object.entries(data.collections)) {
                const collectionElement = document.createElement('div');
                collectionElement.className = 'collection-item';
                collectionElement.innerHTML = `
                    <div class="collection-header">
                        <h4>${collection.name}</h4>
                        <div class="collection-progress">
                            <span class="progress-text">${collection.percentage}%</span>
                            <div class="progress-bar">
                                <div class="progress-fill" style="width: ${collection.percentage}%"></div>
                            </div>
                        </div>
                    </div>
                    <div class="collection-info">
                        <p>${collection.description}</p>
                        <div class="collection-stats">
                            <span>Карт собрано: ${collection.ownedCards.length}/${collection.totalCards}</span>
                            ${collection.completed ? '<span class="completed-badge">✅ Завершено</span>' : ''}
                        </div>
                    </div>
                `;
                collectionsList.appendChild(collectionElement);
            }
        } else {
            document.getElementById('collections-list').innerHTML = 
                '<div class="error">Ошибка загрузки коллекций</div>';
        }
    } catch (error) {
        console.error('Error loading collections:', error);
        document.getElementById('collections-list').innerHTML = 
            '<div class="error">Ошибка загрузки коллекций</div>';
    }
}

// Load missing cards for collections
async function loadMissingCards() {
    try {
        const [collectionsResponse, allCardsResponse] = await Promise.all([
            fetch('/api/user/collections'),
            fetch('/api/cards') // Get all available cards
        ]);
        
        const collectionsData = await collectionsResponse.json();
        const allCardsData = await allCardsResponse.json();
        
        if (collectionsData.success && allCardsData.success) {
            const missingCardsDiv = document.getElementById('missing-cards');
            missingCardsDiv.innerHTML = '';
            
            for (const [collectionId, collection] of Object.entries(collectionsData.collections)) {
                if (!collection.completed) {
                    const missingCards = collection.cards.filter(cardId => !collection.ownedCards.includes(cardId));
                    
                    if (missingCards.length > 0) {
                        const missingSection = document.createElement('div');
                        missingSection.className = 'missing-section';
                        missingSection.innerHTML = `
                            <div class="missing-header">
                                <h4>${collection.name}</h4>
                                <span class="missing-count">Не хватает: ${missingCards.length} карт</span>
                            </div>
                            <div class="missing-cards-grid">
                                ${missingCards.map(cardId => {
                                    // Find card info from all available cards
                                    const cardInfo = allCardsData.cards.find(card => card.id === cardId);
                                    return `
                                        <div class="missing-card">
                                            <div class="card-image">
                                                ${cardInfo && cardInfo.image ? `<img src="${cardInfo.image}" alt="${cardInfo.name}">` : '<div class="card-placeholder">🃏</div>'}
                                            </div>
                                            <div class="card-info">
                                                <h5>${cardInfo ? cardInfo.name : 'Неизвестная карта'}</h5>
                                                <p class="rarity">${cardInfo ? cardInfo.rarity : 'unknown'}</p>
                                            </div>
                                        </div>
                                    `;
                                }).join('')}
                            </div>
                        `;
                        missingCardsDiv.appendChild(missingSection);
                    }
                }
            }
            
            if (missingCardsDiv.children.length === 0) {
                missingCardsDiv.innerHTML = '<div class="no-missing">Все коллекции завершены! 🎉</div>';
            }
        } else {
            document.getElementById('missing-cards').innerHTML = 
                '<div class="error">Ошибка загрузки недостающих карт</div>';
        }
    } catch (error) {
        console.error('Error loading missing cards:', error);
        document.getElementById('missing-cards').innerHTML = 
            '<div class="error">Ошибка загрузки недостающих карт</div>';
    }
}

// Check if card is selected (has a listing in marketplace)
async function isCardSelected(card) {
    try {
        const response = await fetch('/api/user/listings');
        const data = await response.json();
        
        if (data.success && data.listings) {
            return data.listings.some(listing => 
                listing.cardId === card.id && 
                (listing.status === 'active' || listing.status === 'pending')
            );
        }
        return false;
    } catch (error) {
        console.error('Error checking if card is selected:', error);
        return false;
    }
}

// Load duplicate cards for recycling
async function loadDuplicateCards() {
    try {
        const response = await fetch('/api/user/cards');
        const data = await response.json();
        
        if (data.success && data.cards) {
            // Find duplicates
            const cardCounts = {};
            const duplicates = [];
            
            data.cards.forEach(card => {
                if (!cardCounts[card.id]) {
                    cardCounts[card.id] = [];
                }
                cardCounts[card.id].push(card);
            });
            
            // Get cards that appear more than once (excluding legendary cards)
            for (const [cardId, cards] of Object.entries(cardCounts)) {
                if (cards.length > 1) {
                    // Keep one copy, mark others as duplicates (but not legendary)
                    for (let i = 1; i < cards.length; i++) {
                        if (cards[i].rarity !== 'legendary') {
                            duplicates.push(cards[i]);
                        }
                    }
                }
            }
            
            const duplicateCardsDiv = document.getElementById('duplicate-cards');
            const recycleActions = document.querySelector('.recycle-actions');
            
            if (duplicates.length > 0) {
                duplicateCardsDiv.innerHTML = '';
                duplicates.forEach(card => {
                    const cardElement = document.createElement('div');
                    cardElement.className = `duplicate-card ${card.rarity}`;
                    cardElement.innerHTML = `
                        <div class="card-checkbox">
                            <input type="checkbox" class="card-select" data-card-id="${card.id}" data-rarity="${card.rarity}">
                        </div>
                        <div class="card-image">
                            ${card.image ? `<img src="${card.image}" alt="${card.name}">` : '<div class="card-placeholder">🃏</div>'}
                        </div>
                        <div class="card-info">
                            <h4>${card.name}</h4>
                            <p class="rarity">${card.rarity}</p>
                            <p class="recycle-value">+${getRecycleValue(card.rarity)} NMCoin</p>
                        </div>
                    `;
                    duplicateCardsDiv.appendChild(cardElement);
                });
                recycleActions.style.display = 'block';
                
                // Add event listeners to checkboxes
                document.querySelectorAll('.card-select').forEach(checkbox => {
                    checkbox.addEventListener('change', updateRecycleTotal);
                });
            } else {
                duplicateCardsDiv.innerHTML = '<div class="no-duplicates">Нет дубликатов для переработки</div>';
                recycleActions.style.display = 'none';
            }
        }
    } catch (error) {
        console.error('Error loading duplicate cards:', error);
        document.getElementById('duplicate-cards').innerHTML = 
            '<div class="error">Ошибка загрузки дубликатов</div>';
    }
}

// Get recycle value for card rarity
function getRecycleValue(rarity) {
    const values = {
        'common': 10,
        'uncommon': 15,
        'rare': 25,
        'epic': 50,
        'legendary': 100
    };
    return values[rarity] || 10;
}

// Update recycle total
function updateRecycleTotal() {
    const selectedCards = document.querySelectorAll('.card-select:checked');
    let total = 0;
    
    selectedCards.forEach(checkbox => {
        const rarity = checkbox.dataset.rarity;
        total += getRecycleValue(rarity);
    });
    
    document.getElementById('recycle-total').textContent = `Итого: ${total} NMCoin`;
    document.getElementById('recycle-selected').disabled = selectedCards.length === 0;
}

// Recycle selected cards
async function recycleSelectedCards() {
    const selectedCards = document.querySelectorAll('.card-select:checked');
    const cardIds = Array.from(selectedCards).map(checkbox => checkbox.dataset.cardId);
    
    if (cardIds.length === 0) {
        alert('Выберите карты для переработки');
        return;
    }
    
    // Check if any selected cards are legendary or have active listings
    const legendaryCards = Array.from(selectedCards).filter(checkbox => 
        checkbox.dataset.rarity === 'legendary'
    );
    
    if (legendaryCards.length > 0) {
        alert('Легендарные карты нельзя перерабатывать!');
        return;
    }
    
    // Check for selected cards (cards with active listings)
    try {
        const response = await fetch('/api/user/listings');
        const data = await response.json();
        
        if (data.success && data.listings) {
            const activeListings = data.listings.filter(listing => 
                listing.status === 'active' || listing.status === 'pending'
            );
            
            const selectedCardIds = activeListings.map(listing => listing.cardId);
            const conflictingCards = cardIds.filter(cardId => selectedCardIds.includes(cardId));
            
            if (conflictingCards.length > 0) {
                alert('Нельзя перерабатывать карты, которые выставлены на продажу!');
                return;
            }
        }
    } catch (error) {
        console.error('Error checking listings:', error);
        // Continue with recycling if we can't check listings
    }
    
    if (!confirm(`Переработать ${cardIds.length} карт?`)) {
        return;
    }
    
    try {
        const response = await fetch('/api/cards/recycle', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                cardIds: cardIds
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            alert(`Переработано ${data.recycledCards.length} карт за ${data.totalCoins} NMCoin!`);
            // Update balance
            const balanceElement = document.getElementById('balance');
            if (balanceElement) {
                balanceElement.textContent = data.newBalance;
            }
            // Reload duplicate cards
            loadDuplicateCards();
        } else {
            alert('Ошибка при переработке: ' + (data.error || 'Неизвестная ошибка'));
        }
    } catch (error) {
        console.error('Error recycling cards:', error);
        alert('Ошибка при переработке: ' + error.message);
    }
}

// Recycle all duplicate cards at once
async function recycleAllDuplicates() {
    if (!confirm('Переработать ВСЕ дубликаты сразу? Это действие нельзя отменить!')) {
        return;
    }
    
    try {
        const response = await fetch('/api/user/cards');
        const data = await response.json();
        
        if (data.success && data.cards) {
            // Find all duplicates
            const cardCounts = {};
            const duplicateIds = [];
            
            data.cards.forEach(card => {
                if (!cardCounts[card.id]) {
                    cardCounts[card.id] = [];
                }
                cardCounts[card.id].push(card);
            });
            
            // Get all duplicate cards (keep one copy, mark others as duplicates)
            for (const [cardId, cards] of Object.entries(cardCounts)) {
                if (cards.length > 1) {
                    for (let i = 1; i < cards.length; i++) {
                        duplicateIds.push(cards[i].id);
                    }
                }
            }
            
            if (duplicateIds.length === 0) {
                alert('Нет дубликатов для переработки');
                return;
            }
            
            // Recycle all duplicates
            const recycleResponse = await fetch('/api/cards/recycle', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    cardIds: duplicateIds
                })
            });
            
            const recycleData = await recycleResponse.json();
            
            if (recycleData.success) {
                alert(`Переработано ${recycleData.recycledCards.length} дубликатов за ${recycleData.totalCoins} NMCoin!`);
                // Update balance
                const balanceElement = document.getElementById('balance');
                if (balanceElement) {
                    balanceElement.textContent = recycleData.newBalance;
                }
                // Reload all sections
                loadCollections();
                loadMissingCards();
                loadDuplicateCards();
            } else {
                alert('Ошибка при переработке: ' + (recycleData.error || 'Неизвестная ошибка'));
            }
        }
    } catch (error) {
        console.error('Error recycling all duplicates:', error);
        alert('Ошибка при переработке: ' + error.message);
    }
}
