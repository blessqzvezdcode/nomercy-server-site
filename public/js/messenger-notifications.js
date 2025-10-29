// Messenger notifications system
let notificationInterval = null;

// Initialize notifications
function initMessengerNotifications() {
    // Check for unread messages every 30 seconds
    notificationInterval = setInterval(checkUnreadMessages, 30000);
    // Check immediately
    checkUnreadMessages();
}

// Check for unread messages
async function checkUnreadMessages() {
    try {
        const response = await fetch('/api/messenger/unread-count');
        const data = await response.json();
        
        if (data.success) {
            updateNotificationDot(data.unreadCount);
        }
    } catch (error) {
        console.error('Error checking unread messages:', error);
    }
}

// Update notification dot
function updateNotificationDot(unreadCount) {
    const messengerBtns = document.querySelectorAll('.nav-messenger-btn');
    
    messengerBtns.forEach(btn => {
        let dot = btn.querySelector('.notification-dot');
        
        if (unreadCount > 0) {
            if (!dot) {
                dot = document.createElement('span');
                dot.className = 'notification-dot';
                btn.appendChild(dot);
            }
        } else {
            if (dot) {
                dot.remove();
            }
        }
    });
}

// Clean up on page unload
window.addEventListener('beforeunload', () => {
    if (notificationInterval) {
        clearInterval(notificationInterval);
    }
});

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    // Only initialize if user is logged in and not on messenger page
    if (document.querySelector('.nav-messenger-btn') && !window.location.pathname.includes('/messenger')) {
        initMessengerNotifications();
    }
});
