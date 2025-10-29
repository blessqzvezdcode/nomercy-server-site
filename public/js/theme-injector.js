// Auto-inject theme switcher into all pages
document.addEventListener('DOMContentLoaded', function() {
    // Check if theme switcher already exists
    if (document.getElementById('theme-toggle')) {
        return;
    }
    
    // Find dropdown menu
    const dropdownMenu = document.querySelector('.dropdown-menu');
    if (!dropdownMenu) {
        return;
    }
    
    // Find logout button
    const logoutItem = dropdownMenu.querySelector('a[href="/logout"]');
    if (!logoutItem) {
        return;
    }
    
    // Create theme toggle button
    const themeToggle = document.createElement('button');
    themeToggle.className = 'dropdown-item theme-toggle';
    themeToggle.id = 'theme-toggle';
    themeToggle.innerHTML = '🌙 Светлая тема';
    
    // Create divider
    const divider = document.createElement('div');
    divider.className = 'dropdown-divider';
    
    // Insert before logout button
    logoutItem.parentNode.insertBefore(divider, logoutItem);
    logoutItem.parentNode.insertBefore(themeToggle, logoutItem);
    
    // Add another divider after theme toggle
    const divider2 = document.createElement('div');
    divider2.className = 'dropdown-divider';
    logoutItem.parentNode.insertBefore(divider2, logoutItem);
});

