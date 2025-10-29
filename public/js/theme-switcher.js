// Theme Switcher
document.addEventListener('DOMContentLoaded', function() {
    const themeToggle = document.getElementById('theme-toggle');
    const body = document.body;
    
    // Load saved theme from localStorage
    const savedTheme = localStorage.getItem('theme') || 'dark';
    setTheme(savedTheme);
    
    if (themeToggle) {
        themeToggle.addEventListener('click', function(e) {
            e.preventDefault();
            e.stopPropagation();
            
            const currentTheme = body.getAttribute('data-theme') || 'dark';
            const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
            
            setTheme(newTheme);
            saveTheme(newTheme);
        });
    }
    
    function setTheme(theme) {
        body.setAttribute('data-theme', theme);
        
        if (themeToggle) {
            // Check if it's a landing page button (has class theme-toggle-btn)
            if (themeToggle.classList.contains('theme-toggle-btn')) {
                themeToggle.innerHTML = theme === 'light' ? '☀️' : '🌙';
            } else {
                // Regular dropdown button
                if (theme === 'light') {
                    themeToggle.innerHTML = '☀️ Темная тема';
                } else {
                    themeToggle.innerHTML = '🌙 Светлая тема';
                }
            }
        }
    }
    
    function saveTheme(theme) {
        localStorage.setItem('theme', theme);
    }
});

