// Dropdown Menu JavaScript
document.addEventListener('DOMContentLoaded', function() {
    // Initialize all dropdowns
    const dropdowns = document.querySelectorAll('.dropdown');
    
    dropdowns.forEach(dropdown => {
        const toggle = dropdown.querySelector('.dropdown-toggle');
        const menu = dropdown.querySelector('.dropdown-menu');
        
        if (toggle && menu) {
            // Toggle dropdown on click
            toggle.addEventListener('click', function(e) {
                e.preventDefault();
                e.stopPropagation();
                
                // Close other dropdowns
                dropdowns.forEach(otherDropdown => {
                    if (otherDropdown !== dropdown) {
                        const otherToggle = otherDropdown.querySelector('.dropdown-toggle');
                        const otherMenu = otherDropdown.querySelector('.dropdown-menu');
                        if (otherToggle && otherMenu) {
                            otherToggle.classList.remove('active');
                            otherMenu.classList.remove('show');
                        }
                    }
                });
                
                // Toggle current dropdown
                toggle.classList.toggle('active');
                menu.classList.toggle('show');
            });
            
            // Close dropdown when clicking outside
            document.addEventListener('click', function(e) {
                if (!dropdown.contains(e.target)) {
                    toggle.classList.remove('active');
                    menu.classList.remove('show');
                }
            });
            
            // Close dropdown when pressing Escape
            document.addEventListener('keydown', function(e) {
                if (e.key === 'Escape') {
                    toggle.classList.remove('active');
                    menu.classList.remove('show');
                }
            });
            
            // Handle dropdown item clicks
            const items = menu.querySelectorAll('.dropdown-item');
            items.forEach(item => {
                item.addEventListener('click', function(e) {
                    // Remove active class from all items
                    items.forEach(otherItem => {
                        otherItem.classList.remove('active');
                    });
                    
                    // Add active class to clicked item
                    this.classList.add('active');
                    
                    // Close dropdown after a short delay
                    setTimeout(() => {
                        toggle.classList.remove('active');
                        menu.classList.remove('show');
                    }, 150);
                });
            });
        }
    });
    
    // Set active item based on current page
    setActiveDropdownItem();
});

function setActiveDropdownItem() {
    const currentPath = window.location.pathname;
    const dropdownItems = document.querySelectorAll('.dropdown-item');
    
    dropdownItems.forEach(item => {
        const href = item.getAttribute('href');
        if (href && currentPath.includes(href.replace('/', ''))) {
            // Remove active from all items
            dropdownItems.forEach(otherItem => {
                otherItem.classList.remove('active');
            });
            
            // Add active to current item
            item.classList.add('active');
        }
    });
}

// Smooth scroll for dropdown items
function smoothScrollTo(target) {
    const element = document.querySelector(target);
    if (element) {
        element.scrollIntoView({
            behavior: 'smooth',
            block: 'start'
        });
    }
}

