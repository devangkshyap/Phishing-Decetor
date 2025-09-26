// Main JavaScript file for CyberGuard platform

// Utility functions
const utils = {
    // Show loading overlay
    showLoading() {
        const loading = document.getElementById('loading-overlay');
        if (loading) {
            loading.style.display = 'flex';
        }
    },

    // Hide loading overlay
    hideLoading() {
        const loading = document.getElementById('loading-overlay');
        if (loading) {
            loading.style.display = 'none';
        }
    },

    // Format file size
    formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    },

    // Animate counter
    animateCounter(element, target, duration = 2000) {
        const start = 0;
        const startTime = performance.now();
        
        const animate = (currentTime) => {
            const elapsed = currentTime - startTime;
            const progress = Math.min(elapsed / duration, 1);
            
            // Easing function
            const easeOut = 1 - Math.pow(1 - progress, 3);
            const current = Math.floor(start + (target - start) * easeOut);
            
            element.textContent = current;
            
            if (progress < 1) {
                requestAnimationFrame(animate);
            }
        };
        
        requestAnimationFrame(animate);
    },

    // Show notification
    showNotification(message, type = 'info') {
        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        notification.innerHTML = `
            <i class="fas fa-${type === 'success' ? 'check-circle' : type === 'error' ? 'exclamation-circle' : 'info-circle'}"></i>
            <span>${message}</span>
            <button class="notification-close">&times;</button>
        `;
        
        // Add styles
        Object.assign(notification.style, {
            position: 'fixed',
            top: '20px',
            right: '20px',
            background: type === 'success' ? '#10b981' : type === 'error' ? '#ef4444' : '#3b82f6',
            color: 'white',
            padding: '1rem 1.5rem',
            borderRadius: '12px',
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
            zIndex: '10000',
            boxShadow: '0 10px 15px -3px rgb(0 0 0 / 0.1)',
            transform: 'translateX(100%)',
            transition: 'transform 0.3s ease'
        });
        
        document.body.appendChild(notification);
        
        // Animate in
        setTimeout(() => {
            notification.style.transform = 'translateX(0)';
        }, 100);
        
        // Auto remove
        setTimeout(() => {
            notification.style.transform = 'translateX(100%)';
            setTimeout(() => {
                if (notification.parentNode) {
                    notification.parentNode.removeChild(notification);
                }
            }, 300);
        }, 5000);
        
        // Close button
        const closeBtn = notification.querySelector('.notification-close');
        closeBtn.style.cssText = 'background: none; border: none; color: white; font-size: 1.2rem; cursor: pointer; margin-left: 0.5rem;';
        closeBtn.addEventListener('click', () => {
            notification.style.transform = 'translateX(100%)';
            setTimeout(() => {
                if (notification.parentNode) {
                    notification.parentNode.removeChild(notification);
                }
            }, 300);
        });
    },

    // Debounce function
    debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    }
};

// Animation helpers
const animations = {
    // Intersection Observer for scroll animations
    observer: new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('animate-in');
            }
        });
    }, {
        threshold: 0.1,
        rootMargin: '0px 0px -50px 0px'
    }),

    // Initialize scroll animations
    initScrollAnimations() {
        const elements = document.querySelectorAll('.feature-card, .stat-item, .tip-card');
        elements.forEach(el => {
            el.style.opacity = '0';
            el.style.transform = 'translateY(30px)';
            el.style.transition = 'opacity 0.6s ease, transform 0.6s ease';
            this.observer.observe(el);
        });

        // Add CSS for animation
        const style = document.createElement('style');
        style.textContent = `
            .animate-in {
                opacity: 1 !important;
                transform: translateY(0) !important;
            }
        `;
        document.head.appendChild(style);
    },

    // Counter animation for stats
    animateStats() {
        const statNumbers = document.querySelectorAll('.stat-number');
        statNumbers.forEach(stat => {
            const target = parseInt(stat.dataset.target);
            utils.animateCounter(stat, target);
        });
    },

    // Parallax effect for hero section
    initParallax() {
        const hero = document.querySelector('.hero-visual');
        if (!hero) return;

        const handleScroll = utils.debounce(() => {
            const scrolled = window.pageYOffset;
            const rate = scrolled * -0.5;
            hero.style.transform = `translateY(${rate}px)`;
        }, 10);

        window.addEventListener('scroll', handleScroll);
    }
};

// Form handlers
const forms = {
    // Generic form submission handler
    async submitForm(url, data, options = {}) {
        try {
            utils.showLoading();
            
            const response = await fetch(url, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    ...options.headers
                },
                body: JSON.stringify(data)
            });

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const result = await response.json();
            return result;
        } catch (error) {
            console.error('Form submission error:', error);
            throw error;
        } finally {
            utils.hideLoading();
        }
    },

    // File upload handler
    async uploadFile(url, formData) {
        try {
            utils.showLoading();
            
            const response = await fetch(url, {
                method: 'POST',
                body: formData
            });

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const result = await response.json();
            return result;
        } catch (error) {
            console.error('File upload error:', error);
            throw error;
        } finally {
            utils.hideLoading();
        }
    }
};

// Navigation handler
const navigation = {
    init() {
        // Mobile menu toggle (if needed)
        const navToggle = document.querySelector('.nav-toggle');
        const navMenu = document.querySelector('.nav-menu');
        
        if (navToggle && navMenu) {
            navToggle.addEventListener('click', () => {
                navMenu.classList.toggle('nav-menu-open');
            });
        }

        // Active link highlighting
        const currentPath = window.location.pathname;
        const navLinks = document.querySelectorAll('.nav-link');
        
        navLinks.forEach(link => {
            if (link.getAttribute('href') === currentPath) {
                link.classList.add('active');
            }
        });

        // Smooth scrolling for anchor links
        document.querySelectorAll('a[href^="#"]').forEach(anchor => {
            anchor.addEventListener('click', function (e) {
                e.preventDefault();
                const target = document.querySelector(this.getAttribute('href'));
                if (target) {
                    target.scrollIntoView({
                        behavior: 'smooth',
                        block: 'start'
                    });
                }
            });
        });
    }
};

// Theme and preferences
const theme = {
    // Initialize theme
    init() {
        // Check for saved theme preference or default to light mode
        const savedTheme = localStorage.getItem('theme') || 'light';
        this.setTheme(savedTheme);
        
        // Listen for theme toggle clicks
        const themeToggle = document.querySelector('.theme-toggle');
        if (themeToggle) {
            themeToggle.addEventListener('click', () => {
                this.toggleTheme();
            });
        }
    },

    // Set theme
    setTheme(theme) {
        document.documentElement.setAttribute('data-theme', theme);
        localStorage.setItem('theme', theme);
        
        // Update toggle button if exists
        const themeToggle = document.querySelector('.theme-toggle');
        if (themeToggle) {
            const icon = themeToggle.querySelector('i');
            if (icon) {
                icon.className = theme === 'dark' ? 'fas fa-sun' : 'fas fa-moon';
            }
        }
    },

    // Toggle theme
    toggleTheme() {
        const currentTheme = localStorage.getItem('theme') || 'light';
        const newTheme = currentTheme === 'light' ? 'dark' : 'light';
        this.setTheme(newTheme);
    }
};

// Error handling
const errorHandler = {
    // Display error message
    show(message, error = null) {
        console.error('Error:', message, error);
        
        // Show user-friendly error message
        utils.showNotification(
            message || 'An unexpected error occurred. Please try again.',
            'error'
        );
    },

    // Handle network errors
    handleNetworkError(error) {
        if (!navigator.onLine) {
            this.show('No internet connection. Please check your network and try again.');
        } else if (error.name === 'AbortError') {
            this.show('Request timed out. Please try again.');
        } else {
            this.show('Network error occurred. Please try again.');
        }
    },

    // Handle validation errors
    handleValidationError(errors) {
        if (Array.isArray(errors)) {
            errors.forEach(error => this.show(error));
        } else {
            this.show(errors);
        }
    }
};

// Performance monitoring
const performance = {
    // Mark performance
    mark(name) {
        if (window.performance && window.performance.mark) {
            window.performance.mark(name);
        }
    },

    // Measure performance
    measure(name, startMark, endMark) {
        if (window.performance && window.performance.measure) {
            window.performance.measure(name, startMark, endMark);
            const measure = window.performance.getEntriesByName(name)[0];
            console.log(`${name}: ${measure.duration.toFixed(2)}ms`);
        }
    }
};

// Initialize everything when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    performance.mark('app-start');
    
    try {
        // Initialize core features
        navigation.init();
        theme.init();
        animations.initScrollAnimations();
        
        // Initialize page-specific features
        if (document.querySelector('.stats-container')) {
            // Animate stats when they come into view
            const statsObserver = new IntersectionObserver((entries) => {
                entries.forEach(entry => {
                    if (entry.isIntersecting) {
                        animations.animateStats();
                        statsObserver.unobserve(entry.target);
                    }
                });
            });
            
            const statsContainer = document.querySelector('.stats-container');
            if (statsContainer) {
                statsObserver.observe(statsContainer);
            }
        }

        // Initialize parallax
        animations.initParallax();
        
        performance.mark('app-end');
        performance.measure('app-init', 'app-start', 'app-end');
        
        console.log('CyberGuard platform initialized successfully');
    } catch (error) {
        errorHandler.show('Failed to initialize application', error);
    }
});

// Handle global errors
window.addEventListener('error', (event) => {
    errorHandler.show('An unexpected error occurred', event.error);
});

window.addEventListener('unhandledrejection', (event) => {
    errorHandler.show('An unexpected promise rejection occurred', event.reason);
});

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { utils, forms, errorHandler, animations, theme, navigation };
}