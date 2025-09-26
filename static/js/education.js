// Education-specific JavaScript functionality

class CybersecurityEducation {
    constructor() {
        this.currentQuestion = 1;
        this.totalQuestions = 3;
        this.answers = {};
        this.quizCompleted = false;
        
        this.initializeQuiz();
        this.initializeInteractions();
    }

    // Initialize quiz functionality
    initializeQuiz() {
        const quiz = document.querySelector('.quiz-container');
        if (!quiz) return;

        // Initialize navigation buttons
        const prevBtn = document.getElementById('prev-question');
        const nextBtn = document.getElementById('next-question');
        const submitBtn = document.getElementById('submit-quiz');

        if (prevBtn) {
            prevBtn.addEventListener('click', () => this.previousQuestion());
        }

        if (nextBtn) {
            nextBtn.addEventListener('click', () => this.nextQuestion());
        }

        if (submitBtn) {
            submitBtn.addEventListener('click', () => this.submitQuiz());
        }

        // Initialize option selection
        this.initializeQuestionOptions();
        
        // Update navigation state
        this.updateNavigation();
    }

    // Initialize question option handling
    initializeQuestionOptions() {
        const questions = document.querySelectorAll('.quiz-question');
        
        questions.forEach((question, index) => {
            const options = question.querySelectorAll('input[type="radio"]');
            
            options.forEach(option => {
                option.addEventListener('change', (e) => {
                    const questionNum = index + 1;
                    this.answers[questionNum] = e.target.value;
                    this.updateNavigation();
                    
                    // Add visual feedback
                    const selectedOption = e.target.closest('.quiz-option');
                    const allOptions = question.querySelectorAll('.quiz-option');
                    
                    allOptions.forEach(opt => opt.classList.remove('selected'));
                    selectedOption.classList.add('selected');
                });
            });
        });

        // Add CSS for selected state
        const style = document.createElement('style');
        style.textContent = `
            .quiz-option.selected {
                border-color: var(--primary-color) !important;
                background: rgba(99, 102, 241, 0.1) !important;
            }
        `;
        document.head.appendChild(style);
    }

    // Navigate to previous question
    previousQuestion() {
        if (this.currentQuestion > 1) {
            this.showQuestion(this.currentQuestion - 1);
        }
    }

    // Navigate to next question
    nextQuestion() {
        if (this.currentQuestion < this.totalQuestions) {
            this.showQuestion(this.currentQuestion + 1);
        }
    }

    // Show specific question
    showQuestion(questionNum) {
        // Hide all questions
        document.querySelectorAll('.quiz-question').forEach(q => {
            q.classList.remove('active');
        });

        // Show target question
        const targetQuestion = document.querySelector(`[data-question="${questionNum}"]`);
        if (targetQuestion) {
            targetQuestion.classList.add('active');
            this.currentQuestion = questionNum;
            this.updateNavigation();
        }
    }

    // Update navigation button states
    updateNavigation() {
        const prevBtn = document.getElementById('prev-question');
        const nextBtn = document.getElementById('next-question');
        const submitBtn = document.getElementById('submit-quiz');
        const currentQ = document.getElementById('current-q');

        if (prevBtn) {
            prevBtn.disabled = this.currentQuestion === 1;
        }

        if (currentQ) {
            currentQ.textContent = this.currentQuestion;
        }

        // Show submit button on last question if all answered
        if (this.currentQuestion === this.totalQuestions) {
            const allAnswered = Object.keys(this.answers).length === this.totalQuestions;
            
            if (nextBtn) nextBtn.style.display = 'none';
            if (submitBtn) {
                submitBtn.style.display = allAnswered ? 'inline-flex' : 'none';
            }
        } else {
            if (nextBtn) nextBtn.style.display = 'inline-flex';
            if (submitBtn) submitBtn.style.display = 'none';
        }
    }

    // Submit quiz and show results
    submitQuiz() {
        if (this.quizCompleted) return;

        const correctAnswers = {
            1: 'b', // https://amaz0n-security.tk/verify is suspicious
            2: 'b', // Urgent language demanding immediate action
            3: 'b'  // photo.jpg.exe is potentially malicious with double extension
        };

        let score = 0;
        const totalQuestions = Object.keys(correctAnswers).length;

        // Calculate score
        Object.keys(correctAnswers).forEach(questionNum => {
            if (this.answers[questionNum] === correctAnswers[questionNum]) {
                score++;
            }
        });

        // Hide quiz questions and navigation
        document.querySelectorAll('.quiz-question').forEach(q => {
            q.style.display = 'none';
        });
        
        const navigation = document.querySelector('.quiz-navigation');
        if (navigation) {
            navigation.style.display = 'none';
        }

        // Show results
        this.showQuizResults(score, totalQuestions, correctAnswers);
        this.quizCompleted = true;
    }

    // Display quiz results
    showQuizResults(score, total, correctAnswers) {
        const resultContainer = document.getElementById('quiz-result');
        if (!resultContainer) return;

        const percentage = Math.round((score / total) * 100);
        const scoreElement = document.getElementById('final-score');
        const feedbackElement = document.getElementById('quiz-feedback');

        if (scoreElement) {
            scoreElement.textContent = `${score}/${total}`;
        }

        // Generate feedback based on score
        let feedback = '';
        let feedbackClass = '';

        if (percentage >= 80) {
            feedback = `
                <h4 style="color: var(--success-color);">🎉 Excellent Work!</h4>
                <p>You have a strong understanding of cybersecurity fundamentals. Keep up the great work and continue to stay vigilant against cyber threats.</p>
                <div class="feedback-tips">
                    <h5>Continue Learning:</h5>
                    <ul>
                        <li>Stay updated with the latest cyber threats</li>
                        <li>Share your knowledge with others</li>
                        <li>Consider advanced cybersecurity training</li>
                    </ul>
                </div>
            `;
            feedbackClass = 'success-feedback';
        } else if (percentage >= 60) {
            feedback = `
                <h4 style="color: var(--warning-color);">👍 Good Progress!</h4>
                <p>You're on the right track but there's room for improvement. Review the educational materials and practice identifying security threats.</p>
                <div class="feedback-tips">
                    <h5>Areas to Focus On:</h5>
                    <ul>
                        <li>URL structure and suspicious patterns</li>
                        <li>Email phishing indicators</li>
                        <li>File extension verification</li>
                    </ul>
                </div>
            `;
            feedbackClass = 'warning-feedback';
        } else {
            feedback = `
                <h4 style="color: var(--danger-color);">📚 Keep Learning!</h4>
                <p>Cybersecurity is a complex field that requires continuous learning. Don't get discouraged! Review the materials and try again.</p>
                <div class="feedback-tips">
                    <h5>Study Recommendations:</h5>
                    <ul>
                        <li>Review all educational modules carefully</li>
                        <li>Practice with real-world examples</li>
                        <li>Take time to understand each security concept</li>
                        <li>Retake the quiz after studying</li>
                    </ul>
                </div>
            `;
            feedbackClass = 'danger-feedback';
        }

        // Add detailed answer explanations
        feedback += `
            <div class="answer-explanations">
                <h5>Answer Explanations:</h5>
                <div class="explanation-item">
                    <strong>Question 1:</strong> The URL "https://amaz0n-security.tk/verify" is suspicious because:
                    <ul>
                        <li>Uses "0" instead of "o" in "amazon" (typosquatting)</li>
                        <li>Uses suspicious TLD ".tk"</li>
                        <li>Subdomain "security" to appear legitimate</li>
                    </ul>
                </div>
                <div class="explanation-item">
                    <strong>Question 2:</strong> Urgent language is the biggest red flag because:
                    <ul>
                        <li>Creates pressure to act without thinking</li>
                        <li>Bypasses normal verification processes</li>
                        <li>Common tactic in social engineering</li>
                    </ul>
                </div>
                <div class="explanation-item">
                    <strong>Question 3:</strong> "photo.jpg.exe" has a double extension:
                    <ul>
                        <li>Appears to be an image but is actually executable</li>
                        <li>Common malware disguise technique</li>
                        <li>Could install malicious software when opened</li>
                    </ul>
                </div>
            </div>
        `;

        if (feedbackElement) {
            feedbackElement.innerHTML = feedback;
            feedbackElement.className = `result-feedback ${feedbackClass}`;
        }

        // Animate score circle
        const scoreCircle = document.querySelector('.score-circle');
        if (scoreCircle) {
            scoreCircle.style.background = this.getScoreGradient(percentage);
        }

        // Show result container with animation
        resultContainer.style.display = 'block';
        resultContainer.style.opacity = '0';
        resultContainer.style.transform = 'translateY(20px)';
        
        setTimeout(() => {
            resultContainer.style.transition = 'opacity 0.5s ease, transform 0.5s ease';
            resultContainer.style.opacity = '1';
            resultContainer.style.transform = 'translateY(0)';
        }, 100);

        // Add retry button
        const retryButton = document.createElement('button');
        retryButton.className = 'btn btn-primary';
        retryButton.innerHTML = '<i class="fas fa-redo"></i> Retake Quiz';
        retryButton.style.marginTop = '1rem';
        retryButton.addEventListener('click', () => this.resetQuiz());
        
        resultContainer.appendChild(retryButton);

        // Scroll to results
        resultContainer.scrollIntoView({ behavior: 'smooth', block: 'start' });

        utils.showNotification(`Quiz completed! Score: ${score}/${total}`, 'success');
    }

    // Get gradient color based on score
    getScoreGradient(percentage) {
        if (percentage >= 80) {
            return 'linear-gradient(135deg, #10b981 0%, #059669 100%)';
        } else if (percentage >= 60) {
            return 'linear-gradient(135deg, #f59e0b 0%, #d97706 100%)';
        } else {
            return 'linear-gradient(135deg, #ef4444 0%, #dc2626 100%)';
        }
    }

    // Reset quiz to initial state
    resetQuiz() {
        this.currentQuestion = 1;
        this.answers = {};
        this.quizCompleted = false;

        // Reset all options
        document.querySelectorAll('.quiz-option').forEach(option => {
            option.classList.remove('selected');
        });

        document.querySelectorAll('input[type="radio"]').forEach(radio => {
            radio.checked = false;
        });

        // Show first question
        document.querySelectorAll('.quiz-question').forEach((q, index) => {
            q.style.display = 'block';
            q.classList.remove('active');
            if (index === 0) {
                q.classList.add('active');
            }
        });

        // Show navigation
        const navigation = document.querySelector('.quiz-navigation');
        if (navigation) {
            navigation.style.display = 'flex';
        }

        // Hide results
        const resultContainer = document.getElementById('quiz-result');
        if (resultContainer) {
            resultContainer.style.display = 'none';
        }

        this.updateNavigation();
        
        // Scroll back to quiz
        const quizContainer = document.querySelector('.quiz-container');
        if (quizContainer) {
            quizContainer.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
    }

    // Initialize interactive elements
    initializeInteractions() {
        this.initializeModuleAccordions();
        this.initializeHighlighting();
        this.initializeProgressTracking();
    }

    // Initialize module accordion behavior
    initializeModuleAccordions() {
        const moduleHeaders = document.querySelectorAll('.module-header');
        
        moduleHeaders.forEach(header => {
            header.style.cursor = 'pointer';
            header.addEventListener('click', () => {
                const module = header.closest('.education-module');
                const content = module.querySelector('.module-content');
                
                if (content.style.display === 'none') {
                    content.style.display = 'block';
                    content.style.animation = 'slideDown 0.3s ease';
                } else {
                    content.style.animation = 'slideUp 0.3s ease';
                    setTimeout(() => {
                        content.style.display = 'none';
                    }, 300);
                }
            });
        });

        // Add CSS animations
        const style = document.createElement('style');
        style.textContent = `
            @keyframes slideDown {
                from {
                    opacity: 0;
                    max-height: 0;
                }
                to {
                    opacity: 1;
                    max-height: 1000px;
                }
            }
            
            @keyframes slideUp {
                from {
                    opacity: 1;
                    max-height: 1000px;
                }
                to {
                    opacity: 0;
                    max-height: 0;
                }
            }
        `;
        document.head.appendChild(style);
    }

    // Initialize text highlighting for key terms
    initializeHighlighting() {
        const keyTerms = [
            'phishing', 'malware', 'ransomware', 'spyware', 'trojan',
            'suspicious', 'malicious', 'cybersecurity', 'threat', 'vulnerability'
        ];

        const contentSections = document.querySelectorAll('.content-section p, .content-section li');
        
        contentSections.forEach(section => {
            let html = section.innerHTML;
            
            keyTerms.forEach(term => {
                const regex = new RegExp(`\\b${term}\\b`, 'gi');
                html = html.replace(regex, `<mark class="key-term">$&</mark>`);
            });
            
            section.innerHTML = html;
        });

        // Add CSS for key terms
        const style = document.createElement('style');
        style.textContent = `
            .key-term {
                background: linear-gradient(120deg, rgba(99, 102, 241, 0.3) 0%, rgba(139, 92, 246, 0.3) 100%);
                padding: 0.1em 0.3em;
                border-radius: 3px;
                font-weight: 600;
                transition: background 0.3s ease;
            }
            
            .key-term:hover {
                background: linear-gradient(120deg, rgba(99, 102, 241, 0.5) 0%, rgba(139, 92, 246, 0.5) 100%);
            }
        `;
        document.head.appendChild(style);
    }

    // Initialize progress tracking
    initializeProgressTracking() {
        // Track reading progress
        const modules = document.querySelectorAll('.education-module');
        const progressData = JSON.parse(localStorage.getItem('cybersecurity-progress') || '{}');

        modules.forEach((module, index) => {
            const moduleId = `module-${index}`;
            
            // Mark as read when scrolled into view
            const observer = new IntersectionObserver((entries) => {
                entries.forEach(entry => {
                    if (entry.isIntersecting && entry.intersectionRatio > 0.7) {
                        progressData[moduleId] = {
                            completed: true,
                            timestamp: new Date().toISOString()
                        };
                        localStorage.setItem('cybersecurity-progress', JSON.stringify(progressData));
                        
                        // Add visual indicator
                        const header = module.querySelector('.module-header');
                        if (header && !header.querySelector('.completed-indicator')) {
                            const indicator = document.createElement('i');
                            indicator.className = 'fas fa-check-circle completed-indicator';
                            indicator.style.cssText = 'color: var(--success-color); margin-left: auto;';
                            header.appendChild(indicator);
                        }
                    }
                });
            }, { threshold: 0.7 });

            observer.observe(module);

            // Show existing progress
            if (progressData[moduleId]?.completed) {
                const header = module.querySelector('.module-header');
                if (header && !header.querySelector('.completed-indicator')) {
                    const indicator = document.createElement('i');
                    indicator.className = 'fas fa-check-circle completed-indicator';
                    indicator.style.cssText = 'color: var(--success-color); margin-left: auto;';
                    header.appendChild(indicator);
                }
            }
        });
    }

    // Get progress statistics
    getProgressStats() {
        const progressData = JSON.parse(localStorage.getItem('cybersecurity-progress') || '{}');
        const totalModules = document.querySelectorAll('.education-module').length;
        const completedModules = Object.keys(progressData).filter(key => progressData[key].completed).length;
        
        return {
            total: totalModules,
            completed: completedModules,
            percentage: totalModules > 0 ? Math.round((completedModules / totalModules) * 100) : 0
        };
    }

    // Update progress display
    updateProgressDisplay() {
        const stats = this.getProgressStats();
        const progressStats = document.getElementById('progress-stats');
        const progressFill = document.getElementById('progress-fill');
        
        if (progressStats && progressFill) {
            progressStats.textContent = `${stats.percentage}% Complete (${stats.completed}/${stats.total} modules)`;
            progressFill.style.width = `${stats.percentage}%`;
        }
    }

    // Initialize completion buttons
    initializeCompletionButtons() {
        const completeButtons = document.querySelectorAll('.complete-module');
        const progressData = JSON.parse(localStorage.getItem('cybersecurity-progress') || '{}');
        
        completeButtons.forEach(button => {
            const moduleId = button.getAttribute('data-module');
            const module = button.closest('.education-module');
            const statusDiv = button.parentElement.querySelector('.completion-status');
            
            // Check if module is already completed
            if (progressData[moduleId] && progressData[moduleId].completed) {
                this.markModuleAsCompleted(module, button, statusDiv);
            }
            
            // Add click handler
            button.addEventListener('click', () => {
                this.completeModule(moduleId, module, button, statusDiv);
            });
        });
    }

    // Mark module as completed
    markModuleAsCompleted(module, button, statusDiv) {
        module.classList.add('completed');
        button.style.display = 'none';
        statusDiv.style.display = 'flex';
    }

    // Complete a module
    completeModule(moduleId, module, button, statusDiv) {
        // Save progress
        const progressData = JSON.parse(localStorage.getItem('cybersecurity-progress') || '{}');
        progressData[moduleId] = {
            completed: true,
            completedAt: new Date().toISOString()
        };
        localStorage.setItem('cybersecurity-progress', JSON.stringify(progressData));
        
        // Update UI
        this.markModuleAsCompleted(module, button, statusDiv);
        this.updateProgressDisplay();
        
        // Show notification
        const stats = this.getProgressStats();
        if (typeof utils !== 'undefined' && utils.showNotification) {
            if (stats.completed === stats.total) {
                utils.showNotification('🎉 Congratulations! You\'ve completed all cybersecurity modules!', 'success');
            } else {
                utils.showNotification(`Module completed! Progress: ${stats.percentage}% (${stats.completed}/${stats.total} modules)`, 'success');
            }
        }
    }

    // Reset all progress (for testing/demo purposes)
    resetProgress() {
        localStorage.removeItem('cybersecurity-progress');
        location.reload();
    }
}

// Initialize education features when DOM is ready
let education;
document.addEventListener('DOMContentLoaded', () => {
    if (document.querySelector('.education-container')) {
        education = new CybersecurityEducation();
        
        // Initialize completion system
        education.initializeCompletionButtons();
        education.updateProgressDisplay();
        
        console.log('Cybersecurity education module initialized');
        
        // Show welcome message based on progress
        setTimeout(() => {
            const stats = education.getProgressStats();
            if (stats.completed === 0) {
                if (typeof utils !== 'undefined' && utils.showNotification) {
                    utils.showNotification('Welcome to CyberGuard Education! Complete modules to track your progress.', 'info');
                }
            } else if (stats.completed === stats.total) {
                if (typeof utils !== 'undefined' && utils.showNotification) {
                    utils.showNotification('🎉 All modules completed! You\'re a cybersecurity expert!', 'success');
                }
            }
        }, 1500);
        
        // Set global instance
        window.education = education;
    }
});

// Global education instance for onclick handlers
window.education = education;