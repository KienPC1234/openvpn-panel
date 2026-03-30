/*
 * Admin Toasts Handler with SweetAlert2
 * Maps Django messages to SweetAlert2 toast notifications.
 */
function initAdminToasts() {
    if (typeof Swal === 'undefined') {
        console.error("Admin Toasts: SweetAlert2 is not loaded!");
        return;
    }

    const Toast = Swal.mixin({
        toast: true,
        position: 'top-end',
        showConfirmButton: false,
        timer: 4000,
        timerProgressBar: true,
        didOpen: (toast) => {
            toast.addEventListener('mouseenter', Swal.stopTimer)
            toast.addEventListener('mouseleave', Swal.resumeTimer)
        }
    });

    const processMessages = () => {
        const messageSelectors = [
            '.unfold-message', 
            '.messagelist li',
            '.messages li',
            '[class*="unfold-message"]',
            '.alert',
            '.alert-success',
            '.alert-error'
        ];
        
        const messageElements = document.querySelectorAll(messageSelectors.join(','));
        
        messageElements.forEach(el => {
            if (el.dataset.toastProcessed === 'true') return;
            
            const text = el.textContent.trim();
            if (!text) return;

            let icon = 'info';
            const classStr = el.className.toLowerCase();
            
            if (classStr.includes('success') || classStr.includes('teal')) icon = 'success';
            else if (classStr.includes('warning') || classStr.includes('orange')) icon = 'warning';
            else if (classStr.includes('error') || classStr.includes('red')) icon = 'error';

            Toast.fire({
                icon: icon,
                title: text
            });
            
            // Mark as processed
            el.dataset.toastProcessed = 'true';
            
            // Hide original
            el.style.display = 'none';
            el.style.visibility = 'hidden';
            el.style.height = '0';
            el.style.padding = '0';
            el.style.margin = '0';
            el.style.overflow = 'hidden';
            
            // Hide parent container if empty or if it's a known message list
            const parent = el.parentElement;
            if (parent && (parent.classList.contains('messagelist') || parent.classList.contains('messages'))) {
                setTimeout(() => {
                    const visibleChildren = Array.from(parent.children).filter(c => c.style.display !== 'none');
                    if (visibleChildren.length === 0) {
                        parent.style.display = 'none';
                    }
                }, 100);
            }
        });
    };

    // Initial check
    processMessages();
    
    // MutationObserver to catch dynamic messages
    const observer = new MutationObserver((mutations) => {
        processMessages();
    });
    
    observer.observe(document.body, {
        childList: true,
        subtree: true
    });
}

// Run immediately and also on DOMContentLoaded
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initAdminToasts);
} else {
    initAdminToasts();
}
