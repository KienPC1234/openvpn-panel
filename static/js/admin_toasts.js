function initAdminToasts() {
    if (typeof Swal === 'undefined') {
        console.warn("Admin Toasts: SweetAlert2 is not loaded yet, retrying in 500ms...");
        setTimeout(initAdminToasts, 500);
        return;
    }

    const Toast = Swal.mixin({
        toast: true,
        position: 'top-end',
        showConfirmButton: false,
        timer: 4000,
        timerProgressBar: true,
        customClass: {
            popup: 'bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-xl shadow-2xl',
            title: 'text-gray-900 dark:text-gray-100 font-bold ml-2 text-sm',
            timerProgressBar: 'bg-blue-600'
        },
        didOpen: (toast) => {
            toast.addEventListener('mouseenter', Swal.stopTimer)
            toast.addEventListener('mouseleave', Swal.resumeTimer)
        }
    });

    const processMessages = () => {
        const messageSelectors = [
            '.unfold-message', 
            '.unfold-toast',
            '.messagelist li',
            '.messages li',
            '.alert',
            'div[role="alert"]',
            '.django-messages div'
        ];
        
        const messageElements = document.querySelectorAll(messageSelectors.join(','));
        
        messageElements.forEach(el => {
            if (el.dataset.toastProcessed === 'true') return;
            el.dataset.toastProcessed = 'true';
            
            let text = el.textContent.trim();
            if (!text) {
                const inner = el.querySelector('span, p, .text-sm');
                if (inner) text = inner.textContent.trim();
            }

            if (!text || text.length < 2) return;

            let icon = 'info';
            const classStr = el.className.toLowerCase();
            const textStr = text.toLowerCase();
            
            // Priority icon detection
            if (classStr.includes('error') || classStr.includes('red') || classStr.includes('danger') || textStr.includes('lỗi')) icon = 'error';
            else if (classStr.includes('success') || classStr.includes('teal') || classStr.includes('green') || textStr.includes('thành công')) icon = 'success';
            else if (classStr.includes('warning') || classStr.includes('orange') || classStr.includes('yellow') || textStr.includes('cảnh báo')) icon = 'warning';
            else if (classStr.includes('info') || classStr.includes('blue')) icon = 'info';

            Toast.fire({
                icon: icon,
                title: text
            });
            
            // Hide original element
            el.style.display = 'none';
            // Also hide parent if it's just a wrapper
            if (el.parentElement && el.parentElement.tagName === 'UL') {
                el.parentElement.style.display = 'none';
            }
        });
    };

    processMessages();
    
    // Throttled observer to avoid high CPU or loops
    let timeout = null;
    const observer = new MutationObserver((mutations) => {
        if (timeout) return;
        timeout = setTimeout(() => {
            processMessages();
            timeout = null;
        }, 150);
    });
    
    observer.observe(document.body, { childList: true, subtree: true });
}

function generateOTP(apiUrl, username) {
    if (typeof Swal === 'undefined') {
        alert("SweetAlert2 is not loaded yet.");
        return;
    }

    Swal.fire({
        title: 'Đang tạo mã...',
        text: `Vui lòng đợi trong khi tạo mã cho ${username}`,
        allowOutsideClick: false,
        showConfirmButton: false,
        didOpen: () => {
            Swal.showLoading();
        }
    });

    fetch(apiUrl)
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                Swal.fire({
                    icon: 'success',
                    title: 'Mã OTP Thành Công',
                    html: `
                        <div class="space-y-4">
                            <p class="text-sm text-slate-400">Mã OTP mới cho <b>${data.username}</b>:</p>
                            <div class="text-4xl font-black tracking-widest text-blue-400 py-6 bg-slate-800 rounded-2xl border border-blue-500/20 shadow-inner">
                                ${data.code}
                            </div>
                            <div class="flex flex-col gap-2 pt-2">
                                <button onclick="navigator.clipboard.writeText('${data.code}'); this.innerText='Đã copy!';" class="w-full py-3 bg-blue-600 hover:bg-blue-500 text-white font-bold rounded-xl transition-all">Sao chép mã</button>
                                <p class="text-[10px] text-slate-500 uppercase tracking-widest">Mã này có hiệu lực trong 24 giờ</p>
                            </div>
                        </div>
                    `,
                    showConfirmButton: true,
                    confirmButtonText: 'Xong',
                    customClass: {
                        popup: 'rounded-3xl border border-white/10 bg-slate-900 text-white',
                        title: 'text-white font-black',
                        confirmButton: 'bg-slate-800 border border-white/10 px-8 py-3 rounded-xl font-bold hover:bg-slate-700'
                    }
                });
            } else {
                Swal.fire({
                    icon: 'error',
                    title: 'Lỗi',
                    text: data.error || 'Không thể tạo mã OTP',
                    confirmButtonText: 'Đóng',
                    customClass: {
                        popup: 'rounded-3xl border border-white/10 bg-slate-900 text-white',
                        title: 'text-white font-black',
                        confirmButton: 'bg-rose-600 px-8 py-3 rounded-xl font-bold'
                    }
                });
            }
        })
        .catch(err => {
            console.error('OTP Gen Error:', err);
            Swal.fire({
                icon: 'error',
                title: 'Lỗi Hệ Thống',
                text: 'Có lỗi xảy ra khi gọi API.',
                confirmButtonText: 'Đóng',
                customClass: {
                    popup: 'rounded-3xl border border-white/10 bg-slate-900 text-white',
                    title: 'text-white font-black',
                    confirmButton: 'bg-rose-600 px-8 py-3 rounded-xl font-bold'
                }
            });
        });
}

// Run immediately and also on DOMContentLoaded
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initAdminToasts);
} else {
    initAdminToasts();
}
