/**
 * ShieldCall VN - Global Notification & Real-time System
 * Handles WebSocket connections and WebPush registration.
 */

window.NotificationManager = {
    ws: null,
    isStaff: false,
    _version: '2026-v6',
    _recentHashes: {},
    _prefKey: 'sc_notification_pref',
    _snoozeKey: 'sc_notification_snooze_until',
    _tabId: null,
    _leaderKey: 'sc_notification_leader',
    _leaderTtlMs: 10000,
    _leaderHeartbeatMs: 3000,
    _leaderHeartbeatTimer: null,

    _log(...args) {
        console.info('[WebPush]', ...args);
    },

    showReliableToast(message, type = 'info') {
        if (typeof window.showToast === 'function') {
            window.showToast(message, type);
            return;
        }
        try {
            const colorMap = {
                success: { bg: 'rgba(16,185,129,0.18)', border: 'rgba(16,185,129,0.45)' },
                error: { bg: 'rgba(239,68,68,0.18)', border: 'rgba(239,68,68,0.45)' },
                warning: { bg: 'rgba(245,158,11,0.18)', border: 'rgba(245,158,11,0.45)' },
                info: { bg: 'rgba(6,182,212,0.18)', border: 'rgba(6,182,212,0.45)' },
            };
            const c = colorMap[type] || colorMap.info;
            const toast = document.createElement('div');
            toast.className = 'sc-ws-toast';
            toast.textContent = message;
            toast.style.position = 'fixed';
            toast.style.right = '16px';
            toast.style.bottom = '92px';
            toast.style.maxWidth = '420px';
            toast.style.padding = '10px 14px';
            toast.style.borderRadius = '12px';
            toast.style.backdropFilter = 'blur(10px)';
            toast.style.border = `1px solid ${c.border}`;
            toast.style.background = c.bg;
            toast.style.color = '#fff';
            toast.style.fontSize = '13px';
            toast.style.fontWeight = '600';
            toast.style.zIndex = '2147483647';
            toast.style.boxShadow = '0 10px 30px rgba(0,0,0,0.35)';
            toast.style.transform = 'translateX(20px)';
            toast.style.opacity = '0';
            toast.style.transition = 'all .2s ease';

            const stack = document.querySelectorAll('.sc-ws-toast');
            let offset = 92;
            stack.forEach(el => { offset += (el.offsetHeight || 44) + 8; });
            toast.style.bottom = `${offset}px`;

            document.body.appendChild(toast);
            requestAnimationFrame(() => {
                toast.style.transform = 'translateX(0)';
                toast.style.opacity = '1';
            });

            setTimeout(() => {
                toast.style.opacity = '0';
                toast.style.transform = 'translateX(20px)';
                setTimeout(() => toast.remove(), 240);
            }, 3600);
        } catch (e) {
            console.info('Notification:', message);
        }
    },

    init(isStaff = false) {
        this.isStaff = isStaff;
        this._tabId = this._tabId || (`sc-tab-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`);
        this._log('Initializing (isStaff=' + isStaff + ')...');
        
        this._initTabLeadership();
        
        if (window.is_authenticated) {
            this.connectNotifications();
            this.setupWebPush();
        }
    },

    _initTabLeadership() {
        this._writeLeader();
        this._leaderHeartbeatTimer = setInterval(() => {
            this._writeLeader();
        }, this._leaderHeartbeatMs);
    },

    _writeLeader() {
        const payload = { id: this._tabId, ts: Date.now() };
        localStorage.setItem(this._leaderKey, JSON.stringify(payload));
    },

    _isLeaderTab() {
        try {
            const raw = localStorage.getItem(this._leaderKey);
            if (!raw) return true;
            const leader = JSON.parse(raw);
            return leader.id === this._tabId;
        } catch (_) { return true; }
    },

    setupWebPush() {
        if (!('Notification' in window) || !('serviceWorker' in navigator)) return;
        
        if (Notification.permission === 'default') {
            // Auto-request for now as requested for notification logic
            this.requestPermission();
        } else if (Notification.permission === 'granted') {
            this.ensureWebPushSubscription();
            this.togglePushCard(false);
        } else {
            this.togglePushCard(false); // Hide if denied too to avoid clutter
        }
    },

    togglePushCard(show) {
        const card = document.getElementById('webpush-card');
        if (card) {
            card.style.display = show ? 'block' : 'none';
        }
    },

    async requestPermission() {
        const permission = await Notification.requestPermission();
        if (permission === 'granted') {
            this.ensureWebPushSubscription();
            this.togglePushCard(false);
            this.showReliableToast("Đã bật thông báo hệ thống", "success");
        }
    },

    async ensureWebPushSubscription() {
        try {
            if (!window.WEBPUSH_PUBLIC_KEY) return;
            
            const registration = await navigator.serviceWorker.ready;
            let subscription = await registration.pushManager.getSubscription();
            
            if (!subscription) {
                subscription = await registration.pushManager.subscribe({
                    userVisibleOnly: true,
                    applicationServerKey: this.urlBase64ToUint8Array(window.WEBPUSH_PUBLIC_KEY),
                });
            }

            await fetch('/api/v1/push/subscribe/', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': this.getCSRFToken(),
                },
                body: JSON.stringify(subscription.toJSON()),
            });
        } catch (e) {
            this._log('Subscription failed', e);
        }
    },

    urlBase64ToUint8Array(base64String) {
        const padding = '='.repeat((4 - (base64String.length % 4)) % 4);
        const base64 = (base64String + padding).replace(/-/g, '+').replace(/_/g, '/');
        const rawData = window.atob(base64);
        const outputArray = new Uint8Array(rawData.length);
        for (let i = 0; i < rawData.length; ++i) {
            outputArray[i] = rawData.charCodeAt(i);
        }
        return outputArray;
    },

    getCSRFToken() {
        return document.querySelector('[name=csrfmiddlewaretoken]')?.value || '';
    },

    connectNotifications() {
        const proto = window.location.protocol === 'https:' ? 'wss' : 'ws';
        this.ws = new WebSocket(`${proto}://${window.location.host}/ws/notifications/`);

        this.ws.onmessage = (e) => {
            const data = JSON.parse(e.data);
            if (data.type === 'notification') {
                this.handleNotification(data);
            }
        };

        this.ws.onclose = () => {
            setTimeout(() => this.connectNotifications(), 5000);
        };
    },

    handleNotification(data) {
        if (!this._isLeaderTab()) return;
        
        const cleanMsg = data.message.replace(/<[^>]*>/g, '');
        
        // Use SweetAlert2 for toasts if available
        if (typeof Swal !== 'undefined') {
            Swal.fire({
                toast: true,
                position: 'bottom-end',
                showConfirmButton: false,
                timer: 4000,
                timerProgressBar: true,
                icon: data.notification_type || 'info',
                title: data.title || 'Thông báo',
                text: cleanMsg,
                background: '#111827',
                color: '#fff',
                iconColor: '#3b82f6'
            });
        } else {
            this.showReliableToast(cleanMsg, data.notification_type || 'info');
        }
        
        if (Notification.permission === 'granted') {
            new Notification(data.title || 'Thông báo', {
                body: cleanMsg,
                icon: '/static/images/logo.png'
            });
        }
    }
};

// Initialize after DOM load
document.addEventListener('DOMContentLoaded', () => {
    window.NotificationManager.init(window.is_staff || false);
});
