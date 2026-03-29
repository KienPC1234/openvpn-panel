self.__SC_SW_VERSION__ = '2026-03-12-pwa';

self.addEventListener('install', event => {
  self.skipWaiting();
});

self.addEventListener('activate', event => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener('push', event => {
  let payload = {};
  try {
    payload = event.data ? event.data.json() : {};
  } catch (e) {
    payload = { message: event.data ? event.data.text() : '' };
  }

  const title = payload.head || payload.title || 'OpenVPN Manager';
  const body = payload.body || payload.message || 'Bạn có thông báo mới';
  const url = payload.url || '/dashboard/';
  const tag = payload.tag || 'openvpn-push';
  const icon = payload.icon || '/static/favicon/favicon-96x96.png';
  const badge = '/static/favicon/favicon-96x96.png';

  event.waitUntil(
    self.registration.showNotification(title, {
      body,
      icon,
      badge,
      data: { url },
      tag,
      renotify: false,
      requireInteraction: false,
    })
  );
});

self.addEventListener('notificationclick', event => {
  event.notification.close();
  const targetUrl = (event.notification.data && event.notification.data.url) || '/dashboard/';
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(windowClients => {
      for (const client of windowClients) {
        if ('focus' in client) {
          client.postMessage({ type: 'push_click', url: targetUrl });
          return client.focus();
        }
      }
      if (clients.openWindow) return clients.openWindow(targetUrl);
      return null;
    })
  );
});
