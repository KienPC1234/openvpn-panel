

var isPushEnabled = false,
  registration,
  subBtn;

window.addEventListener('load', function () {
  subBtn = document.getElementById('webpush-subscribe-button');

  if (subBtn) {
    subBtn.textContent = typeof gettext !== 'undefined' ? gettext('Subscribe to Push Messaging') : 'Subscribe to Push Messaging';

    subBtn.addEventListener('click',
      function () {
        subBtn.disabled = true;
        if (isPushEnabled) {
          return unsubscribe(registration);
        }
        return subscribe(registration);
      }
    );
  }

  // Do everything if the Browser Supports Service Worker
  if ('serviceWorker' in navigator) {
    const swMeta = document.querySelector('meta[name="service-worker-js"]');
    if (swMeta) {
      const serviceWorker = swMeta.content;
      navigator.serviceWorker.register(serviceWorker).then(
        function (reg) {
          registration = reg;
          initialiseState(reg);
        }).catch(err => {
          console.warn("WebPush Service Worker registration failed:", err);
        });
    }
  }
  // If service worker not supported, show warning to the message box
  else {
    showMessage(typeof gettext !== 'undefined' ? gettext('Service workers are not supported in your browser.') : 'Service workers are not supported in your browser.');
  }

  // Once the service worker is registered set the initial state
  function initialiseState(reg) {
    // Are Notifications supported in the service worker?
    if (!(reg.showNotification)) {
      // Show a message and activate the button
      showMessage(typeof gettext !== 'undefined' ? gettext('Showing notifications are not supported in your browser.') : 'Showing notifications are not supported in your browser.');
      return;
    }

    // Check the current Notification permission.
    if (Notification.permission === 'denied') {
      // Show a message and activate the button
      if (subBtn) subBtn.disabled = false;
      showMessage(typeof gettext !== 'undefined' ? gettext('Push notifications are blocked by your browser.') : 'Push notifications are blocked by your browser.');
      return;
    }

    // Check if push messaging is supported
    if (!('PushManager' in window)) {
      // Show a message and activate the button
      if (subBtn) subBtn.disabled = false;
      showMessage(typeof gettext !== 'undefined' ? gettext('Push notifications are not available in your browser.') : 'Push notifications are not available in your browser.');
      return;
    }

    // We need to get subscription state for push notifications and send the information to server
    reg.pushManager.getSubscription().then(
      function (subscription) {
        if (subscription) {
          postSubscribeObj('subscribe', subscription,
            function (response) {
              // Check the information is saved successfully into server
              if (response.status === 201) {
                // Show unsubscribe button instead
                if (subBtn) {
                  subBtn.textContent = typeof gettext !== 'undefined' ? gettext('Unsubscribe from Push Messaging') : 'Unsubscribe from Push Messaging';
                  subBtn.disabled = false;
                }
                isPushEnabled = true;
                showMessage(typeof gettext !== 'undefined' ? gettext('Successfully subscribed to push notifications.') : 'Successfully subscribed to push notifications.');
              }
            });
        }
      });
  }
}
);

function showMessage(message) {
  const messageBox = document.getElementById('webpush-message');
  if (messageBox) {
    messageBox.textContent = message;
    messageBox.style.display = 'block';
  }
}

function subscribe(reg) {
  if (!reg) {
    console.error("Service worker registration is null");
    if (subBtn) subBtn.disabled = false;
    return;
  }
  // Get the Subscription or register one
  reg.pushManager.getSubscription().then(
    function (subscription) {
      var metaObj, applicationServerKey, options;
      // Check if Subscription is available
      if (subscription) {
        return subscription;
      }

      metaObj = document.querySelector('meta[name="django-webpush-vapid-key"]');
      if (!metaObj) {
        console.error("VAPID key meta tag not found");
        if (subBtn) subBtn.disabled = false;
        return;
      }
      applicationServerKey = metaObj.content;
      options = {
        userVisibleOnly: true
      };
      if (applicationServerKey) {
        options.applicationServerKey = urlB64ToUint8Array(applicationServerKey)
      }
      // If not, register one
      reg.pushManager.subscribe(options)
        .then(
          function (subscription) {
            postSubscribeObj('subscribe', subscription,
              function (response) {
                // Check the information is saved successfully into server
                if (response.status === 201) {
                  // Show unsubscribe button instead
                  if (subBtn) {
                    subBtn.textContent = typeof gettext !== 'undefined' ? gettext('Unsubscribe from Push Messaging') : 'Unsubscribe from Push Messaging';
                    subBtn.disabled = false;
                  }
                  isPushEnabled = true;
                  showMessage(typeof gettext !== 'undefined' ? gettext('Successfully subscribed to push notifications.') : 'Successfully subscribed to push notifications.');
                }
              });
          })
        .catch(
          function () {
            const errorMsg = typeof gettext !== 'undefined' ? gettext('Error while subscribing to push notifications.') : 'Error while subscribing to push notifications.';
            console.log(errorMsg, arguments);
            if (subBtn) subBtn.disabled = false;
          })
    }
  );
}

function urlB64ToUint8Array(base64String) {
  const padding = '='.repeat((4 - base64String.length % 4) % 4);
  const base64 = (base64String + padding)
    .replace(/\-/g, '+')
    .replace(/_/g, '/');

  const rawData = window.atob(base64);
  const outputArray = new Uint8Array(rawData.length);

  for (var i = 0; i < rawData.length; ++i) {
    outputArray[i] = rawData.charCodeAt(i);
  }
  return outputArray;
}

function unsubscribe(reg) {
  if (!reg) return;
  // Get the Subscription to unregister
  reg.pushManager.getSubscription()
    .then(
      function (subscription) {

        // Check we have a subscription to unsubscribe
        if (!subscription) {
          // No subscription object, so set the state
          // to allow the user to subscribe to push
          if (subBtn) subBtn.disabled = false;
          showMessage(typeof gettext !== 'undefined' ? gettext('Subscription is not available.') : 'Subscription is not available.');
          return;
        }
        postSubscribeObj('unsubscribe', subscription,
          function (response) {
            // Check if the information is deleted from server
            if (response.status === 202) {
              // Get the Subscription
              // Remove the subscription
              subscription.unsubscribe()
                .then(
                  function (successful) {
                    if (subBtn) {
                      subBtn.textContent = typeof gettext !== 'undefined' ? gettext('Subscribe to Push Messaging') : 'Subscribe to Push Messaging';
                      subBtn.disabled = false;
                    }
                    showMessage(typeof gettext !== 'undefined' ? gettext('Successfully unsubscribed from push notifications.') : 'Successfully unsubscribed from push notifications.');
                    isPushEnabled = false;
                  }
                )
                .catch(
                  function (error) {
                    if (subBtn) {
                      subBtn.textContent = typeof gettext !== 'undefined' ? gettext('Unsubscribe from Push Messaging') : 'Unsubscribe from Push Messaging';
                      subBtn.disabled = false;
                    }
                    showMessage(typeof gettext !== 'undefined' ? gettext('Error while unsubscribing from push notifications.') : 'Error while unsubscribing from push notifications.');
                  }
                );
            }
          });
      }
    )
}

function postSubscribeObj(statusType, subscription, callback) {
  if (!subBtn) return;
  var agent = navigator.userAgent.match(/(firefox|msie|chrome|safari|trident)/ig);
  var browser = agent ? agent[0].toLowerCase() : 'unknown',
    user_agent = navigator.userAgent,
    data = {
      status_type: statusType,
      subscription: subscription.toJSON(),
      browser: browser,
      user_agent: user_agent,
      group: subBtn.dataset.group
    };

  fetch(subBtn.dataset.url, {
    method: 'post',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRFToken': getCookie('csrftoken')
    },
    body: JSON.stringify(data),
    credentials: 'include'
  }).then(callback);
}

function getCookie(name) {
  let cookieValue = null;
  if (document.cookie && document.cookie !== '') {
    const cookies = document.cookie.split(';');
    for (let i = 0; i < cookies.length; i++) {
      const cookie = cookies[i].trim();
      if (cookie.substring(0, name.length + 1) === (name + '=')) {
        cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
        break;
      }
    }
  }
  return cookieValue;
}
