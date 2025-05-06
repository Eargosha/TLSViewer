

const notificationQueue = [];
let isProcessing = false;

function showSystemMessage(message) {
    const container = document.getElementById("system-notification");
    if (!container) return;

    // Добавляем сообщение в очередь
    notificationQueue.push(message);

    // Если сейчас ничего не показывается — начинаем обработку
    if (!isProcessing) {
        processNextNotification();
    }
}

function processNextNotification() {
    const container = document.getElementById("system-notification");
    if (!container) return;

    if (notificationQueue.length === 0) {
        isProcessing = false;
        return;
    }

    isProcessing = true;
    const message = notificationQueue.shift();

    // Создаём элемент уведомления
    const el = document.createElement("div");
    el.className = "notification-item";
    el.textContent = message;

    container.appendChild(el);

    // Удаляем через 5 секунд с анимацией
    setTimeout(() => {
        el.classList.add("hidden");
        setTimeout(() => {
            el.remove();
            processNextNotification(); // Обрабатываем следующее
        }, 300);
    }, 5000);
}