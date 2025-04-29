
const logContainer = document.getElementById('log-container');

// Подключение к WebSocket серверу
const socket = io();

// // Обработка новых данных из лога
// socket.on('log_update', function (data) {
//     if (data && data.data) {
//         // Разделяем пакеты по двойным переносам строк (если каждый пакет отделен пустой строкой)
//         if (data.new_session && data.new_session == 1) {
//             logContainer.innerHTML = "";
//         }

//         const packets = data.data.split(/\n\s*\n/).filter(p => p.trim().length > 0);

//         packets.forEach(packet => {
//             const packetDiv = document.createElement('div');
//             packetDiv.className = 'tls-packet';

//             // Проверяем, является ли пакет ошибкой
//             if (packet.includes('ERROR') || packet.includes('error') || packet.includes('failed')) {
//                 packetDiv.classList.add('error');
//             }

//             console.log(packet)

//             packetDiv.textContent = packet;
//             logContainer.appendChild(packetDiv);
//         });

//         // Автоскролл к новым сообщениям
//         // logContainer.scrollTop = logContainer.scrollHeight;
//     }
// });


// Обработка системных сообщений
socket.on('system_message', function (data) {
    const sysDiv = document.createElement('div');
    sysDiv.className = `system-message ${data.type}`;
    sysDiv.innerHTML = `
        <span class="sys-timestamp">${new Date(data.timestamp).toLocaleTimeString()}</span>
        <span class="sys-text">${data.message}</span>
    `;
    logContainer.appendChild(sysDiv);
    logContainer.scrollTop = logContainer.scrollHeight;
});

// Обработка статистики сервера
socket.on('server_stats', function (data) {
    console.log('Server stats:', data);
    // Можно выводить в специальный блок в интерфейсе
    document.getElementById('server-stats').innerHTML = ` Clients: ${data.clients_connected} | Log size: ${(data.log_size / 1024).toFixed(2)} KB | Monitoring: ${data.monitoring_active ? 'ACTIVE' : 'INACTIVE'}`;
});

socket.on('log_update', function (data) {
    if (!data) return;

    const isHandshake = data.is_handshake;
    const parsed = data.parsed_data;

    // Создаем элемент для пакета
    const packetDiv = document.createElement('div');
    packetDiv.className = `tls-packet ${isHandshake ? 'handshake' : ''} ${parsed.errors.length ? 'error' : ''}`;

    // Заголовок пакета
    const header = document.createElement('div');
    header.className = 'packet-header';
    header.innerHTML = `
        <strong>TLS Packet</strong>
        <span class="timestamp">${parsed.timestamp}</span>
        ${isHandshake ? '<span class="handshake-badge">HANDSHAKE</span>' : ''}
        ${parsed.errors.length ? '<span class="error-badge">ERROR</span>' : ''}
    `;
    packetDiv.appendChild(header);

    // Основное содержимое
    const content = document.createElement('div');
    content.className = 'packet-content';

    // Отображение атрибутов
    if (isHandshake && parsed.attributes) {
        const attrs = document.createElement('div');
        attrs.className = 'attributes';
        for (const [key, value] of Object.entries(parsed.attributes)) {
            const row = document.createElement('div');
            row.className = 'attribute-row';
            row.innerHTML = `<span class="attr-key">${key}:</span> <span class="attr-value">${value}</span>`;
            attrs.appendChild(row);
        }
        content.appendChild(attrs);
    }

    // Отображение ошибок
    if (parsed.errors.length) {
        const errors = document.createElement('div');
        errors.className = 'errors';
        parsed.errors.forEach(error => {
            const err = document.createElement('div');
            err.className = 'error-message';
            err.textContent = error;
            errors.appendChild(err);
        });
        content.appendChild(errors);
    }

    // Source/Destination
    const networkInfo = document.createElement('div');
    networkInfo.className = 'network-info';
    networkInfo.innerHTML = `
        <span class="source">${parsed.source}</span> →
        <span class="destination">${parsed.destination}</span>
    `;
    content.appendChild(networkInfo);

    packetDiv.appendChild(content);
    logContainer.appendChild(packetDiv);

    // // Автоскролл
    // if (logContainer.scrollTop > logContainer.scrollHeight - logContainer.clientHeight - 100) {
    //     logContainer.scrollTop = logContainer.scrollHeight;
    // }
});


// Обработка ошибок соединения
socket.on('connect_error', function (err) {
    const errorDiv = document.createElement('div');
    errorDiv.className = 'tls-packet error';
    errorDiv.textContent = `Connection error: ${err.message}`;
    logContainer.appendChild(errorDiv);
    logContainer.scrollTop = logContainer.scrollHeight;
});

// Уведомление о переподключении
socket.on('reconnect', function (attempt) {
    const infoDiv = document.createElement('div');
    infoDiv.className = 'tls-packet';
    infoDiv.textContent = `Reconnected after ${attempt} attempts`;
    logContainer.appendChild(infoDiv);
    logContainer.scrollTop = logContainer.scrollHeight;
});
