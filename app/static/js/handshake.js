const handshakeStepsTLS12 = {
    'client_hello': ['Client Hello'],
    'server_hello': ['Server Hello'],
    'certificate': ['Certificate'],
    'server_key_exchange': ['Server Key Exchange'],
    'server_hello_done': ['Server Hello Done'],
    'client_key_exchange': ['Client Key Exchange'],
    'change_cipher_spec': ['Change Cipher Spec'],
    'finished': ['Finished']
};

const handshakeStepsTLS13 = {
    'client_hello': ['Client Hello'],
    'server_hello': ['Server Hello'],
    'encrypted_extensions': ['Encrypted Extensions'],
    'certificate': ['Certificate (Optional)'],
    'finished': ['Finished']
};

function formatTimestamp(ts) {
    const date = new Date(ts * 1000);
    return date.toLocaleString('ru-RU', {
        day: '2-digit',
        month: '2-digit',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        fractionalSecondDigits: 3
    });
}

// Запрос всех handshake при подключении
socket.on('connect', () => {
    socket.emit('request_all_handshakes');
});

// Обработчик ответа
socket.on('all_handshakes', displayAllHandshakes);

function displayAllHandshakes(data) {
    const container = document.getElementById('all-handshakes');
    container.innerHTML = ''; // Очистка контейнера

    if (!data.length) {
        container.innerHTML = '<div class="alert alert-info">Нет активных handshake-соединений</div>';
        return;
    }

    data.forEach(handshake => {
        const card = document.createElement('div');
        card.className = 'handshake-status-card mb-3';
        card.innerHTML = `
            <h4>Соединение: ${handshake.ip}</h4>
            <p>Статус: ${handshake.status}</p>
            <p>Версия TLS: ${handshake.tls_version}</p>
            <p>Последняя активность: ${formatTimestamp(handshake.last_update)}</p>
            <button class="btn btn-sm btn-primary" onclick="requestHandshakeStatus('${handshake.ip}')">Подробнее</button>
        `;
        container.appendChild(card);
    });
}


function displayHandshakeStatus(data) {
    const container = document.getElementById('handshake-status');
    if (data.error) {
        container.innerHTML = `<div class="alert alert-danger">${data.error}</div>`;
        return;
    }

    // console.log(data);

    const statusBadge = data.status === 'completed' ?
        '<span class="badge bg-success">Завершено</span>' :
        '<span class="badge bg-warning">Соединяется...</span>';

    // Выбираем нужные шаги в зависимости от версии TLS
    const tlsVersion = data.tls_version || 'TLS 1.2';
    console.log(data)
    let stepsToShow = tlsVersion.includes('1.3') ? handshakeStepsTLS13 : handshakeStepsTLS12;

                // <p>Идентификация по имени сервера: ${data.sni}</p>
    container.innerHTML = `
        <div class="handshake-status-card">
            <h4>Статус для TLS соединения ${data.ip} ${statusBadge}</h4>
            <p>Клиент: ${data.participants.client}</p>
            <p>Сервер: ${data.participants.server}</p>
            <p>Версия TLS: ${data.tls_version || 'TLS 1.2'}</p>
            <p>Стадия сейчас: ${data.current_state?.toUpperCase().replace('_', ' ') || 'Not started'}</p>
            <p>Последняя активность: ${formatTimestamp(data.last_update)}</p>
            <h5>Последовательность Handshake:</h5>
            <div class="handshake-progress">
                ${Object.entries(stepsToShow).map(([step, types]) => `
                    <div class="step ${data.seen_steps.includes(step) ? 'completed' : ''} 
                                 ${data.current_state === step ? 'active' : ''}">
                        <div class="step-circle"></div>
                        <div class="step-label">${step.replace('_', ' ').toUpperCase()}</div>
                        <div class="step-types">${types.join(', ')}</div>
                    </div>
                `).join('')}
            </div>
        </div>
    `;
}

// Обновить обработчик handshake_status
socket.on('handshake_status', displayHandshakeStatus);


function requestHandshakeStatus(ip = null) {
    if (!ip) {
        const ip1 = document.getElementById('targetIp1').value.trim();
        const ip2 = document.getElementById('targetIp2').value.trim();
        if (!ip1 || !ip2) {
            alert('Введите оба IP-адреса');
            return;
        }
        ip = `${ip1}:${ip2}`;
    }

    socket.emit('request_handshake_status', { ip });
    const statusContainer = document.getElementById('handshake-status');
    statusContainer.innerHTML = '<div class="text-center">Проверка статуса...</div>';
}
