const handshakeSteps = {
    'client_hello': ['Client Hello'],
    'server_hello': ['Server Hello'],
    'certificate': ['Certificate'],
    'server_key_exchange': ['Server Key Exchange'],
    'server_hello_done': ['Server Hello Done'],
    'client_key_exchange': ['Client Key Exchange'],
    'change_cipher_spec': ['Change Cipher Spec'],
    'finished': ['Finished']
};

function displayHandshakeStatus(data) {
    const container = document.getElementById('handshake-status');
    if (data.error) {
        container.innerHTML = `<div class="alert alert-danger">${data.error}</div>`;
        return;
    }

    console.log(data)
    
    const statusBadge = data.status === 'completed' ? 
        '<span class="badge bg-success">Завершено</span>' :
        '<span class="badge bg-warning">Соединяется...</span>';

    container.innerHTML = `
        <div class="handshake-status-card">
            <h4>Статус для TLS соединения ${data.ip} ${statusBadge}</h4>
            <p>Клиент: ${data.participants.client}</p>
            <p>Сервер: ${data.participants.server}</p>
            <p>Стадия сейчас: ${data.current_state?.toUpperCase().replace('_', ' ') || 'Not started'}</p>
            <p>Последняя активность: ${new Date(data.last_update).toLocaleString()}</p>
            <h5>Последовательность Handshake:</h5>
            <div class="handshake-progress">
                ${Object.entries(handshakeSteps).map(([step, types]) => `
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


function requestHandshakeStatus() {
    // Получаем введенный IP-адрес из input-поля
    const ip1 = document.getElementById('targetIp1').value.trim();
    const ip2 = document.getElementById('targetIp2').value.trim();
    
    const ip = ip1 + ":" + ip2;

    // Проверяем, что IP-адрес не пустой
    if (!ip) {
        alert('Please enter a valid IP address');
        return;
    }
    
    // Отправляем запрос на сервер через WebSocket
    socket.emit('request_handshake_status', { 
        ip: ip 
    });
    
    // Можно добавить индикатор загрузки
    const statusContainer = document.getElementById('handshake-status');
    statusContainer.innerHTML = '<div class="text-center">Checking status...</div>';
}
