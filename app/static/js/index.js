const logContainer = document.getElementById('log-container');
const systemMessageContainerr = document.getElementById('system-notification');

// КОНСТАНТЫ, КОНТЕЙНЕРЫ
const allFilteredPackets = [];

let totalPackets = 0;

// Подключение к WebSocket серверу
const socket = io();


socket.on('log_update', function (data) {
    console.log('Received data:', data.parsed_data);
});

// Обработка статистики сервера
socket.on('server_stats', function (data) {
    // Можно выводить в специальный блок в интерфейсе
    document.getElementById('server-stats').innerHTML = ` Clients: ${data.clients_connected} | Log size: ${(data.log_size / 1024).toFixed(2)} KB | Monitoring: ${data.monitoring_active ? 'ACTIVE' : 'INACTIVE'}`;
});

// Обработка системных сообщений
socket.on('system_message', function (data) {
    showSystemMessage(new Date(data.timestamp).toLocaleTimeString() + "  " + data.message)
});

// Обработка ошибок соединения
socket.on('connect_error', function (err) {
    let textContent = `Connection error: ${err.message}`;
    showSystemMessage(textContent)
});

// Уведомление о переподключении
socket.on('reconnect', function (attempt) {
    let textContent = `Reconnected after ${attempt} attempts`;
    showSystemMessage(textContent)
});



// // Управление демоном

// const daemonButton = document.getElementById('toggle-daemon-btn');
// const daemonStatus = document.getElementById('daemon-status');

// let isRunning = false;

// function updateDaemonUI(running, pid = null) {
//     isRunning = running;
//     if (running) {
//         daemonButton.textContent = "Остановить демон";
//         daemonButton.className = "btn btn-danger";
//         daemonStatus.innerHTML = `Статус: Запущен <span class="badge bg-primary">PID: ${pid}</span>`;
//     } else {
//         daemonButton.textContent = "Запустить демон";
//         daemonButton.className = "btn btn-success";
//         daemonStatus.textContent = "Статус: Не запущен";
//     }
// }

// daemonButton.addEventListener('click', function () {
//     if (!isRunning) {
//         socket.emit('start_daemon');
//     } else {
//         socket.emit('stop_daemon');
//     }
// });

// // Обработка сообщений от сервера
// socket.on('system_message', function (data) {
//     if (data.type === 'info' && data.message.includes('Daemon запущен')) {
//         const pidMatch = data.message.match(/PID: (\d+)/);
//         if (pidMatch && pidMatch[1]) {
//             updateDaemonUI(true, pidMatch[1]);
//         }
//     } else if (data.type === 'info' && data.message === 'Daemon успешно остановлен') {
//         updateDaemonUI(false);
//     } else if (data.type === 'info' && data.message === 'Daemon не запущен') {
//         updateDaemonUI(false);
//     }
// });




// Функция обновления счетчика
function updatePacketCounter() {
    const counterElement = document.querySelector('.counter-value');
    if (counterElement) {
        counterElement.textContent = totalPackets;
    }
}

// Создание обьекта пакета
function createPacketElement(data) {
    const parsed = data.parsed_data;
    const packetDiv = document.createElement('div');

    let whatTLSRecordType = ' '

    if (parsed.is_handshake) {
        whatTLSRecordType = 'handshake'
    }

    if (parsed.is_cipher) {
        whatTLSRecordType = 'cipher'
    }

    if (parsed.is_application) {
        whatTLSRecordType = 'application'
    }

    if (parsed.is_alert) {
        whatTLSRecordType = 'alert'
    }

    if (parsed.is_heartbeat) {
        whatTLSRecordType = 'heartbeat'
    }
    packetDiv.className = `tls-packet ${whatTLSRecordType} ${parsed.errors.length ? 'error' : ''}`;

    // Заголовок пакета
    const header = document.createElement('div');
    header.className = 'packet-header';
    header.innerHTML = `
        <span class="timestamp">Frame #${parsed.frame_number}, time: ${parsed.timestamp.slice(0, -1)}</span>
        ${parsed.is_handshake ? `<img class="imgages" src="https://www.svgrepo.com/show/134487/handshake.svg"></img> <span class="handshake-badge"> HANDSHAKE (${parsed.tls_details.handshake_type}) </span>` : ''}
        ${parsed.is_application ? '<img class="imgages" src="https://www.svgrepo.com/show/14385/computer.svg"></img> <span class="application-badge">APPLICATION</span>' : ''}
        ${parsed.is_cipher ? '<img class="imgages" src="https://www.svgrepo.com/show/95936/security.svg"></img> <span class="cipher-badge">CIPHER</span>' : ''}
        ${parsed.is_alert ? '<img class="imgages" src="https://www.svgrepo.com/show/95925/user.svg"></img> <span class="alert-badge">ALERT</span>' : ''}
        ${parsed.is_heartbeat ? '<img class="imgages" src="https://www.svgrepo.com/show/164965/strategy.svg"></img> <span class="alert-badge">HEARTBEAT</span>' : ''}
        ${parsed.errors.length ? '<span class="error-badge">ERROR</span>' : ''}
    `;
    packetDiv.appendChild(header);

    // Основное содержимое
    const content = document.createElement('div');
    content.className = 'packet-content';

    // Сетевая информация
    const networkInfo = document.createElement('div');
    networkInfo.className = 'network-info';
    networkInfo.innerHTML = `
    <div class="centeredBox">
        <div class="address-box">
            <h4>Source</h4>
            <p>MAC: ${parsed.source.mac || 'N/A'}</p>
            <p>IP: ${parsed.source.ip || 'N/A'}</p>
            <p>Port: ${parsed.source.port || 'N/A'}</p>
        </div>
        <div class="arrow">→</div>
        <div class="address-box">
            <h4>Destination</h4>
            <p>MAC: ${parsed.destination.mac || 'N/A'}</p>
            <p>IP: ${parsed.destination.ip || 'N/A'}</p>
            <p>Port: ${parsed.destination.port || 'N/A'}</p>
        </div>
    </div>
    `;
    content.appendChild(networkInfo);

    // Детали TLS
    if (parsed.tls_details) {
        const tlsSection = document.createElement('div');
        tlsSection.className = 'tls-details';
        tlsSection.innerHTML = '<h4>TLS Details</h4>';

        const tlsTable = document.createElement('table');
        for (const [key, value] of Object.entries(parsed.tls_details)) {
            const row = tlsTable.insertRow();
            row.innerHTML = `<td>${key}</td><td class="table-value">${value}</td>`;
        }
        tlsSection.appendChild(tlsTable);
        content.appendChild(tlsSection);
    }

    // Сертификаты
    if (parsed.certificates.length > 0) {
        const certsSection = document.createElement('div');
        certsSection.className = 'certificates';
        certsSection.innerHTML = '<h4>Certificates</h4>';

        parsed.certificates.forEach((cert, index) => {
            const certDiv = document.createElement('div');
            certDiv.className = 'certificate';
            certDiv.innerHTML = `
                <details>
                    <summary>Certificate #${index + 1} (${cert.raw.length} lines)</summary>
                    <pre>${cert.raw.join('\n')}</pre>
                </details>
            `;
            certsSection.appendChild(certDiv);
        });
        content.appendChild(certsSection);
    }

    // Ошибки
    if (parsed.errors.length) {
        const errors = document.createElement('div');
        errors.className = 'errors';
        errors.innerHTML = '<h4>Errors/Warnings</h4>';
        parsed.errors.forEach(error => {
            const err = document.createElement('div');
            err.className = 'error-message';
            err.textContent = error;
            errors.appendChild(err);
        });
        content.appendChild(errors);
    }

    packetDiv.appendChild(content);
    return packetDiv;
}

// Функция автоскролла
function autoScroll(element) {
    if (element.scrollTop > element.scrollHeight - element.clientHeight - 100) {
        element.scrollTop = element.scrollHeight;
    }
}


// Обновить обработчик log_update для сбора статистики
socket.on('log_update', function (data) {
    if (!data || !data.parsed_data) return;

    // Обрабатываем массив записей, если он пришел
    const records = Array.isArray(data.parsed_data) ?
        data.parsed_data : [data.parsed_data];


    // Увеличиваем счетчик пакетов
    totalPackets += records.length;
    updatePacketCounter();

    records.forEach(record => {
        // Собираем статистику по версиям TLS
        if (record.tls_details && record.tls_details.version) {
            updateTlsVersionStats(record.tls_details.version.trim());
        }
        if (record.tls_details && record.tls_details.version) {
            updateTlsVersionStats(record.tls_details.version);
        }

        const packetData = {
            raw_data: data.raw_data,
            parsed_data: record,
            is_handshake: record.is_handshake
        };

        const packetDiv = createPacketElement(packetData);
        logContainer.appendChild(packetDiv);

         // Сохраняем в "все пакеты"
         allFilteredPackets.push({
            type: getPacketType(record),
            element: packetDiv
        });

        // Добавляем в фильтруемый контейнер
        document.getElementById("filtered-packet-container").appendChild(packetDiv.cloneNode(true));

    });

    autoScroll(logContainer);
    autoScroll(document.getElementById("filtered-packet-container"));
});



// LOADER
document.addEventListener("DOMContentLoaded", function () {
    // Находим все заголовки с классом section-header
    const headers = document.querySelectorAll(".section-header");

    headers.forEach(header => {
        // По умолчанию не сворачиваем — можно раскомментировать, если нужно
        // toggleSection(header); // Чтобы свернуть все при загрузке

        header.addEventListener("click", function () {
            toggleSection(this);
        });
    });

    function toggleSection(header) {
        const content = header.nextElementSibling;
        console.log(content)
        console.log(headers)
        const isCollapsed = content.classList.contains("collapsed");

        if (isCollapsed) {
            content.style.maxHeight = content.scrollHeight + "px";
            content.classList.remove("collapsed");
            header.classList.remove("collapsed");
        } else {
            content.style.maxHeight = 0;
            content.classList.add("collapsed");
            header.classList.add("collapsed");
        }
    }

});