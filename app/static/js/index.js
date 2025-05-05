const logContainer = document.getElementById('log-container');
const handshakeContainer = document.getElementById('handshake-container');

// Подключение к WebSocket серверу
const socket = io();

socket.on('log_update', function (data) {
    console.log('Received data:', data.parsed_data);
});


// Добавить в начало файла
let totalPackets = 0;

// Функция обновления счетчика
function updatePacketCounter() {
    const counterElement = document.querySelector('.counter-value');
    if (counterElement) {
        counterElement.textContent = totalPackets;
    }
}

// ДИАГРАММЫ
// Добавить в начало файла
const tlsVersionStats = {};
let tlsChart = null;

// Функция для обновления статистики версий TLS
function updateTlsVersionStats(version) {
    if (!version) return;

    if (tlsVersionStats[version]) {
        tlsVersionStats[version]++;
    } else {
        tlsVersionStats[version] = 1;
    }

    updateTlsChart();
}

// Функция для создания/обновления диаграммы
function updateTlsChart() {
    const ctx = document.getElementById('tlsChart').getContext('2d');
    const versions = Object.keys(tlsVersionStats);
    const counts = Object.values(tlsVersionStats);

    // Расширенная палитра цветов для версий TLS
    const versionColors = {
        'TLSv1.3': '#72a5db',
        'TLSv1.2': '#dd9a57',
        'TLSv1.1': '#e15759',
        'TLSv1.0': '#76b7b2',
        'SSLv3': '#59a14f',
        'SSLv2': '#edc948',
        'Unknown': '#b07aa1',
        // Добавьте возможные альтернативы:
    };

    // Создаем массив цветов, используя версию как ключ, или серый по умолчанию
    const backgroundColors = versions.map(v => {
        // Нормализуем название версии (может приходить с дополнительными символами)
        const normalizedVersion = v.trim()
            .replace(/[^a-zA-Z0-9.]/g, '') // Удаляет лишние символы
            .replace(/^TLS(\d+)\.(?=\d)/, 'TLSv$1.'); // "TLS1.2" → "TLSv1.2"
        console.log('Raw version:', v);
        console.log('Normalized version:', normalizedVersion);
        console.log('Color used:', versionColors[normalizedVersion] || '#cccccc');
        return versionColors[normalizedVersion] || '#cccccc';
    });

    if (!tlsChart) {
        tlsChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: versions,
                datasets: [{
                    data: counts,
                    backgroundColor: backgroundColors,
                    borderWidth: 1,
                    borderColor: '#fff'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'right',
                        labels: {
                            boxWidth: 20,
                            padding: 15,
                            font: {
                                family: 'monospace',
                                size: 12
                            }
                        }
                    },
                    tooltip: {
                        callbacks: {
                            label: function (context) {
                                const label = context.label || '';
                                const value = context.raw || 0;
                                const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                const percentage = Math.round((value / total) * 100);
                                return `${label}: ${value} (${percentage}%)`;
                            }
                        },
                        bodyFont: {
                            family: 'monospace',
                            size: 12
                        }
                    }
                },
                cutout: '70%'
            }
        });
    } else {
        tlsChart.data.labels = versions;
        tlsChart.data.datasets[0].data = counts;
        tlsChart.data.datasets[0].backgroundColor = backgroundColors;
        tlsChart.update();
    }
}







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
        <span class="timestamp">Frame time: ${parsed.timestamp.slice(0, -1)}</span>
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










// // Обработка новых данных из лога
// socket.on('log_update', function (data) {
//     if (!data) return;

//     const isHandshake = data.is_handshake;
//     const parsed = data.parsed_data;

//     // Создаем элемент для основного лога
//     const packetDiv = createPacketElement(data);
//     logContainer.appendChild(packetDiv);

//     // Дублируем handshake-пакеты в специальный контейнер
//     if (isHandshake) {
//         const handshakePacketDiv = createPacketElement(data);
//         handshakeContainer.appendChild(handshakePacketDiv);
//     }

//     // Автоскролл
//     autoScroll(logContainer);
//     if (isHandshake) autoScroll(handshakeContainer);
// });

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
            console.log('Detected TLS version:', record.tls_details.version);
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

        if (record.is_handshake) {
            const handshakePacketDiv = createPacketElement(packetData);
            handshakeContainer.appendChild(handshakePacketDiv);
        }
    });

    autoScroll(logContainer);
    autoScroll(handshakeContainer);
});



















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