const logContainer = document.getElementById('log-container');
const systemMessageContainerr = document.getElementById('system-notification');

// КОНСТАНТЫ, КОНТЕЙНЕРЫ
const allFilteredPackets = [];

let totalPackets = 0;

// Подключение к WebSocket серверу
const socket = io();


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


// Функция обновления счетчика
function updatePacketCounter() {
    const counterElement = document.querySelector('.counter-value');
    if (counterElement) {
        counterElement.textContent = totalPackets;
    }
}

function clear_log_file() {
    // Отправляем запрос на сервер через WebSocket
    socket.emit('clear_log');
    // Перезагружаем страницу
    location.reload();
}

function isEmpty(value) {
    if (value === null || value === undefined) return true;

    if (typeof value === 'string' || Array.isArray(value)) {
        return value.length === 0;
    }

    if (typeof value === 'object') {
        return Object.keys(value).length === 0;
    }

    if (typeof value === 'number' || typeof value === 'boolean') {
        return false; // числа и boolean всегда "непустые"
    }

    return false; // всё остальное считаем "не пустым"
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

    if (parsed.is_unknown) {
        whatTLSRecordType = 'unknown'
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
        ${parsed.is_unknown ? '<img class="imgages" src="https://www.svgrepo.com/show/435670/file-unknown.svg"></img> <span class="unknown-badge">UNKNOWN</span>' : ''}
        ${parsed.is_alert ? '<img class="imgages" src="https://www.svgrepo.com/show/95925/user.svg"></img> <span class="alert-badge">ALERT</span>' : ''}
        ${parsed.is_heartbeat ? '<img class="imgages" src="https://www.svgrepo.com/show/164965/strategy.svg"></img> <span class="alert-badge">HEARTBEAT</span>' : ''}
        ${parsed.errors.length ? '<span class="error-badge">ERROR</span>' : ''}
    `;
    packetDiv.appendChild(header);

    console.log(parsed.frame_number)
    console.log(parsed)

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
            if (isEmpty(value)) {
                continue;
            }
            let displayValue = ""
            if (key == 'http2_frames') {
                displayValue = prettyPrintHttp2(value);
            } else {
                displayValue = formatValue(value);
            }

            // // Если значение — объект, преобразуем его в читаемую строку
            // if (typeof value === 'object' && value !== null) {
            //     displayValue = Object.entries(value)
            //         .filter(([_, v]) => v !== undefined && v !== null && v !== "")
            //         .map(([k, v]) => `${k}: ${v}`)
            //         .join(', ') || '—';
            // }

            row.innerHTML = `<td>${key}</td><td class="table-value"><pre>${displayValue}</pre></td>`;
        }
        tlsSection.appendChild(tlsTable);
        content.appendChild(tlsSection);
    }

    // Полезная нагрузка
    if (parsed.is_application && parsed.application_data && parsed.application_data.data) {
        const appDataBtn = document.createElement('button');
        appDataBtn.className = 'btn btn-info btn-sm mt-2 mb-2';
        appDataBtn.textContent = 'Показать данные';

        // Создаем popup-элемент
        const popupOverlay = document.createElement('div');
        popupOverlay.className = 'popup-overlay';

        const popupContent = document.createElement('div');
        popupContent.className = 'popup-content';

        const closeBtn = document.createElement('span');
        closeBtn.className = 'popup-close';
        closeBtn.innerHTML = '&times;';

        const contentType = document.createElement('h5');
        contentType.textContent = `Тип данных: ${parsed.application_data.content_type}`;

        if (parsed.application_data.encoding) {
            const encodingLabel = document.createElement('p');
            encodingLabel.textContent = `Кодировка: ${parsed.application_data.encoding}`;
            popupContent.appendChild(encodingLabel);
        }

        // === Здесь проверяем тип данных и создаём iframe или pre ===
        let contentPreview;

        if (parsed.application_data.content_type === 'text/html') {
            // Создаём iframe для отображения HTML
            const iframe = document.createElement('iframe');
            iframe.style.width = '100%';
            iframe.style.height = '400px';
            iframe.style.border = '1px solid #ccc';
            iframe.style.marginTop = '10px';


            // Создаём Blob URL из HTML-контента
            const blob = new Blob([parsed.application_data.data], { type: 'text/html' });
            iframe.src = URL.createObjectURL(blob);

            contentPreview = iframe;
        } else {
            // Иначе просто показываем как текст
            const preformatted = document.createElement('pre');
            preformatted.textContent = parsed.application_data.data;
            contentPreview = preformatted;
        }

        popupContent.appendChild(closeBtn);
        popupContent.appendChild(contentType);
        popupContent.appendChild(contentPreview);
        popupOverlay.appendChild(popupContent);

        // Прикрепляем обработчики
        appDataBtn.addEventListener('click', () => {
            popupOverlay.style.display = 'flex';
        });

        closeBtn.addEventListener('click', () => {
            popupOverlay.style.display = 'none';
        });

        popupOverlay.addEventListener('click', (e) => {
            if (e.target === popupOverlay) {
                popupOverlay.style.display = 'none';
            }
        });

        content.appendChild(appDataBtn);
        content.appendChild(popupOverlay);

        const foundDataDiv = document.getElementById('found-readable-data');

        if (foundDataDiv) {
            const frameNumber = parsed.frame_number;

            // Проверяем наличие HTML
            if (parsed.application_data?.content_type === 'text/html') {
                const htmlLine = document.createElement('div');
                htmlLine.innerHTML = `<strong>HTML</strong> найден в кадре ${frameNumber}`;
                foundDataDiv.appendChild(htmlLine);
            }

            // Проверяем наличие SVG
            if (parsed.application_data?.svg_data?.content_type === 'image/svg+xml') {
                const svgLine = document.createElement('div');
                svgLine.innerHTML = `<strong>SVG</strong> найден в кадре ${frameNumber}`;
                foundDataDiv.appendChild(svgLine);
            }

            // Проверяем наличие HEADERS во frames
            if (parsed.tls_details.http2_frames &&
                parsed.tls_details.http2_frames.some(frame => frame.frame_type === "HEADERS")) {

                const headersLine = document.createElement('div');
                headersLine.innerHTML = `<strong>HEADERS</strong> найдены в кадре ${frameNumber}`;
                foundDataDiv.appendChild(headersLine);
            }
        }

    }


    // function formatValue(value) {
    //     // Если значение — объект, рекурсивно форматируем его
    //     if (typeof value === 'object' && value !== null) {
    //         const entries = Object.entries(value)
    //             .map(([k, v]) => {
    //                 const formattedValue = formatValue(v);
    //                 // Если значение после форматирования не пустое — возвращаем "ключ: значение"
    //                 if (formattedValue !== '—') {
    //                     return `${k}: ${formattedValue}`;
    //                 }
    //                 // Иначе возвращаем null, чтобы потом отфильтровать
    //                 return null;
    //             })
    //             .filter(Boolean); // Убираем все null

    //         return entries.length ? `{ ${entries.join(', ')} }` : '—';
    //     }

    //     // Для примитивов: возвращаем '—', если значение пустое
    //     if (value === null || value === undefined || value === '') {
    //         return '—';
    //     }

    //     return value;
    // }


    function formatValue(value, indent = 0) {
        const INDENT_SIZE = 4;
        const SPACE = ' '.repeat(INDENT_SIZE);

        // Вспомогательная функция для проверки "пустого" значения
        function isEmpty(val) {
            return val === null || val === undefined || val === '' || val === '—';
        }

        if (typeof value === 'object' && value !== null) {
            if (Array.isArray(value)) {
                const formattedItems = value.map(v => formatValue(v, indent + 1)).filter(Boolean);
                return formattedItems.length
                    ? `[${'\n' + SPACE.repeat(indent + 1) + formattedItems.join(',\n' + SPACE.repeat(indent + 1))}\n${SPACE.repeat(indent)}]`
                    : '[]';
            }

            const entries = Object.entries(value)
                .map(([k, v]) => {
                    const formattedValue = formatValue(v, indent + 1);
                    // Пропускаем пустые значения
                    if (!isEmpty(formattedValue)) {
                        return `${SPACE.repeat(indent)}${k}: ${formattedValue}`;
                    }
                    return null; // Чтобы потом отфильтровать
                })
                .filter(Boolean); // Убираем null

            return entries.length
                ? `{\n${entries.join(',\n')}\n${SPACE.repeat(indent)}}`
                : '—'; // Если всё-таки ничего не осталось
        }

        if (isEmpty(value)) {
            return '—';
        }

        return String(value);
    }

    function prettyPrintHttp2(frames) {
        if (!Array.isArray(frames)) return 'Не удалось расшифровать encrypted data';
        if (frames.length === 0) return 'Не удалось расшифровать encrypted data';

        const INDENT = '  ';

        function formatEntry(key, value, depth = 0) {
            const prefix = INDENT.repeat(depth);

            // Для массива объектов
            if (Array.isArray(value)) {
                if (value.length === 0) return null;

                const items = value
                    .map(item => {
                        if (typeof item === 'object' && item !== null) {
                            // Если это объект — делаем красивый вывод с подполями
                            const subLines = Object.entries(item)
                                .map(([subKey, subValue]) => `${INDENT.repeat(depth + 2)}${subKey}: ${subValue}`)
                                .join('\n');

                            return `${INDENT.repeat(depth + 1)}- \n${subLines}`;
                        }
                        return `${INDENT.repeat(depth + 1)}- ${item}`;
                    })
                    .filter(Boolean)
                    .join('\n');

                return `${prefix}${key}:\n${items}`;
            }

            // Для объекта
            if (typeof value === 'object' && value !== null) {
                const entries = Object.entries(value)
                    .map(([k, v]) => formatEntry(k, v, depth + 1))
                    .filter(Boolean)
                    .join('\n');

                return `${prefix}${key}:\n${entries}`;
            }

            return `${prefix}${key}: ${value}`;
        }

        return frames
            .map((frame, index) => {
                const lines = Object.entries(frame)
                    .map(([key, value]) => formatEntry(key, value, 1))
                    .filter(Boolean);

                return `HTTP/2 Frame #${index + 1}:\n${lines.join('\n')}`;
            })
            .join('\n\n');
    }

    // // Полезная нагрузка
    // if (parsed.is_application && parsed.application_data && parsed.application_data.data) {
    //     const appDataBtn = document.createElement('button');
    //     appDataBtn.className = 'btn btn-info btn-sm mt-2 mb-2';
    //     appDataBtn.textContent = 'Показать данные';

    //     // Создаем popup-элемент
    //     const popupOverlay = document.createElement('div');
    //     popupOverlay.className = 'popup-overlay';

    //     const popupContent = document.createElement('div');
    //     popupContent.className = 'popup-content';

    //     const closeBtn = document.createElement('span');
    //     closeBtn.className = 'popup-close';
    //     closeBtn.innerHTML = '&times;';

    //     const preformatted = document.createElement('pre');
    //     preformatted.textContent = parsed.application_data.data;

    //     const contentType = document.createElement('h5');
    //     contentType.textContent = `Тип данных: ${parsed.application_data.content_type}`;

    //     if (parsed.application_data.encoding) {
    //         const encodingLabel = document.createElement('p');
    //         encodingLabel.textContent = `Кодировка: ${parsed.application_data.encoding}`;
    //         popupContent.appendChild(encodingLabel);
    //     }

    //     popupContent.appendChild(closeBtn);
    //     popupContent.appendChild(contentType);
    //     popupContent.appendChild(preformatted);
    //     popupOverlay.appendChild(popupContent);

    //     // Прикрепляем обработчики
    //     appDataBtn.addEventListener('click', function() {
    //         popupOverlay.style.display = 'flex';
    //     });

    //     closeBtn.addEventListener('click', () => {
    //         popupOverlay.style.display = 'none';
    //     });

    //     // Закрытие кликом вне окна
    //     popupOverlay.addEventListener('click', (e) => {
    //         if (e.target === popupOverlay) {
    //             popupOverlay.style.display = 'none';
    //         }
    //     });

    //     content.appendChild(appDataBtn);
    //     content.appendChild(popupOverlay);
    // }

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

function validateURL() {
    const input = document.getElementById("urlInput");
    const url = input.value.trim();

    // Простая регулярка для проверки http:// или https://
    const pattern = /^https?:\/\//i;

    if (!pattern.test(url)) {
        showSystemMessage("Ошибка: URL должен начинаться с http:// или https://");
        input.focus();
        return false;
    }

    return true;
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

        if (record.packet_type) {
            updateTlsTypeStats(record.packet_type.trim());
        }

        if (record.tls_details && record.tls_details.length) {
            updatePacketSizeStats(record.tls_details.length);
        }

        if (record.timestamp) {
            updateRequestTimeline(record.timestamp.slice(0, -1));
        }

        const packetData = {
            raw_data: data.raw_data,
            parsed_data: record,
            is_handshake: record.is_handshake
        };

        const packetDiv = createPacketElement(packetData);
        logContainer.appendChild(packetDiv);
        filterPackets();

        // Сохраняем в "все пакеты"
        allFilteredPackets.push({
            type: getPacketType(record),
            parsed_data: record // сохраняем только данные
        });

        // // Добавляем в фильтруемый контейнер
        // document.getElementById("filtered-packet-container").appendChild(packetDiv.cloneNode(true));

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
        // console.log(content)
        // console.log(headers)
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