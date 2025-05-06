function getPacketType(record) {
    if (record.is_handshake) return 'handshake';
    if (record.is_application) return 'application';
    if (record.is_cipher) return 'cipher';
    return 'other';
}

function filterPackets() {
    const filter = document.getElementById("packet-type-filter").value;
    const container = document.getElementById("filtered-packet-container");

    // Очистка контейнера
    container.innerHTML = "";

    // Фильтрация и добавление подходящих пакетов
    for (const item of allFilteredPackets) {
        if (item.type === filter) {
            container.appendChild(item.element.cloneNode(true));
        }
    }

    // Прокрутка вниз
    autoScroll(container);
}

socket.on('log_update', function (data) {
    if (!data || !data.parsed_data) return;

    const records = Array.isArray(data.parsed_data) ? data.parsed_data : [data.parsed_data];

    records.forEach(record => {
        const packetData = {
            raw_data: data.raw_data,
            parsed_data: record,
            is_handshake: record.is_handshake
        };

        const packetDiv = createPacketElement(packetData);

        // Сохраняем в "все пакеты"
        allFilteredPackets.push({
            type: getPacketType(record),
            element: packetDiv
        });

        // Добавляем в фильтруемый контейнер
        document.getElementById("filtered-packet-container").appendChild(packetDiv.cloneNode(true));
    });

    autoScroll(document.getElementById("filtered-packet-container"));
});

document.addEventListener("DOMContentLoaded", function () {
    const filterSelect = document.getElementById("packet-type-filter");
    if (filterSelect) {
        filterSelect.value = "handshake"; // начальный фильтр
        setTimeout(filterPackets, 100);   // применить фильтр после загрузки
    }
});