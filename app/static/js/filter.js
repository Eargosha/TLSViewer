function getPacketType(record) {
    if (record.is_handshake) return 'handshake';
    if (record.is_application) return 'application';
    if (record.is_cipher) return 'cipher';
    if (record.is_alert) return 'alert';
    if (record.is_unknown) return 'unknown'
    return 'other';
}

function filterPackets() {
    const filter = document.getElementById("packet-type-filter").value;
    const container = document.getElementById("filtered-packet-container");

    // Очистка контейнера
    container.innerHTML = "";

    // Фильтрация и создание новых элементов
    for (const item of allFilteredPackets) {
        if (item.type === filter) {
            const packetElement = createPacketElement({ parsed_data: item.parsed_data });
            container.appendChild(packetElement);
        }
    }

    autoScroll(container);
}

document.addEventListener("DOMContentLoaded", function () {
    const filterSelect = document.getElementById("packet-type-filter");
    if (filterSelect) {
        filterSelect.value = "handshake"; // начальный фильтр
        filterPackets()  // применить фильтр после загрузки
    }
});