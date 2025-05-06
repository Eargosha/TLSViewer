function getPacketType(record) {
    if (record.is_handshake) return 'handshake';
    if (record.is_application) return 'application';
    if (record.is_cipher) return 'cipher';
    if (record.is_alert) return 'alert';
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

document.addEventListener("DOMContentLoaded", function () {
    const filterSelect = document.getElementById("packet-type-filter");
    if (filterSelect) {
        filterSelect.value = "handshake"; // начальный фильтр
        setTimeout(filterPackets, 100);   // применить фильтр после загрузки
    }
});