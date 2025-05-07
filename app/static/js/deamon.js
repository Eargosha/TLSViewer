const interfaceSelect = document.getElementById('interface-select');
const daemonButton = document.getElementById('start-daemon-btn');
const daemonStatus = document.getElementById('daemon-status');

let isDaemonRunning = false;

function updateDaemonUI(running, pid = null) {
    isDaemonRunning = running;
    if (running) {
        daemonButton.disabled = true;
        daemonStatus.innerHTML = `Статус: Запущен <span class="badge bg-primary">PID: ${pid}</span>`;
    } else {
        daemonButton.disabled = false;
        daemonButton.textContent = "Запустить демон";
        daemonButton.className = "btn btn-success w-100";
        daemonStatus.textContent = "Статус: Не запущен";
    }
}

// Получаем список интерфейсов
socket.emit("get_interfaces");

// Обрабатываем полученный список
socket.on("interface_list", function(data) {
    const interfaces = data.interfaces;
    const displays = data.display;
    interfaceSelect.innerHTML = "";

    if (!interfaces.length) {
        const option = document.createElement("option");
        option.value = "";
        option.text = "Нет доступных интерфейсов";
        interfaceSelect.appendChild(option);
        return;
    }

    for (let i = 0; i < interfaces.length; i++) {
        const option = document.createElement("option");
        option.value = interfaces[i];
        option.text = displays[i];
        interfaceSelect.appendChild(option);
    }
});

// // Кнопка запуска/остановки
// daemonButton.addEventListener("click", function () {
//     if (!isDaemonRunning) {
//         const selectedIface = interfaceSelect.value;
//         if (!selectedIface) {
//             alert("Пожалуйста, выберите сетевой интерфейс!");
//             return;
//         }
//         socket.emit("start_daemon", { interface: selectedIface });
//     } else {
//         socket.emit("stop_daemon");
//     }
// });

// Обработка ответов от сервера
socket.on("system_message", function (data) {
    if (data.type === 'info' && data.message.includes("Daemon запущен")) {
        const pidMatch = data.message.match(/PID: (\d+)/);
        if (pidMatch && pidMatch[1]) {
            updateDaemonUI(true, pidMatch[1]);
        }
    } else if (data.type === 'info' && data.message === 'Daemon успешно остановлен') {
        updateDaemonUI(false);
    } else if (data.type === 'info' && data.message === 'Daemon не запущен') {
        updateDaemonUI(false);
    }
});

// Обработка переключателя режима
const modeAll = document.getElementById("modeAll");
const modeURL = document.getElementById("modeURL");
const urlInputContainer = document.getElementById("urlInputContainer");
const urlInput = document.getElementById("urlInput");

document.querySelectorAll('input[name="analysisMode"]').forEach((radio) => {
    radio.addEventListener("change", function () {
        urlInputContainer.style.display = modeURL.checked ? "block" : "none";
    });
});

// Кнопка запуска/остановки
daemonButton.addEventListener("click", function () {
    if (!isDaemonRunning) {
        const selectedIface = interfaceSelect.value;
        if (!selectedIface) {
            alert("Пожалуйста, выберите сетевой интерфейс!");
            return;
        }

        const mode = document.querySelector('input[name="analysisMode"]:checked').value;
        const url = mode === "url" ? urlInput.value.trim() : "";

        console.log(mode)

        socket.emit("start_daemon", { interface: selectedIface, mode: mode, url: url });
    } else {
        socket.emit("stop_daemon");
    }
});