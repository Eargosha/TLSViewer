
// диаграммы
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