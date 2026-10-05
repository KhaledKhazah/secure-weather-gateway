const sensorContainer =
    document.getElementById("sensor-container");

const sensorCount =
    document.getElementById("sensor-count");

const latestSequence =
    document.getElementById("latest-sequence");

const systemStatus =
    document.getElementById("system-status");


async function loadStatus() {
    try {
        const response =
            await fetch("/api/status");

        const data =
            await response.json();

        systemStatus.textContent =
            data.status;

        sensorCount.textContent =
            data.sensors;

    } catch (error) {
        systemStatus.textContent =
            "Offline";
    }
}


async function loadSensors() {
    try {
        const response =
            await fetch("/api/sensors");

        const sensors =
            await response.json();

        if (sensors.length === 0) {
            sensorContainer.innerHTML =
                `
                <p class="empty-message">
                    Waiting for sensor data...
                </p>
                `;

            latestSequence.textContent = "-";

            return;
        }

        sensorContainer.innerHTML = "";

        let highestSequence = 0;

        sensors.forEach(sensor => {

            if (
                sensor.sequence_number
                > highestSequence
            ) {
                highestSequence =
                    sensor.sequence_number;
            }

            const card =
                document.createElement("div");

            card.className =
                "sensor-card";

            card.innerHTML = `
                <h3>Sensor ${sensor.uid}</h3>

                <div class="sensor-row">
                    <span>Temperature</span>
                    <strong>
                        ${sensor.temperature} °C
                    </strong>
                </div>

                <div class="sensor-row">
                    <span>Humidity</span>
                    <strong>
                        ${sensor.humidity} %
                    </strong>
                </div>

                <div class="sensor-row">
                    <span>Wind Speed</span>
                    <strong>
                        ${sensor.wind_speed} km/h
                    </strong>
                </div>

                <div class="sensor-row">
                    <span>Sequence</span>
                    <strong>
                        ${sensor.sequence_number}
                    </strong>
                </div>

                <div class="sensor-row">
                    <span>Source Port</span>
                    <strong>
                        ${sensor.source_port}
                    </strong>
                </div>

                <span class="sensor-status">
                    HMAC VERIFIED
                </span>
            `;

            sensorContainer.appendChild(card);
        });

        latestSequence.textContent =
            highestSequence;

    } catch (error) {
        console.error(
            "Could not load sensor data:",
            error
        );
    }
}


async function updateDashboard() {
    await loadStatus();
    await loadSensors();
}


updateDashboard();

setInterval(
    updateDashboard,
    1000
);