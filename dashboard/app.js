const sensorContainer =
    document.getElementById(
        "sensor-container"
    );


const securityEventsContainer =
    document.getElementById(
        "security-events"
    );


const sensorCount =
    document.getElementById(
        "sensor-count"
    );


const validPackets =
    document.getElementById(
        "valid-packets"
    );


const blockedPackets =
    document.getElementById(
        "blocked-packets"
    );


const latestSequence =
    document.getElementById(
        "latest-sequence"
    );


const systemStatus =
    document.getElementById(
        "system-status"
    );


// =================================
// STATUS
// =================================

async function loadStatus() {

    try {

        const response =
            await fetch(
                "/api/status"
            );


        const data =
            await response.json();


        systemStatus.textContent =
            data.status;


        sensorCount.textContent =
            data.sensors;


        validPackets.textContent =
            data.valid_packets;


        blockedPackets.textContent =
            data.blocked_packets;

    }

    catch (error) {

        systemStatus.textContent =
            "Offline";


        console.error(
            "Could not load status:",
            error
        );
    }
}


// =================================
// SENSOR DATA
// =================================

async function loadSensors() {

    try {

        const response =
            await fetch(
                "/api/sensors"
            );


        const sensors =
            await response.json();


        if (
            sensors.length === 0
        ) {

            sensorContainer.innerHTML =
                `
                <p class="empty-message">
                    Waiting for sensor data...
                </p>
                `;


            latestSequence.textContent =
                "-";


            return;
        }


        sensorContainer.innerHTML =
            "";


        let highestSequence = 0;


        sensors.forEach(
            sensor => {

                if (
                    sensor.sequence_number
                    > highestSequence
                ) {

                    highestSequence =
                        sensor.sequence_number;
                }


                const card =
                    document.createElement(
                        "div"
                    );


                card.className =
                    "sensor-card";


                card.innerHTML = `

                    <h3>
                        Sensor ${sensor.uid}
                    </h3>


                    <div class="sensor-row">

                        <span>
                            Temperature
                        </span>

                        <strong>
                            ${sensor.temperature} °C
                        </strong>

                    </div>


                    <div class="sensor-row">

                        <span>
                            Humidity
                        </span>

                        <strong>
                            ${sensor.humidity} %
                        </strong>

                    </div>


                    <div class="sensor-row">

                        <span>
                            Wind Speed
                        </span>

                        <strong>
                            ${sensor.wind_speed} km/h
                        </strong>

                    </div>


                    <div class="sensor-row">

                        <span>
                            Sequence
                        </span>

                        <strong>
                            ${sensor.sequence_number}
                        </strong>

                    </div>


                    <div class="sensor-row">

                        <span>
                            Source Port
                        </span>

                        <strong>
                            ${sensor.source_port}
                        </strong>

                    </div>


                    <span class="sensor-status">
                        HMAC VERIFIED
                    </span>

                `;


                sensorContainer.appendChild(
                    card
                );
            }
        );


        latestSequence.textContent =
            highestSequence;

    }

    catch (error) {

        console.error(
            "Could not load sensor data:",
            error
        );
    }
}


// =================================
// SECURITY EVENTS
// =================================

async function loadSecurityEvents() {

    try {

        const response =
            await fetch(
                "/api/security-events"
            );


        const events =
            await response.json();


        if (
            events.length === 0
        ) {

            securityEventsContainer.innerHTML =
                `
                <p class="empty-message">
                    No security events detected.
                </p>
                `;


            return;
        }


        securityEventsContainer.innerHTML =
            "";


        events.forEach(
            event => {


                const eventElement =
                    document.createElement(
                        "div"
                    );


                const isVerified =
                    (
                        event.type
                        === "hmac_verified"
                    );


                if (isVerified) {

                    eventElement.className =
                        (
                            "security-event "
                            + "verified-event"
                        );

                }

                else {

                    eventElement.className =
                        (
                            "security-event "
                            + "blocked-event"
                        );
                }


                eventElement.innerHTML = `

                    <div>

                        <p class="
                            event-title
                            ${
                                isVerified
                                    ? "verified-title"
                                    : "blocked-title"
                            }
                        ">

                            ${
                                isVerified
                                    ? "✓ HMAC VERIFIED"
                                    : "⚠ INVALID HMAC"
                            }

                        </p>


                        <p class="event-details">

                            Sensor ${event.uid}

                            · Sequence
                            ${event.sequence_number}

                            · Port
                            ${event.source_port}

                        </p>

                    </div>


                    <span class="
                        ${
                            isVerified
                                ? "verified-badge"
                                : "blocked-badge"
                        }
                    ">

                        ${
                            isVerified
                                ? "VERIFIED"
                                : "BLOCKED"
                        }

                    </span>

                `;


                securityEventsContainer
                    .appendChild(
                        eventElement
                    );

            }
        );

    }

    catch (error) {

        console.error(
            "Could not load security events:",
            error
        );
    }
}


// =================================
// DASHBOARD UPDATE
// =================================

async function updateDashboard() {

    await Promise.all([
        loadStatus(),
        loadSensors(),
        loadSecurityEvents()
    ]);
}


updateDashboard();


setInterval(
    updateDashboard,
    1000
);