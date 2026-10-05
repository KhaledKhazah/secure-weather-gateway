# Secure Weather Gateway

A network security project that validates UDP sensor data using HMAC and SHA-256 and visualizes the results in a live web dashboard.


---

## Overview

The system simulates multiple weather sensors that transmit data using UDP.

Each sensor sends:

- Sensor UID
- Sequence number
- Temperature
- Humidity
- Wind speed
- Source port
- HMAC

The Security Warden verifies the integrity of every incoming packet.

Valid packets are forwarded to the collector, while packets with an invalid HMAC are blocked and reported as security events.

---

## Architecture


                     UDP + HMAC
Sensor Simulator --------------------+
                                      |
                                      v
                            +-------------------+
                            |  Security Warden  |
                            |   HMAC Check      |
                            +---------+---------+
                                      |
                     +----------------+----------------+
                     |                                 |
              Valid HMAC                        Invalid HMAC
                     |                                 |
                     v                                 v
              UDP Port 4811                     UDP Port 4812
                     |                                 |
                     +---------------+-----------------+
                                     |
                                     v
                            +------------------+
                            |    Collector     |
                            |    Flask API     |
                            +--------+---------+
                                     |
                                     | HTTP / JSON
                                     v
                            +------------------+
                            |  Web Dashboard   |
                            +------------------+


---

## Features

- UDP-based sensor communication
- HMAC integrity verification
- Detection of manipulated sensor packets
- Multi-sensor simulation
- Simulation of malicious sensors / bad actors
- Separation of verified data and security events
- Live packet statistics
- REST API using Flask
- Live web dashboard
- Green HMAC verification events
- Red blocked HMAC events
- Graceful shutdown of simulated sensor threads

---

## Technologies

### Backend

- Python
- Flask
- UDP sockets
- Threading
- JSON
- REST API

### Security / Networking

- HMAC
- SHA-256
- UDP
- Packet serialization with `struct`
- Network byte order
- Integrity verification

### Frontend

- HTML
- CSS
- JavaScript
- Fetch API

### Development

- Git
- GitHub
- Python Virtual Environment

---

## Live Dashboard

The dashboard displays verified sensor data and security events in real time.

![Secure Weather Gateway Dashboard](screenshots/dashboard.png)

Green events represent successfully verified HMAC values.

Red events represent manipulated packets that failed integrity verification and were blocked by the Security Warden.

---

## Installation

### 1. Clone the repository


git clone https://github.com/KhaledKhazah/secure-weather-gateway.git
cd secure-weather-gateway


### 2. Create a virtual environment

Windows:


python -m venv .venv


Activate it:


.\.venv\Scripts\Activate.ps1


Linux:


python3 -m venv .venv
source .venv/bin/activate


### 3. Install dependencies


python -m pip install -r requirements.txt


---

## Running the Project

The project uses three components.

### 1. Start the Collector and Web API


python collector/collector_server.py


The dashboard will be available at:


http://127.0.0.1:8000


### 2. Start the Security Warden

Open another terminal:


python warden/weather_warden.py


### 3. Start the Sensor Simulator

For example, start five sensors with two simulated bad actors:


python simulator/sensor_simulator.py --sensors 5 --bad-actors 2


This creates:


Sensor 0 -> VERIFIED
Sensor 1 -> VERIFIED
Sensor 2 -> VERIFIED
Sensor 3 -> BAD ACTOR
Sensor 4 -> BAD ACTOR


---

## REST API

The collector provides several API endpoints.

### Sensor data


GET /api/sensors


Returns the latest verified data for each sensor.

### System status


GET /api/status


Returns statistics including:

- Verified sensors
- Valid packets
- Blocked packets

### Security events


GET /api/security-events


Returns the latest HMAC verification and blocking events.

---

## Security Flow

For every incoming sensor packet, the Security Warden separates the sensor data from the transmitted HMAC.

It calculates the expected HMAC and compares both values.


Received HMAC == Calculated HMAC
            |
            +---- YES ---> VERIFIED ---> Forward packet
            |
            +---- NO ----> BLOCKED ----> Security event


Manipulated sensor data is never forwarded to the normal collector.

---

## Background

The original `weather_warden.py` was developed as part of an IT and Network Security university exercise.

The goal of the original exercise was to verify the integrity of UDP sensor messages using HMAC and only forward messages with a valid integrity check.

For this portfolio project, the original implementation was extended with:

- A custom sensor simulator
- Multi-sensor support
- Bad actor simulation
- A custom collector server
- Security event monitoring
- A Flask REST API
- A live web dashboard
- Live visualization of verified and blocked packets
- Git and GitHub project structure

The provided university client and server executables are not included in this repository.

---

## Author

Khaled Khazah

Computer Science Student  
University of Osnabrück