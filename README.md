# JA4/JA4S Fingerprinting Tool

This project is a Go-based implementation for generating JA4 and JA4S fingerprints from TLS Client Hello and Server Hello messages. The implementation is inspired by the specifications outlined in [this blog post](https://blog.foxio.io/), and the provided Wireshark traces are currently used to manually test the code.

## Motivation

I started this project because there wasn't an existing Go library that could:
1. Accurately parse JA4 and JA4S fingerprints.
2. Handle real traffic effectively, especially in scenarios involving TCP segmentation.

This tool addresses those gaps by using `gopacket` for packet capture and reassembly, ensuring accurate handling of fragmented traffic and generating fingerprints based on TLS handshake data.

## Features

- **TLS Fingerprinting**: Generates JA4 (Client Hello) and JA4S (Server Hello) fingerprints for identifying TLS configurations.
- **TCP Reassembly**: Handles TCP segmentation to capture and reassemble fragmented packets.
- **Protocol Support**: Currently supports only the TCP protocol.

## Project Status

This is an **early-stage project**. More work is needed, including:
- Project restructuring for better maintainability.
- Unit tests and integration tests to ensure reliability and correctness.
- Enhanced automation for testing with real-world traffic.

## Requirements

- Go 1.18 or later
- Administrative privileges (for live packet capture)
- A network interface capable of capturing traffic (e.g., `enp0s3`)

## Installation

```bash
git clone https://github.com/voukatas/go-ja4.git
cd go-ja4

go mod tidy
go build -o ja4tool

```

## Usage

Update the network interface in the code (enp0s3) to match your system.

```bash
sudo ./ja4tool

```
## Testing

Currently, Wireshark traces from the [FoxIO blog](https://blog.foxio.io/) are used to manually test the tool. Integration with automated testing is a planned enhancement.


## Limitations
- Only the TCP protocol is supported.
- No support for QUIC/UDP traffic (future scope).
- Automated testing and benchmarking are not yet implemented.

## To-Do
- Restructure the project for better modularity.
- Add unit and integration tests.
- Extend support for QUIC/UDP traffic.
- Automate testing with real-world traffic captures.

