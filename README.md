# Link Scanner – Chrome Extension

## Overview

This repository contains a personal Chrome extension project focused on identifying and assessing potentially unsafe URLs before user interaction.

The extension combines local URL sanitization with optional reputation checks via the VirusTotal API, allowing users to evaluate links using their own API key. The project explores practical browser-side security concepts while respecting user privacy and API ownership.

## Purpose

Users frequently encounter unknown or shortened links through email, messaging platforms, and the web. This project examines how client-side validation and third-party reputation data can be combined to provide lightweight link risk awareness before navigation.

### Primary goals

- Practice secure handling of untrusted input in a browser context
- Integrate a real-world security API responsibly
- Design logic that is transparent, minimal, and user-controlled

## Core Functionality

- Accepts user-provided URLs for inspection
- Sanitizes and normalizes URLs before processing
- Blocks or flags unsafe or malformed URL schemes
- Queries the VirusTotal API for reputation data
- Requires users to supply and manage their own API key
- Runs entirely client-side with no backend services

## Technical Highlights

- JavaScript (ES6+)
- Chrome Extension APIs
- URL parsing and normalization
- VirusTotal REST API integration
- Defensive checks beyond basic string matching
- Unit-tested URL sanitization logic

The design intentionally avoids naïve approaches (e.g., simple prefix checks) and instead uses structured URL parsing combined with external reputation signals.

## API Key Handling

- The extension does not ship with an API key
- Users provide their own VirusTotal API key
- No keys or scan results are transmitted to any backend
- API usage and limits are fully controlled by the user

This approach was chosen to avoid shared credentials, reduce privacy concerns, and mirror real-world security tooling practices.

## Testing

Core sanitization logic is covered by unit tests to validate behavior across:

- Valid URLs
- Malformed input
- Unsafe or unsupported schemes

API interactions are intentionally kept modular to simplify testing and auditing.

## Scope & Design Choices

This project is intentionally scoped:

- No backend infrastructure
- No persistent data storage
- No automated blocking claims

It is designed as a learning-focused security utility, not a production-grade threat prevention system.

## Motivation

Built as a personal project to deepen hands-on understanding of:

- Browser security considerations
- Responsible third-party API usage
- Input validation and defensive programming
- Writing readable, auditable security-related code
