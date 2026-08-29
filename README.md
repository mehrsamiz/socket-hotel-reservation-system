# Concurrent Multi-Threaded Hotel Reservation System

A concurrent, socket-based client-server system written in Python that provides room management, multi-user authentication, and reservation tracking over custom TCP socket abstractions. The architecture incorporates thread-safe concurrent state synchronization, cryptographic security primitives, and custom JSON payload framing.

---

## Technical Overview

The application follows a distributed client-server model over standard TCP sockets:
* **Concurrency & Synchronization:** The server handles multiple concurrent client connections using POSIX-style threading (`threading.Thread`). Mutual exclusion locks (`threading.Lock`) prevent race conditions during persistent state updates (`UsersInfo.json`, `RoomsInfo.json`).
* **Network Framing & Protocol:** Communications rely on UTF-8 encoded JSON payload messages over stream sockets. Command arguments and status codes mirror HTTP-style transaction paradigms to enforce request-response integrity.
* **Cryptographic Password Protection:** Account security utilizes PBKDF2-HMAC-SHA256 hashing with 100,000 iterations and a 16-byte random per-user salt. Plaintext passwords are never stored on disk.
* **Client-Side Log Privacy:** Sensitive payload fields (`password`, `new_password`) are redacted (`***REDACTED***`) before writing client-side event logs to disk.
* **State & Clock Persistence:** System date settings persist across application restarts (`system_state.json`), enabling auto-checkout background processing based on temporal boundaries[cite: 17, 18].

---

## Repository Architecture

```text
.
├── client.py          # Interactive CLI client with payload redaction & log handlers
├── server.py          # Multi-threaded server managing socket pools & thread safety
├── config.json        # Network socket binding metadata (Host & Port)
├── UsersInfo.json     # User registry with cryptographic hashes & purse balances
├── RoomsInfo.json     # Room inventory state matrix and user reservation rosters
├── system_state.json  # Persistent system simulation clock
└── client_logs/       # Client session audit logs (auto-generated)
```
---

## System Capabilities

### 1. Administrative Capabilities

* **System Clock Initialization:** Establishes the temporal baseline (`setTime`), triggering automated checkout evaluations for expired bookings.


* **Inventory Management:** Admin features allow dynamic room creation (`admin_add_room`), capacity/pricing adjustments (`admin_modify_room`), and room deletion (`admin_remove_room`).


* **User Oversight:** Full access to view complete user accounts and system reservation rosters.



### 2. User & Guest Features

* **Authentication:** Secure multi-stage registration (`signup`) and authentication (`signin`).


* **Room Reservation & Cost Calculation:** Room search, temporal availability validation, capacity checks, and automated cost deductions against account balances.


* **Cancellation & Partial Refund:** Booking cancellation calculations credit 50% of the total booking cost back to the user's purse.


* **Profile Management:** Dynamic editing of user contact information, addresses, and account credentials.



---

## Protocol Response Codes

The server communicates execution status back to the client via structured application response codes:

| Status Code | Description | Context |
| --- | --- | --- |
| **104** | Room Added | Successfully added a new room to inventory.|
| **105** | Room Modified | Room capacity or pricing successfully updated.|
| **106** | Room Deleted | Room successfully removed from inventory.|
| **108** | Insufficient Balance | User account purse is insufficient for booking cost.|
| **109** | Capacity Full | Room requested is occupied or lacks sufficient remaining capacity.|
| **110** | Action Successful | Booking or cancellation successfully processed.|
| **200** | OK | Standard request completion.|
| **230** | Authentication Success | User successfully logged in.|
| **231** | Registration Complete | User account registration completed.|
| **311** | Registration Step 2 | Username accepted; awaiting extended profile details.|
| **401** | Unauthorized / Format Error | Missing authentication or malformed command.|
| **403** | Permission Denied | Attempted action exceeds current role privileges.|
| **451** | Conflict | Account username already exists in registry.|
| **503** | Service Unavailable / Error | Uninitialized system clock or invalid request sequence.|

---

## Getting Started

### Prerequisites

* Python 3.8+ (Standard Library: `socket`, `threading`, `json`, `hashlib`, `os`, `datetime`).



### Configuration

Edit `config.json` to configure host IP and target command channel port:

```json
{
    "hostName": "127.0.0.1",
    "commandChannelPort": 8000
}

```

### Running the Server

Execute the server script in your terminal:

```bash
python server.py

```

### Running the Client

Launch one or more concurrent client processes in separate terminal instances:

```bash
python client.py

```

