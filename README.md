
# Chat Application with Network Traffic Analysis

A **Tkinter-based client-server chat application** enhanced with a **network traffic analyzer** to monitor and secure communications. The system supports user authentication, real-time messaging, file sharing, and database inspection.

---

## 🛠️ Setup Instructions

### 1. Clone the Repository

Clone the repository to your local machine:

```bash
git clone: "https://github.com/ARYAAKSHATH/COMPUTER-NETWORKS-PROJECT.git"
cd COMPUTER-NETWORKS-PROJECT

````

### 2. Create and Activate Virtual Environment

#### Create the virtual environment:

```bash
python -m venv venv
```

#### Activate the virtual environment:

* **On Windows**:

  ```bash
  venv\Scripts\activate
  ```

* **On macOS/Linux**:

  ```bash
  source venv/bin/activate
  ```

### 3. Install Required Dependencies

Install the necessary Python libraries:

```bash
pip install scapy matplotlib seaborn pandas plotly
```

---

## 📁 File Descriptions and Execution

### `check_db.py`

* **Description**: Utility script to inspect the `chat.db` SQLite database. Displays:

  * Available tables
  * Number of users
  * Recent messages

* **Run Command**:

  ```bash
  python check_db.py
  ```

---

### `client_messaging.py`

* **Description**: Implements a **Tkinter-based chat client** with the following features:

  * User registration & login
  * Real-time messaging
  * File sharing with the server

* **Run Command**:

  ```bash
  python client_messaging.py
  ```

---

### `message_server.py`

* **Description**: A **socket-based server** that handles:

  * User registration & authentication
  * Message and file transfers
  * SQLite-based message and user storage

* **Run Command**:

  ```bash
  python message_server.py
  ```

---

### `config.py`

* **Description**: Contains global **configuration settings** used across the application:

  * Server host and port
  * File size limits
  * Directory paths

* **Run Command**: This file is **not run directly**; it is **imported by** `message_server.py` and `client_messaging.py`.


