
# OSINT Tool

This OSINT (Open Source Intelligence) tool provides a range of reconnaissance functionalities including DNS lookups, WHOIS lookups, IP geolocation, email harvesting, subdomain enumeration, Nmap scanning, and more.

## Prerequisites

Before setting up the tool, ensure that the following prerequisites are met:

1. **Python 3.8 or later**: The tool is developed in Python, so make sure you have Python installed.
2. **MariaDB**: A relational database management system to store and manage data.
3. **Additional Tools**: Several command-line tools and libraries are used for various functionalities (e.g., `theHarvester`, `sublist3r`, `wafw00f`, `whatweb`).
4. **Required Python Packages**: Libraries needed for the Flask web application and data processing.

## Installation Steps

### 1. Clone the Repository

Clone the repository to your local machine using:

```bash
git clone https://github.com/yourusername/your-repo-name.git
cd your-repo-name
```

### 2. Set Up a Virtual Environment

It's recommended to use a virtual environment to manage dependencies:

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
```

### 3. Install Required Python Packages

Install the necessary Python packages using `pip`:

```bash
pip install -r requirements.txt
```

**Note:** If `requirements.txt` does not exist, you can create it with:

```bash
pip freeze > requirements.txt
```

### 4. Install System Dependencies

You need to install some system dependencies and tools:

- **MariaDB**: Follow the installation instructions for your operating system on the [MariaDB official website](https://mariadb.org/download/).

- **Additional Tools**: Install the following tools via your package manager or from their official sources:

  ```bash
  sudo apt-get install theharvester sublist3r wafw00f whatweb
  ```

  On macOS, you can use Homebrew:

  ```bash
  brew install theharvester sublist3r wafw00f whatweb
  ```

### 5. Set Up MariaDB

#### Create Databases

Log in to MariaDB and create the required databases:

```sql
CREATE DATABASE Tooling_DB;
CREATE DATABASE recon_DB;
CREATE DATABASE sensor_DB;
```

#### Create Tables

Execute the following SQL scripts to create tables in the respective databases. You can use a MariaDB client or a tool like phpMyAdmin.

**Tooling_DB:**

```sql
CREATE TABLE IF NOT EXISTS whatweb_results (
    id INT AUTO_INCREMENT PRIMARY KEY,
    url VARCHAR(255),
    result TEXT,
    scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS dns_records (
    id INT AUTO_INCREMENT PRIMARY KEY,
    domain VARCHAR(255),
    record_type VARCHAR(10),
    record_value TEXT
);
CREATE TABLE IF NOT EXISTS nmap_results (
    id INT AUTO_INCREMENT PRIMARY KEY,
    target_ip VARCHAR(255),
    port INT,
    state VARCHAR(255)
);
```

**recon_DB:**

```sql
CREATE TABLE IF NOT EXISTS dns_info (
    id INT AUTO_INCREMENT PRIMARY KEY,
    target VARCHAR(255),
    a_records TEXT
);
CREATE TABLE IF NOT EXISTS whois_info (
    id INT AUTO_INCREMENT PRIMARY KEY,
    target VARCHAR(255),
    domain VARCHAR(255),
    registrar VARCHAR(255),
    creation_date DATETIME,
    expiration_date DATETIME,
    registrant_name VARCHAR(255),
    registrant_email TEXT
);
CREATE TABLE IF NOT EXISTS emails (
    id INT AUTO_INCREMENT PRIMARY KEY,
    target VARCHAR(255),
    email VARCHAR(255)
);
CREATE TABLE IF NOT EXISTS subdomains (
    id INT AUTO_INCREMENT PRIMARY KEY,
    target VARCHAR(255),
    subdomain VARCHAR(255)
);
```

**sensor_DB:**

```sql
CREATE TABLE IF NOT EXISTS sensor_data (
    id INT AUTO_INCREMENT PRIMARY KEY,
    temperature FLOAT,
    humidity FLOAT,
    air_quality FLOAT,
    distance FLOAT
);
```

### 6. Configure Database Credentials

Update the database credentials in the code to match your MariaDB setup. Replace placeholders in your Python code with your actual database credentials.

### 7. Run the Application

Start the Flask application with:

```bash
python app.py
```

By default, the application will be available at `http://127.0.0.1:5000/`.

### 8. Access the Tool

Open your web browser and navigate to `http://127.0.0.1:5000/` to start using the OSINT tool.

## Troubleshooting

- **Database Connection Issues**: Ensure that MariaDB is running and that the credentials in the code are correct.
- **Missing Tools**: Ensure all external tools (e.g., `theHarvester`, `sublist3r`) are installed and available in your PATH.
- **Dependency Issues**: If you encounter issues with Python packages, ensure you are using the correct versions and that all dependencies are installed.

## Contributing

Contributions are welcome! If you'd like to contribute, please submit a pull request or open an issue on the GitHub repository.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

This README provides a step-by-step guide for setting up and running your OSINT tool. Adjust the instructions according to any specific configurations or requirements of your tool.
