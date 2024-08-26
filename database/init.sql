ALTER USER 'root'@'localhost' IDENTIFIED BY 'YourStrong!Passw0rd';

CREATE SCHEMA if not exists CommunicationLTD;

CREATE USER IF NOT EXISTS 'sa'@'%' IDENTIFIED BY 'YourStrong@Passw0rd';
GRANT SELECT, INSERT, UPDATE ON CommunicationLTD.* TO 'sa'@'%';

CREATE USER IF NOT EXISTS 'sa'@'localhost' IDENTIFIED BY 'YourStrong@Passw0rd';

-- Grant privileges to the user
GRANT SELECT, INSERT, UPDATE ON CommunicationLTD.* TO 'sa'@'localhost';


-- Use the created database
USE CommunicationLTD;

-- Create the regions table
CREATE TABLE IF NOT EXISTS regions (
    region_id INT AUTO_INCREMENT PRIMARY KEY,
    region_name VARCHAR(255) NOT NULL
);

-- Create the internet_packages table
CREATE TABLE IF NOT EXISTS internet_packages (
    package_name VARCHAR(255) NOT NULL PRIMARY KEY,
    speed VARCHAR(50) NOT NULL,
    price DECIMAL(10, 2) NOT NULL,
    details TEXT
);

-- Create the users table
CREATE TABLE IF NOT EXISTS users (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    reset_token VARCHAR(200)
);

-- Create the customers table
CREATE TABLE IF NOT EXISTS customers (
    customer_id INT AUTO_INCREMENT PRIMARY KEY,
    agent_id INT,
    package_name VARCHAR(255),
    ssn VARCHAR(11),
    first_name VARCHAR(255) NOT NULL,
    last_name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    phone VARCHAR(50) NOT NULL,
    address VARCHAR(255),
    region_id INT,
    FOREIGN KEY (agent_id) REFERENCES users(user_id),
    FOREIGN KEY (region_id) REFERENCES regions(region_id),
    FOREIGN KEY (package_name) REFERENCES internet_packages(package_name)
);

-- Create the password_history table
CREATE TABLE IF NOT EXISTS password_history (
    history_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    password VARCHAR(255) NOT NULL,
    salt VARCHAR(64),
    changed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

-- Create the user_regions table
CREATE TABLE IF NOT EXISTS user_regions (
    user_id INT,
    region_id INT,
    PRIMARY KEY (user_id, region_id),
    FOREIGN KEY (user_id) REFERENCES users(user_id),
    FOREIGN KEY (region_id) REFERENCES regions(region_id)
);

-- Create the user_info table
CREATE TABLE IF NOT EXISTS user_info (
    user_id INT PRIMARY KEY,
    salt VARCHAR(64),
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);
-- Drop the view if it exists
DROP VIEW IF EXISTS customer_view;

-- Create the customer_view view
CREATE VIEW customer_view AS
SELECT
    c.customer_id,
    c.agent_id ,
    c.package_name as package,
    c.ssn,
    c.first_name,
    c.last_name,
    c.email,
    c.phone,
    c.address,
    r.region_name
FROM
    customers c
JOIN
    regions r ON c.region_id = r.region_id;

delete from regions;
-- Insert initial data into regions table
INSERT INTO regions (region_name) VALUES
    ('North America'),
    ('South America'),
    ('Europe'),
    ('Asia Pacific'),
    ('Middle East'),
    ('Africa'),
    ('Australia');

delete from internet_packages;
-- Insert initial data into internet_packages table
INSERT INTO internet_packages (package_name, speed, price, details) VALUES
    ('Free', '1 Mbps', 0.00, 'Basic internet package with minimal speed.'),
    ('Common', '10 Mbps', 10.00, 'Standard internet package suitable for basic browsing and streaming.'),
    ('Rare', '50 Mbps', 25.00, 'Enhanced internet package for high-speed browsing and HD streaming.'),
    ('Epic', '100 Mbps', 50.00, 'Premium internet package for heavy usage and multiple devices.'),
    ('Legendary', '1 Gbps', 100.00, 'Ultimate internet package with top-tier speed and unlimited data.');
