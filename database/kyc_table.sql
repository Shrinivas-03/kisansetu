-- Create KYC table
CREATE TABLE IF NOT EXISTS kyc (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    fruit_id VARCHAR(50) NOT NULL,
    city VARCHAR(100) NOT NULL,
    state VARCHAR(100) NOT NULL,
    country VARCHAR(100) NOT NULL,
    document_type ENUM('aadhar', 'pan') NOT NULL,
    document_number VARCHAR(20) NOT NULL,
    document_image VARCHAR(255) NOT NULL,
    status ENUM('pending', 'approved', 'rejected') DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES user(id),
    UNIQUE KEY unique_user (user_id),
    UNIQUE KEY unique_document (document_type, document_number)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Create index for faster lookups
CREATE INDEX idx_kyc_status ON kyc(status);
CREATE INDEX idx_kyc_user ON kyc(user_id);
