-- Create fruit registration table
CREATE TABLE IF NOT EXISTS fruit (
    id VARCHAR(50) PRIMARY KEY,
    registration_date DATE NOT NULL,
    fruit_name VARCHAR(100) NOT NULL,
    variety VARCHAR(100),
    farm_size DECIMAL(10,2) NOT NULL COMMENT 'Size in acres',
    farm_location VARCHAR(200) NOT NULL,
    soil_type VARCHAR(50),
    irrigation_type VARCHAR(50),
    annual_production DECIMAL(10,2) COMMENT 'Production in tons',
    certification_type VARCHAR(100),
    owner_name VARCHAR(100) NOT NULL,
    owner_contact VARCHAR(15) NOT NULL,
    registration_authority VARCHAR(100) NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    -- Add indexes for frequently searched columns
    INDEX idx_fruit_name (fruit_name),
    INDEX idx_location (farm_location),
    INDEX idx_owner (owner_name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Insert some sample data
INSERT INTO fruit (id, registration_date, fruit_name, variety, farm_size, farm_location, 
                  soil_type, irrigation_type, annual_production, certification_type, 
                  owner_name, owner_contact, registration_authority) 
VALUES 
    ('FID001', '2023-01-15', 'Mango', 'Alphonso', 5.5, 'Ratnagiri, Maharashtra', 
     'Laterite', 'Drip', 12.5, 'Organic', 'Rajesh Patil', '9876543210', 'Maharashtra Agriculture Board'),
    ('FID002', '2023-02-20', 'Apple', 'Shimla', 3.2, 'Kullu, Himachal Pradesh', 
     'Loamy', 'Sprinkler', 8.0, 'GI Certified', 'Suresh Kumar', '9876543211', 'HP Horticulture Board'),
    ('FID003', '2023-03-10', 'Grape', 'Thompson Seedless', 4.0, 'Nashik, Maharashtra', 
     'Black', 'Drip', 15.0, 'GMP Certified', 'Amit Deshmukh', '9876543212', 'Maharashtra Agriculture Board');

-- Create a trigger to update the updated_at timestamp
DELIMITER //
CREATE TRIGGER fruit_update_timestamp
BEFORE UPDATE ON fruit
FOR EACH ROW
BEGIN
    SET NEW.updated_at = CURRENT_TIMESTAMP;
END;//
DELIMITER ;
