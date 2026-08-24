ALTER TABLE users 
ADD COLUMN subscription_status VARCHAR(20) DEFAULT 'free' NOT NULL,
ADD COLUMN subscription_expiry TIMESTAMP;
