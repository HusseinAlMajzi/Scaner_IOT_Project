#!/bin/bash

# IoT Security Scanner - PostgreSQL Setup Script
# This script sets up PostgreSQL database for the project

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}    IoT Security Scanner - PostgreSQL Database Setup${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo ""

# Database configuration (change these if needed)
DB_NAME="iot_scanner_db"
DB_USER="hussein"
DB_PASSWORD="IoT_123456"

echo -e "${YELLOW}Database Configuration:${NC}"
echo "  • Database Name: $DB_NAME"
echo "  • Username: $DB_USER"
echo "  • Password: $DB_PASSWORD"
echo ""

# Check if PostgreSQL is installed
echo -e "${BLUE}▶${NC} Checking PostgreSQL installation..."
if ! command -v psql &> /dev/null; then
    echo -e "${RED}✗${NC} PostgreSQL is not installed!"
    echo ""
    echo "Please install PostgreSQL first:"
    echo "  Ubuntu/Debian: sudo apt-get install postgresql postgresql-contrib"
    echo "  Fedora/RHEL:   sudo dnf install postgresql-server postgresql-contrib"
    echo "  macOS:         brew install postgresql"
    exit 1
else
    echo -e "${GREEN}✓${NC} PostgreSQL is installed"
fi

# Check if PostgreSQL service is running
echo -e "${BLUE}▶${NC} Checking PostgreSQL service..."
if sudo systemctl is-active --quiet postgresql; then
    echo -e "${GREEN}✓${NC} PostgreSQL service is running"
else
    echo -e "${YELLOW}⚠${NC} PostgreSQL service is not running. Starting it..."
    sudo systemctl start postgresql
    sudo systemctl enable postgresql
    echo -e "${GREEN}✓${NC} PostgreSQL service started"
fi

echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}    Creating Database and User${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo ""

# Create database and user
echo -e "${BLUE}▶${NC} Creating database and user..."
echo -e "${YELLOW}Note:${NC} You may be prompted for the PostgreSQL password"
echo ""

# Run SQL commands as postgres user
sudo -u postgres psql << EOF
-- Drop database if exists (for clean setup)
DROP DATABASE IF EXISTS $DB_NAME;

-- Drop user if exists
DROP USER IF EXISTS $DB_USER;

-- Create user
CREATE USER $DB_USER WITH PASSWORD '$DB_PASSWORD';

-- Create database
CREATE DATABASE $DB_NAME WITH OWNER $DB_USER;

-- Grant all privileges
GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;

-- Connect to the database and set permissions
\c $DB_NAME

-- Grant schema permissions
GRANT ALL ON SCHEMA public TO $DB_USER;

-- Display success message
\echo ''
\echo '✓ Database and user created successfully!'
\echo ''
EOF

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓${NC} Database setup completed successfully!"
else
    echo -e "${RED}✗${NC} Database setup failed!"
    exit 1
fi

echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}    Verifying Connection${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo ""

# Test connection
echo -e "${BLUE}▶${NC} Testing database connection..."
PGPASSWORD=$DB_PASSWORD psql -h localhost -U $DB_USER -d $DB_NAME -c "SELECT version();" > /dev/null 2>&1

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓${NC} Database connection successful!"
else
    echo -e "${RED}✗${NC} Database connection failed!"
    echo "Please check your configuration and try again."
    exit 1
fi

echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}    Configuration Summary${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo "Your PostgreSQL database is ready!"
echo ""
echo "Connection Details:"
echo "  • Host:     localhost"
echo "  • Port:     5432"
echo "  • Database: $DB_NAME"
echo "  • Username: $DB_USER"
echo "  • Password: $DB_PASSWORD"
echo ""
echo "Connection String (already in .env):"
echo "  DATABASE_URL=postgresql://$DB_USER:$DB_PASSWORD@localhost:5432/$DB_NAME"
echo ""
echo -e "${GREEN}✓ Next Steps:${NC}"
echo "  1. Make sure .env file has the correct DATABASE_URL"
echo "  2. Run: python init_db.py (to create tables)"
echo "  3. Run: python src/main.py (to start the application)"
echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
