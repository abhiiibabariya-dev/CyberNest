-- CyberNest PostgreSQL Initialization
-- Creates extensions and schema for the platform

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Separate schemas for modularity
CREATE SCHEMA IF NOT EXISTS siem;
CREATE SCHEMA IF NOT EXISTS soar;
CREATE SCHEMA IF NOT EXISTS auth;
CREATE SCHEMA IF NOT EXISTS assets;
CREATE SCHEMA IF NOT EXISTS threat_intel;
CREATE SCHEMA IF NOT EXISTS audit;
