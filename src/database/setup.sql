-- Security Monitoring Dashboard Database Setup Script
-- Run this script to create the database and initial configuration

USE master;
GO

-- Create database if it doesn't exist
IF NOT EXISTS (SELECT name FROM sys.databases WHERE name = 'SecurityMonitoring')
BEGIN
    CREATE DATABASE SecurityMonitoring;
END
GO

USE SecurityMonitoring;
GO

-- Create login and user for the application
IF NOT EXISTS (SELECT name FROM sys.server_principals WHERE name = 'security_monitor_app')
BEGIN
    CREATE LOGIN security_monitor_app WITH PASSWORD = 'SecureP@ssw0rd123!';
END
GO

IF NOT EXISTS (SELECT name FROM sys.database_principals WHERE name = 'security_monitor_app')
BEGIN
    CREATE USER security_monitor_app FOR LOGIN security_monitor_app;
    ALTER ROLE db_datareader ADD MEMBER security_monitor_app;
    ALTER ROLE db_datawriter ADD MEMBER security_monitor_app;
    ALTER ROLE db_ddladmin ADD MEMBER security_monitor_app;
END
GO

-- Create file groups for partitioning (optional for large deployments)
IF NOT EXISTS (SELECT name FROM sys.filegroups WHERE name = 'EVENTS_FG')
BEGIN
    ALTER DATABASE SecurityMonitoring ADD FILEGROUP EVENTS_FG;
    ALTER DATABASE SecurityMonitoring 
    ADD FILE (
        NAME = 'SecurityEvents_Data',
        FILENAME = 'C:\Program Files\Microsoft SQL Server\MSSQL15.SQLEXPRESS\MSSQL\DATA\SecurityEvents.ndf',
        SIZE = 100MB,
        FILEGROWTH = 10MB
    ) TO FILEGROUP EVENTS_FG;
END
GO

-- Create partition function for date-based partitioning
IF NOT EXISTS (SELECT name FROM sys.partition_functions WHERE name = 'DatePartitionFunction')
BEGIN
    CREATE PARTITION FUNCTION DatePartitionFunction (datetime)
    AS RANGE RIGHT FOR VALUES (
        '2024-01-01', '2024-02-01', '2024-03-01', '2024-04-01',
        '2024-05-01', '2024-06-01', '2024-07-01', '2024-08-01',
        '2024-09-01', '2024-10-01', '2024-11-01', '2024-12-01',
        '2025-01-01'
    );
END
GO

-- Create partition scheme
IF NOT EXISTS (SELECT name FROM sys.partition_schemes WHERE name = 'DatePartitionScheme')
BEGIN
    CREATE PARTITION SCHEME DatePartitionScheme
    AS PARTITION DatePartitionFunction
    ALL TO (EVENTS_FG);
END
GO