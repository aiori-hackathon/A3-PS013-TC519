
CREATE DATABASE IF NOT EXISTS cybertrace
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;


USE cybertrace;


SELECT 
    SCHEMA_NAME AS database_name,
    DEFAULT_CHARACTER_SET_NAME AS character_set,
    DEFAULT_COLLATION_NAME AS collation_name
FROM information_schema.SCHEMATA
WHERE SCHEMA_NAME = 'cybertrace';
