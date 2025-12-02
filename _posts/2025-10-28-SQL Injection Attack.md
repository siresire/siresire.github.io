---
title: SQL Injection Attack
author: siresire
date: 2025-10-28 06:10:00 +0800
categories: [Seed, Web-Security]
tags: [Computer Security,XSS,JavaScript,burp]
render_with_liquid: false
---

# Basics of SQL
## Introduction to SLQ 

Logging onto the mysql and then checking the database we have 

```yaml
root@9c6e27fbb603:/# mysql -u root -p
Enter password: 
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 14
Server version: 8.0.22 MySQL Community Server - GPL

Copyright (c) 2000, 2020, Oracle and/or its affiliates. All rights reserved.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> SHOW DATABASES;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| sqllab_users       |
| sys                |
+--------------------+
5 rows in set (0.04 sec)

mysql> 

```

## Creating a database 
use the commans create database to create a new database

`mysql> CREATE DATABASE dbtest;`

## Creating tables in database 

```yaml 

mysql> use dbtest;;
Database changed
ERROR: 
No query specified

mysql> CREATE TABLE employee (
    ->     ID INT(6) NOT NULL AUTO_INCREMENT,
    ->     Name VARCHAR(30) NOT NULL,
    ->     EID VARCHAR(7) NOT NULL,
    ->     Password VARCHAR(60),
    ->     Salary INT(10),
    ->     SSN VARCHAR(11),
    ->     PRIMARY KEY (ID)
    -> );
Query OK, 0 rows affected, 2 warnings (0.13 sec)

mysql> describe employee;
+----------+-------------+------+-----+---------+----------------+
| Field    | Type        | Null | Key | Default | Extra          |
+----------+-------------+------+-----+---------+----------------+
| ID       | int         | NO   | PRI | NULL    | auto_increment |
| Name     | varchar(30) | NO   |     | NULL    |                |
| EID      | varchar(7)  | NO   |     | NULL    |                |
| Password | varchar(60) | YES  |     | NULL    |                |
| Salary   | int         | YES  |     | NULL    |                |
| SSN      | varchar(11) | YES  |     | NULL    |                |
+----------+-------------+------+-----+---------+----------------+
6 rows in set (0.03 sec)


```

## Inserting int the table Employee

```yaml
mysql> INSERT INTO employee (Name, EID, Password, Salary, SSN)
    -> VALUES ('Tom Cruz', 'EID0001', 'Paswd123', 80000, '555-55-5555');
Query OK, 1 row affected (0.12 sec)

mysql> SELECT * FROM employee;
+----+----------+---------+----------+--------+-------------+
| ID | Name     | EID     | Password | Salary | SSN         |
+----+----------+---------+----------+--------+-------------+
|  1 | Tom Cruz | EID0001 | Paswd123 |  80000 | 555-55-5555 |
+----+----------+---------+----------+--------+-------------+
1 row in set (0.02 sec)

mysql> INSERT INTO employee (Name, EID, Password, Salary, SSN)
    -> VALUES
    -> ('Alice Johnson', 'EID0002', 'Admin@123', 92000, '123-45-6789'),
    -> ('Brian Smith', 'EID0003', 'SecurePwd1', 75000, '234-56-7890'),
    -> ('Catherine Lee', 'EID0004', 'MyPass2025', 68000, '345-67-8901'),
    -> ('David Kim', 'EID0005', 'Welcome#45', 88000, '456-78-9012'),
    -> ('Ella Rodriguez', 'EID0006', 'Qwerty!90', 99000, '567-89-0123'),
    -> ('Franklin White', 'EID0007', 'Pass9876', 72000, '678-90-1234'),
    -> ('Grace Brown', 'EID0008', 'Abc123$$', 81000, '789-01-2345'),
    -> ('Henry Wilson', 'EID0009', 'SafeKey22', 94000, '890-12-3456'),
    -> ('Isabella Davis', 'EID0010', 'Pwd!1234', 87000, '901-23-4567'),
    -> ('Jack Thompson', 'EID0011', 'TopSecret', 76000, '012-34-5678');
Query OK, 10 rows affected (0.05 sec)
Records: 10  Duplicates: 0  Warnings: 0

mysql> SELECT * FROM employee;
+----+----------------+---------+------------+--------+-------------+
| ID | Name           | EID     | Password   | Salary | SSN         |
+----+----------------+---------+------------+--------+-------------+
|  1 | Tom Cruz       | EID0001 | Paswd123   |  80000 | 555-55-5555 |
|  2 | Alice Johnson  | EID0002 | Admin@123  |  92000 | 123-45-6789 |
|  3 | Brian Smith    | EID0003 | SecurePwd1 |  75000 | 234-56-7890 |
|  4 | Catherine Lee  | EID0004 | MyPass2025 |  68000 | 345-67-8901 |
|  5 | David Kim      | EID0005 | Welcome#45 |  88000 | 456-78-9012 |
|  6 | Ella Rodriguez | EID0006 | Qwerty!90  |  99000 | 567-89-0123 |
|  7 | Franklin White | EID0007 | Pass9876   |  72000 | 678-90-1234 |
|  8 | Grace Brown    | EID0008 | Abc123$$   |  81000 | 789-01-2345 |
|  9 | Henry Wilson   | EID0009 | SafeKey22  |  94000 | 890-12-3456 |
| 10 | Isabella Davis | EID0010 | Pwd!1234   |  87000 | 901-23-4567 |
| 11 | Jack Thompson  | EID0011 | TopSecret  |  76000 | 012-34-5678 |
+----+----------------+---------+------------+--------+-------------+
11 rows in set (0.00 sec)

mysql> 


```

## SELECT Statement

- The SELECT statement is the most common operation on databases
- It retrieves information from a database
- `*` Is used to ask the database for all its record including all the columns 

Or we can ask for only specific columns such as Name,EID and Salary Columns only 

```yaml 
mysql> 
mysql> SELECT Name,EID,Salary FROM employee;
+----------------+---------+--------+
| Name           | EID     | Salary |
+----------------+---------+--------+
| Tom Cruz       | EID0001 |  80000 |
| Alice Johnson  | EID0002 |  92000 |
| Brian Smith    | EID0003 |  75000 |
| Catherine Lee  | EID0004 |  68000 |
| David Kim      | EID0005 |  88000 |
| Ella Rodriguez | EID0006 |  99000 |
| Franklin White | EID0007 |  72000 |
| Grace Brown    | EID0008 |  81000 |
| Henry Wilson   | EID0009 |  94000 |
| Isabella Davis | EID0010 |  87000 |
| Jack Thompson  | EID0011 |  76000 |
+----------------+---------+--------+
11 rows in set (0.00 sec)

mysql> 

```

## WHERE Clause 
WHERE clause is used to set conditions for several types of SQL statements including SELECT, UPDATE, DELETE etc

Returning records that has EID='92000' with the command `SELECT * FROM employee WHERE EID='EID0003'`

```yaml
mysql> SELECT * FROM employee WHERE EID='EID0003';
+----+-------------+---------+------------+--------+-------------+
| ID | Name        | EID     | Password   | Salary | SSN         |
+----+-------------+---------+------------+--------+-------------+
|  3 | Brian Smith | EID0003 | SecurePwd1 |  75000 | 234-56-7890 |
+----+-------------+---------+------------+--------+-------------+
1 row in set (0.00 sec)

mysql> 

```

Returning records that satisfy either EID=76000 or Name='Grace Brown' with the command `SELECT * WHERE EID='EID0003' OR Name='Grace Brown'`

```yaml
mysql> SELECT * FROM employee WHERE EID='EID0003' or Name='Grace Brown'
    -> ;
+----+-------------+---------+------------+--------+-------------+
| ID | Name        | EID     | Password   | Salary | SSN         |
+----+-------------+---------+------------+--------+-------------+
|  3 | Brian Smith | EID0003 | SecurePwd1 |  75000 | 234-56-7890 |
|  8 | Grace Brown | EID0008 | Abc123$$   |  81000 | 789-01-2345 |
+----+-------------+---------+------------+--------+-------------+
2 rows in set (0.01 sec)

mysql> 


```

If the condition is always True, then all the rows are affected by the SQL statement

```yaml
mysql> SELECT * FROM employee WHERE 1=1;
+----+----------------+---------+------------+--------+-------------+
| ID | Name           | EID     | Password   | Salary | SSN         |
+----+----------------+---------+------------+--------+-------------+
|  1 | Tom Cruz       | EID0001 | Paswd123   |  80000 | 555-55-5555 |
|  2 | Alice Johnson  | EID0002 | Admin@123  |  92000 | 123-45-6789 |
|  3 | Brian Smith    | EID0003 | SecurePwd1 |  75000 | 234-56-7890 |
|  4 | Catherine Lee  | EID0004 | MyPass2025 |  68000 | 345-67-8901 |
|  5 | David Kim      | EID0005 | Welcome#45 |  88000 | 456-78-9012 |
|  6 | Ella Rodriguez | EID0006 | Qwerty!90  |  99000 | 567-89-0123 |
|  7 | Franklin White | EID0007 | Pass9876   |  72000 | 678-90-1234 |
|  8 | Grace Brown    | EID0008 | Abc123$$   |  81000 | 789-01-2345 |
|  9 | Henry Wilson   | EID0009 | SafeKey22  |  94000 | 890-12-3456 |
| 10 | Isabella Davis | EID0010 | Pwd!1234   |  87000 | 901-23-4567 |
| 11 | Jack Thompson  | EID0011 | TopSecret  |  76000 | 012-34-5678 |
+----+----------------+---------+------------+--------+-------------+
11 rows in set (0.01 sec)

mysql> 

```

This 1=1 predicate looks quite useless in real queries, but it will become useful in SQL Injection attacks

## UPDATE Statement
We can use the UPDATE Statement to modify an existing record using the command `UPDATE employee SET Salary=66066 WHERE Name='Tom Cruz'`

```yaml 
mysql> UPDATE employee SET Salary=66066 WHERE Name='Tom Cruz';
Query OK, 1 row affected (0.18 sec)
Rows matched: 1  Changed: 1  Warnings: 0

mysql> SELECT * FROM employee WHERE Name='Tom Cruz'
    -> ;
+----+----------+---------+----------+--------+-------------+
| ID | Name     | EID     | Password | Salary | SSN         |
+----+----------+---------+----------+--------+-------------+
|  1 | Tom Cruz | EID0001 | Paswd123 |  66066 | 555-55-5555 |
+----+----------+---------+----------+--------+-------------+
1 row in set (0.00 sec)

mysql> 

```

## Comments
MySQL supports three comment styles
Text from the # character to the end of line is treated as a comment
Text from the “--” to the end of line is treated as a comment. 
Similar to C language, text between /* and */ is treated as a comment

```yaml
mysql> SELECT * FROM employee; # This is a comment at the end line
mysql> SELECT * FROM employee; -- Comment at the end of line 
mysql> SELECT * FROM /*In-Line commet  */ employee; # This is a commend at the end line

```

# Getting Data from User 
## php 

HTML source of getting a simple login in form :

```yaml
    <form action="process_login.php" method="POST">
        <label for="username">Username:</label>
        <input type="text" id="username" name="username_field">
        <label for="password">Password:</label>
        <input type="password" id="password" name="password_field">
        <button type="submit">Login</button>
    </form>
```

When the user submits the form, the data is sent to the PHP script specified in the action attribute (e.g., process_login.php). Inside this PHP script, the submitted data is accessed using the $_POST superglobal array. The keys of this array correspond to the name attributes of the input fields in the HTML form.

```yaml
    <?php
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $username = $_POST['username_field']; // 'username_field' matches the 'name' attribute in the HTML
        $password = $_POST['password_field']; // 'password_field' matches the 'name' attribute in the HTML

        // Further processing, like validating credentials against a database
        // and establishing a user session.
    }
    ?>
```

Establishing a MySQL Connection:

```yaml
    <?php
    $servername = "localhost";
    $db_username = "your_db_username";
    $db_password = "your_db_password";
    $dbname = "your_database_name";

    // Create connection
    $conn = new mysqli($servername, $db_username, $db_password, $dbname);

    // Check connection
    if ($conn->connect_error) {
        die("Connection failed: " . $conn->connect_error);
    }
    echo "Connected successfully";
    ?>
```

# Launching SQL Injection Attacks