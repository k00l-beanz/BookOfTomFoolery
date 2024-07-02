# SQLi

## Cheatsheets

- [Portswigger SQLi Cheatsheet](https://portswigger.net/web-security/sql-injection/blind)

## Detection

### Wordlists
- https://github.com/PenTestical/sqli
- https://github.com/payloadbox/sql-injection-payload-list
- https://0x1.gitlab.io/web-security/web-attack-payloads-wordlist/
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection

### Examples

#### GET Request
```bash
wfuzz -c -z file,/usr/share/wfuzz/wordlist/Injections/hugeSQL.txt "http://127.0.0.1/index.php?id=FUZZ"
```

#### POST Request
```bash
wfuzz -c -z file,/usr/share/wfuzz/wordlist/Injections/hugeSQL.txt -d "username=admin\&password=FUZZ" http://127.0.0.1/admin
```

## Techniques

- [Retrieving hidden data](https://portswigger.net/web-security/sql-injection#retrieving-hidden-data)
- [Subverting application logic](https://portswigger.net/web-security/sql-injection#subverting-application-logic)
- [UNION attacks](https://portswigger.net/web-security/sql-injection/union-attacks)
- [Blind SQL injection](https://portswigger.net/web-security/sql-injection/blind)

### Examining the database



### UNION Attacks

For `UNION` query to work, two key requirements must be met:

1. The individual queries must return the same number of columns
2. The data types in each column must be compatible between the individual queries

To carry out a SQL injection UNION attack, make sure that your attack meets these two requirements. This normally involves finding out:

1. How many columns are being returned from the original query.
2. Which columns returned from the original query are of a suitable data type to hold the results from the injected query

#### Determine the number of columns required

The first method involves injectin ga series of `ORDER BY` clauses and incrementing the specified column index until an error occurs. For example, if the injection point is a quoted string within the `WHERE` clause of the original query, you would submit:

```
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
```

When the specified column index exceeds the number of actual columns in the result set, the database returns an error, such as: `The ORDER BY position number 3 is out of range of the number of items in the select list.`

The second method involes submitting a series of `UNION SELECT` payloads specifying a different number of null values:

```
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
```

If the number of nulls does not match the number of columns, the database returns an error, such as: `All queries combined using a UNION, INTERSECT or EXCEPT operator must have an equal number of expressions in their target lists.`


The application might actually return the database error in its HTTP response, but it may also issue a generic error response. In other cases, it may simply return no results at all. Either way, as long as you can detect some difference in the response, you can infer how many columns are being returned from the query. 

#### Finding columns with a useful data type

After you determine the number of required columns, you can probe each column to test whether it can hold string data. You can submit a series of `UNION SELECT` payloads that place a string value into each column in turn. For example, if the query returns four columns, you would submit:

```
' UNION SELECT 'a',NULL,NULL,NULL--
' UNION SELECT NULL,'a',NULL,NULL--
' UNION SELECT NULL,NULL,'a',NULL--
' UNION SELECT NULL,NULL,NULL,'a'--
```

If the column data type is not compatible with string data, the injected query will cause a database error, such as: `Conversion failed when converting the varchar value 'a' to data type int.` If an error does not occur, and the application's response contains some additional content including the injected string value, then the relevant column is suitable for retrieving string data. 

#### Retrieving interesting data

#### Retrieving multiple values in a single column

#### Guides
- [Union Based Oracle Injection](http://www.securityidiots.com/Web-Pentest/SQL-Injection/Union-based-Oracle-Injection.html)
- [Oracle Database Specific UNION syntax](https://portswigger.net/web-security/sql-injection/union-attacks#determining-the-number-of-columns-required)


### Blind SQL Injection

