# drupal_password_mysql
This code ported the function hash password of Drupal to MySQL by C language.

Background
----------

My project need to migrate millions of users from old system into new Drupal system, so i developed mysql udf version with C of drupal password hash, then we can use mysql function to hash password when import users by MySQL csv load feature.

This is my first time to learn the C language, of course, is also the first to write programs using the C language. May be this isn't a good code, please forgive me.

Requirements
------------

* libssl dev
* libmysqlclient dev

Tested on
---------

* Linux
* Mac OS X

Support
-------

* Drupal 7
* Drupal 8

Complie
-------

    $ gcc -shared -DMYSQL_DYNAMIC_PLUGIN `mysql_config --cflags` -o drupal_password.so drupal_password.c `mysql_config --libs` -lcrypto

Install
-------

Verify shared library dependencies

    $ ldd -r -d ./drupal_password.so

Install as mysql plugin

    $ sudo install -m 755 drupal_password.so `mysql_config --plugindir`

Create function on MySQL

    mysql> DROP function IF EXISTS drupal_password;
    mysql> CREATE FUNCTION drupal_password RETURNS STRING SONAME 'drupal_password.so';

Usage
-----

Drupal password hash

    mysql> select drupal_password('Your Password');

Update user's password with plain-text.

    mysql> UPDATE users SET pass = drupal_password('Your Password') WHERE uid = 1;

Update user's password with md5 hashed.

    mysql> UPDATE users SET pass = CONCAT('U', drupal_password('Your MD5 Hashed Password', 11)) WHERE uid = 1;

Performance Test
----------------

Compared with my another drupal_hash_password base on MySQL functions.
https://github.com/everright/drupal_hash_password

Sample data: 10K

C version update pass on MySQL

    3 min 45 sec

MySQL function version update pass on MySQL

    19 min 8 sec

PHP Loop output on Terminal by function "user_hash_password"

    5 min 38 sec
