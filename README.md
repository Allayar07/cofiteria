### psql command
create table users (
    id serial not null primary key,
	photo varchar,
	name varchar,
	wezipe varchar,
	email varchar not null unique,
	encryptedpassword varchar not null,
	qrcode varchar,
	role  varchar
);

create table product (
	id serial not null primary key,
	name varchar,
	cost real,
	alynanbaha real,
	sany real,
	shtrixcode integer unique
);

create table statistic (
	id bigserial not null primary key,
	satylansany real,
	totalcost real
);

### UPDATA DATA
update  product set sany = sany + $1 where shtrixcode = $2 returning *
# cofiteria
