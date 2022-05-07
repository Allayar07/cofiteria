### psql command
create table users (
    id bigserial not null primary key,
	photo varchar,
	name varchar,
	wezipe varchar,
	email varchar not null unique,
	encryptedPassword varchar not null,
	qrcode varchar
);

create table product (
	id bigserial not null primary key,
	name varchar,
	cost real,
	alynanbaha real,
	sany integer,
	shtrixcode integer
);

### UPDATA DATA
update  product set sany = sany + $1 where shtrixcode = $2 returning *
