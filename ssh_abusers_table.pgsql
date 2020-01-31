create table if not exists ssh_abusers (
       time timestamptz not null default now(),
       username varchar(32) not null,
       ip inet not null,
       port integer not null,
       country char(2) null
);
