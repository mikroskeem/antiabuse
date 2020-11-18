create table scanners (
       time timestamptz not null default now(),
       ip inet not null,
       country char(2) null
);
