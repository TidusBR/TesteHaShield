#1459870423
ALTER TABLE  `charlog` CHANGE  `time`  `time` DATETIME NOT NULL DEFAULT '1970-01-01 00:00:00';
ALTER TABLE  `interlog` CHANGE  `time`  `time` DATETIME NOT NULL DEFAULT '1970-01-01 00:00:00';
ALTER TABLE  `ipbanlist` CHANGE  `btime`  `btime` DATETIME NOT NULL DEFAULT '1970-01-01 00:00:00';
ALTER TABLE  `ipbanlist` CHANGE  `rtime`  `rtime` DATETIME NOT NULL DEFAULT '1970-01-01 00:00:00';
ALTER TABLE  `login` CHANGE  `lastlogin`  `lastlogin` DATETIME NOT NULL DEFAULT '1970-01-01 00:00:00';
ALTER TABLE  `login` CHANGE  `birthdate`  `birthdate` DATE NOT NULL DEFAULT '1970-01-01';
ALTER TABLE  `updatecharlog` CHANGE  `regdate`  `regdate` DATETIME NOT NULL DEFAULT '1970-01-01 00:00:00';
INSERT INTO `sql_updates` (`timestamp`) VALUES (1459870423);