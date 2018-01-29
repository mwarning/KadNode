#!/bin/sh --
ronn --roff --manual=Kadnode\ Manual --organization=mwarning --date=2017-12-01 manpage.md
mv manpage.1 manpage
