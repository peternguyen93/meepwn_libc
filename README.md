Libc_Collection is a tool that help you find and calculate easier.
Author : peternguyen
Version : 0.7

Libc_Collection use ubuntu repo to find libc symbol.
Repo file is stored in your home folder (~/.repo.json)

Change Log:
	+ add new api get_offset_by_os
	+ add offset of "/bin/sh" (you can get offset by leak address or os version)
	+ if you want to calc offset by using operator '-'
	+ add new feature : libc rop finding :)
	+ support centos/fedora repo
	+ support user authenticate

Requires:
	+ pip
	+ virtualenv
	+ mongodb
	+ flask (use for web interface)
	+ pymongo
	+ axel (default tool helps my project download package)
	+ wget
	+ gunicorn (deploy web service)

Usage:
	python libc_collection.py get # update libc symbol from repo
	python libc_collection.py add /a/b/c/libc.so.6 # add libc symbol from repo 
