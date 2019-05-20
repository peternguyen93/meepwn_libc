#!/usr/bin/python

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection
from pymongo import *
from subprocess import call
from ropgadget.core import Core
from ropgadget.args import Args
import xml.etree.ElementTree as ET
import json
import sys
import os
import datetime
import hashlib
import urllib2
import sqlite3

tmp_file = '/tmp/libc_collection/'
# repo = os.path.expanduser('~/.repo.json') # own repo link
repo = './repo.json'
client = MongoClient('localhost', 27017) # open mongo connection
db = client.libc_collection

def md5sum(file_name):
	'''
		perform md5sum calculation of file
	'''
	if os.path.exists(file_name):
		pfile = open(file_name,'r')
		content = pfile.read()
		pfile.close()

		return hashlib.md5(content).hexdigest()
	return None

def get_machine_arch(libc_path):
	'''
		get binary arch
	'''
	pfile = open(libc_path,'r')

	elffile = ELFFile(pfile)
	arch = elffile.get_machine_arch()

	if arch == 'x86':
		arch = 'i386'
	else:
		arch = 'amd64'

	pfile.close()
	return arch

def get_bin_sh_offset(pfile):
	offset = 0 # /bin/sh offset
	if pfile:
		block = pfile.read(1024)
		size = 0
		while block != '':
			if '/bin/sh' in block:
				offset = size + block.index('/bin/sh')
				break
			size += len(block)
			block = pfile.read(1024)
	return offset

def extract_libc_rop_gadgets(libc_path):
	'''
		extract all gadgets in libc binary
	'''
	gadgets = []
	if os.path.exists(libc_path):
		c = Core(Args(['--binary',libc_path]).getArgs())
		c.do_binary(libc_path,True)
		c.do_load('',True)
		for gadget in c.gadgets():
			gadgets.append({
				'vaddr' : gadget['vaddr'],
				'gadget' : gadget['gadget']
			})
	return gadgets

def extract_libc_symbol(libc_path):
	'''
		extract all libc symbol in .dynsym section
	'''
	pfile = open(libc_path,'r')
	# can't find any thing calculate it
	elffile = ELFFile(pfile)

	# dump symbol table
	symbol_sec = elffile.get_section_by_name(b'.dynsym')
	# can dump ?
	if not isinstance(symbol_sec, SymbolTableSection):
		return None

	func1_addr = 0
	func2_addr = 0

	libc_symbol = {} # generate own symbol

	for symbol in symbol_sec.iter_symbols():
		name = symbol.name.replace('.','_') # remove unused symbol
		if name != '':
			libc_symbol[name] = symbol.entry['st_value']
	# get bin_sh_offset
	# now you can get your /bin/sh offset with leak address or os version
	# p.get_libc_offset(leak_addr,'puts','/bin/sh') => offset between puts and '/bin/sh'
	pfile.seek(0,0) # back to begin
	bin_sh_offset = get_bin_sh_offset(pfile)
	libc_symbol['/bin/sh'] = bin_sh_offset # add offset of /bin/sh into db

	pfile.close()
	return libc_symbol

def download(link,out_file):
	''' require we have wget or axel to download'''
	cmd = ['wget']
	cmd.append(link)
	cmd.append('-O')
	cmd.append(out_file)
	call(cmd)

def extract_rpm_file(path,save_path):
	os.chdir(save_path)
	cmd = 'rpm2cpio {0} | cpio -i --make-directories'.format(path)
	os.system(cmd)

def extract_deb_file(path,save_path):
	# extract .deb file
	os.chdir(save_path)
	download = ['ar']
	download.append('xv')
	download.append(path)
	call(download)

def extract_file(path,save_path,file_type='bz2'):
	# extract bz2 and tar.gz, .xz
	if file_type == 'bz2':
		cmd = ['bzip2']
		cmd.append('-d')
		cmd.append(path)
		call(cmd)
	elif file_type == 'gz':
		cmd = ['gzip']
		cmd.append('-d')
		cmd.append(path)
		call(cmd)
	elif file_type == 'tar.gz':
		cmd = ['tar']
		cmd.append('-xvf')
		cmd.append(path)
		cmd.append('-C')
		cmd.append(save_path)
		call(cmd)
	elif file_type == 'tar.xz':
		cmd = ['tar']
		cmd.append('-xJf')
		cmd.append(path)
		cmd.append('-C')
		cmd.append(save_path)
		call(cmd)
	else:
		print '[!] Extracting file have failed'
		sys.exit(1)

def parsing_deb_package_file(path,name='libc6'):
	''' 
		parsing Package file on the repo and find libc6 package
	'''
	if os.path.exists(path):
		fp = open(path)
		text = fp.read()
		fp.close()

		try:
			m = text[text.index('Package: ' + name):] # name use for libc6-i386 on x86_64 system
			m = m.split('\n')
		except ValueError:
			return None # Not found

		# get version of libc6 , get md5sum
		libc6_version = None
		libc6_md5sum = None
		libc6_link = None
		libc6_arch = None
		# parsing some info
		for l in m:
			if 'Version:' in l:
				libc6_version = l[9:]
			if 'MD5sum:' in l:
				libc6_md5sum = l[8:]
			if 'Filename:' in l:
				libc6_link = l[10:]
			if 'Architecture:' in l:
				libc6_arch = l[14:]
			if libc6_md5sum and libc6_version and libc6_arch and libc6_link:
				break

		return [libc6_link,libc6_version,libc6_md5sum,libc6_arch]
	return None # Parsing failed

# rpm package processing
def rpm_xml_get_db(url):
	xml_string = urllib2.urlopen(url).read()
	root = ET.fromstring(xml_string)
	prefix = root.tag[:-6] # remove repmod

	href_location = ''

	for node in root.findall(".//{0}data[@type='primary_db']/*".format(prefix)):
		if node.attrib.has_key('href'):
			href_location = node.attrib['href']
			break
	return href_location

# query primary_db.sqlite to get glibc package
# select name,location_href from packages where name="glibc"
def parsing_rpm_package_db(db_file):
	infos = []
	if os.path.exists(db_file):
		conn = sqlite3.connect(db_file)
		try:
			with conn:
				cur = conn.cursor()
				
				cur.execute("SELECT location_href,version,'checksum',arch FROM packages where name='glibc'")
				rows = cur.fetchall()
				# get i686 and x86_64 glibc packages
				for row in rows:
					info = list(row)
					infos.append(info)
		except sqlite3.Error:
			pass
	return infos
	

def download_packages_file(repo_collection):
	'''
		Download Packages.bz2 from server , decompress it then parsing it
		Own repo follows by this structure
		[
			{
				'link':'http://us.archive.ubuntu.com/ubuntu/',
				'repo_name':'trusty-updates'
			},
			{
				'link':'http://us.archive.ubuntu.com/ubuntu/',
				'repo_name':'trusty'
			}
		]
	'''
	libc6_info = []
	for item in repo_collection:
		# processing ubuntu/debian repo
		if item['os_name'] == 'ubuntu':
			exts = ['.bz2','.gz'] # fix error when download Packages from ubuntu 16.04 repo
			for ext in exts:
				repo_link =  item['link'] + 'dists/' + item['repo_name']
				link_64 = repo_link + '/main/binary-amd64/Packages' + ext
				link_32 = repo_link + '/main/binary-i386/Packages' + ext

				extract_folder64 = tmp_file + 'Packages_64' + ext
				extract_folder32 = tmp_file + 'Packages_32' + ext

				print '[+] Getting {0}'.format(item['repo_name'])

				download(link_64,tmp_file + 'Packages_64' + ext)
				download(link_32,tmp_file + 'Packages_32' + ext)

				print '[+] Repo {0} - Extracting Package{1}...'.format(item['repo_name'],ext)

				if not os.stat(extract_folder64).st_size:
					print 'Repo {0} : {1} not found'.format(item['repo_name'],extract_folder64)
					continue
				if not os.stat(extract_folder32).st_size:
					print 'Repo {0} : {1} not found'.format(item['repo_name'],extract_folder32)
					continue
				# extract all file then parsing some info
				t_ext = ext[1:] # remove dot before ext
				extract_file(extract_folder64,tmp_file + 'Packages_64',t_ext)
				extract_file(extract_folder32,tmp_file + 'Packages_32',t_ext)

				# getting info of 64 bit package
				info = parsing_deb_package_file(tmp_file + 'Packages_64')
				if info:
					info.append(item['repo_name'])
					info.append(item['link'])
					info.append(item['os_name'])
					info.append(item['os_version'])
					libc6_info.append(info)
				info = parsing_deb_package_file(tmp_file + 'Packages_64','libc6-i386') # getting i386 .deb file
				if info:
					info[-1] = 'i386_amd64' # edit arch info
					info.append(item['repo_name'])
					info.append(item['link'])
					info.append(item['os_name'])
					info.append(item['os_version'])
					libc6_info.append(info)
				# getting info of 32 bit package
				info = parsing_deb_package_file(tmp_file + 'Packages_32')
				if info:
					info.append(item['repo_name'])
					info.append(item['link'])
					info.append(item['os_name'])
					info.append(item['os_version'])
					libc6_info.append(info)

				os.unlink(tmp_file + 'Packages_64')
				os.unlink(tmp_file + 'Packages_32')
				break # break the loop

		# processing centos/fedora repo
		elif item['os_name'] == 'centos':
			p = item['os_name'] + '/' + item['repo_name']
			print '[+] Getting {0}'.format(p)

			sqlite_url = rpm_xml_get_db(item['link'] + '/repodata/repomd.xml')
			save_db = tmp_file + sqlite_url.replace('repodata/','')

			download(item['link'] + sqlite_url,save_db)

			print '[+] Repo {0} - Extracting {1}...'.format(p,save_db)

			extract_file(save_db,'')
			save_db = save_db.replace('.bz2','')

			infos = parsing_rpm_package_db(save_db)
			# append some usefull info
			for info in infos:
				info.append(item['repo_name'])
				info.append(item['link'])
				info.append(item['os_name'])
				info.append(item['os_version'])

			libc6_info.extend(infos)

			os.unlink(save_db) # remove primary.sqlite

	return libc6_info

def libc_get():
	'''
		This function works like apt-get
		Own libc symbol
		{
			"libc_version" : "2.19-0ubuntu6.6",
			"libc_md5sum" : "f57ca4c76bdf2af3117e51d63eb81004",
			"libc_day_added" : "22/10/2015",
			"libc_repo" : "trusty",
			"os_name" : "ubuntu",
			"os_version" : "14.04",
			"os_arch" : "amd64",
			"libc_symbol" : {
				// own libc symbol
			}
			"libc_rop_gadgets" : [
				{
					"vaddr" : // gadget offset,
					"gadget" : // asm code 
				},
				...
			]
		}
	'''

	if not os.path.exists(repo):
		print '[!] Repo file not found, pls add it in to {0}'.format(repo)
		sys.exit(1)

	if not os.path.exists(tmp_file):
		os.mkdir(tmp_file)

	fp = open(repo,'r')
	text = fp.read() # loading own repo
	fp.close()

	repo_collection = json.loads(text)

	print '[+] Starting download...'
	libc6_info = download_packages_file(repo_collection)

	print '[+] Checking information....'
	new_libc6_info = []
	# checking information of libc6 in my database
	for info in libc6_info:
		if not db.libc6.find_one({'libc_md5sum':info[2]}): # check if .deb isn't in my collection
			new_libc6_info.append(info)

	if len(new_libc6_info) == 0:
		print '[!] All libc6 had updated'
		sys.exit(1)
	# download new libc6.so
	for info in new_libc6_info:
		link = info[5] + info[0] # get package link
		save_package = tmp_file + os.path.basename(info[0])
		print '[+] Download {0}...'.format(save_package)
		download(link,save_package)
		if os.path.exists(save_package): # download had done
			libc_symbol = libc_path = None
			if info[6] == 'ubuntu':
				extract_deb_file(save_package,tmp_file)
				# extract_file .tar.gz or tar.xz
				if os.path.exists(tmp_file + 'data.tar.gz'): # extract deb file had done
					extract_file(tmp_file + 'data.tar.gz',tmp_file,'tar.gz')
				if os.path.exists(tmp_file + 'data.tar.xz'):
					extract_file(tmp_file + 'data.tar.xz',tmp_file,'tar.xz')
				
				# getting own symbol
				if info[3] == 'amd64': # x86_64
					libc_path = os.path.realpath(tmp_file + 'lib/x86_64-linux-gnu/libc.so.6')
				elif info[3] == 'i386':
					libc_path = os.path.realpath(tmp_file + 'lib/i386-linux-gnu/libc.so.6')
				elif info[3] == 'i386_amd64':
					libc_path = os.path.realpath(tmp_file + 'lib32/libc.so.6')

			elif info[6] == 'centos':
				tmp_folder = tmp_file + '/rpm_extract'
				if not os.path.exists(tmp_folder): # create tmp folder if it doesn't exsist
					os.mkdir(tmp_folder)
				extract_rpm_file(save_package,tmp_folder)
				# resolve libc.so path
				if info[3] == 'x86_64':
					libc_path = os.path.realpath(tmp_folder + '/lib64/libc.so.6')
				elif info[3] == 'i686':
					libc_path = os.path.realpath(tmp_folder + '/lib/libc.so.6')

			if os.path.exists(libc_path):
				if info[2] == 'checksum': # update libc checksum on rpm repo
					info[2] = md5sum(libc_path)
					# check rpm libc md5sum
					if db.libc6.find_one({'libc_md5sum':info[2]}): 
						# clean tmp
						os.system('rm -rf {0}/*'.format(tmp_file))
						print '[+] Already added'
						continue

				# extract libc symbol sucessfully, save it into my collection
				libc_symbol = extract_libc_symbol(libc_path)
				# extract libc rop gadgets
				libc_rop_gadgets = extract_libc_rop_gadgets(libc_path)

				if libc_symbol:

					libc6 = {
						"link_down" : link,
						"libc_version" : info[1],
						"libc_md5sum" : info[2],
						"libc_day_added" : datetime.datetime.utcnow(),
						"libc_repo" : info[4],
						"os_name" : info[6],
						"os_version" : info[7],
						"libc_arch" : info[3],
						"libc_symbol" : libc_symbol,
						"libc_rop_gadgets" : libc_rop_gadgets
					}
					db.libc6.insert(libc6) # insert into database
					# remove trash file
					os.system('rm -rf {0}/*'.format(tmp_file))
					print '[+] Done.'
			else:
				print '[!] Extracing {0} error'.format(save_package)
		else:
			print '[!] Getting {0} file error'.format(save_package)

def add_libc_local(libc_path):
	'''
		perform add libc.so directly 
	'''
	if os.path.exists(libc_path):
		md5 = md5sum(libc_path)
		if not db.libc6.find_one({'libc_md5sum':md5}):
			libc_symbol = extract_libc_symbol(libc_path)
			libc_rop_gadgets = extract_libc_rop_gadgets(libc_path)
			lib_arch = get_machine_arch(libc_path)
			libc6 = {
				"libc_version" : "unknown",
				"libc_md5sum" :md5 , # md5sum file
				"libc_day_added" : datetime.datetime.utcnow(),
				"libc_repo" : "local",
				"os_name" : "unknown",
				"os_version" : "unknown",
				"libc_arch" : lib_arch,
				"libc_symbol" : libc_symbol,
				"libc_rop_gadgets" : libc_rop_gadgets
			}
			db.libc6.insert(libc6) # insert into database
			print '[+] Adding {0} had sucessfully'.format(libc_path)
		else:
			print '[!] Your {0} was added'.format(libc_path)
	else:
		print '[!] File {0} not found'.format(libc_path)

if __name__ == '__main__':
	if len(sys.argv) < 2:
		print 'Usage {0} <command>'.format(sys.argv[0])
		sys.exit(1)

	if sys.argv[1] == 'help':
		commands = {
			'help' : 'show all command',
			'get' : 'get libc in repo: {0} get'.format(sys.argv[0]),
			'add' : 'add libc.so.6 directly: {0} add libc-2.22.so'.format(sys.argv[0]),
			'remove' : 'repo name <16.04/14.04>'
			'fix' : 'fix symbol'
		}
		for command,description in commands.iteritems():
			print command,'\t',description
	elif sys.argv[1] == 'get': # get new libc version
		libc_get() # generate symbol collection
	elif sys.argv[1] == 'add':
		if len(sys.argv) == 3:
			if sys.argv[2]:
				add_libc_local(sys.argv[2])
		else:
			print '[!] Invalid argument'