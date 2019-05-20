#!/usr/bin/python

from datetime import timedelta
from flask import *
from pymongo import *
import hashlib
import time
import os

app = Flask(__name__)
key='3a37c56f2e56918ad526eaceb5135b36d70e562ff894d0be39657c67634259ba'.decode('hex')
app.config['SECRET_KEY'] = key # fit your secret key here

client = MongoClient('mongodb', 27017) # open mongo connection
db = client.libc_collection

def authenticate(authkey):
	# use md5 for authkeys
	for row in db.authkeys.find():
		# suitable for old user
		if authkey > 32:
			authkey = authkey[:32]

		if row['authkey'][:32] == authkey:
			return row
	return None

# @app.before_request
# # make session is valid in 5 minutes
# def make_session_permanent():
# 	session.permanent = True
# 	app.permanent_session_lifetime = timedelta(minutes=5)

@app.route('/',methods=['POST','GET'])
def index():
	try:	
		if session['authkey']:
			return render_template('index.html')
	except KeyError:
		pass
	
	try:
		if request.method == 'POST': # verify baby's user
			auth = request.form['authkey']
			r = authenticate(auth)
			if r != None:
				session['authkey'] = True
				if r['is_admin']:
					session['is_admin'] = True
				return render_template('index.html')
	except KeyError:
		pass

	return render_template('auth.html')

@app.route('/libc_rop',methods=['POST','GET'])
def libc_rop():
	try:
		if session['authkey']:
			return render_template('libc_rop_find.html')
	except KeyError:
		pass
	return redirect(url_for('index'))

@app.route('/libc_find',methods=['POST','GET'])
def libc_find():
	'''
		Calculate address of function from leaking address's function
	'''
	offset = 0 # offset between func and func2
	offset2 = 0 # store offset of your request function to libc base address
	out_record = {}
	is_authen = False
	if request.method == 'POST':

		if not session.has_key('authkey'):
			if authenticate(request.form['auth']):
				is_authen = True
		elif session['authkey']:
			is_authen = True

		if is_authen:
			try:
				func_addr = int(request.form['func_addr'],16) #only accept hex value
				func_name = request.form['func_name']
				func2_name = request.form['func2_name']
				# finding suitable offset
				libc_records = db.libc6.find()
				for record in libc_records:
					func_offset = record['libc_symbol'][func_name]
					if ((func_addr - func_offset) & 0xfff) == 0: # ok founded
						func2_offset = record['libc_symbol'][func2_name]	
						offset = func_offset - func2_offset # offset between func and func2
						offset2 = func_offset
						out_record['os_name'] = record['os_name']
						out_record['os_version'] = record['os_version']
						out_record['link_down'] = record['link_down']
						
			except KeyError:
				pass
			except ValueError:
				pass
	return jsonify(offset=offset,offset2=offset2,info=out_record)

@app.route('/get_libc_base_addr',methods=['POST','GET'])
def get_libc_base_addr():
	'''
		Find libc base address from known leak address of some functions in libc
	'''
	is_authen = False
	base_addr = 0
	if request.method == 'POST':
		if not session.has_key('authkey'):
			if authenticate(request.form['auth']):
				is_authen = True
		elif session['authkey']:
			is_authen = True

		if is_authen:
			try:
				leak_addr = int(request.form['leak_addr'],16) # only accept hex value
				func_name = request.form['func_name']

				collection = db.libc6.find()
				for info in collection:
					func_offset = info['libc_symbol'][func_name]
					if ((leak_addr - func_offset) & 0xfff) == 0:
						base_addr = leak_addr - func_offset
						break
			except KeyError:
				pass
			except ValueError:
				pass
	return jsonify(libc_base_addr=base_addr)

@app.route('/get_offset_by_os_name',methods=['POST','GET'])
def get_offset_by_os_name():
	offset = []
	is_authen = False
	if request.method == 'POST':
		if not session.has_key('authkey'):
			if authenticate(request.form['auth']):
				is_authen = True
		elif session['authkey']:
			is_authen = True

		if is_authen:
			try:
				func_name = request.form['func_name']
				os_name = request.form['os_name']
				os_version = request.form['os_version']
				arch = request.form['arch']

				query = {
					'os_name' : os_name,
					'os_version' : os_version
				}
				collection = db.libc6.find(query)
				for info in collection:
					if info['libc_arch'].startswith(arch):
						# getting all possible offset
						offset.append(info['libc_symbol'][func_name])
			except KeyError:
				pass
			except ValueError:
				pass
	return jsonify(offset=offset)

@app.route('/find_libc_rop_gadget',methods=['POST','GET'])
def find_libc_rop_gadget():
	'''
		Calculate address of function from leaking address's function
	'''
	gadgets = []
	base_addr = 0
	offset = 0
	is_authen = False
	if request.method == 'POST':
		try:
			if session['authkey'] or authenticate(request.form['auth']):
				is_authen = True
		except KeyError:
			pass

		if is_authen:
			try:
				leak_addr = int(request.form['leak_addr'],16) # only accept hex value
				func_name = request.form['func_name']

				# finding suitable offset
				collection = db.libc6.find()
				for info in collection:
					func_offset = info['libc_symbol'][func_name]
					if ((leak_addr - func_offset) & 0xfff) == 0:
						gadgets = info['libc_rop_gadgets']
						base_addr = leak_addr - func_offset
						offset = func_offset # offset from this function to libc base address
						break
			except KeyError:
				pass
			except ValueError:
				pass
	return jsonify(gadgets=gadgets,base_addr=base_addr,offset=offset)

@app.route('/admin_del_key',methods=['POST'])
def admin_del_key():
	try:
		if request.method == 'POST':
			user_name = request.form['user_name']

			if not db.authkeys.find_one({'name':user_name}):
				return jsonify(error=True,msg='User not found')
			
			r = db.authkeys.delete_one({'name':user_name})
			if r.deleted_count != 1:
				return jsonify(error=True,msg='Delete fail')

			return jsonify(error=False,msg='Delete ok')

	except KeyError:
		pass

@app.route('/admin_remove_repo',methods=['POST','GET'])
def admin_remove_repo():
	try:
		if session['is_admin']:
			all_repo = set()
			for row in db.libc6.find():
				repo = row['libc_repo']
	except KeyError:
		pass
	return redirect(url_for('index'))

@app.route('/admin',methods=['POST','GET'])
def admin():
	try:
		if session['is_admin']:
			new_key = None

			if request.method == "POST":
				# create new user
				if request.form.has_key('name'):
					name = request.form['name']
					xor_key = os.urandom(len(name))
					enc = ''
					for i in xrange(len(name)):
						enc += chr(ord(name[i]) ^ ord(xor_key[i]))

					new_key = hashlib.sha512(enc).hexdigest()

					if db.authkeys.count({'name':name}) < 1:
						record = {'authkey':new_key,'is_admin':False,'name':name}
						db.authkeys.insert(record)
			
			# list all user in data base
			user_list = []
			for row in db.authkeys.find():
				if not row['is_admin']:
					user_list.append({'name':row['name'],'key':row['authkey'][:32]})

			return render_template('admin.html',authkey=new_key,user_list=user_list)
	except KeyError:
		pass
	return redirect(url_for('index'))

if __name__ == '__main__':
	app.run(host='0.0.0.0',debug=True)