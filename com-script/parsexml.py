import xml.etree.ElementTree as ET
cpptree = ET.parse('res_0601.xml')
nasactree = ET.parse('testset_all.xml')
#root = cpptree.getroot()
# cpptree = ET.ElementTree(file='res.xml')
# for elem in cpptree.iterfind('results/errors[@id="BUFFER_OVERFLOW"]'):
cppcheckcount = 0
# BUFFER_OVERFLOW error count
buffcount = 0
# double free error count.
dfcount = 0
npdcount = 0
# testcase count in nasac
testcount = 0
# memery no free count.
# memnfcount = 0
#dangerous function count
# dangercount = 0
# insecureCmdLineArgs count
# iscmdargcount = 0

# parse cppcheck tree
for cppelem in cpptree.iter(tag='error'):
	cppcheckcount += 1
	# print cppelem
	if cppelem.get('id') == 'BUFFER_OVERFLOW' or cppelem.get('id') == 'arrayIndexOutOfBounds':
		buffcount += 1
	if cppelem.get('id') == 'DOUBLE_FREE':
		dfcount += 1
	if cppelem.get('id') == 'nullPointer' or cppelem.get('id') == 'ctunullpointer':
		npdcount += 1
	# if cppelem.get('id') == 'insecureCmdLineArgs':
	# 	iscmdargcount += 1
	# if cppelem.get('id') == 'MemoryNoFree':
	# 	memnfcount += 1
	# if cppelem.get('id') == 'DangerousFunction':
	# 	dangercount += 1
print '-----------------------------------------'
print 'cppcheck Total detect count : ' + str(cppcheckcount)
print 'cppcheck BUFFER_OVERFLOW count : ' + str(buffcount)
print 'cppcheck DOUBLE_FREE count : ' + str(dfcount)
print 'cppcheck NULL_POINTER_DEREFERENCE count : ' + str(npdcount)
# print 'cppcheck MemoryNoFree count : ' + str(memnfcount)

# parse nasac tree
realtotal = 0
realbuffcount = 0
realdfcount = 0
realnpdcount = 0
for nasacelem in nasactree.iter(tag = 'testcase'):
	for vulchild in nasacelem.iter(tag = 'vul'):
		testcount += 1
		if vulchild.find('iscounterexample').text == 'No':
			realtotal += 1
		if vulchild.find('iscounterexample').text == 'No' and vulchild.find('type').text == 'BUFFER_OVERFLOW':
			realbuffcount += 1
		if vulchild.find('iscounterexample').text == 'No' and vulchild.find('type').text == 'DOUBLE_FREE':
			realdfcount += 1
		if vulchild.find('iscounterexample').text == 'No' and vulchild.find('type').text == 'NULL_POINTER_DEREFERENCE':
			realnpdcount += 1

print '\ntotal nasac testcase count : ' + str(testcount)
print 'Total BUG testcase : ' + str(realtotal)
print 'real BUFFER_OVERFLOW : ' + str(realbuffcount)
print 'real DOUBLE_FREE : ' + str(realdfcount)
print 'real NULL_POINTER_DEREFERENCE : ' + str(realnpdcount) 
	# print element.tag, element.attrib

hitbuffcount = 0
hitdfcount = 0
hitnpdcount = 0
missbuff = 0
falsebuff = 0
for cppelem in cpptree.iter('error'):
	location = cppelem.find('location').get('file') + '/' + cppelem.find('location').get('line')
	# print location
	for nasacelem in nasactree.iter(tag = 'testcase'):
		for vulchild in nasacelem.iter(tag = 'vul'):
			goodsink = nasacelem.get('id') + '/' + vulchild.find('sink').find('file').text + '/' + vulchild.find('sink').find('line').text
			# print goodsink
			if cppelem.get('id') == 'arrayIndexOutOfBounds' and vulchild.find('type').text == 'BUFFER_OVERFLOW':
				if vulchild.find('iscounterexample').text == 'No' and location == goodsink:
					hitbuffcount += 1
					print 'HIT ARRAY--->' + goodsink + '\n'
				elif vulchild.find('iscounterexample').text == 'Yes' and location == goodsink:
					print 'False ARRAY--->' + location + '\n'
			if cppelem.get('id') == 'BUFFER_OVERFLOW' and vulchild.find('type').text == 'BUFFER_OVERFLOW':
				if vulchild.find('iscounterexample').text == 'No' and location == goodsink:
					hitbuffcount += 1
					print 'HIT BUFF--->' + goodsink + '\n'
				elif vulchild.find('iscounterexample').text == 'Yes' and location == goodsink:
					falsebuff += 1
					print 'False BUFF--->'+ goodsink + '\n'
			if cppelem.get('id') == 'DOUBLE_FREE' and vulchild.find('type').text == 'DOUBLE_FREE':
				if vulchild.find('iscounterexample').text == 'No' and location == goodsink:
					hitdfcount += 1
			if cppelem.get('id') == 'nullPointer' and vulchild.find('type').text == 'NULL_POINTER_DEREFERENCE':
				if vulchild.find('iscounterexample').text == 'No' and location == goodsink:
					hitnpdcount += 1
			if cppelem.get('id') == 'ctunullpointer' and vulchild.find('type').text == 'NULL_POINTER_DEREFERENCE':
				if vulchild.find('iscounterexample').text == 'No' and location == goodsink:
					hitnpdcount += 1
print '\nhit BUFFER_OVERFLOW : ' + str(hitbuffcount)
print 'hit DOUBLE_FREE :' + str(hitdfcount)
print 'hit NULL_POINTER_DEREFERENCE : ' + str(hitnpdcount)
print 'false BUFFER_OVERFLOW :' + str(falsebuff)
