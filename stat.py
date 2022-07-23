#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
import re
import xlrd
import collections
import string
from pyExcelerator import *

reload(sys)
sys.setdefaultencoding("utf-8")

# 全局字体
commonFont = u'宋体'
# 全局样式
# 边框样式
borders = Borders()  
borders.left = 1  
borders.right = 1  
borders.top = 1  
borders.bottom = 1  

# 头部字体
headFnt = Font()  
headFnt.size = 11
headFnt.bold = 1
headFnt.height = 250
headFnt.name = commonFont
 
# 公共字体
fnt = Font()  
fnt.size = 9
fnt.bold = 0
fnt.name = commonFont

# 背景
pattern = Pattern()
pattern.pattern = 4
pattern.pattern_back_colour=22	# 这儿可以调节背景色

#对齐方式  
al = Alignment()  
al.horz = Alignment.HORZ_CENTER  
al.vert = Alignment.VERT_CENTER

# 头部样式
headStyle = XFStyle()  
headStyle.borders = borders 
headStyle.font = headFnt
headStyle.pattern = pattern
headStyle.alignment = al

# 端口样式
portStyle = XFStyle()  
portStyle.borders = borders 
portStyle.font = fnt

# 公共样式
style = XFStyle()  
style.borders = borders 
style.font = fnt
style.alignment = al

# merge two dicts
def merge_dicts(x, y):
	z = x.copy()
	z.update(y)
	return z

# sort dict by key
def sortedDictValues(adict):
	result = {}
	keys = adict.keys()
	# 倒叙
	keys.sort(reverse=True)

	result = collections.OrderedDict()
	for key in keys:
		result[key] = adict[key]

	return result

# open html flie
def open_html(file):
	try:
		idp_list =[]
		with open(file,'r') as f:
			content = f.read()
	except Exception,e:
		print "read html file error." , e
		exit()
	return content

# get idp list
def get_idp_list(data):
	idp_list =[]
	idps = re.findall('<li style="margin: 0 0 10px 0; color: #000000;"><a href="#(idp\d+?)">((25[0-5]|2[0-4]\d|((1\d{2})|([1-9]?\d)))\.){3}(25[0-5]|2[0-4]\d|((1\d{2})|([1-9]?\d)))</a></li>',data)
	num = 0
	for idp in idps:
		num += 1
		idp_list.append(idp[0])
	print u"开始处理",num,u"个IP..."
	return idp_list

# parse html
def parse_html(data, idpList):
	num = 0
	result = {}
	info_result = {}
	# 无序转有序
	result = collections.OrderedDict()
	info_result = collections.OrderedDict()
	idp_len = len(idpList)
	if 0 == idp_len:
		print "read ipd list error."
		exit()
	for k in xrange(idp_len):
		if k == (idp_len - 1):
			content = re.findall('<div xmlns="" id="'+idpList[k]+'"[\s\S]*?>Remediations</h6>', data)
		else :
			content = re.findall('<div xmlns="" id="'+idpList[k]+'" .*?></div>[\s\S]*?<div xmlns="" id="'+idpList[k+1]+'"', data)
		for detail in content:
			crit = 0
			high = 0
			medium = 0
			low = 0
			leak_sum = 0
			port_list_slice = []
			port_list_str = []
			risk_score = u'0'
			risk_type = u'比较安全'
			if "" == detail.strip():
				continue
			port_list = []
			leak_list = []
			leak_map = {}
			# get ip
			ip_re = re.findall('<td class="#ffffff">IP:</td>[\s\S]*?([0-9.]+)</td>', detail)
			ip = ''
			if 0 != len(ip_re):
				ip = ip_re[0]

			# get port list
			port_re = re.findall('<h2>(tcp|udp|icmp)/(\d+)</h2>', detail)
			if 0 != len(port_re):
				for port in port_re:
					#print port
					if '0' == port[1]:
						continue
					elif 'udp' == port[0]:
						port_list.append(port[1]+'(udp)')
					else:
						port_list.append(port[1])	

			#print port_list_str
			port_list = list(set(port_list))
			seg = ','
			port_list_str = seg.join(port_list)
			#print port_list_str
			# get leak list
			leak_re = re.findall('<div xmlns="" id="(idp\d+)".*?background: (.*?)font-weight.*?toggleSection.*this.style.cursor=\'pointer\'">\d+ - (.*?)<div id=[\s\S]*?</div>', detail)
			if 0 != len(leak_re):
				for leak in leak_re:
					#print leak
					if "#0071b9;" != leak[1].strip():
						leak_list.append(leak)
						if "#d43f3a;" == leak[1].strip():
							crit += 1
						elif "#ee9336;" == leak[1].strip():
							high += 1
						elif "#fdc431;" == leak[1].strip():
							medium += 1
						elif "#3fae49;" == leak[1].strip():
							low += 1

			leak_sum = crit + high + medium + low

			level_re = re.findall('<div style="line-height: 20px; padding: 0 0 20px 0;">(Low|Medium|High|Critical)<div class="clear"></div>', detail)
			if 0 != len(level_re):
				max_level = 0
				for level in level_re:
					if 'Low' == level:
						level_score = 1
					elif 'Medium' == level:
						level_score = 2
					elif 'High' == level:
						level_score = 3
					elif 'Critical' == level:
						level_score = 4
					if level_score > max_level:
						max_level = level_score
				if 1 == max_level:
					risk_type = u'低度危险'
				elif 2 == max_level:
					risk_type = u'中度危险'
				elif 3 == max_level:
					risk_type = u'高度危险'
				elif 4 == max_level:
					risk_type = u'极度危险' 
			# get cvss score
			score_re = re.findall('CVSS Base Score[\s\S]+?<div style="line-height: 20px; padding: 0 0 20px 0;">(\d+[.]\d+) \(CVSS2', detail)
			if 0 != len(score_re):
				max_score = 0
				for score in score_re:
					#print ip, score
					if string.atof(score) > max_score:
						max_score = string.atof(score)
				
				risk_score = bytes(max_score)
			#print ip, risk_score
			leak_map["ip"] = ip
			leak_map["sum"] = leak_sum
			leak_map["crit"] = crit
			leak_map["high"] = high
			leak_map["medium"] = medium
			leak_map["low"] = low
			leak_map["port_list"] = port_list_str
			leak_map["score"] = risk_score
			leak_map["risk"] = risk_type
			num += 1

			#print ip, leak_map
			result[ip] = leak_map

	#print result
	return result

# create excel file 
def create_excel():
	try:
		excel = Workbook()		
		return excel
	except Exception,e:
		print str(e)

# write excel
def write_excel(excel, data):
	try:
		excel.col(0).width = 6 * 256
		excel.col(1).width = 15 * 256
		excel.col(2).width = 12 * 256
		excel.col(3).width = 12 * 256
		excel.col(4).width = 12 * 256
		excel.col(5).width = 12 * 256
		excel.col(6).width = 12 * 256
		excel.col(7).width = 25 * 256
		excel.col(8).width = 12 * 256
		excel.col(9).width = 12 * 256
		len_data = len(data)
		if 0 == len_data:
			print "empty data."
			return
		row = 0
		#num = 0
		excel.write(row, 0, u'序号', headStyle)
		excel.write(row, 1, u'IP地址', headStyle)
		excel.write(row, 2, u'漏洞总数', headStyle)
		excel.write(row, 3, u'极度危险漏洞', headStyle)
		excel.write(row, 4, u'高危险漏洞', headStyle)
		excel.write(row, 5, u'中危险漏洞', headStyle)
		excel.write(row, 6, u'低危险漏洞', headStyle)
		excel.write(row, 7, u'开放端口', headStyle)
		excel.write_merge(row, row, 7, 8)
		excel.write(row, 8, '', headStyle)
		excel.write(row, 9, u'CVSS评分', headStyle)
		excel.write(row, 10, u'安全状态', headStyle)
		for ip in data:
			#num += 1
			#print num
			detail = data[ip]

			# 构造列表
			row += 1
			excel.write(row, 0, row, style)
			excel.write(row, 1, detail['ip'], style)
			excel.write(row, 2, detail['sum'], style)
			excel.write(row, 3, detail['crit'], style)
			excel.write(row, 4, detail['high'], style)
			excel.write(row, 5, detail['medium'], style)
			excel.write(row, 6, detail['low'], style)
			excel.write_merge(row, row, 7, 8)
			excel.write(row, 7, detail['port_list'], portStyle)
			excel.write(row, 8, '', portStyle)
			excel.write(row, 9, detail['score'], style)
			excel.write(row, 10, detail['risk'], style)
				
	except Exception,e:
		print str(e)
	
def main():
	argc = len(sys.argv)
	if argc <= 1:
		print "Input html file "
	else:
		print "==== start ===="
		content = open_html(sys.argv[1])
		idp_list = get_idp_list(content)
		data = parse_html(content, idp_list)

		excel = create_excel()
		table = excel.add_sheet('result')

		write_excel(table, data)	
			
		excel.save('result_'+sys.argv[1].split('.')[0]+'_stat.xls')
		print 'Success Output File: result_'+sys.argv[1].split('.')[0]+'_stat.xls'
		print "==== end ===="
		return sys.argv[1].split('.')[0]+'.xls'
		
	
if __name__=="__main__":
	main()
