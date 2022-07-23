#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
import re
import xlrd
import collections
from pyExcelerator import *
#from operator import itemgetter

reload(sys)
sys.setdefaultencoding("utf-8")

# 全局字体
commonFont = u'宋体'
# 全局样式
# ip-边框样式
ipBorders = Borders()   
ipBorders.bottom = 1 

# 边框样式
borders = Borders()  
borders.left = 1  
borders.right = 1  
borders.top = 1  
borders.bottom = 1  

# ip字体
ipFnt = Font()
ipFnt.size = 12
ipFnt.bold = 1
ipFnt.height = 280
ipFnt.name = commonFont

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

# 头部公共背景色
pattern = Pattern()
pattern.pattern = 4
pattern.pattern_back_colour = 22 # 这儿可以调节背景色

# 漏洞行头部背景色
leakPattern = Pattern()
leakPattern.pattern = 4
leakPattern.pattern_back_colour = 23 # 这儿可以调节背景色

#对齐方式  
al = Alignment()  
al.horz = Alignment.HORZ_CENTER  
al.vert = Alignment.VERT_CENTER

# 头部样式
headStyle = XFStyle()  
headStyle.borders = borders 
headStyle.font = headFnt
headStyle.pattern = pattern

# 漏洞头部样式
leakStyle = XFStyle()  
leakStyle.borders = borders 
leakStyle.font = headFnt
leakStyle.pattern = leakPattern

# ip样式
ipStyle = XFStyle()  
ipStyle.borders = ipBorders 
ipStyle.font = ipFnt

# 列表头部样式
listStyle = XFStyle()  
listStyle.borders = borders 
listStyle.font = fnt
listStyle.pattern = pattern

# 居中样式
centerStyle = XFStyle()  
centerStyle.borders = borders 
centerStyle.font = fnt
centerStyle.alignment = al

# 头部居中样式
headCeStyle = XFStyle()  
headCeStyle.borders = borders 
headCeStyle.font = fnt
headCeStyle.alignment = al
headCeStyle.pattern = pattern

# 公告样式
style = XFStyle()  
style.borders = borders 
style.font = fnt

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

#open port file
def open_port(file='port.txt'):
	dict = {}
	try:
		with open(file,'r') as f:
			for line in f:
				content = line.split("\t")
				dict[content[0]] = content[1].strip().decode("UTF-8")
	except Exception,e:
		print "read port file error."
		exit()

	return dict

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

			#get os
			os_re = re.findall('<td class="#ffffff">OS:</td>[\s\S]*?<td class="#ffffff">(.*?)</td>', detail)
			os = ''
			if 0 != len(os_re):
				os = os_re[0]

			# get port list
			port_re = re.findall('<h2>(tcp|udp|icmp)/(\d+)</h2>', detail)
			if 0 != len(port_re):
				for port in port_re:
					port_list.append(port)
					#del repeat port
					port_list = list(set(port_list))
			
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

			leak_map["ip"] = ip
			leak_map["os"] = os
			leak_map["port"] = port_list
			leak_map["leak"] = leak_list
			num += 1

			map_key = bytes(crit)+bytes(high)+bytes(medium)+bytes(low)
			#print ip, map_key
			if '0000' == map_key:
				info_result[ip] = leak_map
			else:
				result[map_key+ip] = leak_map
	
	result = sortedDictValues(result)
	info_result = sortedDictValues(info_result)
	result = merge_dicts(result, info_result)
	return result

# create excel file 
def create_excel():
	try:
		excel = Workbook()		
		return excel
	except Exception,e:
		print str(e)

# write excel
def write_excel(excel, data, leak_only):
	try:
		excel.col(0).width = 6 * 256
		excel.col(1).width = 8 * 256
		excel.col(2).width = 8 * 256
		len_data = len(data)
		if 0 == len_data:
			print "empty data."
			return
		port_detail = open_port()
		row = 0
		#num = 0
		for ip in data:
			#num += 1
			#print num
			detail = data[ip]
			if 0 == len(detail['leak']) and '1' == leak_only:
				continue
			excel.write(row, 0, detail['ip'].encode('utf8'), ipStyle)
			for i in range(7):
				excel.write(row, i+1, '', ipStyle)
			excel.write_merge(row, row, 0, 7)

			row += 1
			excel.write(row, 0, u'基本信息', headStyle)
			for i in range(7):
				excel.write(row, i+1, '', headStyle)
			excel.write_merge(row, row, 0, 7)

			row += 1
			excel.write(row, 0, u'资产名称', listStyle)
			excel.write(row, 1, '', listStyle)
			excel.write_merge(row, row, 0, 1)
			excel.write(row, 2, '', style)
			excel.write(row, 3, '', style)
			excel.write_merge(row, row, 2, 3)
			excel.write(row, 4, u'所属部门', listStyle)
			excel.write(row, 5, '', listStyle)
			excel.write_merge(row, row, 4, 5)
			excel.write_merge(row, row, 6, 7)
			excel.write(row, 6, '', style)
			excel.write(row, 7, '', style)

			row += 1
			excel.write(row, 0, u'资产类型', listStyle)
			excel.write(row, 1, '', listStyle)
			excel.write_merge(row, row, 0, 1)
			excel.write(row, 2, u'个人办公', style)
			excel.write(row, 3, '', style)
			excel.write_merge(row, row, 2, 3)
			excel.write(row, 4, u'主机名', listStyle)
			excel.write(row, 5, '', style)
			excel.write_merge(row, row, 4, 5)
			excel.write_merge(row, row, 6, 7)
			excel.write(row, 6, '', style)
			excel.write(row, 7, '', style)

			row += 1
			excel.write(row, 0, u'操作系统信息', listStyle)
			excel.write_merge(row, row, 0, 1)
			excel.write(row, 1, '', listStyle)
			excel.write(row, 2, detail['os'].encode('utf8'), style)
			excel.write_merge(row, row, 2, 7)
			for i in range(5):
				excel.write(row, i+3, '', style)

			row += 1
			excel.write(row, 0, u'服务列表', headStyle)
			excel.write_merge(row, row, 0, 7)
			for i in range(7):
				excel.write(row, i+1, '', headStyle)

			row += 1
			excel.write(row, 0, u'序号', headCeStyle)
			excel.write(row, 1, u'端口', headCeStyle)
			excel.write(row, 2, u'协议', headCeStyle)
			excel.write(row, 3, u'描述', listStyle)
			excel.write_merge(row, row, 3, 7)
			for i in range(4):
				excel.write(row, i+4, '', listStyle)

			# 构造服务列表
			if 0 != len(detail['port']):
				port_no = 0
				for port_k in xrange(len(detail['port'])):
					# 过滤0端口
					if "0" == detail['port'][port_k][1].strip():
						continue
					row += 1
					port_no += 1
					excel.write(row, 0, port_no, centerStyle)
					excel.write(row, 1, detail['port'][port_k][1].decode('utf8'), centerStyle)
					excel.write(row, 2, detail['port'][port_k][0].encode('utf8'), centerStyle)
					if port_detail.has_key(detail['port'][port_k][1].strip()):
						excel.write(row, 3, port_detail[detail['port'][port_k][1].strip()], style)
					else:
						excel.write(row, 3, u'未知端口', style)
					excel.write_merge(row, row, 3, 7)
					for i in range(4):
						excel.write(row, i+4, '', style)
			else:
				row += 1
				excel.write_merge(row, row, 0, 7)
				for i in range(8):
					excel.write(row, i, '', style)

			# 构造漏洞列表
			row += 1
			excel.write(row, 0, u'漏洞列表', leakStyle)
			for i in range(7):
				excel.write(row, i+1, '', leakStyle)
			excel.write_merge(row, row, 0, 7)

			row += 1
			excel.write(row, 0, u'序号', headCeStyle)
			excel.write(row, 1, u'漏洞名称', listStyle)
			excel.write_merge(row, row, 1, 5)
			for i in range(4):
				excel.write(row, i+2, '', listStyle)
			excel.write(row, 6, u'漏洞分类', listStyle)
			excel.write(row, 7, u'危险级别', listStyle)

			if 0 != len(detail['leak']):
				for leak_k in xrange(len(detail['leak'])):
					row += 1
					excel.write(row, 0, leak_k+1, centerStyle)
					excel.write(row, 1, detail['leak'][leak_k][2].encode('utf8'), style)
					excel.write_merge(row, row, 1, 5)
					for i in range(4):
						excel.write(row, i+2, '', style)				
					excel.write(row, 6, '', style)
					if "#d43f3a;" == detail['leak'][leak_k][1].strip():
						excel.write(row, 7, u'严重', style)
					elif "#ee9336;" == detail['leak'][leak_k][1].strip():
						excel.write(row, 7, u'高', style)
					elif "#fdc431;" == detail['leak'][leak_k][1].strip():
						excel.write(row, 7, u'中', style)
					elif "#3fae49;" == detail['leak'][leak_k][1].strip():
						excel.write(row, 7, u'低', style)
								
			else:
				row += 1
				excel.write_merge(row, row, 0, 7)
				for i in range(8):
					excel.write(row, i, '', style)
			row += 2
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

		# 命令行第2个参数表示是否只导出有漏洞的IP列表
		try:
			leak_only = '0'
			if sys.argv[2] > '0':
				leak_only = '1'
		except Exception,e:
			leak_only = '0'

		write_excel(table, data, leak_only)	
			
		excel.save('result_'+sys.argv[1].split('.')[0]+'.xls')
		print 'Success Output File: result_'+sys.argv[1].split('.')[0]+'.xls'
		print "==== end ===="
		return sys.argv[1].split('.')[0]+'.xls'
		
	
if __name__=="__main__":
	main()
