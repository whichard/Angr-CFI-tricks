#!/usr/bin/env python
#coding=utf-8

' CFI漏洞自动发掘  '

__author__ = 'whichard'
import sys
import nose
import logging
import os
import string
import angr
import claripy
import time
import sys
import re
#from angrutils import *
import pdb
import copy
from simuvex import abihint_global_list as agl

if __name__=='__main__':
	#File=sys.argv[1]
	#b = angr.Project("File", load_options={'auto_load_libs': False})
	b = angr.Project("overflow", load_options={'auto_load_libs': False})#indirect_call
	cfg=b.analyses.CFGAccurate(keep_state=True,enable_symbolic_back_traversal = True)  
	f=open('CFGnodes.txt','w')  
	print >>f,cfg.nodes()
	f=open('CFGnodes.txt','r')
	line=f.read()
	nodes=line.split(',') 
	#print nodes
	s1=[]
	for node in nodes:
	    s=re.findall('[(](0x.*)[)]',node)
	    if s:
		#print s
		s1.append(s[0])
	blocks=s1

	def findrip(block):
	    irsb = b.factory.block(block).vex
	#save irsb.pp() result to irsb.log
	    origin = sys.stdout
	    f = open('irsb.log', 'w')
	    sys.stdout = f
	    irsb.pp()
	    sys.stdout = origin
	    f.close()
	#save irsb.pp() result to irsb.log
	    f = open('irsb.log', 'r')
	    lines = f.readlines()
	    for line in lines:
		s=re.findall('NEXT: PUT[(]rip[)] = (.*);',line)
		s1=re.findall('if.*PUT[(]rip[)] = (.*)L',line)
		if s1:
		    for s2 in s1:
			#print 'a if at'
			#print s2
			find0=s2
	    	        find0x=re.findall('(0x.*)',find0)
	    	        findt=re.findall('(t.*)',find0)
			if find0x:
			    find0x1=int(find0x[0],16)
			    findrip(find0x1)
	    	        if findt:
			    #print 'indirect call at:'
			    #print findt
	       		    #print hex(block)	
			    set0.add(hex(block))	   
		if s:
		    find0=s
	    	    find0x=re.findall('(0x.*)',find0[0])
	    	    findt=re.findall('(t.*)',find0[0])
		    if find0x:
			find0x1=int(find0x[0],16)
			findrip(find0x1)
	   	    if findt:
			#print 'indirect call at:'
			#print findt
			#print hex(block)
			set0.add(hex(block))

	set0=set([])
	angrMemoErr=[]
	#set0 is a set, used to save blocks found
	for block in blocks:
	    #print block
	    try:
		findrip(int(block,16))
	    except angr.errors.AngrMemoryError:
		angrMemoErr.append(block)
	if(len(angrMemoErr)>0):
	    print 'angr.errors.AngrMemoryError: No bytes in memory for block starting at:',angrMemoErr
	else :
	    pass
	print 'found indirect-call blocks:',set0
	#
	#
	#task3add
	f=open('CFGedges.txt','w')  
	print >>f,cfg.graph.edges()
	f=open('CFGedges.txt','r')
	line=f.read()
	edges=line.split(',')
	#print edges
	s1=[]
	for edge in edges:
	    s=re.findall('0x\w{5,20}',edge)
	    if s:
		s1.append(s[0])
		#print s
	blocks=s1
	f=open('CFGedge_blocks.txt','w')  
	print >>f,blocks
	f=open('CFGedge_jmp.txt','w') 

	print "looking for vulnerabilities....."
	set_b=[]
	vulnerability=[]
	err_block=[]
	for test_block in set0:
		for i in range(len(blocks)):
		    if(i%2==0):
		    
			if(blocks[i]==test_block):
			    set_b.append(blocks[i+1]) #将跳转地址存到set_b
		#proj=angr.Project('CFI', load_options={'auto_load_libs': False})
	#
	#
	#help_add
		start_pg=b.factory.path_group()	
		#寻找指定地点
		addr=0x400621
		addr=int(test_block,16)
		agl.block_addr.append(addr)
		start_pg.explore(find=addr,num_find=1)
		try:
		    found=start_pg.found[0]
		except IndexError:
		    err_block.append(test_block)
		    continue
		f2=found.step()
		so=claripy.Solver()
		for tmp in agl.need_tmp_value:
		#print "judging the type of temp value..."
		    if tmp.concrete:
			pass#print 'no crash at:',test_block#
		    else:
			for j in range(len(set_b)):
			    	    so.add(tmp!=int(set_b[j],16)) 
				    #print 'constraint:',test_block,set_b[j]
			so.add(agl.now_pc)
			if(so.satisfiable()==True):
			    #print 'vulnerability at:',test_block
			    vulnerability.append(test_block)
		set_b=[]	#每次循环完后初始化
		agl.block_addr=[]
		agl.need_tmp_value=[]
		#print 'another try'

	if(len(err_block)>0):
	    print 'can not find:',err_block,'with path_group'
	else :
	    pass
	if(len(vulnerability)>0):
	    print 'Found CFI Vulnerabilities at:',vulnerability
	else :
	    print 'No CFI Vulnerability found'
		    
		   
