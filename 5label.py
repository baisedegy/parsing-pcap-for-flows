#coding:utf-8
import binascii as ba
import numpy as np
import csv

try:
    from scapy.all import *
    import scapy.all as scapy
except ImportError:
    import scapy

try:
    # This import works from the project directory
    import scapy_http.http
except ImportError:
    # If you installed this package via pip, you just need to execute this
    from scapy.layers import http

packets = scapy.rdpcap('/Users/macbookpro/Documents/script/python/DATA/TSL/TSL20170403-01_Mantis_MantisBT_Bug_Tracker_adm_config_report_php_move_attachments_page_php_XSS/normal.pcap')
# f =open("/Users/macbookpro/Documents/script/python/DATA/TSL/TSL20170403-01_Mantis_MantisBT_Bug_Tracker_adm_config_report_php_move_attachments_page_php_XSS/result.txt","w+")

def compare_list(list1,list2):
    if (list1[0]==list2[0]) and (((list1[1]==list2[1] and list1[2]==list2[2]) and(list1[3]==list2[3] and list1[4]==list2[4]))\
        or ((list1[1]==list2[2] and list1[2]==list2[1]) and (list1[3]==list2[4] and list1[4]==list2[3]))):
        return True
    else:
        return False
flow_label=[]
diction=[]
value=[]
p_num=[]
for pkt in packets:
    if not isinstance(pkt.payload, NoPayload) and not isinstance(pkt.payload.payload, NoPayload) and \
        not isinstance(pkt.payload.payload.payload, NoPayload):
        temp = pkt.payload.payload.payload.original
        value.append(ba.hexlify(temp).decode())
        #print(ba.hexlify(temp).decode())
        #flag.append(1)       
    else:
        value.append(0)
num=0
for pkt in packets:
    try:
        dic = []
        dic.append(pkt[1].proto)
        dic.append(pkt[1].dst)
        dic.append(pkt[1].src)
        dic.append(pkt[1].sport)
        dic.append(pkt[1].dport)
        dic.append(str(pkt[2].flags))
        dic.append(num)
        diction.append(dic)
        num+=1
    except AttributeError:
        continue
# print(diction)
for i in range(len(diction)):
    p_num.append(i)
flow=[]
while(p_num):    
    flow.append(p_num[0])
    for i in range(len(p_num)):
        if i < len(p_num)-1:
            if compare_list(diction[p_num[0]],diction[p_num[i+1]])==True:
                flow.append(p_num[i+1])
        else:
            pass
    for i in flow:
        p_num.remove(i)
    flow_label.append(flow)
    flow=[]
# print(flow_label)

flow=[]
flow_result=[]
for i in range(len(flow_label)):
    for j in range(len(flow_label[i])):
        flow.append(flow_label[i][j])
        if (j+1 < len(flow_label[i])) and ('S' == diction[flow_label[i][j+1]][5]):
            flow_result.append(flow)
            flow=[]
    flow_result.append(flow)
    flow=[]
print(flow_result)

def str2int(list):
    firstbyte=ord(list[0])
    secondbyte=ord(list[1])
    if firstbyte>96:
        firstbyte=firstbyte-87
    else:
        firstbyte=firstbyte-48
    if secondbyte>96:
        secondbyte=secondbyte-87
    else:
        secondbyte=secondbyte-48
    return firstbyte*10+secondbyte

results=[]
for aa in range(len(value)):
    #results.append([])
    if value[aa]==0:
        results.append(0)
    else:
        results.append(['00' for i in range(1600)])
for i in range(len(value)):
    if results[i]==0:
        continue
    else:
        for j in range(0,len(value[i]),2):
            try:
                byte_str=value[i][j]+value[i][j+1]
                results[i][int(j/2)]=byte_str
            except IndexError:
                pass

flow_numbers=[]
for i in range(len(flow_result)):
    for j in range(len(flow_result[i])):
        flow_numbers.append(i+1)
print(flow_numbers)

for i in range(len(results)):
    if results[i]==0:
        continue
    else:
        for j in range(len(results[i])):
            results[i][j]=str2int(results[i][j]) 
        results[i].append(0)
        results[i].append(1)
        results[i].append(flow_numbers[i])
# print(results)

handled_file='/Users/macbookpro/Downloads/TSL_flowlabel_csv/2/normal/normal.csv'
data_file=open(handled_file,'w+',newline='')
for i in range(len(results)):
    print(i)
    if results[i]==0:
        continue
    else:
        csv_writer=csv.writer(data_file)
        csv_writer.writerow(results[i])
#p.show()

