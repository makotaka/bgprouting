#! /usr/bin/python

import datetime
import wget
import os
import sys

sttSvrlist = "/root/work/mrt/serverlist.txt"
strURL = "http://archive.routeviews.org/bgpdata/"
workDir = "/root/work/full/"
today = datetime.date.today() + datetime.timedelta(days=-1)
strDate = today.strftime("%Y.%m/RIBS/rib.%Y%m%d")

url = '%s%s.%02d%02d.bz2' % (strURL,strDate,22,00)
wget.download(url,workDir )  

for svr in open(sttSvrlist, 'r'):
  targetDir = workDir+svr.strip()
  if not os.path.isdir(targetDir):
    os.makedirs(targetDir)
  url = '%s%s.%02d%02d.bz2' % (strURL,strDate,22,00)
  wget.download(url,targetDir )

