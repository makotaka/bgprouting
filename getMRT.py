#! /usr/bin/python

import datetime
import wget
import os
import sys

sttSvrlist = "/root/work/mrt/serverlist.txt"
strURL = "http://archive.routeviews.org/bgpdata/"
workDir = "/root/work/mrt/"
today = datetime.date.today() + datetime.timedelta(days=-1)
strDate = today.strftime("%Y.%m/UPDATES/updates.%Y%m%d")

for hr in range(0, 24):
  for min in range(0, 4):
    url = '%s%s.%02d%02d.bz2' % (strURL,strDate,hr,min*15)
    wget.download(url,workDir )  

for svr in open(sttSvrlist, 'r'):
  targetDir = workDir+svr.strip()
  if not os.path.isdir(targetDir):
    os.makedirs(targetDir)
  for hr in range(0, 24):
    for min in range(0, 4):
      url = '%s%s.%02d%02d.bz2' % (strURL,strDate,hr,min*15)
      wget.download(url,targetDir )

