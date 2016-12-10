#!/usr/b in/env python

import sys, argparse, copy
from datetime import *
from mrtparse import *
import json

peer = None
asns_org = ["16509","45102","8075","15169","36351","54825","9370"]
flgASN = True
#flgASN = False

def parse_args():
    p = argparse.ArgumentParser(
        description='This script converts to bgpdump format.')
    p.add_argument(
        '-m', dest='verbose', default=False, action='store_true',
        help='one-line per entry with unix timestamps')
    p.add_argument(
        '-A', dest='as_list', nargs='?', metavar='file',
        type=argparse.FileType('r'),
        help='target ASN list')
    p.add_argument(
        '-M', dest='verbose', action='store_false',
        help='one-line per entry with human readable timestamps(default format)')
    p.add_argument(
        '-O', dest='output', default=sys.stdout, nargs='?', metavar='file',
        type=argparse.FileType('w'),
        help='output to a specified file')
    p.add_argument(
        '-s', dest='output', action='store_const', const=sys.stdout,
        help='output to STDOUT(default output)')
    p.add_argument(
        '-v', dest='output', action='store_const', const=sys.stderr,
        help='output to STDERR')
    p.add_argument(
        '-t', dest='ts_format', default='dump', choices=['dump', 'change'],
        help='timestamps for RIB dumps reflect the time of the dump \
            or the last route modification(default: dump)')
    p.add_argument(
        '-p', dest='pkt_num', default=False, action='store_true',
        help='show packet index at second position')
    p.add_argument(
        'path_to_file',
        help='specify path to MRT format file')
    return p.parse_args()

class BgpDump:
    __slots__ = [
        'verbose', 'output', 'ts_format', 'pkt_num', 'type', 'num', 'ts',
        'org_time', 'flag', 'peer_ip', 'peer_as', 'nlri', 'withdrawn',
        'as_path', 'origin', 'next_hop', 'local_pref', 'med', 'comm',
        'atomic_aggr', 'aggr', 'as4_path', 'as4_aggr', 'old_state', 'new_state',
        'as_list',
    ]

    def __init__(self, args):
        self.verbose = args.verbose
        self.output = args.output
        self.ts_format = args.ts_format
        self.pkt_num = args.pkt_num
        self.type = ''
        self.num = 0
        self.ts = 0
        self.org_time = 0
        self.flag = ''
        self.peer_ip = ''
        self.peer_as = 0
        self.nlri = []
        self.withdrawn = []
        self.as_path = []
        self.origin = ''
        self.next_hop = []
        self.local_pref = 0
        self.med = 0
        self.comm = ''
        self.atomic_aggr = 'NAG'
        self.aggr = ''
        self.as4_path = []
        self.as4_aggr = ''
        self.old_state = 0
        self.new_state = 0
        self.as_list = args.as_list 
    def bgp4mpJson(self, m, count,jsOut):
        objBGP = {}
        objBGP["type"] = 'BGP4MP'
        objBGP["timestamp"] = str(m.ts)
        objBGP["num"] = count
        objBGP["org_time"] = str(m.ts)
        objBGP["peer_ip"] = m.bgp.peer_ip
        objBGP["peer_as"] = m.bgp.peer_as
        if (m.subtype == BGP4MP_ST['BGP4MP_STATE_CHANGE']
            or m.subtype == BGP4MP_ST['BGP4MP_STATE_CHANGE_AS4']):
            objBGP["flag"] = 'STATE'
            objBGP["old_state"] = m.bgp.old_state
            objBGP["new_state"] = m.bgp.new_state
        elif (m.subtype == BGP4MP_ST['BGP4MP_MESSAGE']
            or m.subtype == BGP4MP_ST['BGP4MP_MESSAGE_AS4']
            or m.subtype == BGP4MP_ST['BGP4MP_MESSAGE_LOCAL']
            or m.subtype == BGP4MP_ST['BGP4MP_MESSAGE_AS4_LOCAL']):
            if m.bgp.msg.type != BGP_MSG_T['UPDATE']:
                return
            for attr in m.bgp.msg.attr:
                self.bgp_attr_obj(objBGP, attr)
            for withdrawn in m.bgp.msg.withdrawn:
                if 'withdrawn' in objBGP: 
                   objBGP["withdrawn"].append(
                       '%s/%d' % (withdrawn.prefix, withdrawn.plen))
                else:
                   objBGP["withdrawn"] = ['%s/%d' % (withdrawn.prefix, withdrawn.plen)] 
            for nlri in m.bgp.msg.nlri:
                if 'nlri' in objBGP: 
                   objBGP["nlri"].append('%s/%d' % (nlri.prefix, nlri.plen))
                else:
                   objBGP["nlri"] = ['%s/%d' % (nlri.prefix, nlri.plen)]
#            if 'as_path' in objBGP:
#               objBGP["as_path_dic"] = dict(zip(range(len(objBGP["as_path"]),0,-1), objBGP["as_path"]))
            if flgASN:
               if "as_path_dic" in  objBGP:
                  if 1 in objBGP["as_path_dic"]: 
                     asns = asns_org
                     for asn in asns: 
                        if objBGP["as_path_dic"][1] == asn: 
                           strJson = json.dumps(objBGP, ensure_ascii=False)
                           print (strJson)
            else:
               strJson = json.dumps(objBGP, ensure_ascii=False)
               print(strJson) 
    def bgp_attr_obj(self, obj, attr):
        if attr.type == BGP_ATTR_T['ORIGIN']:
            obj["origin"] = ORIGIN_T[attr.origin]
        elif attr.type == BGP_ATTR_T['NEXT_HOP']:
            if 'next_hop' in obj:
                obj["next_hop"].append(attr.next_hop)
            else:
                obj["next_hop"] = attr.next_hop 
        elif attr.type == BGP_ATTR_T['AS_PATH']:
            obj["as_path"] = []
            for seg in attr.as_path:
                if seg['type'] == AS_PATH_SEG_T['AS_SET']: 
                    obj["as_path"].append('{%s}' % ','.join(seg['val']))
                elif seg['type'] == AS_PATH_SEG_T['AS_CONFED_SEQUENCE']:
                    obj["as_path"].append('(' + seg['val'][0])
                    obj["as_path"] += seg['val'][1:-1]
                    obj["as_path"].append(seg['val'][-1] + ')')
                elif seg['type'] == AS_PATH_SEG_T['AS_CONFED_SET']:
                    obj["as_path"].append('[%s]' % ','.join(seg['val']))
                else:
                    obj["as_path"] += seg['val']
            if 'as_path' in obj:
                obj["as_path_dic"] = dict(zip(range(len(obj["as_path"]),0,-1), obj["as_path"]))
#            if self.as_list:
#                asns = self.as_list.readlines()
#                for asn in asns:
#                   print asn.strip()
#                   print obj["as_path_dic"][1] 
#                   if asn.strip() == obj["as_path_dic"][1]:
#                       return
#                obj["as_path_dic"] = []    
        elif attr.type == BGP_ATTR_T['MULTI_EXIT_DISC']:
            obj["med"] = attr.med
        elif attr.type == BGP_ATTR_T['LOCAL_PREF']:
            obj["local_pref"] = attr.local_pref
        elif attr.type == BGP_ATTR_T['ATOMIC_AGGREGATE']:
            obj["atomic_aggr"] = 'AG'
        elif attr.type == BGP_ATTR_T['AGGREGATOR']:
            obj["aggr"] = '%s %s' % (attr.aggr['asn'], attr.aggr['id'])
        elif attr.type == BGP_ATTR_T['COMMUNITY']:
            obj["comm"] = ' '.join(attr.comm)
        elif attr.type == BGP_ATTR_T['MP_REACH_NLRI']:
            obj["next_hop"] = attr.mp_reach['next_hop']
            if obj["type"] != 'BGP4MP':
                return
            for nlri in attr.mp_reach['nlri']:
                if 'nlri' in obj:
                   obj["nlri"].append('%s/%d' % (nlri.prefix, nlri.plen))
                else:
                   obj["nlri"] = ['%s/%d' % (nlri.prefix, nlri.plen)] 
        elif attr.type == BGP_ATTR_T['MP_UNREACH_NLRI']:
            if obj["type"] != 'BGP4MP':
                return
            for withdrawn in attr.mp_unreach['withdrawn']:
                if 'withdrawn' in obj: 
                   obj["withdrawn"].append(
                       '%s/%d' % (withdrawn.prefix, withdrawn.plen))
                else:
                   obj["withdrawn"] = ['%s/%d' % (withdrawn.prefix, withdrawn.plen)]
        elif attr.type == BGP_ATTR_T['AS4_PATH']:
            obj["as4_path"] = []
            for seg in attr.as4_path:
                if seg['type'] == AS_PATH_SEG_T['AS_SET']:
                    if 'as4_path' in obj:   
                       obj["as4_path"].append('{%s}' % ','.join(seg['val']))
                    else:
                       obj["as4_path"]= ['{%s}' % ','.join(seg['val'])]
                elif seg['type'] == AS_PATH_SEG_T['AS_CONFED_SEQUENCE']:
                    obj["as4_path"].append('(' + seg['val'][0])
                    obj["as4_path"] += seg['val'][1:-1]
                    obj["as4_path"].append(seg['val'][-1] + ')')
                elif seg['type'] == AS_PATH_SEG_T['AS_CONFED_SET']:
                    obj["as4_path"].append('[%s]' % ','.join(seg['val']))
                else:
                    obj["as4_path"] += seg['val']
        elif attr.type == BGP_ATTR_T['AS4_AGGREGATOR']:
            obj["as4_aggr"] = '%s %s' % (attr.as4_aggr['asn'], attr.as4_aggr['id'])

def main():
    args = parse_args()
    d = Reader(args.path_to_file)
    count = 0
    jOut = {} 
    for m in d:
        m = m.mrt
        if m.err:
            continue
        b = BgpDump(args)
        if m.type == MRT_T['BGP4MP']:
            b.bgp4mpJson( m, count, jOut)
            count += 1
#        if count == 10000:
#            strJson = json.dumps(jOut, ensure_ascii=False)
#            print(strJson)
#            return

if __name__ == '__main__':
    main()
