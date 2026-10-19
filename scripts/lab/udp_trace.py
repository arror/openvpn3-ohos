#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Disposable UDP relay. Records packet headers/timing only, never payloads."""
import argparse,json,selectors,socket,time

def run(host,listen_port,target_port):
    selector=selectors.DefaultSelector()
    listener=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    listener.bind((host,listen_port));listener.setblocking(False)
    selector.register(listener,selectors.EVENT_READ,None)
    clients={}
    print(json.dumps({'event':'ready','at':time.time(),'listen':listen_port,'target':target_port}),flush=True)
    while True:
        for key,_ in selector.select(.02):
            try:data,source=key.fileobj.recvfrom(65535)
            except OSError as error:
                print(json.dumps({'at':time.time(),'event':'socket_error','errno':error.errno}),flush=True)
                continue
            if key.fileobj is listener:
                client=source
                if client not in clients:
                    upstream=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
                    upstream.connect((host,target_port));upstream.setblocking(False)
                    selector.register(upstream,selectors.EVENT_READ,client);clients[client]=upstream
                clients[client].send(data)
                direction='to_server'
            else:
                client=key.data;direction='to_client'
                listener.sendto(data,client)
            print(json.dumps({'at':time.time(),'direction':direction,'client_port':client[1],'length':len(data),'opcode':data[0]>>3}),flush=True)

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--host',required=True)
    parser.add_argument('--listen',type=int,required=True);parser.add_argument('--target',type=int,required=True)
    args=parser.parse_args();run(args.host,args.listen,args.target)
