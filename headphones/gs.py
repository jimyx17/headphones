#!/usr/bin/env python


import httplib2
from hashlib import sha1, md5
import json
import random
from uuid import uuid4
import re
import threading


GROOVESHARK_CLIENT = []

gs_lock = threading.Lock()



revTokens = { 'htmlshark': 'greenPlants', 'jsqueue': 'greenPlants'}

basicPackage = {"header":{"client":"htmlshark","clientRevision":"20120830","privacy":0,"country":{"ID":65,"CC1":0,"CC2":1,"CC3":0,"CC4":0,"DMA":0,"IPR":0}}, "method":"", "parameters":{}}

basicHeaders = { "Accept":"application/json",
                 "Accept-Charset":"ISO-8859-1,utf-8;q=0.7,*;q=0.3",
                 "Accept-Encoding":"gzip,deflate,sdch",
                 "Accept-Language":"en-GB,en-US;q=0.8,en;q=0.6",
                 "Connection":"keep-alive",
                 "Content-Type":"text/plain",
                 "Origin":"http://grooveshark.com",
                 "Referer":"http://grooveshark.com/",
                 "User-Agent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.22 (KHTML, like Gecko) Chrome/25.0.1364.172 Safari/537.22"}

def grooveComClient(function):
    global GROOVESHARK_CLIENT
    if len(GROOVESHARK_CLIENT)!=3:
        GROOVESHARK_CLIENT = generateClient()

    def inner(*args, **kargs):
        kargs['groove_client']= GROOVESHARK_CLIENT
        return function(*args, **kargs)
    return inner


def randToken():
   return "%06x"%random.randint(0,16777215)

def createToken(method, curToken, revToken):
    r = randToken()
    data = ":".join([method, curToken, revToken, r])
    s = sha1()
    s.update(data)
    return "%s%s" % (r,s.hexdigest())

def getSecret(ses):
    m = md5()
    m.update(ses)
    return m.hexdigest()

def getSession(http, headers):
    resp = http.request("http://grooveshark.com/", headers=headers)
    return re.findall("PHPSESSID=([^;]+)", resp[0]['set-cookie'])[0]

def generateBasicPayload(http, headers, session, uuid=None):
    payload = basicPackage
    payload['header']['session']=session
    payload['header']['uuid']= uuid if uuid else str(uuid4())
    payload['parameters']={'secretKey':getSecret(session)}
    headers['Cookie']="PHPSESSID=%s;"%session
    return payload, headers

def getInitialToken(http, headers, payload):
    resp = http.request("https://grooveshark.com/more.php?getCommunicationToken", method="POST", body=json.dumps(payload), headers=headers)
    data = json.loads(resp[1])
    return data['result']

def generateClient():
    http = httplib2.Http()
    headers = basicHeaders
    try:
        session = getSession(http, headers)
    except Exception:
        print "Error recogiendo sesion"

    payload,headers = generateBasicPayload(http, headers, session)
    payload['method'] = 'getCommunicationToken'
    initToken = getInitialToken(http, headers, payload)
    return session, initToken, payload['header']['uuid']


@grooveComClient
def search(query, groove_client=None, limit=10):
    http = httplib2.Http()
    headers = basicHeaders
    session, initToken, uuid = groove_client
    payload,headers = generateBasicPayload(http, headers, session, uuid=uuid)
    token = createToken('getResultsFromSearch', initToken, revTokens['htmlshark'])
    payload['method'] = 'getResultsFromSearch'
    payload['header']['token'] = token
    payload['header']['client'] = 'htmlshark'
    payload['parameters'] =  {"query":query,"type":["Songs","Artists","Albums"],"guts":0}
    resp = http.request('http://grooveshark.com/more.php?getStreamKeysFromSongIDs', method  ='POST', body=json.dumps(payload), headers=headers)
    try:
        jresp = json.loads(resp[1])
        jresp = jresp['result']['result']
    except Exception, e:
        jresp = {"result": "ERROR", "reason": "%s" % str(e)}
    return jresp

@grooveComClient
def getAlbumsFromArtist(ArtistId, groove_client=None):
    http = httplib2.Http()
    headers = basicHeaders
    session, initToken, uuid = groove_client
    payload,headers = generateBasicPayload(http, headers, session, uuid=uuid)
    token = createToken('artistGetAllAlbums', initToken, revTokens['htmlshark'])
    payload['method'] = 'artistGetAllAlbums'
    payload['header']['token'] = token
    payload['header']['client'] = 'htmlshark'
    payload['parameters'] =  {"artistID":ArtistId}
    resp = http.request('http://grooveshark.com/more.php?artistGetAllAlbums', method  ='POST', body=json.dumps(payload), headers=headers)
    try:
        jresp = json.loads(resp[1])
    except Exception, e:
        jresp = {"result": "ERROR", "reason": "%s" % str(e)}

    return jresp

@grooveComClient
def getSongsFromArtist(ArtistId, groove_client=None):
    http = httplib2.Http()
    headers = basicHeaders
    session, initToken, uuid = groove_client
    payload,headers = generateBasicPayload(http, headers, session, uuid=uuid)
    token = createToken('artistGetArtistSongs', initToken, revTokens['htmlshark'])
    payload['method'] = 'artistGetArtistSongs'
    payload['header']['token'] = token
    payload['header']['client'] = 'htmlshark'
    payload['parameters'] =  {"artistID":ArtistId}
    resp = http.request('http://grooveshark.com/more.php?artistGetArtistSongs', method  ='POST', body=json.dumps(payload), headers=headers)
    try:
        jresp = json.loads(resp[1])
    except Exception, e:
        jresp = {"result": "ERROR", "reason": "%s" % str(e)}
    return jresp

@grooveComClient
def getSongsFromAlbum(AlbumId, groove_client=None):
    http = httplib2.Http()
    headers = basicHeaders
    session, initToken, uuid = groove_client
    payload,headers = generateBasicPayload(http, headers, session, uuid=uuid)
    token = createToken('albumGetAllSongs', initToken, revTokens['htmlshark'])
    payload['method'] = 'albumGetAllSongs'
    payload['header']['token'] = token
    payload['header']['client'] = 'htmlshark'
    payload['parameters'] =  {"albumID":AlbumId}
    resp = http.request('http://grooveshark.com/more.php?albumGetAllSongs', method  ='POST', body=json.dumps(payload), headers=headers)
    try:
        jresp = json.loads(resp[1])
    except Exception, e:
        jresp = {"result": "ERROR", "reason": "%s" % str(e)}
    return jresp

def downloadSongs(client, songIDs):
    http = httplib2.Http()
    headers = basicHeaders
    session, initToken, uuid = client
    payload,headers = generateBasicPayload(http, headers, session, uuid=uuid)
    token = createToken('getStreamKeysFromSongIDs', initToken, revTokens['jsqueue'])
    payload['method'] = 'getStreamKeysFromSongIDs'
    payload['header']['token'] = token
    payload['header']['client'] = 'jsqueue'
    payload['parameters'] = {"prefetch":False,"jsqueue":True,"songIDs":songIDs,"country":{"ID":65,"CC1":0,"CC2":1,"CC3":0,"CC4":0,"DMA":0,"IPR":0}}
    resp = http.request('http://grooveshark.com/more.php?getStreamKeysFromSongIDs', method  ='POST', body=json.dumps(payload), headers=headers)

    try:
        jresp = json.loads(resp[1])
    except Exception, e:
        jresp = {"result": "ERROR", "reason": "%s" % str(e)}


    token = createToken('markSongDownloadedEx', initToken, revTokens['jsqueue'])
    payload['method'] = 'markSongDownloadedEx'
    payload['header']['token'] = token
    payload['header']['client'] = 'jsqueue'

    datasongs = {}
    for song in jresp['result'].items():
        nid,sid= song
        url = 'http://%s/stream.php?streamKey=%s' % (sid['ip'], sid['streamKey'])
        streamkey = sid['streamKey']
        streamsrvkey = sid['streamServerID']
        data = http.request(url, headers=headers)
        datasongs[str(nid)] = data[1]

        payload['parameters'] = {"streamKey":"%s" % streamkey,"streamServerID":streamsrvkey,"songID":nid}
        resp =  http.request('http://grooveshark.com/more.php?markSongDownloadedEx', method='POST', body=json.dumps(payload), headers=headers)

        try:
            jresp = json.loads(resp[1])
        except Exception, e:
            jresp = {"result": "ERROR", "reason": "%s" % str(e)}
            continue

    return datasongs


